/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::c_void;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::os::raw::c_int;
use std::str::FromStr;

use bstr::{BStr, BString, ByteSlice};
use itertools::Itertools;
use percent_encoding::percent_decode;
use sha1::{Digest, Sha1};
use url::Url;

use crate::hg_bundle::copy_bundle;
use crate::hg_connect_http::get_http_connection;
use crate::hg_connect_stdio::get_stdio_connection;
use crate::libcinnabar::send_buffer_to;
use crate::oid::ObjectId;
use crate::store::HgChangesetId;
use crate::util::SliceExt;

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct hg_connection(c_void);

pub struct OneHgArg<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

pub struct HgArgs<'a> {
    pub args: &'a [OneHgArg<'a>],
    pub extra_args: Option<&'a [OneHgArg<'a>]>,
}

#[macro_export]
macro_rules! args {
    ($($n:ident : $v:expr,)* $(*: $a:expr)?) => {
        HgArgs {
            args: $crate::args!(@args $($n:$v),*),
            extra_args: $crate::args!(@extra $($a)?),
        }
    };
    ($($n:ident : $v:expr),*) => { $crate::args!($($n:$v,)*) };
    (@args $($n:ident : $v:expr),*) => {&[
        $(OneHgArg { name: stringify!($n), value: $v }),*
    ]};
    (@extra) => { None };
    (@extra $a:expr) => { Some($a) };
}

#[derive(Default)]
pub struct HgCapabilities {
    capabilities: Vec<(BString, BString)>,
}

impl HgCapabilities {
    /* Split the list of capabilities a mercurial server returned. Also url-decode
     * the bundle2 value (TODO: in place). */
    pub fn new_from(buf: &[u8]) -> Self {
        let mut capabilities = Vec::new();
        for item in buf.split(|&b| b == b' ') {
            let (name, value) = match item.find_byte(b'=') {
                Some(off) => {
                    let (name, value) = item.split_at(off);
                    (name, &value[1..])
                }
                None => (item, &b""[..]),
            };
            capabilities.push((
                BString::from(name.to_owned()),
                if name == b"bundle2" {
                    BString::from(percent_decode(value).collect::<Vec<_>>())
                } else {
                    BString::from(value.to_owned())
                },
            ));
        }
        HgCapabilities { capabilities }
    }

    pub fn get_capability(&self, needle: &[u8]) -> Option<&BStr> {
        for (name, value) in self.capabilities.iter() {
            if name == needle {
                return Some(value.as_ref());
            }
        }
        None
    }
}

pub trait HgConnectionBase {
    fn get_capability(&self, _name: &[u8]) -> Option<&BStr> {
        None
    }
}

pub trait HgWireConnection: HgConnectionBase {
    fn simple_command(&mut self, command: &str, args: HgArgs) -> Box<[u8]>;

    fn changegroup_command(&mut self, out: &mut (dyn Write + Send), command: &str, args: HgArgs);

    fn push_command(&mut self, input: File, command: &str, args: HgArgs) -> Box<[u8]>;
}

pub trait HgConnection: HgConnectionBase {
    fn wire(&mut self) -> Option<&mut dyn HgWireConnection> {
        None
    }

    fn listkeys(&mut self, _namespace: &str) -> Box<[u8]> {
        unimplemented!();
    }

    fn getbundle(
        &mut self,
        _out: &mut (dyn Write + Send),
        _heads: &[HgChangesetId],
        _common: &[HgChangesetId],
        _bundle2caps: Option<&str>,
    ) {
        unimplemented!();
    }

    fn lookup(&mut self, _key: &str) -> Box<[u8]> {
        unimplemented!();
    }
}

impl HgConnectionBase for Box<dyn HgWireConnection> {
    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        (**self).get_capability(name)
    }
}

impl HgConnection for Box<dyn HgWireConnection> {
    fn wire(&mut self) -> Option<&mut dyn HgWireConnection> {
        Some(&mut **self)
    }

    fn listkeys(&mut self, namespace: &str) -> Box<[u8]> {
        self.simple_command("listkeys", args!(namespace: namespace))
    }

    fn getbundle(
        &mut self,
        out: &mut (dyn Write + Send),
        heads: &[HgChangesetId],
        common: &[HgChangesetId],
        bundle2caps: Option<&str>,
    ) {
        let mut args = Vec::new();
        let heads = heads.iter().join(" ");
        let common = common.iter().join(" ");
        args.push(OneHgArg {
            name: "heads",
            value: &heads,
        });
        args.push(OneHgArg {
            name: "common",
            value: &common,
        });
        if let Some(caps) = bundle2caps {
            if !caps.is_empty() {
                args.push(OneHgArg {
                    name: "bundlecaps",
                    value: caps,
                });
            }
        }
        self.changegroup_command(out, "getbundle", args!(*: &args[..]));
    }

    fn lookup(&mut self, key: &str) -> Box<[u8]> {
        self.simple_command("lookup", args!(key: key))
    }
}

fn unescape_batched_output(out: &[u8]) -> Box<[u8]> {
    // This will fail if `split` has more than 3 items.
    let mut start = 0;
    let mut out = out;
    let mut buf = Vec::new();
    loop {
        if let Some(colon) = out[start..].find_byte(b':') {
            let (before, after) = out.split_at(start + colon);
            let replace = match after.get(..2) {
                Some(b":e") => Some(b"="),
                Some(b":s") => Some(b";"),
                Some(b":o") => Some(b","),
                Some(b":c") => Some(b":"),
                // This is not supposed to happen, but just in case:
                // XXX: throw an error?
                _ => None,
            };
            if let Some(replace) = replace {
                buf.extend_from_slice(before);
                buf.extend_from_slice(replace);
                out = &after[2..];
                if out.is_empty() {
                    break;
                }
            } else {
                start += colon + 1;
            }
        } else {
            buf.extend_from_slice(out);
            break;
        }
    }
    buf.into_boxed_slice()
}

#[test]
fn test_unescape_batched_output() {
    let buf = unescape_batched_output(b"");
    assert_eq!(buf.as_bstr(), b"".as_bstr());

    let buf = unescape_batched_output(b"abc");
    assert_eq!(buf.as_bstr(), b"abc".as_bstr());

    let buf = unescape_batched_output(b"abc:def");
    assert_eq!(buf.as_bstr(), b"abc:def".as_bstr());

    let buf = unescape_batched_output(b"abc:def:");
    assert_eq!(buf.as_bstr(), b"abc:def:".as_bstr());

    let buf = unescape_batched_output(b"abc:edef:");
    assert_eq!(buf.as_bstr(), b"abc=def:".as_bstr());

    let buf = unescape_batched_output(b"abc:edef:c");
    assert_eq!(buf.as_bstr(), b"abc=def:".as_bstr());

    let buf = unescape_batched_output(b"abc:edef:c:s:e:oz");
    assert_eq!(buf.as_bstr(), b"abc=def:;=,z".as_bstr());
}

fn do_known(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    let conn = conn.wire().unwrap();
    let nodes = args
        .iter()
        .map(|s| HgChangesetId::from_str(s))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let nodes_str = nodes.iter().join(" ");
    let result = conn.simple_command(
        "known",
        args!(
            nodes: &nodes_str,
            *: &[]
        ),
    );
    send_buffer_to(&*result, out);
}

fn do_listkeys(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert_eq!(args.len(), 1);
    let namespace = args[0];
    let result = conn.listkeys(namespace);
    send_buffer_to(&*result, out);
}

fn do_getbundle(conn: &mut dyn HgConnection, args: &[&str], out: &mut (impl Write + Send)) {
    let mut args = args.iter();

    let arg_list = |a: &&str| {
        if a.is_empty() {
            Vec::new()
        } else {
            a.split(',')
                .map(|s| HgChangesetId::from_str(s).unwrap())
                .collect()
        }
    };

    let heads = args.next().map(arg_list).unwrap_or_else(Vec::new);
    let common = args.next().map(arg_list).unwrap_or_else(Vec::new);
    let bundle2caps = args.next().cloned();
    assert!(args.next().is_none());

    conn.getbundle(out, &heads, &common, bundle2caps);
}

fn do_unbundle(
    conn: &mut dyn HgConnection,
    args: &[&str],
    input: &mut impl Read,
    out: &mut impl Write,
) {
    let heads_str = if args.is_empty() || args[..] == ["force"] {
        hex::encode("force")
    } else {
        let mut heads = args.iter().map(|a| HgChangesetId::from_str(a).unwrap());
        if conn.get_capability(b"unbundlehash").is_none() {
            heads.join(" ")
        } else {
            let mut hash = Sha1::new();
            for h in heads.sorted().dedup() {
                hash.update(h.as_raw_bytes());
            }
            format!("{} {:x}", hex::encode("hashed"), hash.finalize())
        }
    };

    /* Neither the stdio nor the HTTP protocols can handle a stream for
     * push commands, so store the data as a temporary file. */
    //TODO: error checking
    let tempfile = tempfile::Builder::new()
        .prefix("hg-bundle-")
        .suffix(".hg")
        .rand_bytes(6)
        .tempfile()
        .unwrap();
    let (mut f, path) = tempfile.into_parts();
    copy_bundle(input, &mut f).unwrap();
    drop(f);

    let file = File::open(path).unwrap();
    let response = conn
        .wire()
        .unwrap()
        .push_command(file, "unbundle", args!(heads: &heads_str));
    send_buffer_to(&*response, out);
}

fn do_pushkey(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert_eq!(args.len(), 4);
    let (namespace, key, old, new) = (args[0], args[1], args[2], args[3]);
    let conn = conn.wire().unwrap();
    //TODO: handle the response being a mix of return code and output
    let response = conn.simple_command(
        "pushkey",
        args!(namespace: namespace, key: key, old: old, new: new,),
    );
    send_buffer_to(&*response, out);
}

fn do_capable(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert_eq!(args.len(), 1);
    let name = args[0];
    send_buffer_to(
        conn.get_capability(name.as_bytes()).map(|b| b.as_bytes()),
        out,
    )
}

fn do_state(conn: &mut dyn HgConnection, args: &[&str], mut out: &mut impl Write) {
    assert!(args.is_empty());
    let branchmap;
    let heads;
    let bookmarks;
    if conn.get_capability(b"batch".as_bstr()).is_none() {
        // TODO: when not batching, check for coherency
        // (see the cinnabar.remote_helper python module)
        let wire = conn.wire().unwrap();
        branchmap = wire.simple_command("branchmap", args!());
        heads = wire.simple_command("heads", args!());
        bookmarks = conn.listkeys("bookmarks");
    } else {
        let out = conn.wire().unwrap().simple_command(
            "batch",
            args!(
                cmds: "branchmap ;heads ;listkeys namespace=bookmarks",
                *: &[]
            ),
        );
        let split: [_; 3] = out.splitn_exact(b';').unwrap();
        branchmap = unescape_batched_output(split[0]);
        heads = unescape_batched_output(split[1]);
        bookmarks = unescape_batched_output(split[2]);
    }
    send_buffer_to(&*branchmap, &mut out);
    send_buffer_to(&*heads, &mut out);
    send_buffer_to(&*bookmarks, &mut out);
}

fn do_lookup(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert_eq!(args.len(), 1);
    let key = args[0];
    let result = conn.lookup(key);
    send_buffer_to(&*result, out);
}

fn do_clonebundles(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert!(args.is_empty());
    let conn = conn.wire().unwrap();
    let result = conn.simple_command("clonebundles", args!());
    send_buffer_to(&*result, out);
}

fn do_cinnabarclone(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert!(args.is_empty());
    let conn = conn.wire().unwrap();
    let result = conn.simple_command("cinnabarclone", args!());
    send_buffer_to(&*result, out);
}

pub fn get_connection(url: &Url, flags: c_int) -> Option<Box<dyn HgConnection>> {
    if ["http", "https"].contains(&url.scheme()) {
        get_http_connection(url)
    } else if ["ssh", "file"].contains(&url.scheme()) {
        get_stdio_connection(url, flags)
    } else {
        die!("protocol '{}' is not supported", url.scheme());
    }
}

fn hg_connect(
    url: &str,
    flags: c_int,
    out: &mut (impl Write + Send),
) -> Option<Box<dyn HgConnection>> {
    let url = Url::parse(url).unwrap();
    let mut conn = get_connection(&url, flags)?;

    if conn.wire().is_none() {
        // For now the wire helper just sends the bundle to the given output writer.
        out.write_all(b"bundle\n").unwrap();
        conn.getbundle(out, &[], &[], None);
        return None;
    }

    const REQUIRED_CAPS: [&str; 5] = [
        "getbundle",
        "branchmap",
        "known",
        "pushkey",
        //TODO: defer to when pushing.
        "unbundle",
    ];

    for cap in &REQUIRED_CAPS {
        if conn.get_capability(cap.as_bytes()).is_none() {
            die!(
                "Mercurial repository doesn't support the required \"{}\" capability.",
                cap
            );
        }
    }

    Some(conn)
}

fn connect_main_internal() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut connect_command = String::new();
    stdin.read_line(&mut connect_command)?;
    let [connect, url] = connect_command.splitn_exact(' ').unwrap();
    assert_eq!(connect, "connect");
    let mut conn = match hg_connect(url, 0, &mut out) {
        Some(conn) => {
            out.write_all(b"ok\n").unwrap();
            out.flush().unwrap();
            conn
        }
        None => {
            out.write_all(b"failed\n").unwrap();
            out.flush().unwrap();
            return Ok(());
        }
    };

    loop {
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        let mut args = line.trim_matches('\n').split(' ');
        let command = args.next().ok_or("Missing command")?;
        let args = args.collect::<Vec<_>>();
        match command {
            "known" => do_known(&mut *conn, &*args, &mut out),
            "listkeys" => do_listkeys(&mut *conn, &*args, &mut out),
            "getbundle" => do_getbundle(&mut *conn, &*args, &mut out),
            "unbundle" => do_unbundle(&mut *conn, &*args, &mut stdin, &mut out),
            "pushkey" => do_pushkey(&mut *conn, &*args, &mut out),
            "capable" => do_capable(&mut *conn, &*args, &mut out),
            "state" => do_state(&mut *conn, &*args, &mut out),
            "lookup" => do_lookup(&mut *conn, &*args, &mut out),
            "clonebundles" => do_clonebundles(&mut *conn, &*args, &mut out),
            "cinnabarclone" => do_cinnabarclone(&mut *conn, &*args, &mut out),
            "" => return Ok(()),
            _ => return Err(format!("Unknown command: {}", command).into()),
        }
        out.flush().unwrap();
    }
}

pub fn connect_main() -> c_int {
    connect_main_internal().map(|_| 0).unwrap_or_else(|e| {
        eprintln!("{}", e);
        1
    })
}
