/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::fs::File;
use std::io::{stderr, BufRead, Read, Write};
use std::os::raw::c_int;
use std::str::FromStr;

use bstr::{BStr, ByteSlice};
use itertools::Itertools;
use percent_encoding::{percent_decode, percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha1::{Digest, Sha1};
use url::Url;

use crate::hg_bundle::{copy_bundle, BundleReader};
use crate::hg_connect_http::get_http_connection;
use crate::hg_connect_stdio::get_stdio_connection;
use crate::libcinnabar::send_buffer_to;
use crate::oid::ObjectId;
use crate::store::{store_changegroup, HgChangesetId};
use crate::util::{ImmutBString, PrefixWriter, SliceExt, ToBoxed};
use crate::HELPER_LOCK;

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
    capabilities: Vec<(ImmutBString, ImmutBString)>,
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
                name.to_boxed(),
                if name == b"bundle2" {
                    percent_decode(value).collect_vec().into()
                } else {
                    value.to_boxed()
                },
            ));
        }
        HgCapabilities { capabilities }
    }

    pub fn get_capability(&self, needle: &[u8]) -> Option<&BStr> {
        for (name, value) in self.capabilities.iter() {
            if &**name == needle {
                return Some(value.as_bstr());
            }
        }
        None
    }
}

pub enum UnbundleResponse<'a> {
    Raw(ImmutBString),
    Bundlev2(Box<dyn Read + 'a>),
}

pub trait HgConnectionBase {
    fn get_capability(&self, _name: &[u8]) -> Option<&BStr> {
        None
    }

    fn require_capability(&self, name: &[u8]) -> &BStr {
        if let Some(cap) = self.get_capability(name) {
            cap
        } else {
            die!(
                "Mercurial repository doesn't support the required \"{}\" capability.",
                name.as_bstr()
            );
        }
    }
}

pub trait HgWireConnection: HgConnectionBase {
    fn simple_command(&mut self, command: &str, args: HgArgs) -> ImmutBString;

    fn changegroup_command<'a>(
        &'a mut self,
        command: &str,
        args: HgArgs,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString>;

    fn push_command(&mut self, input: File, command: &str, args: HgArgs) -> UnbundleResponse;
}

pub trait HgConnection: HgConnectionBase {
    fn known(&mut self, _nodes: &[HgChangesetId]) -> Box<[bool]> {
        unimplemented!();
    }

    fn listkeys(&mut self, _namespace: &str) -> ImmutBString {
        unimplemented!();
    }

    fn getbundle<'a>(
        &'a mut self,
        _heads: &[HgChangesetId],
        _common: &[HgChangesetId],
        _bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
        unimplemented!();
    }

    fn unbundle(&mut self, _heads: Option<&[HgChangesetId]>, _input: File) -> UnbundleResponse {
        unimplemented!();
    }

    fn pushkey(&mut self, _namespace: &str, _key: &str, _old: &str, _new: &str) -> ImmutBString {
        unimplemented!();
    }

    fn branchmap(&mut self) -> ImmutBString {
        unimplemented!();
    }

    fn heads(&mut self) -> ImmutBString {
        unimplemented!();
    }

    fn batch(&mut self, _cmds: &str) -> ImmutBString {
        unimplemented!();
    }

    fn lookup(&mut self, _key: &str) -> ImmutBString {
        unimplemented!();
    }

    fn clonebundles(&mut self) -> ImmutBString {
        unimplemented!();
    }

    fn cinnabarclone(&mut self) -> ImmutBString {
        unimplemented!();
    }
}

impl HgConnectionBase for Box<dyn HgWireConnection> {
    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        (**self).get_capability(name)
    }
}

impl HgConnection for Box<dyn HgWireConnection> {
    fn known(&mut self, nodes: &[HgChangesetId]) -> Box<[bool]> {
        let nodes_str = nodes.iter().join(" ");
        self.simple_command(
            "known",
            args!(
                nodes: &nodes_str,
                *: &[]
            ),
        )
        .iter()
        .map(|b| *b == b'1')
        .collect_vec()
        .into()
    }

    fn listkeys(&mut self, namespace: &str) -> ImmutBString {
        self.simple_command("listkeys", args!(namespace: namespace))
    }

    fn getbundle<'a>(
        &'a mut self,
        heads: &[HgChangesetId],
        common: &[HgChangesetId],
        bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
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
        self.changegroup_command("getbundle", args!(*: &args[..]))
    }

    fn unbundle(&mut self, heads: Option<&[HgChangesetId]>, input: File) -> UnbundleResponse {
        let heads_str = if let Some(heads) = heads {
            if self.get_capability(b"unbundlehash").is_none() {
                heads.iter().join(" ")
            } else {
                let mut hash = Sha1::new();
                for h in heads.iter().sorted().dedup() {
                    hash.update(h.as_raw_bytes());
                }
                format!("{} {:x}", hex::encode("hashed"), hash.finalize())
            }
        } else {
            hex::encode("force")
        };

        self.push_command(input, "unbundle", args!(heads: &heads_str))
    }

    fn pushkey(&mut self, namespace: &str, key: &str, old: &str, new: &str) -> ImmutBString {
        //TODO: handle the response being a mix of return code and output
        self.simple_command(
            "pushkey",
            args!(namespace: namespace, key: key, old: old, new: new,),
        )
    }

    fn branchmap(&mut self) -> ImmutBString {
        self.simple_command("branchmap", args!())
    }

    fn heads(&mut self) -> ImmutBString {
        self.simple_command("heads", args!())
    }

    fn batch(&mut self, _cmds: &str) -> ImmutBString {
        self.simple_command(
            "batch",
            args!(
                cmds: "branchmap ;heads ;listkeys namespace=bookmarks",
                *: &[]
            ),
        )
    }

    fn lookup(&mut self, key: &str) -> ImmutBString {
        self.simple_command("lookup", args!(key: key))
    }

    fn clonebundles(&mut self) -> ImmutBString {
        self.simple_command("clonebundles", args!())
    }

    fn cinnabarclone(&mut self) -> ImmutBString {
        self.simple_command("cinnabarclone", args!())
    }
}

fn unescape_batched_output(out: &[u8]) -> ImmutBString {
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
    buf.into()
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
    conn.require_capability(b"known");
    let nodes = args
        .iter()
        .map(|s| HgChangesetId::from_str(s))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let result = conn
        .known(&nodes)
        .iter()
        .map(|k| if *k { b'1' } else { b'0' })
        .collect_vec();
    send_buffer_to(&*result, out);
}

fn do_listkeys(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert_eq!(args.len(), 1);
    let namespace = args[0];
    let result = conn.listkeys(namespace);
    send_buffer_to(&*result, out);
}

fn do_get_store_bundle(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
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

    let heads = args.next().map_or_else(Vec::new, arg_list);
    let common = args.next().map_or_else(Vec::new, arg_list);
    assert!(args.next().is_none());
    match get_store_bundle(conn, &heads, &common) {
        Ok(()) => out.write_all(b"ok\n").unwrap(),
        Err(e) => {
            out.write_all(b"err\n").unwrap();
            let stderr = stderr();
            let mut writer = PrefixWriter::new("remote: ", stderr.lock());
            writer.write_all(&e).unwrap();
        }
    }
}

const PYTHON_QUOTE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

fn encodecaps(
    caps: impl IntoIterator<
        Item = (
            impl AsRef<str>,
            Option<impl IntoIterator<Item = impl AsRef<str>>>,
        ),
    >,
) -> Box<str> {
    caps.into_iter()
        .map(|(k, v)| {
            let k = percent_encode(k.as_ref().as_bytes(), PYTHON_QUOTE_SET).to_string();
            match v {
                Some(v) => format!(
                "{}={}",
                k,
                v.into_iter()
                    .map(|v| percent_encode(v.as_ref().as_bytes(), PYTHON_QUOTE_SET).to_string())
                    .join(",")
            ),
                None => k,
            }
        })
        .join("\n")
        .into_boxed_str()
}

#[test]
fn test_encodecaps() {
    let caps = [("HG20", None), ("changegroup", Some(&["01", "02"]))];
    assert_eq!(&*encodecaps(caps), "HG20\nchangegroup=01,02");

    // Real case
    let caps = [
        ("HG20", None),
        ("bookmarks", None),
        ("changegroup", Some(&["01", "02"][..])),
        ("digests", Some(&["md5", "sha1", "sha512"])),
        (
            "error",
            Some(&["abort", "unsupportedcontent", "pushraced", "pushkey"]),
        ),
        ("hgtagsfnodes", None),
        ("listkeys", None),
        ("phases", Some(&["heads"])),
        ("pushkey", None),
        ("remote-changegroup", Some(&["http", "https"])),
    ];
    assert_eq!(
        &*encodecaps(caps),
        "HG20\n\
         bookmarks\n\
         changegroup=01,02\n\
         digests=md5,sha1,sha512\n\
         error=abort,unsupportedcontent,pushraced,pushkey\n\
         hgtagsfnodes\n\
         listkeys\n\
         phases=heads\n\
         pushkey\n\
         remote-changegroup=http,https"
    );

    // Hypothetical case
    let caps = [
        ("ab%d", Some(&["foo\nbar"][..])),
        ("qux\n", None),
        ("hoge", Some(&["fuga,", "toto"])),
    ];
    assert_eq!(
        &*encodecaps(caps),
        "ab%25d=foo%0Abar\n\
         qux%0A\n\
         hoge=fuga%2C,toto"
    );
}

pub fn get_store_bundle(
    conn: &mut dyn HgConnection,
    heads: &[HgChangesetId],
    common: &[HgChangesetId],
) -> Result<(), ImmutBString> {
    let bundle2caps = conn.get_capability(b"bundle2").map(|_| {
        let bundle2caps = [("HG20", None), ("changegroup", Some(&["01", "02"]))];
        format!(
            "HG20,bundle2={}",
            percent_encode(encodecaps(bundle2caps).as_bytes(), PYTHON_QUOTE_SET)
        )
    });
    conn.getbundle(heads, common, bundle2caps.as_deref())
        .map(|r| {
            let mut bundle = BundleReader::new(r).unwrap();
            while let Some(part) = bundle.next_part().unwrap() {
                if &*part.part_type == "changegroup" {
                    let version = part
                        .params
                        .get("version")
                        .map_or(1, |v| u8::from_str(v).unwrap());
                    let _locked = HELPER_LOCK.lock().unwrap();
                    store_changegroup(part, version);
                }
            }
        })
}

fn do_unbundle(
    conn: &mut dyn HgConnection,
    args: &[&str],
    input: &mut impl Read,
    out: &mut impl Write,
) {
    conn.require_capability(b"unbundle");
    let heads = if args.is_empty() || args[..] == ["force"] {
        None
    } else {
        Some(
            args.iter()
                .map(|a| HgChangesetId::from_str(a).unwrap())
                .collect_vec(),
        )
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
    let response = conn.unbundle(heads.as_deref(), file);
    match response {
        UnbundleResponse::Bundlev2(data) => {
            let mut bundle = BundleReader::new(data).unwrap();
            while let Some(part) = bundle.next_part().unwrap() {
                match part.part_type.as_bytes() {
                    b"reply:changegroup" => {
                        // TODO: should check in-reply-to param.
                        let response = part.params.get("return").unwrap();
                        send_buffer_to(response.as_bytes(), out);
                    }
                    b"error:abort" => {
                        let mut message = part.params.get("message").unwrap().to_string();
                        if let Some(hint) = part.params.get("hint") {
                            message.push_str("\n\n");
                            message.push_str(hint);
                        }
                        error!(target: "root", "{}", message);
                    }
                    _ => {}
                }
            }
        }
        UnbundleResponse::Raw(response) => {
            send_buffer_to(&*response, out);
        }
    }
}

fn do_pushkey(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert_eq!(args.len(), 4);
    let (namespace, key, old, new) = (args[0], args[1], args[2], args[3]);
    conn.require_capability(b"pushkey");
    let response = conn.pushkey(namespace, key, old, new);
    send_buffer_to(&*response, out);
}

fn do_capable(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert_eq!(args.len(), 1);
    let name = args[0];
    send_buffer_to(
        conn.get_capability(name.as_bytes()).map(|b| b.as_bytes()),
        out,
    );
}

fn do_state(conn: &mut dyn HgConnection, args: &[&str], mut out: &mut impl Write) {
    assert!(args.is_empty());
    let branchmap;
    let heads;
    let bookmarks;
    if conn.get_capability(b"batch").is_none() {
        // TODO: when not batching, check for coherency
        // (see the cinnabar.remote_helper python module)
        branchmap = conn.branchmap();
        heads = conn.heads();
        bookmarks = conn.listkeys("bookmarks");
    } else {
        let out = conn.batch("branchmap ;heads ;listkeys namespace=bookmarks");
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
    let result = conn.clonebundles();
    send_buffer_to(&*result, out);
}

fn do_cinnabarclone(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert!(args.is_empty());
    let result = conn.cinnabarclone();
    send_buffer_to(&*result, out);
}

fn can_use_clonebundle(line: &[u8]) -> Result<Option<Url>, String> {
    const SUPPORTED_BUNDLES: [&[u8]; 2] = [b"v1", b"v2"];
    const SUPPORTED_COMPRESSIONS: [&[u8]; 4] = [b"none", b"gzip", b"bzip2", b"zstd"];

    let mut line = line.splitn(2, |&b| b == b' ');
    let url = match line.next() {
        None => return Ok(None),
        Some(url) => std::str::from_utf8(url)
            .ok()
            .and_then(|url| Url::parse(url).ok())
            .ok_or("invalid url")?,
    };
    if !["http", "https"].contains(&url.scheme()) {
        return Err("non http/https url".to_string());
    }
    let attributes = line
        .next()
        .map(|l| {
            l.split(|&b| b == b' ')
                .map(|a| {
                    a.splitn_exact::<2>(b'=').map(|[a, b]| {
                        (
                            // TODO: Ideally, we'd avoid the extra allocations here.
                            percent_decode(a).collect_vec().as_bstr().to_boxed(),
                            percent_decode(b).collect_vec().as_bstr().to_boxed(),
                        )
                    })
                })
                .collect::<Option<HashMap<_, _>>>()
                .ok_or("failed to decode")
        })
        .transpose()?;
    trace!(target: "clonebundle", "{:?}", attributes);

    //TODO: should we care about REQUIRESNI, or can we assume curl always supports
    //SNI? (for now, we assume it does).

    let mut bundlespec = attributes
        .as_ref()
        .and_then(|attrs| attrs.get(b"BUNDLESPEC".as_bstr()))
        .ok_or("missing BUNDLE_SPEC")?
        .split(|&b| b == b';');
    if let Some([compression, version]) = bundlespec
        .next()
        .ok_or("empty BUNDLESPEC?")?
        .splitn_exact(b'-')
    {
        if !SUPPORTED_COMPRESSIONS.contains(&compression) {
            return Err(format!(
                "unsupported compression: {}",
                compression.as_bstr()
            ))?;
        }
        if !SUPPORTED_BUNDLES.contains(&version) {
            return Err(format!("unsupported bundle type: {}", version.as_bstr()))?;
        }
    }
    let params = bundlespec
        .map(|b| {
            b.splitn_exact::<2>(b'=')
                .map(|[k, v]| (k.as_bstr(), v.as_bstr()))
        })
        .collect::<Option<HashMap<_, _>>>()
        .ok_or("failed to decode BUNDLESPEC")?;
    trace!(target: "clonebundle", "{:?}", params);

    Ok((!params.contains_key(b"stream".as_bstr()))
        .then(|| Some(url))
        .ok_or("stream bundles are not supported")?)
}

fn do_get_clonebundle_url(conn: &mut dyn HgConnection, args: &[&str], out: &mut impl Write) {
    assert!(args.is_empty());
    if let Some(url) = get_clonebundle_url(conn) {
        write!(out, "{}", url).unwrap();
    }
    out.write_all(b"\n").unwrap();
}

pub fn get_clonebundle_url(conn: &mut dyn HgConnection) -> Option<Url> {
    let bundles = conn.clonebundles();

    for line in ByteSlice::lines(&*bundles) {
        debug!(target: "clonebundle", "{:?}", line.as_bstr());
        match can_use_clonebundle(line) {
            Ok(None) => {}
            Ok(Some(url)) => {
                return Some(url);
            }
            Err(e) => {
                debug!(target: "clonebundle", " Skipping ({})", e);
            }
        }
    }
    None
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

fn hg_connect(url: &str, flags: c_int) -> Option<Box<dyn HgConnection>> {
    let url = Url::parse(url).unwrap();
    let conn = get_connection(&url, flags)?;

    const REQUIRED_CAPS: [&str; 2] = ["getbundle", "branchmap"];

    for cap in &REQUIRED_CAPS {
        conn.require_capability(cap.as_bytes());
    }

    Some(conn)
}

pub fn connect_main_with(
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connections = BTreeMap::new();
    let mut count = 0u32;
    loop {
        let mut line = String::new();
        input.read_line(&mut line)?;
        let line = line.trim_matches('\n');
        if line.is_empty() {
            return Ok(());
        }
        let mut args = line.split(' ');
        let command = args.next().ok_or("Missing command")?;
        if command == "connect" {
            let url = args.next().unwrap();
            assert!(args.next().is_none());
            match hg_connect(url, 0) {
                // We allow multiple connect commands.
                Some(conn) => {
                    connections.insert(count, conn);
                    writeln!(out, "ok {count}").unwrap();
                    count += 1;
                }
                _ => {
                    out.write_all(b"failed\n").unwrap();
                }
            }
            out.flush().unwrap();
            continue;
        }
        if connections.is_empty() {
            return Err(format!("Unknown command: {}", command).into());
        }
        let (conn_id, connection) = u32::from_str(args.next().ok_or("Missing connection id")?)
            .ok()
            .and_then(|c| connections.get_mut(&c).map(|conn| (c, conn)))
            .ok_or("Invalid connection id")?;
        let args = args.collect_vec();
        let conn = &mut **connection;
        match command {
            "known" => do_known(conn, &*args, out),
            "listkeys" => do_listkeys(conn, &*args, out),
            "get_store_bundle" => do_get_store_bundle(conn, &*args, out),
            "unbundle" => do_unbundle(conn, &*args, input, out),
            "pushkey" => do_pushkey(conn, &*args, out),
            "capable" => do_capable(conn, &*args, out),
            "state" => do_state(conn, &*args, out),
            "lookup" => do_lookup(conn, &*args, out),
            "clonebundles" => do_clonebundles(conn, &*args, out),
            "get_clonebundle_url" => do_get_clonebundle_url(conn, &*args, out),
            "cinnabarclone" => do_cinnabarclone(conn, &*args, out),
            "close" => {
                connections.remove(&conn_id);
                continue;
            }
            _ => return Err(format!("Unknown command: {}", command).into()),
        }
        out.flush().unwrap();
    }
}
