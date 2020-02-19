/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::{c_char, c_int};
use std::ptr;

use bstr::{BString, ByteSlice};
use itertools::Itertools;
use libc::{off_t, FILE};
use percent_encoding::percent_decode;

use crate::hg_connect_http::HgHTTPConnection;
use crate::libcinnabar::{
    bufferize_writer, copy_bundle, hg_connect_stdio, hg_connection_stdio, stdio_finish,
    stdio_read_response, stdio_write, writer,
};
use crate::libgit::{die, object_id, oid_array, strbuf};

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct hg_connection(c_void);

unsafe fn to_wire_connection<'a>(ptr: *mut hg_connection) -> &'a mut (dyn HgWireConnection + 'a) {
    &mut **(ptr as *mut Box<dyn HgWireConnection>).as_mut().unwrap()
}

pub struct OneHgArg<'a> {
    pub name: &'a str,
    pub value: &'a [u8],
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

pub struct HgConnection<Inner> {
    pub capabilities: Vec<(BString, CString)>,
    pub inner: Inner,
}

type HgStdIOConnection = HgConnection<*mut hg_connection_stdio>;

pub trait HgCapabilities {
    fn get_capability(&self, name: &[u8]) -> Option<&CStr>;
}

pub trait HgWireConnection: HgCapabilities {
    unsafe fn simple_command(&mut self, response: &mut strbuf, command: &str, args: HgArgs);

    unsafe fn changegroup_command(&mut self, out: &mut writer, command: &str, args: HgArgs);

    unsafe fn push_command(
        &mut self,
        response: &mut strbuf,
        input: File,
        len: off_t,
        command: &str,
        args: HgArgs,
    );

    unsafe fn finish(&mut self) -> c_int;

    fn listkeys(&mut self, result: &mut strbuf, namespace: &[u8]) {
        unsafe { self.simple_command(result, "listkeys", args!(namespace: namespace)) }
    }
}

/* Split the list of capabilities a mercurial server returned. Also url-decode
 * the bundle2 value (TODO: in place). */
pub fn split_capabilities(buf: &[u8]) -> Vec<(BString, CString)> {
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
                CString::new(percent_decode(value).collect::<Vec<_>>()).unwrap()
            } else {
                CString::new(value.to_owned()).unwrap()
            },
        ));
    }
    capabilities
}

#[no_mangle]
unsafe extern "C" fn hg_get_capability(
    conn: *mut hg_connection,
    name: *const c_char,
) -> *const c_char {
    to_wire_connection(conn)
        .get_capability(CStr::from_ptr(name.as_ref().unwrap()).to_bytes().as_bstr())
        .map(CStr::as_ptr)
        .unwrap_or(ptr::null())
}

impl<Inner> HgCapabilities for HgConnection<Inner> {
    fn get_capability(&self, needle: &[u8]) -> Option<&CStr> {
        for (name, value) in self.capabilities.iter() {
            if name == needle {
                return Some(&value);
            }
        }
        None
    }
}

#[no_mangle]
unsafe extern "C" fn hg_get_repo_state(
    conn: *mut hg_connection,
    branchmap: *mut strbuf,
    heads: *mut strbuf,
    bookmarks: *mut strbuf,
) {
    let conn = to_wire_connection(conn);
    let branchmap = branchmap.as_mut().unwrap();
    let heads = heads.as_mut().unwrap();
    let bookmarks = bookmarks.as_mut().unwrap();
    if conn.get_capability(b"batch".as_bstr()).is_none() {
        // TODO: when not batching, check for coherency
        // (see the cinnabar.remote_helper python module)
        conn.simple_command(branchmap, "branchmap", args!());
        conn.simple_command(heads, "heads", args!());
        conn.listkeys(bookmarks, b"bookmarks");
    } else {
        let mut out = strbuf::new();
        conn.simple_command(
            &mut out,
            "batch",
            args!(
                cmds: b"branchmap ;heads ;listkeys namespace=bookmarks",
                *: &[]
            ),
        );
        let split = out.as_bytes().split(|&b| b == b';');
        for (out, buf) in Iterator::zip(
            split,
            &mut [Some(branchmap), Some(heads), Some(bookmarks), None],
        ) {
            let buf = buf.as_mut().unwrap();
            unescape_batched_output(out, buf);
        }
    }
}

fn unescape_batched_output(out: &[u8], buf: &mut strbuf) {
    // This will fail if `split` has more than 3 items.
    let mut start = 0;
    let mut out = out;
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
}

#[test]
fn test_unescape_batched_output() {
    let mut buf = strbuf::new();
    unescape_batched_output(b"", &mut buf);
    assert_eq!(buf.as_bytes().as_bstr(), b"".as_bstr());

    let mut buf = strbuf::new();
    unescape_batched_output(b"abc", &mut buf);
    assert_eq!(buf.as_bytes().as_bstr(), b"abc".as_bstr());

    let mut buf = strbuf::new();
    unescape_batched_output(b"abc:def", &mut buf);
    assert_eq!(buf.as_bytes().as_bstr(), b"abc:def".as_bstr());

    let mut buf = strbuf::new();
    unescape_batched_output(b"abc:def:", &mut buf);
    assert_eq!(buf.as_bytes().as_bstr(), b"abc:def:".as_bstr());

    let mut buf = strbuf::new();
    unescape_batched_output(b"abc:edef:", &mut buf);
    assert_eq!(buf.as_bytes().as_bstr(), b"abc=def:".as_bstr());

    let mut buf = strbuf::new();
    unescape_batched_output(b"abc:edef:c", &mut buf);
    assert_eq!(buf.as_bytes().as_bstr(), b"abc=def:".as_bstr());

    let mut buf = strbuf::new();
    unescape_batched_output(b"abc:edef:c:s:e:oz", &mut buf);
    assert_eq!(buf.as_bytes().as_bstr(), b"abc=def:;=,z".as_bstr());
}

#[no_mangle]
unsafe extern "C" fn hg_known(
    conn: *mut hg_connection,
    result: *mut strbuf,
    nodes: *const oid_array,
) {
    let conn = to_wire_connection(conn);
    let nodes = nodes.as_ref().unwrap();
    let nodes_str = nodes.iter().join(" ");
    conn.simple_command(
        result.as_mut().unwrap(),
        "known",
        args!(
            nodes: nodes_str.as_bytes(),
            *: &[]
        ),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_listkeys(
    conn: *mut hg_connection,
    result: *mut strbuf,
    namespace: *const c_char,
) {
    let conn = to_wire_connection(conn);
    conn.listkeys(
        result.as_mut().unwrap(),
        CStr::from_ptr(namespace.as_ref().unwrap()).to_bytes(),
    )
}

#[allow(non_camel_case_types)]
pub enum param_value<'a> {
    size(usize),
    value(&'a [u8]),
}

pub fn prepare_command<'a, F: FnMut(&str, param_value) + 'a>(
    mut command_add_param: F,
    args: HgArgs,
) {
    for OneHgArg { name, value } in args.args {
        command_add_param(name, param_value::value(value));
    }
    if let Some(extra_args) = args.extra_args {
        command_add_param("*", param_value::size(extra_args.len()));
        for OneHgArg { name, value } in extra_args {
            command_add_param(name, param_value::value(value));
        }
    }
}

#[no_mangle]
unsafe extern "C" fn hg_getbundle(
    conn: *mut hg_connection,
    out: *mut FILE,
    heads: *const oid_array,
    common: *const oid_array,
    bundle2caps: *const c_char,
) {
    let conn = to_wire_connection(conn);
    let mut args = Vec::<(&str, BString)>::new();
    if let Some(heads) = heads.as_ref() {
        args.push(("heads", heads.iter().join(" ").into()));
    }
    if let Some(common) = common.as_ref() {
        args.push(("common", common.iter().join(" ").into()));
    }
    let bundle2caps = bundle2caps.as_ref();
    if let Some(bundle2caps) = bundle2caps {
        let bundle2caps = CStr::from_ptr(bundle2caps).to_bytes();
        if !bundle2caps.is_empty() {
            args.push(("bundlecaps", bundle2caps.to_owned().into()));
        }
    }
    let mut writer = writer::new(crate::libc::File::new(out));
    let args = args
        .iter()
        .map(|(n, v)| OneHgArg { name: n, value: v })
        .collect::<Vec<_>>();
    conn.changegroup_command(&mut writer, "getbundle", args!(*: &args[..]));
}

#[no_mangle]
unsafe extern "C" fn hg_unbundle(
    conn: *mut hg_connection,
    response: *mut strbuf,
    input: *mut FILE,
    heads: *const oid_array,
) {
    let conn = to_wire_connection(conn);
    let heads = heads.as_ref().unwrap();
    let heads_str = if heads.is_empty() {
        hex::encode("force")
    } else if conn.get_capability(b"unbundlehash").is_none() {
        heads.iter().join(" ")
    } else {
        let mut hash = object_id::create();
        for h in heads.iter().sorted().dedup() {
            hash.input(h.raw());
        }
        format!("{} {}", hex::encode("hashed"), hash.result())
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
    copy_bundle(input, &mut writer::new(&mut f));
    drop(f);

    let file = File::open(path).unwrap();
    let len = file.metadata().unwrap().len();
    conn.push_command(
        response.as_mut().unwrap(),
        file,
        len.try_into().unwrap(),
        "unbundle",
        args!(heads: heads_str.as_bytes()),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_pushkey(
    conn: *mut hg_connection,
    response: *mut strbuf,
    namespace: *const c_char,
    key: *const c_char,
    old: *const c_char,
    new: *const c_char,
) {
    let conn = to_wire_connection(conn);
    //TODO: handle the response being a mix of return code and output
    conn.simple_command(
        response.as_mut().unwrap(),
        "pushkey",
        args!(
            namespace: CStr::from_ptr(namespace.as_ref().unwrap()).to_bytes(),
            key: CStr::from_ptr(key.as_ref().unwrap()).to_bytes(),
            old: CStr::from_ptr(old.as_ref().unwrap()).to_bytes(),
            new: CStr::from_ptr(new.as_ref().unwrap()).to_bytes(),
        ),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_lookup(conn: *mut hg_connection, result: *mut strbuf, key: *const c_char) {
    let conn = to_wire_connection(conn);
    conn.simple_command(
        result.as_mut().unwrap(),
        "lookup",
        args!(key: CStr::from_ptr(key.as_ref().unwrap()).to_bytes()),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_clonebundles(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = to_wire_connection(conn);
    conn.simple_command(result.as_mut().unwrap(), "clonebundles", args!());
}

#[no_mangle]
unsafe extern "C" fn hg_cinnabarclone(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = to_wire_connection(conn);
    conn.simple_command(result.as_mut().unwrap(), "cinnabarclone", args!());
}

/* The mercurial "stdio" protocol is used for both local repositories and
 * remote ssh repositories.
 * A mercurial client sends commands in the following form:
 *   <command> LF
 *   (<param> SP <length> LF <value>)*
 *   ('*' SP <num> LF (<param> SP <length> LF <value>){num})
 *
 * <value> is <length> bytes long. The number of parameters depends on the
 * command.
 *
 * The '*' special parameter introduces a variable number of extra parameters.
 * The number following the '*' is the number of extra parameters.
 *
 * The server response, for simple commands, is of the following form:
 *   <length> LF
 *   <content>
 *
 * <content> is <length> bytes long.
 */
fn stdio_command_add_param(data: &mut BString, name: &str, value: param_value) {
    let is_asterisk = name == "*";
    let len = match value {
        param_value::size(s) => {
            assert!(is_asterisk);
            s
        }
        param_value::value(v) => {
            assert!(!is_asterisk);
            v.len()
        }
    };
    data.extend(name.as_bytes());
    writeln!(data, " {}", len).unwrap();
    match value {
        param_value::value(v) => {
            assert!(!is_asterisk);
            data.extend(v)
        }
        _ => assert!(is_asterisk),
    };
}

fn stdio_send_command(conn: &mut hg_connection_stdio, command: &str, args: HgArgs) {
    let mut data = BString::from(Vec::<u8>::new());
    data.extend(command.as_bytes());
    data.push(b'\n');
    prepare_command(
        |name, value| stdio_command_add_param(&mut data, name, value),
        args,
    );
    unsafe {
        stdio_write(conn, data.as_ptr(), data.len());
    }
}

impl HgWireConnection for HgStdIOConnection {
    unsafe fn simple_command(&mut self, response: &mut strbuf, command: &str, args: HgArgs) {
        let stdio = self.inner.as_mut().unwrap();
        stdio_send_command(stdio, command, args);
        stdio_read_response(stdio, response);
    }

    unsafe fn changegroup_command(&mut self, writer: &mut writer, command: &str, args: HgArgs) {
        let stdio = self.inner.as_mut().unwrap();
        stdio_send_command(stdio, command, args);

        /* We're going to receive a stream, but we don't know how big it is
         * going to be in advance, so we have to read it according to its
         * format: changegroup or bundle2.
         */
        if stdio.is_remote > 0 {
            bufferize_writer(writer);
        }
        copy_bundle(stdio.out, writer);
    }

    unsafe fn push_command(
        &mut self,
        response: &mut strbuf,
        mut input: File,
        len: off_t,
        command: &str,
        args: HgArgs,
    ) {
        let stdio = self.inner.as_mut().unwrap();
        stdio_send_command(stdio, command, args);
        /* The server normally sends an empty response before reading the data
         * it's sent if not, it's an error (typically, the remote will
         * complain here if there was a lost push race). */
        //TODO: handle that error.
        let mut header = strbuf::new();
        stdio_read_response(stdio, &mut header);

        //TODO: chunk in smaller pieces.
        header.extend_from_slice(format!("{}\n", len).as_bytes());
        stdio_write(stdio, header.as_bytes().as_ptr(), header.as_bytes().len());
        drop(header);

        let is_bundle2 = if len > 4 {
            let mut header = [0u8; 4];
            input.read_exact(&mut header).unwrap();
            input.seek(SeekFrom::Start(0)).unwrap();
            &header == b"HG20"
        } else {
            false
        };

        let mut len = len;
        let mut buf = [0u8; 4096];
        while len > 0 {
            let read = input.read(&mut buf).unwrap();
            len -= read as off_t;
            stdio_write(stdio, buf.as_ptr(), read);
        }

        stdio_write(stdio, "0\n".as_ptr(), 2);
        if is_bundle2 {
            copy_bundle(stdio.out, &mut writer::new(response));
        } else {
            /* There are two responses, one for output, one for actual response. */
            //TODO: actually handle output here
            let mut header = strbuf::new();
            stdio_read_response(stdio, &mut header);
            drop(header);
            stdio_read_response(stdio, response);
        }
    }

    unsafe fn finish(&mut self) -> c_int {
        let code = stdio_finish(self.inner);
        libc::free(mem::replace(&mut self.inner, ptr::null_mut()) as *mut c_void);
        code
    }
}

#[no_mangle]
unsafe extern "C" fn stdio_send_empty_command(conn: *mut hg_connection_stdio) {
    let conn = conn.as_mut().unwrap();
    stdio_send_command(conn, "", args!());
}

#[no_mangle]
unsafe extern "C" fn hg_connect(url: *const c_char, flags: c_int) -> *mut hg_connection {
    let url_ = CStr::from_ptr(url).to_bytes();
    let conn: Option<Box<dyn HgWireConnection + '_>> = if url_.starts_with(b"http://")
        || url_.starts_with(b"https://")
    {
        HgHTTPConnection::new(url_).map(|c| Box::new(c) as _)
    } else {
        let inner = if let Some(inner) = hg_connect_stdio(url, flags).as_mut() {
            inner
        } else {
            return ptr::null_mut();
        };

        /* Very old versions of the mercurial server (< 0.9) would ignore
         * unknown commands, and didn't know the "capabilities" command we want
         * to use to retrieve the server capabilities.
         * So, we also emit a command that is supported by those old versions,
         * and will see if we get a response for one or both commands.
         * Note the "capabilities" command is not supported over the stdio
         * protocol before mercurial 1.7, but we require features from at
         * least mercurial 1.9 anyways. Server versions between 0.9 and 1.7
         * will return an empty result for the "capabilities" command, as
         * opposed to no result at all with older servers. */
        stdio_send_command(inner, "capabilities", args!());
        stdio_send_command(
            inner,
            "between",
            args!(
                pairs: b"0000000000000000000000000000000000000000-0000000000000000000000000000000000000000"
            ),
        );

        let mut conn = Box::new(HgStdIOConnection {
            capabilities: Vec::new(),
            inner,
        });

        let mut buf = strbuf::new();
        stdio_read_response(inner, &mut buf);
        if buf.as_bytes() != b"\n" {
            mem::swap(
                &mut conn.capabilities,
                &mut split_capabilities(buf.as_bytes()),
            );
            /* Now read the response for the "between" command. */
            stdio_read_response(inner, &mut buf);
        }

        Some(conn)
    };

    let conn = if let Some(conn) = conn {
        conn
    } else {
        return ptr::null_mut();
    };

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

    Box::into_raw(Box::new(conn)) as *mut hg_connection
}

#[no_mangle]
unsafe extern "C" fn hg_finish_connect(conn: *mut hg_connection) -> c_int {
    let mut conn = Box::from_raw((conn as *mut Box<dyn HgWireConnection>).as_mut().unwrap());
    conn.finish()
}
