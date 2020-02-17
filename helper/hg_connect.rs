/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp;
use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::Write;
use std::mem;
use std::os::raw::{c_char, c_int, c_long};
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
#[cfg(windows)]
use std::os::windows::io::IntoRawHandle;
use std::ptr;
use std::str::FromStr;

use bstr::{BString, ByteSlice};
use curl_sys::{
    curl_easy_getinfo, curl_easy_setopt, curl_slist, curl_slist_append, curl_slist_free_all, CURL,
    CURLINFO_EFFECTIVE_URL, CURLINFO_REDIRECT_COUNT, CURLOPT_FAILONERROR, CURLOPT_FOLLOWLOCATION,
    CURLOPT_HTTPGET, CURLOPT_HTTPHEADER, CURLOPT_NOBODY, CURLOPT_URL, CURLOPT_USERAGENT,
};
use itertools::Itertools;
use libc::{off_t, FILE};
use percent_encoding::{percent_decode, percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::libcinnabar::{
    bufferize_writer, changegroup_response_data, copy_bundle, copy_bundle_to_file,
    copy_bundle_to_strbuf, hg_connect_http, hg_connect_stdio, hg_connection_inner,
    hg_connection_stdio, http_finish, prefix_writer, prepare_caps_request,
    prepare_changegroup_request, prepare_push_request, prepare_pushkey_request,
    prepare_simple_request, push_request_info, stdio_finish, stdio_read_response, stdio_write,
    writer,
};
use crate::libgit::{
    credential_fill, curl_errorstr, die, fwrite_buffer, get_active_slot, http_auth,
    http_follow_config, object_id, oid_array, run_one_slot, slot_results, strbuf, HTTP_OK,
    HTTP_REAUTH,
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct hg_connection {
    simple_command:
        unsafe fn(conn: &mut hg_connection, response: &mut strbuf, command: &str, args: HgArgs),
    changegroup_command:
        unsafe fn(conn: &mut hg_connection, out: &mut writer, command: &str, args: HgArgs),
    push_command: unsafe fn(
        conn: &mut hg_connection,
        response: &mut strbuf,
        input: *mut FILE,
        len: off_t,
        command: &str,
        args: HgArgs,
    ),
    finish: unsafe extern "C" fn(conn: *mut c_void) -> c_int,
    capabilities: Vec<(BString, CString)>,
    inner: hg_connection_inner,
}

struct OneHgArg<'a> {
    name: &'a str,
    value: &'a [u8],
}

struct HgArgs<'a> {
    args: &'a [OneHgArg<'a>],
    extra_args: Option<&'a [OneHgArg<'a>]>,
}

macro_rules! args {
    ($($n:ident : $v:expr,)* $(*: $a:expr)?) => {
        HgArgs {
            args: args!(@args $($n:$v),*),
            extra_args: args!(@extra $($a)?),
        }
    };
    ($($n:ident : $v:expr),*) => { args!($($n:$v,)*) };
    (@args $($n:ident : $v:expr),*) => {&[
        $(OneHgArg { name: stringify!($n), value: $v }),*
    ]};
    (@extra) => { None };
    (@extra $a:expr) => { Some($a) };
}

/* Split the list of capabilities a mercurial server returned. Also url-decode
 * the bundle2 value (TODO: in place). */
fn split_capabilities(buf: &[u8]) -> Vec<(BString, CString)> {
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
    let conn = conn.as_mut().unwrap();
    let needle = CStr::from_ptr(name).to_bytes();
    for (name, value) in conn.capabilities.iter() {
        if name == needle {
            return value.as_ptr();
        }
    }
    ptr::null()
}

#[no_mangle]
unsafe extern "C" fn hg_get_repo_state(
    conn: *mut hg_connection,
    branchmap: *mut strbuf,
    heads: *mut strbuf,
    bookmarks: *mut strbuf,
) {
    let conn = conn.as_mut().unwrap();
    let branchmap = branchmap.as_mut().unwrap();
    let heads = heads.as_mut().unwrap();
    let bookmarks = bookmarks.as_mut().unwrap();
    if hg_get_capability(conn, cstr!("batch").as_ptr()).is_null() {
        // TODO: when not batching, check for coherency
        // (see the cinnabar.remote_helper python module)
        (conn.simple_command)(conn, branchmap, "branchmap", args!());
        (conn.simple_command)(conn, heads, "heads", args!());
        hg_listkeys(conn, bookmarks, cstr!("bookmarks").as_ptr());
    } else {
        let mut out = strbuf::new();
        (conn.simple_command)(
            conn,
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
    let conn = conn.as_mut().unwrap();
    let nodes = nodes.as_ref().unwrap();
    let nodes_str = nodes.iter().join(" ");
    (conn.simple_command)(
        conn,
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
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result.as_mut().unwrap(),
        "listkeys",
        args!(namespace: CStr::from_ptr(namespace.as_ref().unwrap()).to_bytes()),
    );
}

#[allow(non_camel_case_types)]
enum param_value<'a> {
    size(usize),
    value(&'a [u8]),
}

unsafe fn prepare_command<F: FnMut(&str, param_value)>(mut command_add_param: F, args: HgArgs) {
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
    let conn = conn.as_mut().unwrap();
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
    let mut writer = writer {
        write: libc::fwrite as _,
        close: libc::fflush as _,
        context: out as *mut _,
    };
    let args = args
        .iter()
        .map(|(n, v)| OneHgArg { name: n, value: v })
        .collect::<Vec<_>>();
    (conn.changegroup_command)(conn, &mut writer, "getbundle", args!(*: &args[..]));
}

#[no_mangle]
unsafe extern "C" fn hg_unbundle(
    conn: *mut hg_connection,
    response: *mut strbuf,
    input: *mut FILE,
    heads: *const oid_array,
) {
    let conn = conn.as_mut().unwrap();
    let heads = heads.as_ref().unwrap();
    let heads_str = if heads.is_empty() {
        hex::encode("force")
    } else if hg_get_capability(conn, cstr!("unbundlehash").as_ptr()).is_null() {
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
    let (f, path) = tempfile.into_parts();
    let fh = into_raw_fd(f, "w");
    copy_bundle_to_file(input, fh);
    libc::fflush(fh);
    libc::fclose(fh);

    let file = File::open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let fh = into_raw_fd(file, "r");
    (conn.push_command)(
        conn,
        response.as_mut().unwrap(),
        fh,
        len.try_into().unwrap(),
        "unbundle",
        args!(heads: heads_str.as_bytes()),
    );
    libc::fclose(fh);
}

unsafe fn into_raw_fd(file: File, mode: &str) -> *mut FILE {
    #[cfg(unix)]
    let fd = file.into_raw_fd();
    #[cfg(windows)]
    let fd = libc::open_osfhandle(file.into_raw_handle() as _, 0);

    let mode = CString::new(mode).unwrap();
    libc::fdopen(fd, mode.as_ptr())
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
    let conn = conn.as_mut().unwrap();
    //TODO: handle the response being a mix of return code and output
    (conn.simple_command)(
        conn,
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
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result.as_mut().unwrap(),
        "lookup",
        args!(key: CStr::from_ptr(key.as_ref().unwrap()).to_bytes()),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_clonebundles(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(conn, result.as_mut().unwrap(), "clonebundles", args!());
}

#[no_mangle]
unsafe extern "C" fn hg_cinnabarclone(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(conn, result.as_mut().unwrap(), "cinnabarclone", args!());
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

unsafe fn stdio_send_command(conn: &mut hg_connection_stdio, command: &str, args: HgArgs) {
    let mut data = BString::from(Vec::<u8>::new());
    data.extend(command.as_bytes());
    data.push(b'\n');
    prepare_command(
        |name, value| stdio_command_add_param(&mut data, name, value),
        args,
    );
    stdio_write(conn, data.as_ptr(), data.len());
}

unsafe fn stdio_simple_command(
    conn: &mut hg_connection,
    response: &mut strbuf,
    command: &str,
    args: HgArgs,
) {
    let stdio = conn.inner.stdio.as_mut().unwrap();
    stdio_send_command(stdio, command, args);
    stdio_read_response(stdio, response);
}

unsafe fn stdio_changegroup_command(
    conn: &mut hg_connection,
    writer: &mut writer,
    command: &str,
    args: HgArgs,
) {
    let stdio = conn.inner.stdio.as_mut().unwrap();
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

unsafe fn stdio_push_command(
    conn: &mut hg_connection,
    response: &mut strbuf,
    input: *mut FILE,
    len: off_t,
    command: &str,
    args: HgArgs,
) {
    let stdio = conn.inner.stdio.as_mut().unwrap();
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
        libc::fread(header.as_mut_ptr() as *mut c_void, 4, 1, input);
        libc::fseek(input, 0, libc::SEEK_SET);
        &header == b"HG20"
    } else {
        false
    };

    let mut len = len;
    let mut buf = [0u8; 4096];
    while len > 0 {
        let buf_len = buf.len();
        let mut read = cmp::min(buf_len, len.try_into().unwrap_or(buf_len));
        read = libc::fread(buf.as_mut_ptr() as *mut c_void, 1, read, input);
        len -= read as off_t;
        stdio_write(stdio, buf.as_ptr(), read);
    }

    stdio_write(stdio, "0\n".as_ptr(), 2);
    if is_bundle2 {
        copy_bundle_to_strbuf(stdio.out, response);
    } else {
        /* There are two responses, one for output, one for actual response. */
        //TODO: actually handle output here
        let mut header = strbuf::new();
        stdio_read_response(stdio, &mut header);
        drop(header);
        stdio_read_response(stdio, response);
    }
}

#[no_mangle]
unsafe extern "C" fn stdio_send_empty_command(conn: *mut hg_connection_stdio) {
    let conn = conn.as_mut().unwrap();
    stdio_send_command(conn, "", args!());
}

#[allow(non_camel_case_types)]
struct command_request_data<'a> {
    conn: &'a mut hg_connection,
    prepare_request_cb: Box<dyn FnMut(*mut CURL, *mut curl_slist)>,
    command: &'a str,
    args: BString,
}

#[allow(non_camel_case_types)]
struct http_request_info {
    retcode: c_int,
    redirect_url: Option<BString>,
}

fn http_request(data: &mut command_request_data) -> http_request_info {
    unsafe {
        let slot = get_active_slot().as_mut().unwrap();
        curl_easy_setopt(slot.curl, CURLOPT_FAILONERROR, 0);
        curl_easy_setopt(slot.curl, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(slot.curl, CURLOPT_NOBODY, 0);

        let mut headers = ptr::null_mut();
        headers = curl_slist_append(headers, cstr!("Accept: application/mercurial-0.1").as_ptr());
        prepare_command_request(slot.curl, headers, data);

        curl_easy_setopt(slot.curl, CURLOPT_HTTPHEADER, headers);
        /* Strictly speaking, this is not necessary, but bitbucket does
         * user-agent sniffing, and git's user-agent gets 404 on mercurial
         * urls. */
        curl_easy_setopt(
            slot.curl,
            CURLOPT_USERAGENT,
            cstr!("mercurial/proto-1.0").as_ptr(),
        );

        let mut results = slot_results::new();
        let ret = run_one_slot(slot, &mut results);
        curl_slist_free_all(headers);

        let mut redirects: c_long = 0;
        curl_easy_getinfo(slot.curl, CURLINFO_REDIRECT_COUNT, &mut redirects);

        http_request_info {
            retcode: ret,
            redirect_url: if redirects > 0 {
                let mut effective_url: *const c_char = ptr::null();
                curl_easy_getinfo(slot.curl, CURLINFO_EFFECTIVE_URL, &mut effective_url);
                Some(
                    CStr::from_ptr(effective_url.as_ref().unwrap())
                        .to_bytes()
                        .to_owned()
                        .into(),
                )
            } else {
                None
            },
        }
    }
}

fn http_request_reauth(data: &mut command_request_data) -> c_int {
    let http_request_info {
        retcode: ret,
        redirect_url,
    } = http_request(data);

    if ret != HTTP_OK && ret != HTTP_REAUTH {
        return ret;
    }

    if let Some(effective_url) = redirect_url {
        if let Some(query_idx) = effective_url.find("?cmd=") {
            let http = unsafe { data.conn.inner.http.as_mut().unwrap() };
            let mut new_url_buf = strbuf::new();
            let new_url = &effective_url[..query_idx];
            new_url_buf.extend_from_slice(new_url);
            let old_url = mem::replace(&mut http.url, new_url_buf.detach());
            unsafe {
                libc::free(old_url as *mut c_void);
            }
            eprintln!("warning: redirecting to {}", new_url.as_bstr());
        }
    }

    if ret != HTTP_REAUTH {
        return ret;
    }

    unsafe {
        credential_fill(&mut http_auth);
    }
    http_request(data).retcode
}

/* The Mercurial HTTP protocol uses HTTP requests for each individual command.
 * The command name is passed as "cmd" query parameter.
 * The command arguments can be passed in several different ways, but for now,
 * only the following is supported:
 * - each argument is passed as a query parameter.
 *
 * The command results are simply the corresponding HTTP responses.
 */
const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'*')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b' ');

fn http_query_add_param(data: &mut BString, name: &str, value: param_value) {
    if name != "*" {
        let value = match value {
            param_value::value(v) => percent_encode(v, QUERY_ENCODE_SET)
                .to_string()
                .replace(" ", "+"),
            _ => unreachable!(),
        };
        data.extend_from_slice(b"&");
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(b"=");
        data.extend_from_slice(value.as_bytes());
    }
}

unsafe fn prepare_command_request(
    curl: *mut CURL,
    headers: *mut curl_slist,
    data: &mut command_request_data,
) {
    let mut command_url: BString = Vec::new().into();
    let httpheader = hg_get_capability(data.conn, cstr!("httpheader").as_ptr())
        .as_ref()
        .and_then(|c| CStr::from_ptr(c).to_str().ok())
        .and_then(|s| usize::from_str(s).ok())
        .unwrap_or(0);

    let http = data.conn.inner.http.as_mut().unwrap();
    if http_follow_config == http_follow_config::HTTP_FOLLOW_INITIAL && http.initial_request > 0 {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        http.initial_request = 0;
    }

    (data.prepare_request_cb)(curl, headers);

    command_url.extend_from_slice(CStr::from_ptr(http.url).to_bytes());
    command_url.extend_from_slice(b"?cmd=");
    command_url.extend_from_slice(data.command.as_bytes());

    let args = data.args.as_bytes();
    if httpheader > 0 && !args.is_empty() {
        let mut args = &args[1..];
        let mut headers = headers;
        let mut num = 1;
        while !args.is_empty() {
            let mut header = BString::from(format!("X-HgArg-{}: ", num).into_bytes());
            num += 1;
            let (chunk, remainder) = args.split_at(cmp::min(args.len(), httpheader - header.len()));
            header.extend_from_slice(chunk);
            let header = CString::new(header).unwrap();
            headers = curl_slist_append(headers, header.as_ptr());
            args = remainder;
        }
    } else {
        command_url.extend_from_slice(args);
    }

    let command_url = CString::new(command_url).unwrap();
    curl_easy_setopt(curl, CURLOPT_URL, command_url.as_ptr());
}

unsafe fn http_command(
    conn: &mut hg_connection,
    prepare_request_cb: Box<dyn FnMut(*mut CURL, *mut curl_slist)>,
    command: &str,
    args: HgArgs,
) {
    let mut request_data = command_request_data {
        conn,
        prepare_request_cb,
        command,
        args: Vec::new().into(),
    };
    prepare_command(
        |name, value| http_query_add_param(&mut request_data.args, name, value),
        args,
    );
    if http_request_reauth(&mut request_data) != HTTP_OK {
        die!(
            "unable to access '{}': {}",
            CStr::from_ptr(conn.inner.http.as_mut().unwrap().url)
                .to_bytes()
                .as_bstr(),
            CStr::from_ptr(curl_errorstr.as_ptr()).to_bytes().as_bstr()
        );
    }
}

unsafe fn http_simple_command(
    conn: &mut hg_connection,
    response: &mut strbuf,
    command: &str,
    args: HgArgs,
) {
    let response = response as *mut strbuf;
    let is_pushkey = command == "pushkey";
    http_command(
        conn,
        Box::new(move |curl, headers| {
            if is_pushkey {
                prepare_pushkey_request(curl, headers, response)
            } else {
                prepare_simple_request(curl, headers, response)
            }
        }),
        command,
        args,
    )
}

/* The changegroup, changegroupsubset and getbundle commands return a raw
 *  * zlib stream when called over HTTP. */
unsafe fn http_changegroup_command(
    conn: &mut hg_connection,
    writer: &mut writer,
    command: &str,
    args: HgArgs,
) {
    let mut response_data = changegroup_response_data::new(writer);

    http_command(
        conn,
        Box::new(move |curl, headers| {
            prepare_changegroup_request(curl, headers, &mut response_data)
        }),
        command,
        args,
    );
}

extern "C" {
    fn get_stderr() -> *mut FILE;
}

unsafe fn http_push_command(
    conn: &mut hg_connection,
    response: &mut strbuf,
    input: *mut FILE,
    len: off_t,
    command: &str,
    args: HgArgs,
) {
    let mut http_response = strbuf::new();
    let mut info = push_request_info::new(&mut http_response, input, len);
    //TODO: handle errors.
    http_command(
        conn,
        Box::new(move |curl, headers| prepare_push_request(curl, headers, &mut info)),
        command,
        args,
    );

    let http_response = http_response.as_bytes();
    if http_response.get(..4) == Some(b"HG20") {
        response.extend_from_slice(http_response);
    } else {
        let mut writer = writer {
            write: libc::fwrite as _,
            close: libc::fflush as _,
            context: get_stderr() as _,
        };
        match &http_response.splitn_str(2, "\n").collect::<Vec<_>>()[..] {
            [stdout_, stderr_] => {
                response.extend_from_slice(stdout_);
                prefix_writer(&mut writer, cstr!("remote: ").as_ptr());
                writer.write_all(stderr_).unwrap();
            }
            //TODO: better eror handling.
            _ => panic!("Bad output from server"),
        }
    }
}

unsafe fn http_capabilities_command(conn: *mut hg_connection, writer: *mut writer) {
    http_command(
        conn.as_mut().unwrap(),
        Box::new(move |curl, headers| prepare_caps_request(curl, headers, writer)),
        "capabilities",
        args!(),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_connect(url: *const c_char, flags: c_int) -> *mut hg_connection {
    let url_ = CStr::from_ptr(url).to_bytes();
    let mut conn = if url_.starts_with(b"http://") || url_.starts_with(b"https://") {
        let inner = hg_connect_http(url, flags);
        if inner.is_null() {
            return ptr::null_mut();
        }

        let mut conn = Box::new(hg_connection {
            simple_command: http_simple_command,
            changegroup_command: http_changegroup_command,
            push_command: http_push_command,
            finish: http_finish,
            capabilities: Vec::new(),
            inner: hg_connection_inner { http: inner },
        });

        let mut caps = strbuf::new();
        let mut writer = writer {
            write: fwrite_buffer as _,
            close: ptr::null(),
            context: &mut caps as *mut _ as *mut c_void,
        };
        http_capabilities_command(&mut *conn, &mut writer);
        /* Cf. comment above caps_request_write. If the bundle stream was
         * sent to stdout, the writer was switched to fwrite. */
        if writer.write != fwrite_buffer as _ {
            drop(writer);
            http_finish(inner as *mut c_void);
            return ptr::null_mut();
        }
        mem::swap(
            &mut conn.capabilities,
            &mut split_capabilities(caps.as_bytes()),
        );

        conn
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

        let mut conn = Box::new(hg_connection {
            simple_command: stdio_simple_command,
            changegroup_command: stdio_changegroup_command,
            push_command: stdio_push_command,
            finish: stdio_finish,
            capabilities: Vec::new(),
            inner: hg_connection_inner { stdio: inner },
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

        conn
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
        let cap_ = CString::new(*cap).unwrap();
        if hg_get_capability(&mut *conn, cap_.as_ptr()).is_null() {
            die!(
                "Mercurial repository doesn't support the required \"{}\" capability.",
                cap
            );
        }
    }

    Box::into_raw(conn)
}

#[no_mangle]
unsafe extern "C" fn hg_finish_connect(conn: *mut hg_connection) -> c_int {
    let conn = Box::from_raw(conn.as_mut().unwrap());
    let code = (conn.finish)(conn.inner.http as *mut c_void);
    libc::free(conn.inner.http as *mut c_void);
    code
}
