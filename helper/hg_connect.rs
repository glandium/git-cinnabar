/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp::{self, Ordering};
use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;
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
    curl_easy_getinfo, curl_easy_setopt, curl_off_t, curl_slist, curl_slist_append,
    curl_slist_free_all, CURLcode, CURL, CURLINFO_EFFECTIVE_URL, CURLINFO_REDIRECT_COUNT,
    CURLOPT_FAILONERROR, CURLOPT_FOLLOWLOCATION, CURLOPT_HTTPGET, CURLOPT_HTTPHEADER,
    CURLOPT_NOBODY, CURLOPT_URL, CURLOPT_USERAGENT,
};
use itertools::Itertools;
use libc::{off_t, FILE};
use percent_encoding::{percent_decode, percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha1::{Digest, Sha1};

#[allow(non_camel_case_types)]
#[repr(C)]
struct hg_connection {
    simple_command: unsafe extern "C" fn(
        conn: *mut hg_connection,
        response: *mut strbuf,
        command: *const c_char,
        args: args_slice,
    ),
    changegroup_command: unsafe extern "C" fn(
        conn: *mut hg_connection,
        out: *mut writer,
        command: *const c_char,
        args: args_slice,
    ),
    push_command: unsafe extern "C" fn(
        conn: *mut hg_connection,
        response: *mut strbuf,
        input: *mut FILE,
        len: off_t,
        command: *const c_char,
        args: args_slice,
    ),
    finish: unsafe extern "C" fn(conn: *mut hg_connection) -> c_int,
    capabilities: Option<Box<Vec<(BString, CString)>>>,
    inner: hg_connection_inner,
}

#[allow(non_camel_case_types)]
#[repr(C)]
union hg_connection_inner {
    http: hg_connection_inner_http,
    stdio: (),
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct hg_connection_inner_http {
    url: *const c_char,
    initial_request: c_int,
}

#[no_mangle]
unsafe extern "C" fn drop_capabilities(conn: *mut hg_connection) {
    let conn = conn.as_mut().unwrap();
    conn.capabilities.take();
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct args_slice<'a> {
    data: *const *const c_void,
    len: usize,
    marker: PhantomData<&'a ()>,
}

impl<'a> args_slice<'a> {
    fn new(args: &'a [*const c_void]) -> args_slice<'a> {
        args_slice {
            data: args.as_ptr(),
            len: args.len(),
            marker: PhantomData,
        }
    }

    fn as_slice(&'a self) -> &'a [*const c_void] {
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct oid_array {
    oid: *const object_id,
    nr: c_int,
    alloc: c_int,
    sorted: c_int,
}

#[allow(non_camel_case_types)]
struct oid_array_iter<'a> {
    array: &'a oid_array,
    next: Option<c_int>,
}

impl oid_array {
    fn is_empty(&self) -> bool {
        self.nr == 0
    }

    fn iter(&self) -> oid_array_iter {
        oid_array_iter {
            array: self,
            next: Some(0),
        }
    }
}

impl<'a> Iterator for oid_array_iter<'a> {
    type Item = &'a object_id;
    fn next(&mut self) -> Option<Self::Item> {
        let i = self.next.take()?;
        let result = unsafe { self.array.oid.offset(i as isize).as_ref()? };
        self.next = i.checked_add(1).filter(|&x| x < self.array.nr);
        Some(result)
    }
}

const GIT_SHA1_RAWSZ: usize = 20;
const GIT_MAX_RAWSZ: usize = 32;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Eq)]
struct object_id([u8; GIT_MAX_RAWSZ]);

impl Display for object_id {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for x in self.raw() {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

impl object_id {
    fn create() -> object_id_creator {
        object_id_creator(Sha1::new())
    }

    fn raw(&self) -> &[u8] {
        &self.0[..GIT_SHA1_RAWSZ]
    }
}

impl PartialEq for object_id {
    fn eq(&self, other: &Self) -> bool {
        self.raw() == other.raw()
    }
}

impl PartialOrd for object_id {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.raw().cmp(other.raw()))
    }
}

impl Ord for object_id {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw().cmp(other.raw())
    }
}

#[allow(non_camel_case_types)]
struct object_id_creator(Sha1);

impl object_id_creator {
    fn result(self) -> object_id {
        let mut result = object_id([0; GIT_MAX_RAWSZ]);
        result.0[..GIT_SHA1_RAWSZ].copy_from_slice(self.0.result().as_slice());
        result
    }

    fn input(&mut self, data: &[u8]) {
        self.0.input(data)
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct strbuf {
    alloc: usize,
    len: usize,
    buf: *mut c_char,
}

extern "C" {
    static strbuf_slopbuf: *const c_char;
    fn strbuf_add(buf: *mut strbuf, data: *const c_void, len: usize);
    fn strbuf_release(buf: *mut strbuf);
    fn strbuf_detach(buf: *mut strbuf, sz: *mut usize) -> *const c_char;
}

impl strbuf {
    fn new() -> Self {
        strbuf {
            alloc: 0,
            len: 0,
            buf: unsafe { strbuf_slopbuf as *mut _ },
        }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buf as *const u8, self.len) }
    }

    fn extend_from_slice(&mut self, s: &[u8]) {
        unsafe { strbuf_add(self, s.as_ptr() as *const c_void, s.len()) }
    }

    fn detach(mut self) -> *const c_char {
        let result = unsafe { strbuf_detach(&mut self, ptr::null_mut()) };
        mem::forget(self);
        result
    }
}

impl Drop for strbuf {
    fn drop(&mut self) {
        unsafe {
            strbuf_release(self);
        }
    }
}

/* Split the list of capabilities a mercurial server returned. Also url-decode
 * the bundle2 value (TODO: in place). */
#[no_mangle]
unsafe extern "C" fn split_capabilities(conn: *mut hg_connection, buf: *const c_char) {
    let conn = conn.as_mut().unwrap();
    let buf = CStr::from_ptr(buf).to_bytes();
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
    conn.capabilities.replace(Box::new(capabilities));
}

#[no_mangle]
unsafe extern "C" fn hg_get_capability(
    conn: *mut hg_connection,
    name: *const c_char,
) -> *const c_char {
    let conn = conn.as_mut().unwrap();
    let needle = CStr::from_ptr(name).to_bytes();
    if let Some(capabilities) = conn.capabilities.as_ref() {
        for (name, value) in capabilities.iter() {
            if name == needle {
                return value.as_ptr();
            }
        }
    }
    ptr::null()
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct writer {
    write: *const c_void,
    close: *const c_void,
    context: *mut c_void,
}

extern "C" {
    fn write_to(buf: *const c_char, size: usize, nmemb: usize, writer: *mut writer) -> usize;

    fn writer_close(w: *mut writer);
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
        (conn.simple_command)(
            conn,
            branchmap,
            cstr!("branchmap").as_ptr(),
            args_slice::new(&[]),
        );
        (conn.simple_command)(conn, heads, cstr!("heads").as_ptr(), args_slice::new(&[]));
        hg_listkeys(conn, bookmarks, cstr!("bookmarks").as_ptr());
    } else {
        let mut out = strbuf::new();
        (conn.simple_command)(
            conn,
            &mut out,
            cstr!("batch").as_ptr(),
            args_slice::new(&[
                cstr!("cmds").as_ptr() as _,
                cstr!("branchmap ;heads ;listkeys namespace=bookmarks").as_ptr() as _,
                cstr!("*").as_ptr() as _,
                ptr::null::<c_void>(),
            ]),
        );
        if !out.buf.is_null() {
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
    let nodes_str = CString::new(nodes.iter().join(" ")).unwrap();
    (conn.simple_command)(
        conn,
        result,
        cstr!("known").as_ptr(),
        args_slice::new(&[
            cstr!("nodes").as_ptr() as _,
            nodes_str.as_ptr() as _,
            cstr!("*").as_ptr() as _,
            ptr::null::<c_void>(),
        ]),
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
        result,
        cstr!("listkeys").as_ptr(),
        args_slice::new(&[cstr!("namespace").as_ptr() as _, namespace as _]),
    );
}

#[allow(non_camel_case_types)]
enum param_value<'a> {
    size(usize),
    value(&'a [u8]),
}

unsafe fn prepare_command<F: FnMut(&str, param_value)>(mut command_add_param: F, args: args_slice) {
    for item in args.as_slice().chunks(2) {
        if let [name, value] = *item {
            let name = CStr::from_ptr(name as *const c_char).to_str().unwrap();
            if name == "*" {
                let params = (value as *const Vec<(&str, BString)>).as_ref();
                let num = param_value::size(params.map(|p| p.len()).unwrap_or(0));
                command_add_param("*", num);
                if let Some(params) = params {
                    for (name, value) in params {
                        let value = param_value::value(value.as_bytes());
                        command_add_param(name, value);
                    }
                }
            } else {
                command_add_param(
                    name,
                    param_value::value(CStr::from_ptr(value as _).to_bytes()),
                );
            }
        } else {
            unreachable!();
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
    (conn.changegroup_command)(
        conn,
        &mut writer,
        cstr!("getbundle").as_ptr(),
        args_slice::new(&[cstr!("*").as_ptr() as _, &args as *const _ as _]),
    );
    writer_close(&mut writer);
}

extern "C" {
    fn copy_bundle_to_file(input: *mut FILE, file: *mut FILE);
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
    let heads_str = CString::new(if heads.is_empty() {
        hex::encode("force")
    } else if hg_get_capability(conn, cstr!("unbundlehash").as_ptr()).is_null() {
        heads.iter().join(" ")
    } else {
        let mut hash = object_id::create();
        for h in heads.iter().sorted().dedup() {
            hash.input(h.raw());
        }
        format!("{} {}", hex::encode("hashed"), hash.result())
    })
    .unwrap();

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
        response,
        fh,
        len.try_into().unwrap(),
        cstr!("unbundle").as_ptr(),
        args_slice::new(&[cstr!("heads").as_ptr() as _, heads_str.as_ptr() as _]),
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
        response,
        cstr!("pushkey").as_ptr(),
        args_slice::new(&[
            cstr!("namespace").as_ptr() as _,
            namespace as _,
            cstr!("key").as_ptr() as _,
            key as _,
            cstr!("old").as_ptr() as _,
            old as _,
            cstr!("new").as_ptr() as _,
            new as _,
        ]),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_lookup(conn: *mut hg_connection, result: *mut strbuf, key: *const c_char) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result,
        cstr!("lookup").as_ptr(),
        args_slice::new(&[cstr!("key").as_ptr() as _, key as _]),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_clonebundles(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result,
        cstr!("clonebundles").as_ptr(),
        args_slice::new(&[]),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_cinnabarclone(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result,
        cstr!("cinnabarclone").as_ptr(),
        args_slice::new(&[]),
    );
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

extern "C" {
    #[allow(improper_ctypes)]
    fn stdio_write(conn: *mut hg_connection, buf: *const u8, len: usize);
}

#[no_mangle]
unsafe extern "C" fn stdio_send_command(
    conn: *mut hg_connection,
    command: *const c_char,
    args: args_slice,
) {
    let conn = conn.as_mut().unwrap();
    let mut data = BString::from(Vec::<u8>::new());
    data.extend(CStr::from_ptr(command).to_bytes());
    data.push(b'\n');
    prepare_command(
        |name, value| stdio_command_add_param(&mut data, name, value),
        args,
    );
    stdio_write(conn, data.as_ptr(), data.len());
}

#[allow(non_camel_case_types)]
type prepare_request_cb_t =
    unsafe extern "C" fn(curl: *mut CURL, headers: *mut curl_slist, data: *mut c_void);

#[allow(non_camel_case_types)]
struct command_request_data<'a> {
    conn: *mut hg_connection,
    prepare_request_cb: prepare_request_cb_t,
    data: *mut c_void,
    command: &'a str,
    args: BString,
}

#[allow(non_camel_case_types)]
struct http_request_info {
    redirects: c_long,
    effective_url: *const c_char,
}

extern "C" {
    #[allow(improper_ctypes)]
    fn http_command_error(conn: *mut hg_connection) -> !;

    fn free(ptr: *mut c_void);

    fn credential_fill(auth: *mut credential);

    static mut http_auth: credential;

    fn get_active_slot() -> *mut active_request_slot;

    fn run_one_slot(slot: *mut active_request_slot, results: *mut slot_results) -> c_int;
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct credential(c_void);

#[allow(non_camel_case_types)]
#[repr(C)]
struct active_request_slot {
    curl: *mut CURL,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct slot_results {
    curl_result: CURLcode,
    http_code: c_long,
    auth_avail: c_long,
    http_connectcode: c_long,
}

const HTTP_OK: c_int = 0;
const HTTP_REAUTH: c_int = 4;

fn http_request(info: &mut http_request_info, data: &mut command_request_data) -> c_int {
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

        let mut results = slot_results {
            curl_result: 0,
            http_code: 0,
            auth_avail: 0,
            http_connectcode: 0,
        };
        let ret = run_one_slot(slot, &mut results);
        curl_slist_free_all(headers);

        curl_easy_getinfo(slot.curl, CURLINFO_REDIRECT_COUNT, &mut info.redirects);
        curl_easy_getinfo(slot.curl, CURLINFO_EFFECTIVE_URL, &mut info.effective_url);

        ret
    }
}

fn http_request_reauth(data: &mut command_request_data) -> c_int {
    let mut info = http_request_info {
        redirects: 0,
        effective_url: ptr::null(),
    };
    let ret = http_request(&mut info, data);

    if ret != HTTP_OK && ret != HTTP_REAUTH {
        return ret;
    }

    if info.redirects > 0 {
        let effective_url = unsafe { CStr::from_ptr(info.effective_url).to_bytes() };
        if let Some(query_idx) = effective_url.find("?cmd=") {
            let http = unsafe { &mut data.conn.as_mut().unwrap().inner.http };
            let mut new_url_buf = strbuf::new();
            let new_url = &effective_url[..query_idx];
            new_url_buf.extend_from_slice(new_url);
            let old_url = mem::replace(&mut http.url, new_url_buf.detach());
            unsafe {
                free(old_url as *mut c_void);
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
    http_request(&mut info, data)
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

#[allow(dead_code, non_camel_case_types)]
#[repr(C)]
#[derive(PartialEq)]
enum http_follow_config {
    HTTP_FOLLOW_NONE,
    HTTP_FOLLOW_ALWAYS,
    HTTP_FOLLOW_INITIAL,
}

extern "C" {
    static http_follow_config: http_follow_config;
}

unsafe extern "C" fn prepare_command_request(
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

    let http = &mut data.conn.as_mut().unwrap().inner.http;
    if http_follow_config == http_follow_config::HTTP_FOLLOW_INITIAL && http.initial_request > 0 {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        http.initial_request = 0;
    }

    (data.prepare_request_cb)(curl, headers, data.data);

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
    prepare_request_cb: prepare_request_cb_t,
    data: *mut c_void,
    command: &str,
    args: args_slice,
) {
    let mut request_data = command_request_data {
        conn,
        prepare_request_cb,
        data,
        command,
        args: Vec::new().into(),
    };
    prepare_command(
        |name, value| http_query_add_param(&mut request_data.args, name, value),
        args,
    );
    if http_request_reauth(&mut request_data) != HTTP_OK {
        http_command_error(conn);
    }
}

extern "C" {
    fn prepare_simple_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut c_void);
    fn prepare_pushkey_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut c_void);
    fn prepare_changegroup_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut c_void);
    fn prepare_push_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut c_void);
    fn prepare_caps_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut c_void);
}

#[no_mangle]
unsafe extern "C" fn http_simple_command(
    conn: *mut hg_connection,
    response: *mut strbuf,
    command: *const c_char,
    args: args_slice,
) {
    if CStr::from_ptr(command).to_bytes() == b"pushkey" {
        http_command(
            conn.as_mut().unwrap(),
            prepare_pushkey_request,
            response as *mut c_void,
            CStr::from_ptr(command).to_str().unwrap(),
            args,
        )
    } else {
        http_command(
            conn.as_mut().unwrap(),
            prepare_simple_request,
            response as *mut c_void,
            CStr::from_ptr(command).to_str().unwrap(),
            args,
        )
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct changegroup_response_data {
    curl: *mut CURL,
    writer: *mut writer,
}

/* The changegroup, changegroupsubset and getbundle commands return a raw
 *  * zlib stream when called over HTTP. */
#[no_mangle]
unsafe extern "C" fn http_changegroup_command(
    conn: *mut hg_connection,
    writer: *mut writer,
    command: *const c_char,
    args: args_slice,
) {
    let mut response_data = changegroup_response_data {
        curl: ptr::null_mut(),
        writer,
    };

    http_command(
        conn.as_mut().unwrap(),
        prepare_changegroup_request,
        &mut response_data as *mut _ as *mut c_void,
        CStr::from_ptr(command).to_str().unwrap(),
        args,
    );
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct push_request_info {
    response: *mut strbuf,
    input: *mut FILE,
    len: curl_off_t,
}

extern "C" {
    fn get_stderr() -> *mut FILE;

    fn prefix_writer(writer: *mut writer, prefix: *const c_char);
}

#[no_mangle]
unsafe extern "C" fn http_push_command(
    conn: *mut hg_connection,
    response: *mut strbuf,
    input: *mut FILE,
    len: off_t,
    command: *const c_char,
    args: args_slice,
) {
    let mut http_response = strbuf::new();
    let mut info = push_request_info {
        response: &mut http_response,
        input,
        len: len.into(),
    };
    //TODO: handle errors.
    http_command(
        conn.as_mut().unwrap(),
        prepare_push_request,
        &mut info as *mut _ as *mut c_void,
        CStr::from_ptr(command).to_str().unwrap(),
        args,
    );

    let http_response = http_response.as_bytes();
    if http_response.get(..4) == Some(b"HG20") {
        response.as_mut().unwrap().extend_from_slice(http_response);
    } else {
        let mut writer = writer {
            write: libc::fwrite as _,
            close: libc::fflush as _,
            context: get_stderr() as _,
        };
        match &http_response.splitn_str(2, "\n").collect::<Vec<_>>()[..] {
            [stdout_, stderr_] => {
                response.as_mut().unwrap().extend_from_slice(stdout_);
                prefix_writer(&mut writer, cstr!("remote: ").as_ptr());
                write_to(
                    stderr_.as_ptr() as *const c_char,
                    1,
                    stderr_.len(),
                    &mut writer,
                );
                writer_close(&mut writer);
            }
            //TODO: better eror handling.
            _ => panic!("Bad output from server"),
        }
    }
}

#[no_mangle]
unsafe extern "C" fn http_capabilities_command(conn: *mut hg_connection, writer: *mut writer) {
    http_command(
        conn.as_mut().unwrap(),
        prepare_caps_request,
        writer as *mut c_void,
        "capabilities",
        args_slice::new(&[]),
    );
}
