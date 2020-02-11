/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp::Ordering;
use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int};
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
#[cfg(windows)]
use std::os::windows::io::IntoRawHandle;
use std::ptr;

use bstr::{BString, ByteSlice};
use itertools::Itertools;
use libc::{off_t, FILE};
use percent_encoding::percent_decode;
use sha1::{Digest, Sha1};

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
#[repr(C)]
union param_value {
    size: usize,
    value: *const c_char,
}

#[no_mangle]
unsafe extern "C" fn command_add_asterisk(
    data: *mut c_void,
    command_add_param: unsafe extern "C" fn(
        data: *mut c_void,
        name: *const c_char,
        value: param_value,
    ),
    params: *const Vec<(&CStr, CString)>,
) {
    let params = params.as_ref();
    let num = param_value {
        size: params.map(Vec::len).unwrap_or(0),
    };
    (command_add_param)(data, cstr!("*").as_ptr(), num);
    if let Some(params) = params {
        for (name, value) in params {
            let value = param_value {
                value: value.as_ptr(),
            };
            (command_add_param)(data, name.as_ptr(), value);
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
    let mut args = Vec::new();
    if let Some(heads) = heads.as_ref() {
        args.push((
            cstr!("heads"),
            CString::new(heads.iter().join(" ")).unwrap(),
        ));
    }
    if let Some(common) = common.as_ref() {
        args.push((
            cstr!("common"),
            CString::new(common.iter().join(" ")).unwrap(),
        ));
    }
    let bundle2caps = bundle2caps.as_ref().map(|p| CStr::from_ptr(p).to_owned());
    if let Some(bundle2caps) = bundle2caps {
        if !bundle2caps.to_bytes().is_empty() {
            args.push((cstr!("bundlecaps"), bundle2caps));
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
