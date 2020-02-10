/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp::Ordering;
use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::os::raw::{c_char, c_int};
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
#[cfg(windows)]
use std::os::windows::io::IntoRawHandle;
use std::ptr;

use itertools::Itertools;
use libc::{off_t, FILE};
use sha1::{Digest, Sha1};

#[repr(C)]
struct hg_connection {
    simple_command: unsafe extern "C" fn(
        conn: *mut hg_connection,
        response: *mut strbuf,
        command: *const c_char,
        ...
    ),
    changegroup_command: unsafe extern "C" fn(
        conn: *mut hg_connection,
        out: *mut writer,
        command: *const c_char,
        ...
    ),
    push_command: unsafe extern "C" fn(
        conn: *mut hg_connection,
        response: *mut strbuf,
        input: *mut FILE,
        len: off_t,
        command: *const c_char,
        ...
    ),
    finish: unsafe extern "C" fn(conn: *mut hg_connection) -> c_int,
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
}

impl Drop for strbuf {
    fn drop(&mut self) {
        unsafe {
            strbuf_release(self);
        }
    }
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
    fn split_batched_repo_state(
        state: *mut strbuf,
        branchmap: *mut strbuf,
        heads: *mut strbuf,
        bookmarks: *mut strbuf,
    );
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
            ptr::null::<c_void>(),
        );
        (conn.simple_command)(conn, heads, cstr!("heads").as_ptr(), ptr::null::<c_void>());
        hg_listkeys(conn, bookmarks, cstr!("bookmarks").as_ptr());
    } else {
        let mut out = strbuf::new();
        (conn.simple_command)(
            conn,
            &mut out,
            cstr!("batch").as_ptr(),
            cstr!("cmds").as_ptr(),
            cstr!("branchmap ;heads ;listkeys namespace=bookmarks").as_ptr(),
            cstr!("*").as_ptr(),
            ptr::null::<c_void>(),
            ptr::null::<c_void>(),
        );
        if !out.buf.is_null() {
            split_batched_repo_state(&mut out, branchmap, heads, bookmarks);
        }
    }
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
        cstr!("nodes").as_ptr(),
        nodes_str.as_ptr(),
        cstr!("*").as_ptr(),
        ptr::null::<c_void>(),
        ptr::null::<c_void>(),
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
        cstr!("namespace").as_ptr(),
        namespace,
        ptr::null::<c_void>(),
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
        cstr!("*").as_ptr(),
        &args,
        ptr::null::<c_void>(),
    );
    writer_close(&mut writer);
}

extern "C" {
    fn hg_get_capability(conn: *mut hg_connection, name: *const c_char) -> *const c_char;

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
        cstr!("heads").as_ptr(),
        heads_str.as_ptr(),
        ptr::null::<c_void>(),
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
        cstr!("namespace").as_ptr(),
        namespace,
        cstr!("key").as_ptr(),
        key,
        cstr!("old").as_ptr(),
        old,
        cstr!("new").as_ptr(),
        new,
        ptr::null::<c_void>(),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_lookup(conn: *mut hg_connection, result: *mut strbuf, key: *const c_char) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result,
        cstr!("lookup").as_ptr(),
        cstr!("key").as_ptr(),
        key,
        ptr::null::<c_void>(),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_clonebundles(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result,
        cstr!("clonebundles").as_ptr(),
        ptr::null::<c_void>(),
    );
}

#[no_mangle]
unsafe extern "C" fn hg_cinnabarclone(conn: *mut hg_connection, result: *mut strbuf) {
    let conn = conn.as_mut().unwrap();
    (conn.simple_command)(
        conn,
        result,
        cstr!("cinnabarclone").as_ptr(),
        ptr::null::<c_void>(),
    );
}
