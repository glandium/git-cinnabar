/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{c_void, CString};
use std::fmt::{self, Display, Formatter};
use std::os::raw::{c_char, c_int};
use std::ptr;

use itertools::Itertools;
use libc::{off_t, FILE};

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
struct object_id([u8; GIT_MAX_RAWSZ]);

impl Display for object_id {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for x in &self.0[..GIT_SHA1_RAWSZ] {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct strbuf(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct writer(c_void);

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
