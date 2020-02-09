/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};
use std::ptr;

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
#[repr(transparent)]
struct strbuf(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct writer(c_void);

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
