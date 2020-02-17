/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp::Ordering;
use std::ffi::c_void;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::mem;
use std::os::raw::{c_char, c_int, c_long};
use std::ptr;

use curl_sys::{CURLcode, CURL, CURL_ERROR_SIZE};
use sha1::{Digest, Sha1};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct oid_array {
    oid: *const object_id,
    nr: c_int,
    alloc: c_int,
    sorted: c_int,
}

#[allow(non_camel_case_types)]
pub struct oid_array_iter<'a> {
    array: &'a oid_array,
    next: Option<c_int>,
}

impl oid_array {
    pub fn is_empty(&self) -> bool {
        self.nr == 0
    }

    pub fn iter(&self) -> oid_array_iter {
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
pub struct object_id([u8; GIT_MAX_RAWSZ]);

impl Display for object_id {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for x in self.raw() {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

impl object_id {
    pub fn create() -> object_id_creator {
        object_id_creator(Sha1::new())
    }

    pub fn raw(&self) -> &[u8] {
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
pub struct object_id_creator(Sha1);

impl object_id_creator {
    pub fn result(self) -> object_id {
        let mut result = object_id([0; GIT_MAX_RAWSZ]);
        result.0[..GIT_SHA1_RAWSZ].copy_from_slice(self.0.result().as_slice());
        result
    }

    pub fn input(&mut self, data: &[u8]) {
        self.0.input(data)
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct strbuf {
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
    pub fn new() -> Self {
        strbuf {
            alloc: 0,
            len: 0,
            buf: unsafe { strbuf_slopbuf as *mut _ },
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buf as *const u8, self.len) }
    }

    pub fn extend_from_slice(&mut self, s: &[u8]) {
        unsafe { strbuf_add(self, s.as_ptr() as *const c_void, s.len()) }
    }

    pub fn detach(mut self) -> *const c_char {
        let result = unsafe { strbuf_detach(&mut self, ptr::null_mut()) };
        mem::forget(self);
        result
    }
}

impl Write for strbuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for strbuf {
    fn drop(&mut self) {
        unsafe {
            strbuf_release(self);
        }
    }
}

extern "C" {
    pub fn die(fmt: *const c_char, ...) -> !;
}

macro_rules! die {
    ($($e:expr),+) => {
        let s = CString::new(format!($($e),+)).unwrap();
        die(s.as_ptr())
    }
}

extern "C" {
    pub fn credential_fill(auth: *mut credential);

    pub static mut http_auth: credential;

    pub fn get_active_slot() -> *mut active_request_slot;

    pub fn run_one_slot(slot: *mut active_request_slot, results: *mut slot_results) -> c_int;

    pub static curl_errorstr: [c_char; CURL_ERROR_SIZE];
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct credential(c_void);

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct active_request_slot {
    pub curl: *mut CURL,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct slot_results {
    curl_result: CURLcode,
    http_code: c_long,
    auth_avail: c_long,
    http_connectcode: c_long,
}

impl slot_results {
    pub fn new() -> Self {
        slot_results {
            curl_result: 0,
            http_code: 0,
            auth_avail: 0,
            http_connectcode: 0,
        }
    }
}

pub const HTTP_OK: c_int = 0;
pub const HTTP_REAUTH: c_int = 4;

#[allow(dead_code, non_camel_case_types)]
#[repr(C)]
#[derive(PartialEq)]
pub enum http_follow_config {
    HTTP_FOLLOW_NONE,
    HTTP_FOLLOW_ALWAYS,
    HTTP_FOLLOW_INITIAL,
}

extern "C" {
    pub static http_follow_config: http_follow_config;

    pub fn fwrite_buffer(ptr: *const c_char, elt: usize, nmemb: usize, strbuf: *mut c_void);
}
