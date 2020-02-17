/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};
use std::ptr;

use curl_sys::{curl_off_t, curl_slist, CURL};
use libc::{off_t, FILE};

use crate::libgit::strbuf;

#[allow(non_camel_case_types)]
#[repr(C)]
pub union hg_connection_inner {
    pub http: *mut hg_connection_http,
    pub stdio: *mut hg_connection_stdio,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct hg_connection_http {
    pub url: *const c_char,
    pub initial_request: c_int,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct hg_connection_stdio {
    pub out: *mut FILE,
    pub is_remote: c_int,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct writer {
    pub write: *const c_void,
    pub close: *const c_void,
    pub context: *mut c_void,
}

extern "C" {
    pub fn write_to(buf: *const c_char, size: usize, nmemb: usize, writer: *mut writer) -> usize;

    pub fn writer_close(w: *mut writer);
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct changegroup_response_data {
    curl: *mut CURL,
    writer: *mut writer,
}

impl changegroup_response_data {
    pub fn new(writer: &mut writer) -> Self {
        changegroup_response_data {
            curl: ptr::null_mut(),
            writer,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct push_request_info {
    response: *mut strbuf,
    input: *mut FILE,
    len: curl_off_t,
}

impl push_request_info {
    pub fn new(response: &mut strbuf, input: *mut FILE, len: off_t) -> Self {
        push_request_info {
            response,
            input,
            len: len.into(),
        }
    }
}

extern "C" {
    pub fn copy_bundle_to_file(input: *mut FILE, file: *mut FILE);

    pub fn stdio_write(conn: *mut hg_connection_stdio, buf: *const u8, len: usize);

    pub fn stdio_read_response(conn: *mut hg_connection_stdio, response: *mut strbuf);

    pub fn bufferize_writer(writer: *mut writer);

    pub fn copy_bundle(input: *mut FILE, out: *mut writer);

    pub fn copy_bundle_to_strbuf(intput: *mut FILE, out: *mut strbuf);

    pub fn prepare_simple_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut strbuf);
    pub fn prepare_pushkey_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut strbuf);
    pub fn prepare_changegroup_request(
        curl: *mut CURL,
        headers: *mut curl_slist,
        data: *mut changegroup_response_data,
    );
    pub fn prepare_push_request(
        curl: *mut CURL,
        headers: *mut curl_slist,
        data: *mut push_request_info,
    );
    pub fn prepare_caps_request(curl: *mut CURL, headers: *mut curl_slist, data: *mut writer);

    pub fn prefix_writer(writer: *mut writer, prefix: *const c_char);

    pub fn hg_connect_stdio(url: *const c_char, flags: c_int) -> *mut hg_connection_stdio;

    pub fn stdio_finish(conn: *mut c_void) -> c_int;

    pub fn hg_connect_http(url: *const c_char, flags: c_int) -> *mut hg_connection_http;

    pub fn http_finish(conn: *mut c_void) -> c_int;
}
