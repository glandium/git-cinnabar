/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::c_void;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int};
use std::ptr;

use curl_sys::{curl_off_t, curl_slist, CURL};
use libc::{off_t, FILE};

use crate::libgit::strbuf;

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
    write: *const c_void,
    close: *const c_void,
    context: *mut c_void,
}

#[no_mangle]
unsafe extern "C" fn get_writer_fd(writer: *const writer) -> c_int {
    let writer = writer.as_ref().unwrap();
    if writer.write == libc::fwrite as *const c_void
        && writer.close == libc::fflush as *const c_void
    {
        libc::fileno(writer.context as *mut FILE)
    } else if writer.write == write_writer_write as *const c_void
        && writer.close == write_writer_close as *const c_void
    {
        let w = (writer.context as *mut Box<dyn WriteAndGetRawFd>)
            .as_mut()
            .unwrap();
        w.get_writer_fd()
    } else {
        -1
    }
}

pub trait GetRawFd {
    fn get_writer_fd(&mut self) -> c_int {
        -1
    }
}

impl<T: GetRawFd + ?Sized> GetRawFd for &mut T {
    fn get_writer_fd(&mut self) -> c_int {
        (**self).get_writer_fd()
    }
}

impl GetRawFd for strbuf {}

pub trait WriteAndGetRawFd: Write + GetRawFd {}

impl<T: Write + GetRawFd> WriteAndGetRawFd for T {}

extern "C" {
    fn write_to(buf: *const c_char, size: usize, nmemb: usize, writer: *mut writer) -> usize;

    fn writer_close(w: *mut writer);
}

impl writer {
    pub fn new<W: WriteAndGetRawFd>(w: W) -> writer {
        let w: Box<dyn WriteAndGetRawFd + '_> = Box::new(w);
        writer {
            write: write_writer_write as _,
            close: write_writer_close as _,
            context: Box::into_raw(Box::new(w)) as _,
        }
    }
}

unsafe extern "C" fn write_writer_write(
    ptr: *const c_char,
    elt: usize,
    nmemb: usize,
    context: *mut c_void,
) -> usize {
    let w = (context as *mut Box<dyn WriteAndGetRawFd>)
        .as_mut()
        .unwrap();
    let buf = std::slice::from_raw_parts(ptr as *const u8, elt.checked_mul(nmemb).unwrap());
    w.write_all(buf).unwrap();
    buf.len()
}

unsafe extern "C" fn write_writer_close(context: *mut c_void) {
    let mut w = Box::from_raw(
        (context as *mut Box<dyn WriteAndGetRawFd>)
            .as_mut()
            .unwrap(),
    );
    w.flush().unwrap();
    drop(w);
}

impl Write for writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(unsafe { write_to(buf.as_ptr() as *const c_char, 1, buf.len(), self) })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for writer {
    fn drop(&mut self) {
        unsafe {
            writer_close(self);
        }
    }
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
    pub fn decompress_bundle_writer(writer: *mut writer);

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

    pub fn prefix_writer(writer: *mut writer, prefix: *const c_char);

    pub fn hg_connect_stdio(url: *const c_char, flags: c_int) -> *mut hg_connection_stdio;

    pub fn stdio_finish(conn: *mut hg_connection_stdio) -> c_int;

    pub fn hg_connect_http(url: *const c_char, flags: c_int) -> *mut hg_connection_http;

    pub fn http_finish(conn: *mut hg_connection_http) -> c_int;
}
