/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use libc::FILE;

use crate::libgit::{child_process, strbuf};

extern "C" {
    pub fn get_stdout() -> *mut FILE;
    pub fn get_stderr() -> *mut FILE;
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

pub unsafe fn get_writer_fd(writer: &writer) -> c_int {
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

impl GetRawFd for writer {
    fn get_writer_fd(&mut self) -> c_int {
        unsafe { get_writer_fd(self) }
    }
}

impl<T: GetRawFd + ?Sized> GetRawFd for &mut T {
    fn get_writer_fd(&mut self) -> c_int {
        (**self).get_writer_fd()
    }
}

impl GetRawFd for File {
    fn get_writer_fd(&mut self) -> c_int {
        #[cfg(unix)]
        let fd = self.as_raw_fd();
        #[cfg(windows)]
        let fd = unsafe { libc::open_osfhandle(self.as_raw_handle() as _, 0) };
        fd
    }
}

impl GetRawFd for strbuf {}

pub trait WriteAndGetRawFd: Write + GetRawFd {}

impl<T: Write + GetRawFd> WriteAndGetRawFd for T {}

extern "C" {
    fn write_to(buf: *const c_char, size: usize, nmemb: usize, writer: *mut writer) -> usize;

    pub fn writer_close(w: *mut writer);
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

extern "C" {
    pub fn bufferize_writer(writer: *mut writer);
    pub fn decompress_bundle_writer(writer: *mut writer);
    pub fn inflate_writer(writer: *mut writer);

    pub fn copy_bundle(input: *mut FILE, out: *mut writer);

    pub fn prefix_writer(writer: *mut writer, prefix: *const c_char);

    pub fn hg_connect_stdio(
        userhost: *const c_char,
        port: *const c_char,
        path: *const c_char,
        flags: c_int,
    ) -> *mut child_process;

    pub fn stdio_finish(conn: *mut child_process) -> c_int;
}
