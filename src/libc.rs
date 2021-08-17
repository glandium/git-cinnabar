/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::os::raw::c_int;

pub struct FdFile(c_int);

impl FdFile {
    pub unsafe fn from_raw_fd(fd: c_int) -> Self {
        FdFile(fd)
    }

    pub unsafe fn stdout() -> Self {
        FdFile(1)
    }

    pub unsafe fn raw(&mut self) -> c_int {
        self.0
    }
}

extern "C" {
    fn xread(fd: c_int, buf: *mut c_void, size: usize) -> isize;

    fn xwrite(fd: c_int, buf: *const c_void, size: usize) -> isize;
}

impl Read for FdFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            match xread(self.0, buf.as_mut_ptr() as _, buf.len()) {
                s if s < 0 => Err(io::Error::new(io::ErrorKind::Other, "read error")),
                s => Ok(s as usize),
            }
        }
    }
}

impl Write for FdFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match xwrite(self.0, buf.as_ptr() as _, buf.len()) {
                s if s < 0 => Err(io::Error::new(io::ErrorKind::Other, "write error")),
                s => Ok(s as usize),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
