/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::os::raw::c_int;

use libc::{fflush, fread, fwrite, FILE};

use crate::libcinnabar::GetRawFd;

pub struct File(*mut FILE);

impl File {
    pub fn new(f: *mut FILE) -> Self {
        File(f)
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(unsafe { fread(buf.as_mut_ptr() as *mut c_void, 1, buf.len(), self.0) })
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(unsafe { fwrite(buf.as_ptr() as *const c_void, 1, buf.len(), self.0) })
    }

    fn flush(&mut self) -> io::Result<()> {
        unsafe {
            fflush(self.0);
        }
        Ok(())
    }
}

impl GetRawFd for File {
    fn get_writer_fd(&mut self) -> c_int {
        unsafe { libc::fileno(self.0) }
    }
}
