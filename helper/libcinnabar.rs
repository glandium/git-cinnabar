/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::os::raw::{c_char, c_int};

use libc::FILE;

use crate::libgit::child_process;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct hg_connection_stdio {
    pub out: *mut FILE,
    pub is_remote: c_int,
}

extern "C" {
    pub fn hg_connect_stdio(
        userhost: *const c_char,
        port: *const c_char,
        path: *const c_char,
        flags: c_int,
    ) -> *mut child_process;

    pub fn stdio_finish(conn: *mut child_process) -> c_int;
}
