/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate cstr;

#[macro_use]
mod libgit;

pub mod hg_connect;

use std::convert::TryInto;
use std::ffi::OsString;
use std::os::raw::c_int;

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

extern "C" {
    #[cfg(unix)]
    pub fn helper_main(argc: c_int, argv: *const *const c_char) -> c_int;

    #[cfg(windows)]
    pub fn wmain(argc: c_int, argv: *const *const u16) -> c_int;
}

#[cfg(windows)]
use wmain as helper_main;

#[cfg(unix)]
pub fn prepare_arg(arg: OsString) -> CString {
    CString::new(arg.as_bytes()).unwrap()
}

#[cfg(windows)]
pub fn prepare_arg(arg: OsString) -> Vec<u16> {
    let mut arg = arg.encode_wide().collect::<Vec<_>>();
    arg.push(0);
    arg
}

pub fn main() {
    let argv: Vec<_> = std::env::args_os().map(prepare_arg).collect();
    let argc = argv.len();
    let mut argv: Vec<_> = argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let ret = unsafe { helper_main(argc.try_into().unwrap(), &argv[0]) };
    std::process::exit(ret);
}
