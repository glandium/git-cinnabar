/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{CStr, OsStr};
use std::io::{self, Write};
use std::mem;
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(windows)]
use std::os::windows::io::FromRawHandle;
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::str;

use crate::libcinnabar::{get_writer_fd, writer, writer_close, GetRawFd};

struct PipeWriter {
    child: Child,
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.child.stdout.take();
        self.child.stdin.take();
        self.child.wait().unwrap();
    }
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.child.stdin.as_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.child.stdin.as_mut().unwrap().flush()
    }
}

impl GetRawFd for PipeWriter {}

#[no_mangle]
unsafe extern "C" fn pipe_writer(writer: &mut writer, argv: *const *const c_char) {
    let mut args = Vec::new();
    assert!(!argv.is_null());
    for i in 0.. {
        let arg = argv.offset(i).as_ref().unwrap();
        if let Some(arg) = arg.as_ref() {
            let bytes = CStr::from_ptr(arg).to_bytes();
            #[cfg(unix)]
            let os_str = OsStr::from_bytes(bytes);
            #[cfg(windows)]
            let os_str = OsStr::new(str::from_utf8(bytes).unwrap());
            args.push(os_str);
        } else {
            break;
        }
    }

    let fd = get_writer_fd(writer);
    if fd < 0 {
        die!("pipe_writer can only redirect an fwrite writer");
    }
    writer_close(writer);

    #[cfg(unix)]
    let stdout = Stdio::from_raw_fd(fd);
    #[cfg(windows)]
    let stdout = Stdio::from_raw_handle({
        let handle = libc::get_osfhandle(fd);
        if handle == -1 {
            die!("cannot get I/O handle");
        }
        handle as std::os::windows::raw::HANDLE
    });

    let child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut new_writer = writer::new(PipeWriter { child });
    mem::swap(&mut new_writer, writer);
    mem::forget(new_writer);
}
