/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::{Cow, ToOwned};
use std::ffi::{CStr, OsStr};
use std::io::{self, LineWriter, Write};
use std::mem;
use std::ops::Deref;
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

use bstr::ByteSlice;
use flate2::write::ZlibDecoder;
use replace_with::replace_with_or_abort;

use crate::libcinnabar::{writer, GetRawFd, WriteAndGetRawFd};

pub trait SliceExt<T> {
    fn get_split_at(&self, mid: usize) -> Option<(&[T], &[T])>;
}

impl<T> SliceExt<T> for [T] {
    fn get_split_at(&self, mid: usize) -> Option<(&[T], &[T])> {
        if self.len() > mid {
            Some(self.split_at(mid))
        } else {
            None
        }
    }
}

pub struct BorrowingVec<'a, T>(Cow<'a, [T]>)
where
    [T]: ToOwned<Owned = Vec<T>>;

impl<'a, T> BorrowingVec<'a, T>
where
    [T]: ToOwned<Owned = Vec<T>>,
{
    pub fn new() -> Self {
        BorrowingVec(Cow::Borrowed(&[]))
    }
}

impl<'a, T: Clone> BorrowingVec<'a, T>
where
    [T]: ToOwned<Owned = Vec<T>>,
{
    pub fn extend_from_slice(&mut self, other: &'a [T]) {
        if !other.is_empty() {
            if let Cow::Borrowed(b) = &self.0 {
                if !b.is_empty() {
                    self.0 = Cow::Owned((*b).to_owned());
                }
            }
            match &mut self.0 {
                Cow::Borrowed(_) => {
                    self.0 = Cow::Borrowed(other);
                }
                Cow::Owned(o) => {
                    o.extend_from_slice(other);
                }
            }
        }
    }
}

impl<'a, T> Deref for BorrowingVec<'a, T>
where
    [T]: ToOwned<Owned = Vec<T>>,
{
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<'a, T: Clone> From<Vec<T>> for BorrowingVec<'a, T>
where
    [T]: ToOwned<Owned = Vec<T>>,
{
    fn from(v: Vec<T>) -> Self {
        BorrowingVec(v.into())
    }
}

impl<'a, T: Clone> From<BorrowingVec<'a, T>> for Vec<T>
where
    [T]: ToOwned<Owned = Vec<T>>,
{
    fn from(v: BorrowingVec<'a, T>) -> Self {
        v.0.into()
    }
}

pub struct PipeWriter {
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

    replace_with_or_abort(writer, |w| writer::new(PipeWriter::new(w, &args)));
}

impl PipeWriter {
    pub fn new<W: WriteAndGetRawFd>(mut w: W, cmd: &[&OsStr]) -> Self {
        let fd = w.get_writer_fd();
        if fd < 0 {
            die!("pipe_writer can only redirect an fwrite writer");
        }
        w.flush().unwrap();

        #[cfg(unix)]
        let stdout = unsafe { Stdio::from_raw_fd(fd) };
        #[cfg(windows)]
        let stdout = unsafe {
            Stdio::from_raw_handle({
                let handle = libc::get_osfhandle(fd);
                if handle == -1 {
                    die!("cannot get I/O handle");
                }
                handle as std::os::windows::raw::HANDLE
            })
        };

        mem::forget(w);

        let child = Command::new(cmd[0])
            .args(&cmd[1..])
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        PipeWriter { child }
    }
}

impl<W: Write> GetRawFd for ZlibDecoder<W> {}

#[no_mangle]
unsafe extern "C" fn inflate_writer(writer: &mut writer) {
    replace_with_or_abort(writer, |w| writer::new(ZlibDecoder::new(w)));
}

struct PrefixWriter<W: Write> {
    prefix: Vec<u8>,
    line_writer: LineWriter<W>,
}

impl<W: Write> PrefixWriter<W> {
    fn new(prefix: &[u8], w: W) -> Self {
        PrefixWriter {
            prefix: prefix.to_owned(),
            line_writer: LineWriter::new(w),
        }
    }
}

impl<W: Write> GetRawFd for PrefixWriter<W> {}

impl<W: Write> Write for PrefixWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut len = 0;
        for line in buf.lines_with_terminator() {
            self.line_writer.write(&self.prefix)?;
            len += self.line_writer.write(line)?;
        }
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.line_writer.flush()
    }
}

#[no_mangle]
unsafe extern "C" fn prefix_writer(writer: &mut writer, prefix: *mut c_char) {
    let prefix = CStr::from_ptr(prefix.as_ref().unwrap()).to_bytes();
    replace_with_or_abort(writer, |w| writer::new(PrefixWriter::new(prefix, w)));
}
