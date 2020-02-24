/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::{Cow, ToOwned};
use std::io::{LineWriter, Write};
use std::ops::Deref;

use bstr::ByteSlice;
use flate2::write::ZlibDecoder;
use replace_with::replace_with_or_abort;

use crate::libcinnabar::writer;

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

pub fn inflate_writer(writer: &mut writer) {
    replace_with_or_abort(writer, |w| writer::new(ZlibDecoder::new(w)));
}

pub struct PrefixWriter<W: Write> {
    prefix: Vec<u8>,
    line_writer: LineWriter<W>,
}

impl<W: Write> PrefixWriter<W> {
    pub fn new(prefix: &[u8], w: W) -> Self {
        PrefixWriter {
            prefix: prefix.to_owned(),
            line_writer: LineWriter::new(w),
        }
    }
}

impl<W: Write> Write for PrefixWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut len = 0;
        for line in buf.lines_with_terminator() {
            self.line_writer.write_all(&self.prefix)?;
            len += self.line_writer.write(line)?;
        }
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.line_writer.flush()
    }
}
