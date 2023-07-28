/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io::{self, LineWriter, Read, Seek, SeekFrom, Write};
use std::mem;
#[cfg(unix)]
use std::os::unix::ffi;
#[cfg(windows)]
use std::os::windows::ffi;
use std::str::{self, FromStr};

use bstr::{BStr, ByteSlice};

macro_rules! derive_debug_display {
    ($typ:ty) => {
        impl ::std::fmt::Debug for $typ
        where
            $typ: ::std::fmt::Display,
        {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.debug_tuple(stringify!($typ))
                    .field(&format!("{}", self))
                    .finish()
            }
        }
    };
}
pub(crate) use derive_debug_display;

pub struct PrefixWriter<W: Write> {
    prefix: ImmutString,
    line_writer: LineWriter<W>,
}

impl<W: Write> PrefixWriter<W> {
    pub fn new(prefix: &str, w: W) -> Self {
        PrefixWriter {
            prefix: prefix.to_boxed(),
            line_writer: LineWriter::new(w),
        }
    }
}

impl<W: Write> Write for PrefixWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut len = 0;
        for line in buf.lines_with_terminator() {
            self.line_writer.write_all(self.prefix.as_bytes())?;
            len += self.line_writer.write(line)?;
        }
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.line_writer.flush()
    }
}

pub trait ReadExt: Read {
    fn read_all(&mut self) -> io::Result<ImmutBString> {
        let mut buf = Vec::new();
        self.read_to_end(&mut buf)?;
        Ok(buf.into_boxed_slice())
    }

    fn read_all_to_string(&mut self) -> io::Result<ImmutString> {
        let mut buf = String::new();
        self.read_to_string(&mut buf)?;
        Ok(buf.into_boxed_str())
    }

    fn read_exactly(&mut self, len: usize) -> io::Result<ImmutBString> {
        let mut buf = Vec::with_capacity(len);
        self.take(len as u64).read_to_end(&mut buf)?;
        if buf.len() == len {
            Ok(buf.into_boxed_slice())
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }

    fn read_exactly_to_string(&mut self, len: usize) -> io::Result<ImmutString> {
        let mut buf = String::with_capacity(len);
        self.take(len as u64).read_to_string(&mut buf)?;
        if buf.len() == len {
            Ok(buf.into_boxed_str())
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
}

impl<T: Read> ReadExt for T {}

pub trait SeekExt: Seek {
    fn stream_len_(&mut self) -> io::Result<u64> {
        let old_pos = self.stream_position()?;
        let len = self.seek(SeekFrom::End(0))?;
        self.seek(SeekFrom::Start(old_pos))?;
        Ok(len)
    }
}

impl<T: Seek> SeekExt for T {}

pub trait SliceExt<C> {
    fn splitn_exact<const N: usize>(&self, c: C) -> Option<[&Self; N]>;
    fn rsplitn_exact<const N: usize>(&self, c: C) -> Option<[&Self; N]>;
}

impl<T: PartialEq> SliceExt<T> for [T] {
    fn splitn_exact<const N: usize>(&self, x: T) -> Option<[&Self; N]> {
        array_init::from_iter(self.splitn(N, |i| *i == x))
    }

    fn rsplitn_exact<const N: usize>(&self, x: T) -> Option<[&Self; N]> {
        array_init::from_iter_reversed(self.rsplitn(N, |i| *i == x))
    }
}

impl SliceExt<char> for str {
    fn splitn_exact<const N: usize>(&self, c: char) -> Option<[&Self; N]> {
        array_init::from_iter(self.splitn(N, c))
    }

    fn rsplitn_exact<const N: usize>(&self, c: char) -> Option<[&Self; N]> {
        array_init::from_iter_reversed(self.rsplitn(N, c))
    }
}

impl<F: FnMut(&u8) -> bool> SliceExt<F> for [u8] {
    fn splitn_exact<const N: usize>(&self, f: F) -> Option<[&Self; N]> {
        array_init::from_iter(self.splitn(N, f))
    }

    fn rsplitn_exact<const N: usize>(&self, f: F) -> Option<[&Self; N]> {
        array_init::from_iter_reversed(self.rsplitn(N, f))
    }
}

impl SliceExt<&[u8]> for [u8] {
    fn splitn_exact<const N: usize>(&self, b: &[u8]) -> Option<[&Self; N]> {
        // Safety: This works around ByteSlice::splitn_str being too restrictive.
        // https://github.com/BurntSushi/bstr/issues/45
        let iter = self.splitn_str(N, unsafe { mem::transmute::<_, &[u8]>(b) });
        array_init::from_iter(iter)
    }

    fn rsplitn_exact<const N: usize>(&self, b: &[u8]) -> Option<[&Self; N]> {
        let iter = self.rsplitn_str(N, unsafe { mem::transmute::<_, &[u8]>(b) });
        array_init::from_iter_reversed(iter)
    }
}

pub trait OsStrExt: ffi::OsStrExt {
    fn as_bytes(&self) -> &[u8];

    fn from_bytes(b: &[u8]) -> &Self;

    fn to_cstring(&self) -> CString;

    fn strip_prefix(&self, prefix: impl AsRef<OsStr>) -> Option<&Self>;
}

impl OsStrExt for OsStr {
    #[cfg(windows)]
    fn as_bytes(&self) -> &[u8] {
        // git assumes everything is UTF-8-valid on Windows
        self.to_str().unwrap().as_bytes()
    }
    #[cfg(windows)]
    fn from_bytes(b: &[u8]) -> &Self {
        b.to_str().unwrap().as_ref()
    }

    #[cfg(unix)]
    fn as_bytes(&self) -> &[u8] {
        ffi::OsStrExt::as_bytes(self)
    }
    #[cfg(unix)]
    fn from_bytes(b: &[u8]) -> &Self {
        ffi::OsStrExt::from_bytes(b)
    }

    fn to_cstring(&self) -> CString {
        CString::new(self.as_bytes()).unwrap()
    }

    #[cfg(unix)]
    fn strip_prefix(&self, prefix: impl AsRef<OsStr>) -> Option<&Self> {
        self.as_bytes()
            .strip_prefix(prefix.as_ref().as_bytes())
            .map(ffi::OsStrExt::from_bytes)
    }
    #[cfg(windows)]
    fn strip_prefix(&self, prefix: impl AsRef<OsStr>) -> Option<&Self> {
        self.to_str()
            .unwrap()
            .strip_prefix(prefix.as_ref().to_str().unwrap())
            .map(OsStr::new)
    }
}

pub trait CStrExt {
    fn to_osstr(&self) -> &OsStr;
}

impl CStrExt for CStr {
    #[cfg(windows)]
    fn to_osstr(&self) -> &OsStr {
        OsStr::new(self.to_str().unwrap())
    }

    #[cfg(unix)]
    fn to_osstr(&self) -> &OsStr {
        ffi::OsStrExt::from_bytes(self.to_bytes())
    }
}

pub trait FromBytes: Sized {
    type Err;
    fn from_bytes(b: &[u8]) -> Result<Self, Self::Err>;
}

impl<T: FromStr> FromBytes for T {
    type Err = <T as FromStr>::Err;
    fn from_bytes(b: &[u8]) -> Result<Self, Self::Err> {
        //TODO: convert the error from str::from_utf8 to Self::Err
        Self::from_str(str::from_utf8(b).unwrap())
    }
}

pub fn bstr_fmt<S: AsRef<[u8]>>(s: &S, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::Debug::fmt(s.as_ref().as_bstr(), f)
}

pub trait OptionExt<T> {
    fn as_ptr(&self) -> *const T;
}

pub trait OptionMutExt<T>: OptionExt<T> {
    fn as_mut_ptr(&mut self) -> *mut T;
}

impl<T> OptionExt<T> for Option<&T> {
    fn as_ptr(&self) -> *const T {
        match self {
            Some(x) => *x as *const T,
            None => std::ptr::null(),
        }
    }
}

impl<T> OptionExt<T> for Option<&mut T> {
    fn as_ptr(&self) -> *const T {
        match self {
            Some(x) => *x as *const T,
            None => std::ptr::null(),
        }
    }
}

impl<T> OptionMutExt<T> for Option<&mut T> {
    fn as_mut_ptr(&mut self) -> *mut T {
        match self {
            Some(ref mut x) => *x as *mut T,
            None => std::ptr::null_mut(),
        }
    }
}

#[test]
fn test_optionext() {
    use std::sync::atomic::{AtomicBool, Ordering};

    static DROPPED: AtomicBool = AtomicBool::new(false);

    struct Foo;
    impl Drop for Foo {
        fn drop(&mut self) {
            assert!(!DROPPED.load(Ordering::SeqCst));
            DROPPED.store(true, Ordering::SeqCst);
        }
    }

    fn callback(ptr: *const Foo) {
        assert_ne!(ptr, std::ptr::null());
        assert!(!DROPPED.load(Ordering::SeqCst));
    }

    fn callback_mut(ptr: *mut Foo) {
        assert_ne!(ptr, std::ptr::null_mut());
        assert!(!DROPPED.load(Ordering::SeqCst));
    }

    // For good measure, ensure that lifetimes workout fine.
    callback(Some(Foo).as_ref().as_ptr());
    assert!(DROPPED.load(Ordering::SeqCst));
    DROPPED.store(false, Ordering::SeqCst);
    callback(Some(Foo).as_mut().as_ptr());
    assert!(DROPPED.load(Ordering::SeqCst));
    DROPPED.store(false, Ordering::SeqCst);
    callback_mut(Some(Foo).as_mut().as_mut_ptr());
    assert!(DROPPED.load(Ordering::SeqCst));
    assert_eq!(std::ptr::null(), (None as Option<&usize>).as_ptr());
}

pub trait IteratorExt: Iterator {
    fn try_find_<E, F: FnMut(&Self::Item) -> Result<bool, E>>(
        &mut self,
        mut f: F,
    ) -> Result<Option<Self::Item>, E>
    where
        Self: Sized,
    {
        let result = self.try_for_each(|i| match f(&i) {
            Ok(false) => Ok(()),
            Ok(true) => Err(Ok(i)),
            Err(e) => Err(Err(e)),
        });
        match result {
            Ok(()) => Ok(None),
            Err(Ok(item)) => Ok(Some(item)),
            Err(Err(e)) => Err(e),
        }
    }
}

impl<I: Iterator> IteratorExt for I {}

pub type ImmutBString = Box<[u8]>;
pub type ImmutString = Box<str>;

pub trait ToBoxed {
    fn to_boxed(&self) -> Box<Self>;
}

impl<T: Clone> ToBoxed for [T] {
    fn to_boxed(&self) -> Box<Self> {
        self.to_vec().into()
    }
}

impl ToBoxed for BStr {
    fn to_boxed(&self) -> Box<BStr> {
        unsafe { mem::transmute(self.to_vec().into_boxed_slice()) }
    }
}

impl ToBoxed for str {
    fn to_boxed(&self) -> Box<Self> {
        self.to_string().into()
    }
}
