/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::alloc::Layout;
use std::cell::Cell;
use std::ffi::{CStr, CString, OsStr};
use std::io::{self, LineWriter, Read, Write};
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::ffi;
#[cfg(windows)]
use std::os::windows::ffi;
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::str::{self, FromStr};
use std::{fmt, mem};

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

    fn map_map<B, F: FnMut(<Self::Item as Map>::Input) -> B>(self, f: F) -> MapMapIter<Self, F>
    where
        Self: Sized,
        Self::Item: Map,
    {
        MapMapIter { iter: self, f }
    }
}

pub trait Map {
    type Input;
    type Target<U>;

    fn map<U, F: FnMut(Self::Input) -> U>(self, f: F) -> Self::Target<U>;
}

pub trait MapMap: Sized + Map
where
    Self::Input: Map,
{
    fn map_map<U, F: FnMut(<Self::Input as Map>::Input) -> U>(
        self,
        f: F,
    ) -> Self::Target<<Self::Input as Map>::Target<U>>;
}

impl<T> Map for Option<T> {
    type Input = T;
    type Target<U> = Option<U>;

    fn map<U, F: FnMut(Self::Input) -> U>(self, f: F) -> Self::Target<U> {
        self.map(f)
    }
}

impl<T: Map> MapMap for Option<T>
where
    Self::Input: Map,
{
    fn map_map<U, F: FnMut(T::Input) -> U>(
        self,
        f: F,
    ) -> Self::Target<<Self::Input as Map>::Target<U>> {
        self.map(|inner| inner.map(f))
    }
}

impl<T, E> Map for Result<T, E> {
    type Input = T;
    type Target<U> = Result<U, E>;

    fn map<U, F: FnMut(Self::Input) -> U>(self, f: F) -> Self::Target<U> {
        self.map(f)
    }
}

impl<T: Map, E> MapMap for Result<T, E>
where
    Self::Input: Map,
{
    fn map_map<U, F: FnMut(T::Input) -> U>(
        self,
        f: F,
    ) -> Self::Target<<Self::Input as Map>::Target<U>> {
        self.map(|inner| inner.map(f))
    }
}

pub struct MapMapIter<I, F> {
    iter: I,
    f: F,
}

impl<I: Iterator, B, F: FnMut(<I::Item as Map>::Input) -> B> Iterator for MapMapIter<I, F>
where
    I::Item: Map,
{
    type Item = <I::Item as Map>::Target<B>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|item| item.map(&mut self.f))
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

pub trait Transpose {
    type Target;

    fn transpose(self) -> Self::Target;
}

thread_local! {
    static RECYCLED_ALLOC: Cell<Option<(NonNull<u8>, Layout)>> = const { Cell::new(None) };
}

unsafe fn alloc_recycle(layout: Layout) -> (*mut u8, usize) {
    RECYCLED_ALLOC.with(|recycled| {
        if let Some((ptr, recycled_layout)) = recycled.get() {
            if layout.size() <= recycled_layout.size() && layout.align() == recycled_layout.align()
            {
                recycled.take();
                return (ptr.as_ptr(), recycled_layout.size());
            }
        }
        (std::alloc::alloc(layout), layout.size())
    })
}

unsafe fn dealloc_keep(ptr: *mut u8, layout: Layout) {
    RECYCLED_ALLOC.with(|recycled| {
        let to_dealloc = Cell::new(Some((NonNull::new(ptr).unwrap(), layout)));
        if recycled.get().map_or(true, |(_, recycled_layout)| {
            recycled_layout.size() < layout.size()
        }) {
            to_dealloc.swap(recycled);
        }
        if let Some((ptr, layout)) = to_dealloc.take() {
            std::alloc::dealloc(ptr.as_ptr(), layout);
        }
    });
}

#[derive(Clone)]
pub struct RcSlice<T> {
    // The rc spans the initialized part of the array.
    rc: ManuallyDrop<Rc<[T]>>,
    // The real capacity of the allocation.
    capacity: usize,
}

impl<T> RcSlice<T> {
    pub fn new() -> RcSlice<T> {
        RcSlice {
            rc: ManuallyDrop::new(Rc::new([])),
            capacity: 0,
        }
    }
}

impl<T> Drop for RcSlice<T> {
    fn drop(&mut self) {
        if let Some(this) = Rc::get_mut(&mut self.rc) {
            // last reference, we can drop.
            let (layout, offset) = RcSliceBuilder::<T>::layout_for_size(self.capacity);
            unsafe {
                ptr::drop_in_place(this);
                dealloc_keep((this.as_mut_ptr() as *mut u8).sub(offset), layout);
            };
        } else {
            // We don't handle this case.
            assert_ne!(Rc::strong_count(&self.rc), 1);
            unsafe {
                ManuallyDrop::drop(&mut self.rc);
            }
        }
    }
}

impl<T> Deref for RcSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.rc
    }
}

type RcBox = [Cell<usize>; 2];

pub struct RcSliceBuilder<T> {
    ptr: NonNull<T>,
    len: usize,
    capacity: usize,
    marker: PhantomData<T>,
}

impl<T> RcSliceBuilder<T> {
    pub fn new() -> Self {
        RcSliceBuilder {
            ptr: NonNull::dangling(),
            len: 0,
            capacity: 0,
            marker: PhantomData,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut result = Self::new();
        if capacity > 0 {
            result.grow_to(capacity);
        }
        result
    }

    pub fn into_rc(self) -> RcSlice<T> {
        if self.len != 0 {
            let (_layout, offset) = Self::layout_for_size(self.capacity);
            let ptr = self.ptr;
            let len = self.len;
            let capacity = self.capacity;
            mem::forget(self);
            unsafe {
                ptr::write(
                    ptr.cast::<u8>().as_ptr().sub(offset) as *mut RcBox,
                    [Cell::new(1), Cell::new(1)],
                );
                RcSlice {
                    rc: ManuallyDrop::new(Rc::from_raw(
                        NonNull::slice_from_raw_parts(ptr, len).as_ptr(),
                    )),
                    capacity,
                }
            }
        } else {
            RcSlice::new()
        }
    }

    fn layout_for_size(size: usize) -> (Layout, usize) {
        let (layout, offset) = Layout::array::<T>(size)
            .and_then(|layout| Layout::new::<RcBox>().extend(layout))
            .map(|(layout, offset)| (layout.pad_to_align(), offset))
            .unwrap();
        let size = layout.size();
        let align = layout.align();

        // Normalize the allocation size to a power of 2 or the halfway point
        // between to powers of 2.
        let next_pow2 = size.next_power_of_two();
        let gap = next_pow2 / 4 - 1;
        let size = (size + gap) & !gap;
        (Layout::from_size_align(size, align).unwrap(), offset)
    }

    #[inline(never)]
    fn grow_to(&mut self, needed_len: usize) {
        let (layout, offset) = Self::layout_for_size(needed_len);
        unsafe {
            let (ptr, capacity) = if self.capacity == 0 {
                alloc_recycle(layout)
            } else {
                let (current_layout, _) = Self::layout_for_size(self.capacity);
                (
                    std::alloc::realloc(
                        self.ptr.cast::<u8>().as_ptr().sub(offset),
                        current_layout,
                        layout.size(),
                    ),
                    layout.size(),
                )
            };
            if ptr.is_null() {
                panic!("Out of memory");
            }
            self.ptr = NonNull::new_unchecked(ptr.add(offset) as *mut T);
            self.capacity = capacity - offset;
        }
    }

    #[inline(always)]
    pub fn reserve(&mut self, additional: usize) {
        let new_len = self.len.checked_add(additional).unwrap();
        if new_len > self.capacity {
            self.grow_to(new_len);
        }
    }

    pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.ptr.as_ptr().add(self.len) as *mut MaybeUninit<T>,
                self.capacity - self.len,
            )
        }
    }

    pub unsafe fn set_len(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.capacity);
        self.len = new_len;
    }
}

impl<T: Copy> RcSliceBuilder<T> {
    pub fn extend_from_slice(&mut self, other: &[T]) {
        self.reserve(other.len());
        unsafe {
            ptr::copy_nonoverlapping(other.as_ptr(), self.ptr.as_ptr().add(self.len), other.len());
        }
        self.len += other.len();
    }
}

impl<T> Deref for RcSliceBuilder<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T> DerefMut for RcSliceBuilder<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_mut(), self.len) }
    }
}

impl<T> Drop for RcSliceBuilder<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(NonNull::slice_from_raw_parts(self.ptr, self.len).as_ptr());
            if self.capacity > 0 {
                let (layout, offset) = Self::layout_for_size(self.capacity);
                dealloc_keep(self.ptr.cast::<u8>().as_ptr().sub(offset), layout);
            }
        }
    }
}

impl Write for RcSliceBuilder<u8> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub trait RcExt {
    type Builder;

    fn builder() -> Self::Builder;
    fn builder_with_capacity(capacity: usize) -> Self::Builder;
}

impl<T> RcExt for RcSlice<T> {
    type Builder = RcSliceBuilder<T>;

    fn builder() -> Self::Builder {
        Self::Builder::new()
    }

    fn builder_with_capacity(capacity: usize) -> Self::Builder {
        Self::Builder::with_capacity(capacity)
    }
}
