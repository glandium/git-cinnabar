/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::ToOwned;
use std::cmp::Ordering;
use std::convert::TryInto;
use std::fmt;
use std::io::{self, copy, Cursor, LineWriter, Read, Seek, SeekFrom, Write};
use std::mem;
#[cfg(unix)]
pub use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::ffi;
use std::str::{self, FromStr};
use std::sync::mpsc::{channel, Sender};
use std::thread::{self, JoinHandle};

use bstr::ByteSlice;

#[macro_export]
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

pub struct BufferedWriter {
    thread: Option<JoinHandle<io::Result<()>>>,
    sender: Option<Sender<Vec<u8>>>,
}

impl BufferedWriter {
    pub fn new<W: 'static + Write + Send>(mut w: W) -> Self {
        let (sender, receiver) = channel::<Vec<u8>>();
        let thread = thread::spawn(move || {
            for buf in receiver.iter() {
                w.write_all(&buf)?;
            }
            w.flush()?;
            Ok(())
        });
        BufferedWriter {
            thread: Some(thread),
            sender: Some(sender),
        }
    }
}

impl Drop for BufferedWriter {
    fn drop(&mut self) {
        drop(self.sender.take());
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

impl Write for BufferedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sender.as_ref().map(|s| s.send(buf.to_owned()));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_buffered_writer() {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct SlowWrite<W: Write>(Arc<Mutex<W>>);

    impl<W: Write> Write for SlowWrite<W> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            thread::sleep(Duration::from_millis(1));
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().flush()
        }
    }

    let data = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut writer = BufferedWriter::new(SlowWrite(Arc::clone(&data)));

    let start_time = Instant::now();
    for _ in 0..20 {
        assert_eq!(writer.write("0".as_bytes()).unwrap(), 1);
    }
    let write_time = Instant::now();
    drop(writer);
    let drop_time = Instant::now();
    assert_eq!(&data.lock().unwrap()[..], &[b'0'; 20][..]);
    // The writing loop should take (much) less than 1ms.
    assert!((write_time - start_time).as_micros() < 1000);
    // The drop, which waits for the thread to finish, should take at
    // least 20 times the sleep time of 1ms.
    assert!((drop_time - write_time).as_micros() >= 20000);
}

pub trait ReadExt: Read {
    fn read_at_most(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut input = self.take(buf.len().try_into().unwrap());
        let mut buf = Cursor::new(buf);
        copy(&mut input, &mut buf).map(|l| l as usize)
    }
}

impl<T: Read> ReadExt for T {}

pub trait SeekExt: Seek {
    fn stream_len_(&mut self) -> io::Result<u64> {
        let old_pos = self.seek(SeekFrom::Current(0))?;
        let len = self.seek(SeekFrom::End(0))?;
        self.seek(SeekFrom::Start(old_pos))?;
        Ok(len)
    }
}

impl<T: Seek> SeekExt for T {}

pub trait SliceExt<C> {
    fn split2(&self, c: C) -> Option<(&Self, &Self)>;
    fn split3(&self, c: C) -> Option<(&Self, &Self, &Self)>;
    fn rsplit2(&self, c: C) -> Option<(&Self, &Self)>;
    fn rsplit3(&self, c: C) -> Option<(&Self, &Self, &Self)>;
}

//TODO: generate with macros
impl<T: PartialEq> SliceExt<T> for [T] {
    fn split2(&self, x: T) -> Option<(&[T], &[T])> {
        let mut iter = self.splitn(2, |i| *i == x);
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }

    fn split3(&self, x: T) -> Option<(&[T], &[T], &[T])> {
        let mut iter = self.splitn(3, |i| *i == x);
        match (iter.next(), iter.next(), iter.next()) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    }

    fn rsplit2(&self, x: T) -> Option<(&[T], &[T])> {
        let mut iter = self.rsplitn(2, |i| *i == x);
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((b, a)),
            _ => None,
        }
    }

    fn rsplit3(&self, x: T) -> Option<(&[T], &[T], &[T])> {
        let mut iter = self.rsplitn(3, |i| *i == x);
        match (iter.next(), iter.next(), iter.next()) {
            (Some(a), Some(b), Some(c)) => Some((c, b, a)),
            _ => None,
        }
    }
}

impl SliceExt<char> for str {
    fn split2(&self, c: char) -> Option<(&str, &str)> {
        let mut iter = self.splitn(2, c);
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }

    fn split3(&self, c: char) -> Option<(&str, &str, &str)> {
        let mut iter = self.splitn(3, c);
        match (iter.next(), iter.next(), iter.next()) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    }

    fn rsplit2(&self, c: char) -> Option<(&str, &str)> {
        let mut iter = self.rsplitn(2, c);
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((b, a)),
            _ => None,
        }
    }

    fn rsplit3(&self, c: char) -> Option<(&str, &str, &str)> {
        let mut iter = self.rsplitn(3, c);
        match (iter.next(), iter.next(), iter.next()) {
            (Some(a), Some(b), Some(c)) => Some((c, b, a)),
            _ => None,
        }
    }
}

impl SliceExt<&[u8]> for [u8] {
    fn split2(&self, b: &[u8]) -> Option<(&[u8], &[u8])> {
        // Safety: This works around ByteSlice::splitn_str being too restrictive.
        // https://github.com/BurntSushi/bstr/issues/45
        let mut iter = self.splitn_str(2, unsafe { mem::transmute::<_, &[u8]>(b) });
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }

    fn split3(&self, b: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
        let mut iter = self.splitn_str(3, unsafe { mem::transmute::<_, &[u8]>(b) });
        match (iter.next(), iter.next(), iter.next()) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    }

    fn rsplit2(&self, b: &[u8]) -> Option<(&[u8], &[u8])> {
        let mut iter = self.rsplitn_str(2, unsafe { mem::transmute::<_, &[u8]>(b) });
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((b, a)),
            _ => None,
        }
    }

    fn rsplit3(&self, b: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
        let mut iter = self.rsplitn_str(3, unsafe { mem::transmute::<_, &[u8]>(b) });
        match (iter.next(), iter.next(), iter.next()) {
            (Some(a), Some(b), Some(c)) => Some((c, b, a)),
            _ => None,
        }
    }
}

#[cfg(windows)]
pub trait OsStrExt: ffi::OsStrExt {
    fn as_bytes(&self) -> &[u8];
}

#[cfg(windows)]
impl OsStrExt for std::ffi::OsStr {
    // git assumes everything is UTF-8-valid on Windows
    fn as_bytes(&self) -> &[u8] {
        self.to_str().unwrap().as_bytes()
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

pub trait BorrowKey {
    type Key: ?Sized;
    fn borrow_key(&self) -> &Self::Key;
}

impl<T: BorrowKey + ?Sized> BorrowKey for &T {
    type Key = T::Key;
    fn borrow_key(&self) -> &Self::Key {
        (*self).borrow_key()
    }
}

pub struct OrderedByKeyIter<I: Iterator>
where
    I::Item: BorrowKey,
    <I::Item as BorrowKey>::Key: Ord,
{
    iter: I,
    peeked: Option<I::Item>,
}

impl<I: Iterator> OrderedByKeyIter<I>
where
    I::Item: BorrowKey,
    <I::Item as BorrowKey>::Key: Ord,
{
    pub fn new(mut iter: I) -> Self {
        let peeked = iter.next();
        OrderedByKeyIter { iter, peeked }
    }

    pub fn peek(&self) -> Option<&I::Item>
    where
        I::Item: BorrowKey,
        <I::Item as BorrowKey>::Key: Ord,
    {
        self.peeked.as_ref()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct UnorderedError(());

impl<I: Iterator> Iterator for OrderedByKeyIter<I>
where
    I::Item: BorrowKey,
    <I::Item as BorrowKey>::Key: Ord,
{
    type Item = Result<I::Item, UnorderedError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.peeked.take() {
            Some(v) => match self.iter.next() {
                Some(peeked) if peeked.borrow_key() > v.borrow_key() => {
                    self.peeked = Some(peeked);
                    Some(Ok(v))
                }
                Some(_) => Some(Err(UnorderedError(()))),
                None => Some(Ok(v)),
            },
            None => None,
        }
    }
}

#[test]
fn test_ordered_by_key() {
    #[derive(Debug, PartialEq)]
    struct Foo(usize, usize);
    impl BorrowKey for Foo {
        type Key = usize;
        fn borrow_key(&self) -> &usize {
            &self.0
        }
    }
    let a = [Foo(1, 1), Foo(2, 1), Foo(3, 1), Foo(5, 1)];
    let mut o = OrderedByKeyIter::new(a.iter());
    for i in &a {
        assert_eq!(o.peek(), Some(&i));
        assert_eq!(o.next(), Some(Ok(i)));
    }
    assert_eq!(o.peek(), None);
    assert_eq!(o.next(), None);

    let a = [Foo(1, 1), Foo(1, 1), Foo(3, 1), Foo(5, 1)];
    let mut o = OrderedByKeyIter::new(a.iter());
    assert_eq!(o.next(), Some(Err(UnorderedError(()))));
    assert_eq!(o.next(), None);

    let a = [Foo(1, 1), Foo(3, 1), Foo(2, 1), Foo(5, 1)];
    let mut o = OrderedByKeyIter::new(a.iter());
    assert_eq!(o.next(), Some(Ok(&a[0])));
    assert_eq!(o.next(), Some(Err(UnorderedError(()))));
    assert_eq!(o.next(), None);
}

pub struct OrderedZip<A: Iterator, B: Iterator>
where
    A::Item: BorrowKey,
    B::Item: BorrowKey<Key = <A::Item as BorrowKey>::Key>,
    <A::Item as BorrowKey>::Key: Ord,
{
    a: OrderedByKeyIter<A>,
    b: OrderedByKeyIter<B>,
}

impl<A: Iterator, B: Iterator> OrderedZip<A, B>
where
    A::Item: BorrowKey,
    B::Item: BorrowKey<Key = <A::Item as BorrowKey>::Key>,
    <A::Item as BorrowKey>::Key: Ord,
{
    pub fn new(a: A, b: B) -> Self {
        OrderedZip {
            a: OrderedByKeyIter::new(a),
            b: OrderedByKeyIter::new(b),
        }
    }
}

pub struct OrderedZipItem<T: BorrowKey, U: BorrowKey<Key = T::Key>>(Option<T>, Option<U>);

impl<T: BorrowKey, U: BorrowKey<Key = T::Key>> BorrowKey for OrderedZipItem<T, U> {
    type Key = T::Key;
    fn borrow_key(&self) -> &Self::Key {
        match self {
            Self(Some(a), _) => a.borrow_key(),
            Self(_, Some(b)) => b.borrow_key(),
            Self(_, _) => unreachable!(),
        }
    }
}

impl<T: BorrowKey, U: BorrowKey<Key = T::Key>> OrderedZipItem<T, U> {
    pub fn new(
        a: Option<Result<T, UnorderedError>>,
        b: Option<Result<U, UnorderedError>>,
    ) -> Option<Result<Self, UnorderedError>> {
        match (a, b) {
            (Some(Err(e)), _) | (_, Some(Err(e))) => Some(Err(e)),
            (Some(Ok(a)), Some(Ok(b))) => Some(Ok(Self(Some(a), Some(b)))),
            (Some(Ok(a)), None) => Some(Ok(Self(Some(a), None))),
            (None, Some(Ok(b))) => Some(Ok(Self(None, Some(b)))),
            (None, None) => None,
        }
    }

    pub fn into_tuple(self) -> (Option<T>, Option<U>) {
        (self.0, self.1)
    }
}

impl<A: Iterator, B: Iterator> Iterator for OrderedZip<A, B>
where
    A::Item: BorrowKey,
    B::Item: BorrowKey<Key = <A::Item as BorrowKey>::Key>,
    <A::Item as BorrowKey>::Key: Ord,
{
    type Item = Result<OrderedZipItem<A::Item, B::Item>, UnorderedError>;
    fn next(&mut self) -> Option<Self::Item> {
        let order = match (self.a.peek(), self.b.peek()) {
            (Some(a), Some(b)) => Some((*a.borrow_key()).cmp(b.borrow_key())),
            (Some(_), None) => Some(Ordering::Less),
            (None, Some(_)) => Some(Ordering::Greater),
            (None, None) => None,
        };
        match order {
            Some(Ordering::Less) => OrderedZipItem::new(self.a.next(), None),
            Some(Ordering::Equal) => OrderedZipItem::new(self.a.next(), self.b.next()),
            Some(Ordering::Greater) => OrderedZipItem::new(None, self.b.next()),
            None => None,
        }
    }
}

#[test]
fn test_ordered_zip() {
    #[derive(Debug, PartialEq)]
    struct Foo(usize, usize);
    impl BorrowKey for Foo {
        type Key = usize;
        fn borrow_key(&self) -> &usize {
            &self.0
        }
    }
    let a = [Foo(1, 1), Foo(2, 1), Foo(4, 1)];
    let b = [Foo(1, 2), Foo(3, 2), Foo(4, 2), Foo(5, 2)];
    let result = OrderedZip::new(a.iter(), b.iter())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .map(OrderedZipItem::into_tuple)
        .collect::<Vec<_>>();
    assert_eq!(
        &result[..],
        &[
            (Some(&Foo(1, 1)), Some(&Foo(1, 2))),
            (Some(&Foo(2, 1)), None),
            (None, Some(&Foo(3, 2))),
            (Some(&Foo(4, 1)), Some(&Foo(4, 2))),
            (None, Some(&Foo(5, 2))),
        ][..]
    );

    let b = [Foo(1, 2), Foo(3, 2), Foo(2, 2), Foo(5, 2)];
    let mut o = OrderedZip::new(a.iter(), b.iter());
    assert_eq!(
        o.next().map(|x| x.map(|y| y.into_tuple())),
        Some(Ok((Some(&Foo(1, 1)), Some(&Foo(1, 2)))))
    );
    assert_eq!(
        o.next().map(|x| x.map(|y| y.into_tuple())),
        Some(Ok((Some(&Foo(2, 1)), None)))
    );
    assert_eq!(
        o.next().map(|x| x.map(|y| y.into_tuple())),
        Some(Err(UnorderedError(())))
    );
}

pub fn bstr_fmt<S: AsRef<[u8]>>(s: &S, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::Debug::fmt(s.as_ref().as_bstr(), f)
}
