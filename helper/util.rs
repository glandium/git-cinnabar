/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::ToOwned;
use std::convert::TryInto;
use std::io::{self, copy, Cursor, LineWriter, Read, Seek, SeekFrom, Write};
use std::sync::mpsc::{channel, Sender};
use std::thread::{self, JoinHandle};

use bstr::ByteSlice;

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

pub trait SliceExt {
    type Item;
    fn split2(&self, c: Self::Item) -> Option<(&Self, &Self)>;
}

impl<T: PartialEq> SliceExt for [T] {
    type Item = T;
    fn split2(&self, x: T) -> Option<(&[T], &[T])> {
        let mut iter = self.splitn(2, |i| *i == x);
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }
}

impl SliceExt for str {
    type Item = char;
    fn split2(&self, c: char) -> Option<(&str, &str)> {
        let mut iter = self.splitn(2, c);
        match (iter.next(), iter.next()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }
}
