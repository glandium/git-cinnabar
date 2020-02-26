/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::{TryFrom, TryInto};
use std::io::{self, copy, Read, Write};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use bzip2::write::BzDecoder;
use flate2::write::ZlibDecoder;
use replace_with::replace_with_or_abort;
use zstd::stream::write::Decoder as ZstdDecoder;

use crate::util::{BorrowingVec, SliceExt};

pub struct DecompressBundleWriter<'a> {
    initial_buf: Option<Vec<u8>>,
    out: Box<dyn Write + Send + 'a>,
}

impl<'a> DecompressBundleWriter<'a> {
    pub fn new<W: Write + Send + 'a>(w: W) -> Self {
        DecompressBundleWriter {
            initial_buf: Some(Vec::new()),
            out: Box::new(w),
        }
    }
}

// ZstdDecoder doesn't flush on drop, so we have to do it instead.
impl<'a> Drop for DecompressBundleWriter<'a> {
    fn drop(&mut self) {
        self.out.flush().unwrap();
    }
}

struct Bundlev2Header<'a> {
    params: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> Bundlev2Header<'a> {
    fn new(buf: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let (params_len, remainder) = buf.get_split_at(4)?;
        let params_len = usize::try_from(BigEndian::read_u32(params_len)).unwrap();
        let (params, remainder) = remainder.get_split_at(params_len)?;
        let header = Bundlev2Header {
            params: match params {
                buf if buf.len() == 0 => Vec::new(),
                buf => buf
                    .split(|c| *c == b' ')
                    .map(|s| {
                        let mut iter = s.splitn(2, |c| *c == b'=');
                        match (iter.next(), iter.next()) {
                            (Some(k), Some(v)) => (k, v),
                            _ => die!("malformed mercurial bundle header"),
                        }
                    })
                    .collect(),
            },
        };
        Some((header, remainder))
    }

    fn dump<W: Write, F: FnMut(&'a [u8], &'a [u8]) -> bool>(
        &'a self,
        mut w: W,
        mut f: F,
    ) -> io::Result<usize> {
        let mut data = Vec::new();
        for (k, v) in &self.params {
            if f(k, v) {
                data.extend_from_slice(k);
                data.push(b'=');
                data.extend_from_slice(v);
                data.push(b' ');
            }
        }
        data.pop();
        w.write_u32::<BigEndian>(data.len().try_into().unwrap())?;
        w.write(&data)
    }
}

impl<'a> Write for DecompressBundleWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(initial_buf) = self.initial_buf.take() {
            let mut initial_buf = BorrowingVec::from(initial_buf);
            initial_buf.extend_from_slice(buf);
            let len = match initial_buf.get(..4) {
                Some(h @ b"HG20") => {
                    Bundlev2Header::new(&initial_buf[4..]).map(|(header, remainder)| {
                        self.out.write_all(h).unwrap();
                        let mut compression = None;
                        header
                            .dump(&mut self.out, |k, v| {
                                if k == b"Compression" {
                                    compression = Some(v);
                                    false
                                } else {
                                    true
                                }
                            })
                            .unwrap();
                        if let Some(compression) = compression {
                            replace_with_or_abort(&mut self.out, |out| match compression {
                                b"GZ" => Box::new(ZlibDecoder::new(out)),
                                b"BZ" => Box::new(BzDecoder::new(out)),
                                b"ZS" => Box::new(ZstdDecoder::new(out).unwrap()),
                                comp => die!(
                                    "Unknown mercurial bundle compression: {}",
                                    String::from_utf8_lossy(comp)
                                ),
                            });
                        }
                        self.out.write_all(remainder).unwrap();
                        buf.len()
                    })
                }
                Some(h @ b"HG10") => {
                    initial_buf[4..]
                        .get_split_at(2)
                        .map(|(compression, remainder)| {
                            self.out.write_all(h).unwrap();
                            self.out.write_all(b"UN").unwrap();
                            if compression != b"UN" {
                                replace_with_or_abort(&mut self.out, |out| match compression {
                                    b"GZ" => Box::new(ZlibDecoder::new(out)),
                                    b"BZ" => {
                                        let mut out = Box::new(BzDecoder::new(out));
                                        out.write_all(b"BZ").unwrap();
                                        out
                                    }
                                    comp => die!(
                                        "Unknown mercurial bundle compression: {}",
                                        String::from_utf8_lossy(comp)
                                    ),
                                });
                            }
                            self.out.write_all(remainder).unwrap();
                            buf.len()
                        })
                }
                Some(_) => die!("Unrecognized mercurial bundle"),
                None => None,
            };

            if let Some(len) = len {
                return Ok(len);
            }
            self.initial_buf = Some(initial_buf.into());
            return Ok(buf.len());
        }
        self.out.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

#[test]
fn test_decompress_bundle_writer() {
    use bstr::ByteSlice;

    let test_cases = [
        (&b"HG20\0\0\0\0data"[..], &b"HG20\0\0\0\0data"[..]),
        (&b"HG20\0\0\0\x03k=vdata"[..], &b"HG20\0\0\0\x03k=vdata"[..]),
        (
            &b"HG20\0\0\0\x0eCompression=GZ\x78\x9c\x4b\x49\x2c\x49\x04\x00\x04\x00\x01\x9b"[..],
            &b"HG20\0\0\0\0data"[..],
        ),
        (
            &b"HG20\0\0\0\x12k=v Compression=GZ\x78\x9c\x4b\x49\x2c\x49\x04\x00\x04\x00\x01\x9b"[..],
            &b"HG20\0\0\0\x03k=vdata"[..],
        ),
        (
            &b"HG20\0\0\0\x12Compression=GZ k=v\x78\x9c\x4b\x49\x2c\x49\x04\x00\x04\x00\x01\x9b"[..],
            &b"HG20\0\0\0\x03k=vdata"[..],
        ),
        (
            &b"HG20\0\0\0\x18k=v Compression=GZ k2=v2\x78\x9c\x4b\x49\x2c\x49\x04\x00\x04\x00\x01\x9b"[..],
            &b"HG20\0\0\0\x09k=v k2=v2data"[..],
        ),
        (
            &b"HG20\0\0\0\x0eCompression=BZBZ\x68\x39\x31\x41\x59\x26\x53\x59\xaf\xe6\x9e\x72\0\0\x01\x01\x80\x24\0\x04\0\x20\0\x30\xcc\x0c\x7a\x82\x71\x77\x24\x53\x85\x09\x0a\xfe\x69\xe7\x20"[..],
            &b"HG20\0\0\0\0data"[..],
        ),
        (
            &b"HG20\0\0\0\x0eCompression=ZS\x28\xb5\x2f\xfd\x04\x58\x21\0\0\x64\x61\x74\x61\xa3\x1d\x2d\x55"[..],
            &b"HG20\0\0\0\0data"[..],
        ),
        (&b"HG10UNdata"[..], &b"HG10UNdata"[..]),
        (
            &b"HG10GZ\x78\x9c\x4b\x49\x2c\x49\x04\x00\x04\x00\x01\x9b"[..],
            &b"HG10UNdata"[..],
        ),
        (
            &b"HG10BZ\x68\x39\x31\x41\x59\x26\x53\x59\xaf\xe6\x9e\x72\0\0\x01\x01\x80\x24\0\x04\0\x20\0\x30\xcc\x0c\x7a\x82\x71\x77\x24\x53\x85\x09\x0a\xfe\x69\xe7\x20"[..],
            &b"HG10UNdata"[..],
        ),
    ];
    for (input, expected) in &test_cases {
        for chunk_size in 1..12 {
            let mut result = Vec::<u8>::new();
            let mut d = DecompressBundleWriter::new(&mut result);
            for c in input.chunks(chunk_size) {
                assert_eq!(d.write(c).unwrap(), c.len());
            }
            drop(d);
            assert_eq!(result.as_bstr(), expected.as_bstr());
        }
    }
}

fn copy_chunk<R: Read + ?Sized, W: Write + ?Sized>(
    adjust: u64,
    input: &mut R,
    output: &mut W,
) -> io::Result<u64> {
    let mut buf = [0; 4];
    input.read_exact(&mut buf)?;
    output.write_all(&buf)?;
    let len = BigEndian::read_u32(&buf) as u64;
    if len == 0 {
        return Ok(0)
    }
    copy(&mut input.take(len.checked_sub(adjust).unwrap()), output)
}

fn copy_changegroup_chunk<R: Read + ?Sized, W: Write + ?Sized>(
    input: &mut R,
    output: &mut W,
) -> io::Result<u64> {
    copy_chunk(4, input, output)
}

fn copy_changegroup<R: Read + ?Sized, W: Write + ?Sized>(
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    // changesets
    while copy_changegroup_chunk(input, output)? > 0 {}
    // manifests
    while copy_changegroup_chunk(input, output)? > 0 {}
    // files
    while copy_changegroup_chunk(input, output)? > 0 {
        while copy_changegroup_chunk(input, output)? > 0 {}
    }
    Ok(())
}

fn copy_bundle2_chunk<R: Read + ?Sized, W: Write + ?Sized>(
    input: &mut R,
    output: &mut W,
) -> io::Result<u64> {
    copy_chunk(0, input, output)
}

pub fn copy_bundle<R: Read + ?Sized, W: Write + ?Sized>(
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let mut buf = [0; 4];
    input.read_exact(&mut buf)?;
    output.write_all(&buf)?;
    if &buf == b"HG20" {
        // bundle2 parameters
        copy_bundle2_chunk(input, output)?;
        // bundle2 parts
        while copy_bundle2_chunk(input, output)? > 0 {
            while copy_bundle2_chunk(input, output)? > 0 {}
        }
    } else {
        let len = BigEndian::read_u32(&buf) as u64;
        copy(&mut input.take(len - 4), output)?;
        copy_changegroup(input, output)?;
    }
    Ok(())
}
