/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryInto;
use std::io::{self, copy, Cursor, ErrorKind, Read, Write};

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use replace_with::replace_with_or_abort;
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::util::{ReadExt, SliceExt};

pub struct DecompressBundleReader<'a> {
    initial_buf: Option<Cursor<Vec<u8>>>,
    inner: Box<dyn Read + 'a>,
}

impl<'a> DecompressBundleReader<'a> {
    pub fn new<R: Read + 'a>(r: R) -> Self {
        DecompressBundleReader {
            initial_buf: Some(Cursor::new(Vec::new())),
            inner: Box::new(r),
        }
    }
}

enum Compression {
    Bzip,
    BzipNoHeader,
    Gzip,
    Zstd,
}

fn decompress_bundlev2_header<R: Read>(
    mut r: R,
    buf: &mut Vec<u8>,
) -> io::Result<Option<Compression>> {
    let params_len = r.read_u32::<BigEndian>()?;
    let params_str = r.take(params_len.into()).read_all_to_string()?;
    if params_str.len() != params_len.try_into().unwrap() {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "Premature end of bundle v2 header",
        ));
    }
    let mut compression = None;
    let mut params = Vec::new();
    if !params_str.is_empty() {
        for s in params_str.split(' ') {
            match s.splitn_exact('=') {
                Some(["Compression", v]) => {
                    compression = match v {
                        "GZ" => Some(Compression::Gzip),
                        "BZ" => Some(Compression::Bzip),
                        "ZS" => Some(Compression::Zstd),
                        comp => {
                            return Err(io::Error::new(
                                ErrorKind::Other,
                                format!("Unknown mercurial bundle compression: {}", comp),
                            ))
                        }
                    };
                }
                Some(_) => params.push(s),
                _ => {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        "Malformed mercurial bundle header",
                    ));
                }
            }
        }
    }
    let params = params.join(" ");
    buf.write_u32::<BigEndian>(params.len().try_into().unwrap())?;
    buf.write_all(params.as_bytes())?;
    Ok(compression)
}

fn decompress_bundlev1_header<R: Read>(
    mut r: R,
    buf: &mut Vec<u8>,
) -> io::Result<Option<Compression>> {
    let mut buf_ = [0u8; 2];
    r.read_exact(&mut buf_)?;
    buf.write_all(b"UN")?;
    match &buf_ {
        b"GZ" => Ok(Some(Compression::Gzip)),
        b"BZ" => Ok(Some(Compression::BzipNoHeader)),
        b"UN" => Ok(None),
        comp => Err(io::Error::new(
            ErrorKind::Other,
            format!(
                "Unknown mercurial bundle compression: {}",
                String::from_utf8_lossy(comp)
            ),
        )),
    }
}

impl<'a> Read for DecompressBundleReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(mut initial_buf_) = self.initial_buf.take() {
            let mut initial_buf = initial_buf_.get_mut();
            if initial_buf.is_empty() {
                if (&mut self.inner).take(4).read_to_end(&mut initial_buf)? != 4 {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        "Unrecognized mercurial bundle",
                    ));
                }
                let compression = match &initial_buf[..] {
                    b"HG20" => decompress_bundlev2_header(&mut self.inner, &mut initial_buf)?,
                    b"HG10" => decompress_bundlev1_header(&mut self.inner, &mut initial_buf)?,
                    _ => {
                        return Err(io::Error::new(
                            ErrorKind::Other,
                            "Unrecognized mercurial bundle",
                        ))
                    }
                };
                if let Some(compression) = compression {
                    replace_with_or_abort(&mut self.inner, |inner| match compression {
                        Compression::Bzip => Box::new(BzDecoder::new(inner)),
                        Compression::BzipNoHeader => {
                            Box::new(BzDecoder::new(Cursor::new("BZ").chain(inner)))
                        }
                        Compression::Gzip => Box::new(ZlibDecoder::new(inner)),
                        Compression::Zstd => Box::new(ZstdDecoder::new(inner).unwrap()),
                    });
                }
            }
            let result = (&mut initial_buf_).chain(&mut self.inner).read(buf);
            if initial_buf_.position() < initial_buf_.get_ref().len().try_into().unwrap() {
                self.initial_buf = Some(initial_buf_);
            }
            result
        } else {
            self.inner.read(buf)
        }
    }
}

#[test]
fn test_decompress_bundle_reader() {
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
            let mut r = DecompressBundleReader::new(Cursor::new(input));
            for c in expected.chunks(chunk_size) {
                let buf = (&mut r)
                    .take(chunk_size.try_into().unwrap())
                    .read_all()
                    .unwrap();
                assert_eq!(c.as_bstr(), buf.as_bstr());
            }
            assert_eq!(
                r.bytes().collect::<io::Result<Vec<_>>>().unwrap(),
                Vec::new()
            );
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
        return Ok(0);
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
