/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::fs::File;
use std::io::{self, copy, BufRead, Chain, Cursor, ErrorKind, Read, Write};
use std::iter::repeat;
use std::mem::{self, MaybeUninit};
use std::os::raw::c_int;
use std::ptr::NonNull;
use std::str::FromStr;
use std::sync::Mutex;

use bstr::ByteSlice;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use derive_more::Deref;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use indexmap::IndexMap;
use itertools::Itertools;
use once_cell::sync::Lazy;
use tee::TeeReader;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::hg_connect::{encodecaps, HgConnection, HgConnectionBase, HgRepo};
use crate::hg_data::find_parents;
use crate::libcinnabar::files_meta;
use crate::libgit::BlobId;
use crate::oid::GitObjectId;
use crate::progress::Progress;
use crate::store::{
    ChangesetHeads, GitFileMetadataId, HgChangesetId, HgFileId, HgManifestId,
    RawGitChangesetMetadata, RawHgChangeset, RawHgFile, RawHgManifest,
};
use crate::util::{FromBytes, ToBoxed};
use crate::xdiff::textdiff;
use crate::{get_changes, manifest_path, HELPER_LOCK};
use crate::{
    libcinnabar::hg_object_id,
    libgit::strbuf,
    oid::{HgObjectId, ObjectId},
    util::{ImmutBString, ReadExt, SliceExt},
};

extern "C" {
    fn rev_chunk_from_memory(
        result: *mut rev_chunk,
        buf: *mut strbuf,
        delta_node: *const hg_object_id,
    );

    fn rev_diff_start_iter(iterator: *mut rev_diff_part, chunk: *const rev_chunk);

    fn rev_diff_iter_next(iterator: *mut rev_diff_part) -> c_int;
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rev_chunk {
    raw: strbuf,
    node: NonNull<hg_object_id>,
    parent1: NonNull<hg_object_id>,
    parent2: NonNull<hg_object_id>,
    delta_node: NonNull<hg_object_id>,
    diff_data: NonNull<u8>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rev_diff_part<'a> {
    start: usize,
    end: usize,
    data: strbuf,
    chunk: &'a rev_chunk,
}

impl rev_chunk {
    pub fn raw(&self) -> &[u8] {
        self.raw.as_bytes()
    }

    pub fn node(&self) -> &hg_object_id {
        unsafe { self.node.as_ref() }
    }

    pub fn parent1(&self) -> &hg_object_id {
        unsafe { self.parent1.as_ref() }
    }

    pub fn parent2(&self) -> &hg_object_id {
        unsafe { self.parent2.as_ref() }
    }

    pub fn delta_node(&self) -> &hg_object_id {
        unsafe { self.delta_node.as_ref() }
    }

    pub fn iter_diff(&self) -> RevDiffIter {
        unsafe {
            let mut part = MaybeUninit::zeroed();
            rev_diff_start_iter(part.as_mut_ptr(), self);
            RevDiffIter(part.assume_init())
        }
    }
}

pub fn read_rev_chunk<R: Read>(mut r: R, out: &mut strbuf) {
    let mut buf = [0; 4];
    r.read_exact(&mut buf).unwrap();
    let len = BigEndian::read_u32(&buf) as u64;
    if len == 0 {
        return;
    }
    // TODO: should error out on short read
    copy(&mut r.take(len.checked_sub(4).unwrap()), out).unwrap();
}

pub fn read_bundle2_chunk<R: Read>(mut r: R) -> io::Result<ImmutBString> {
    let len = r.read_u32::<BigEndian>()?;
    if len == 0 {
        return Ok(vec![].into_boxed_slice());
    }
    r.read_exactly(len as usize)
}

pub fn write_bundle2_chunk<W: Write>(mut w: W, chunk: &[u8]) -> io::Result<()> {
    w.write_u32::<BigEndian>(chunk.len().try_into().unwrap())?;
    w.write_all(chunk)
}

fn skip_bundle2_chunk<R: Read>(mut r: R) -> io::Result<u64> {
    let len = r.read_u32::<BigEndian>()? as u64;
    if len == 0 {
        return Ok(0);
    }
    // TODO: should error out on short read
    copy(&mut r.take(len.checked_sub(0).unwrap()), &mut io::sink())
}

pub struct RevChunkIter<R: Read> {
    version: u8,
    delta_node: Option<hg_object_id>,
    next_delta_node: Option<hg_object_id>,
    reader: R,
}

impl<R: Read> RevChunkIter<R> {
    pub fn new(version: u8, reader: R) -> Self {
        RevChunkIter {
            version,
            delta_node: None,
            next_delta_node: None,
            reader,
        }
    }
}

impl<R: Read> Iterator for RevChunkIter<R> {
    type Item = rev_chunk;

    fn next(&mut self) -> Option<rev_chunk> {
        let first = self.delta_node.take().is_none();
        self.delta_node = self
            .next_delta_node
            .take()
            .or_else(|| Some(HgObjectId::null().into()));
        let mut buf = strbuf::new();
        read_rev_chunk(&mut self.reader, &mut buf);
        if buf.as_bytes().is_empty() {
            return None;
        }
        let mut chunk = MaybeUninit::zeroed();
        unsafe {
            rev_chunk_from_memory(
                chunk.as_mut_ptr(),
                &mut buf,
                (self.version == 1)
                    .then(|| ())
                    .and(self.delta_node.as_ref())
                    .map_or(std::ptr::null(), |d| d as *const _),
            );
        }
        let chunk = unsafe { chunk.assume_init() };
        if self.version == 1 {
            if first {
                self.delta_node = Some(chunk.parent1().clone());
            }
            self.next_delta_node = Some(chunk.node().clone());
        }
        Some(chunk)
    }
}

pub struct RevDiffIter<'a>(rev_diff_part<'a>);

pub struct RevDiffPart {
    pub start: usize,
    pub end: usize,
    pub data: ImmutBString,
}

impl<'a> Iterator for RevDiffIter<'a> {
    type Item = RevDiffPart;

    fn next(&mut self) -> Option<RevDiffPart> {
        unsafe { rev_diff_iter_next(&mut self.0) != 0 }.then(|| RevDiffPart {
            start: self.0.start,
            end: self.0.end,
            data: self.0.data.as_bytes().to_vec().into_boxed_slice(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleVersion {
    V1,
    V2,
}

pub enum BundleSpec {
    ChangegroupV1,
    V1None,
    V1Gzip,
    V1Bzip,
    V2None,
    V2Gzip,
    V2Bzip,
    V2Zstd,
}

impl FromStr for BundleSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none-v1" => BundleSpec::V1None,
            "gzip-v1" => BundleSpec::V1Gzip,
            "bzip2-v1" => BundleSpec::V1Bzip,
            "none-v2" => BundleSpec::V2None,
            "gzip-v2" => BundleSpec::V2Gzip,
            "bzip2-v2" => BundleSpec::V2Bzip,
            "zstd-v2" => BundleSpec::V2Zstd,
            _ => {
                if let Some([compression, version]) = s.splitn_exact('-') {
                    if !["none", "gzip", "bzip2", "zstd"].contains(&compression) {
                        return Err(format!("unsupported compression: {}", compression));
                    }
                    if !["v1", "v2"].contains(&version) {
                        return Err(format!("unsupported bundle version: {}", version));
                    }
                }
                return Err(format!("unsupported bundle spec: {}", s));
            }
        })
    }
}

impl Display for BundleSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            BundleSpec::ChangegroupV1 => "raw",
            BundleSpec::V1None => "none-v1",
            BundleSpec::V1Gzip => "gzip-v1",
            BundleSpec::V1Bzip => "bzip2-v1",
            BundleSpec::V2None => "none-v2",
            BundleSpec::V2Gzip => "gzip-v2",
            BundleSpec::V2Bzip => "bzip2-v2",
            BundleSpec::V2Zstd => "zstd-v2",
        };
        f.write_str(value)
    }
}

impl TryFrom<&[u8]> for BundleSpec {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        BundleSpec::from_str(
            value
                .to_str()
                .map_err(|_| format!("unsupported bundle spec: {}", value.as_bstr()))?,
        )
    }
}

pub struct BundleReader<'a> {
    reader: Chain<Cursor<ImmutBString>, Box<dyn Read + 'a>>,
    version: BundleVersion,
    remaining: Option<u32>,
}

impl<'a> BundleReader<'a> {
    pub fn new(mut reader: impl Read + 'a) -> io::Result<Self> {
        let mut header = [0; 4];
        reader.read_exact(&mut header)?;
        match &header {
            b"HG20" => Self::new_bundlev2(reader),
            b"HG10" => Self::new_bundlev1(reader),
            _ => Self::new_changegroupv1(header, reader),
        }
    }

    fn new_bundlev2(mut reader: impl Read + 'a) -> io::Result<Self> {
        let header = read_bundle2_chunk(&mut reader)?;
        let compression =
            header
                .split(|&b| b == b' ')
                .find_map(|param| match param.splitn_exact(b'=') {
                    Some([b"Compression", comp]) => Some(comp),
                    _ => None,
                });
        let reader = match compression {
            Some(b"GZ") => Box::new(ZlibDecoder::new(reader)) as Box<dyn Read>,
            Some(b"BZ") => Box::new(BzDecoder::new(reader)),
            Some(b"ZS") => Box::new(ZstdDecoder::new(reader).unwrap()),
            Some(comp) => {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    format!(
                        "Unknown mercurial bundle compression: {}",
                        String::from_utf8_lossy(comp)
                    ),
                ))
            }
            None => Box::from(reader),
        };
        Ok(BundleReader {
            reader: Cursor::new(vec![].into_boxed_slice()).chain(reader),
            version: BundleVersion::V2,
            remaining: Some(0),
        })
    }

    fn new_bundlev1(mut reader: impl Read + 'a) -> io::Result<Self> {
        let mut compression = [0; 2];
        reader.read_exact(&mut compression)?;
        let reader = match &compression {
            b"GZ" => Box::new(ZlibDecoder::new(reader)) as Box<dyn Read>,
            b"BZ" => Box::new(BzDecoder::new(Cursor::new(compression).chain(reader))),
            b"UN" => Box::from(reader),
            comp => {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    format!(
                        "Unknown mercurial bundle compression: {}",
                        String::from_utf8_lossy(comp)
                    ),
                ))
            }
        };
        Ok(BundleReader {
            reader: Cursor::new(vec![].into_boxed_slice()).chain(reader),
            version: BundleVersion::V1,
            remaining: Some(0),
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new_changegroupv1(initial: [u8; 4], reader: impl Read + 'a) -> io::Result<Self> {
        Ok(BundleReader {
            reader: Cursor::new(initial.to_vec().into_boxed_slice()).chain(Box::from(reader)),
            version: BundleVersion::V1,
            remaining: Some(0),
        })
    }

    pub fn next_part(&mut self) -> io::Result<Option<BundlePartReader>> {
        let reader = {
            let (cursor, _) = self.reader.get_mut();
            if cursor.position() >= cursor.get_ref().as_ref().len() as u64 {
                &mut **self.reader.get_mut().1
            } else {
                &mut self.reader
            }
        };
        match self.remaining.take() {
            None => return Ok(None),
            Some(0) => {}
            Some(len) => {
                assert_eq!(self.version, BundleVersion::V2);
                // Advance past last part if it was not read entirely.
                copy(&mut reader.take(len.into()), &mut io::sink())?;
                while skip_bundle2_chunk(&mut *reader)? > 0 {}
            }
        }
        match self.version {
            BundleVersion::V1 => Ok(Some(BundlePartReader {
                info: BundlePartInfo::new(0, "changegroup"),
                reader,
                version: self.version,
                remaining: self.remaining.as_mut(),
            })),
            BundleVersion::V2 => {
                let header = read_bundle2_chunk(&mut *reader)?;
                if header.is_empty() {
                    self.remaining = None;
                    return Ok(None);
                }
                self.remaining = Some(reader.read_u32::<BigEndian>()?);
                Ok(Some(BundlePartReader {
                    info: BundlePartInfo::read_from(&*header)?,
                    reader,
                    version: self.version,
                    remaining: self.remaining.as_mut(),
                }))
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BundlePartInfo {
    pub mandatory: bool,
    pub part_type: Box<str>,
    part_id: u32,
    params: IndexMap<Box<str>, Box<str>>,
}

impl BundlePartInfo {
    pub fn new(part_id: u32, part_type: &str) -> Self {
        BundlePartInfo {
            mandatory: true,
            part_type: part_type.to_lowercase().into_boxed_str(),
            part_id,
            params: IndexMap::new(),
        }
    }

    pub fn read_from(mut reader: impl Read) -> io::Result<Self> {
        let part_type_len = reader.read_u8()?;
        let part_type = reader.read_exactly_to_string(part_type_len.into())?;
        let mandatory = part_type.chars().next().map_or(false, char::is_uppercase);
        let part_type = part_type.to_lowercase().into_boxed_str();
        let part_id = reader.read_u32::<BigEndian>()?;
        let mandatory_params_num = reader.read_u8()?;
        let advisory_params_num = reader.read_u8()?;
        let param_lengths = (0..usize::from(mandatory_params_num + advisory_params_num))
            .map(|_| Ok((reader.read_u8()?, reader.read_u8()?)))
            .collect::<io::Result<Vec<(u8, u8)>>>()?;
        let params = param_lengths
            .into_iter()
            .map(|(name_len, value_len)| {
                Ok((
                    reader.read_exactly_to_string(name_len.into())?,
                    reader.read_exactly_to_string(value_len.into())?,
                ))
            })
            .collect::<io::Result<_>>()?;
        Ok(BundlePartInfo {
            mandatory,
            part_type,
            part_id,
            params,
        })
    }

    pub fn write_into(&self, mut writer: impl Write) -> io::Result<()> {
        assert_lt!(self.part_type.len(), 256);
        assert_lt!(self.params.len(), 256);
        writer.write_u8(self.part_type.len() as u8)?;
        if self.mandatory {
            writer.write_all(self.part_type.to_uppercase().as_bytes())?;
        } else {
            writer.write_all(self.part_type.to_lowercase().as_bytes())?;
        }
        writer.write_u32::<BigEndian>(self.part_id)?;
        writer.write_u8(self.params.len() as u8)?;
        writer.write_u8(0 /* number of advisory params */)?;
        for (k, v) in &self.params {
            assert_lt!(k.len(), 256);
            writer.write_u8(k.len() as u8)?;
            assert_lt!(v.len(), 256);
            writer.write_u8(v.len() as u8)?;
        }
        for (k, v) in &self.params {
            writer.write_all(k.as_bytes())?;
            writer.write_all(v.as_bytes())?;
        }
        Ok(())
    }

    pub fn get_param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|v| &**v)
    }

    pub fn set_param(mut self, name: &str, value: &str) -> Self {
        self.params.insert(name.to_boxed(), value.to_boxed());
        self
    }
}

#[test]
fn test_bundle_part_info() {
    let info = BundlePartInfo::new(0x12345678, "foobar");
    let mut buf = Vec::new();
    info.write_into(&mut buf).unwrap();
    assert_eq!(buf.as_bstr(), b"\x06FOOBAR\x12\x34\x56\x78\0\0".as_bstr());
    assert_eq!(BundlePartInfo::read_from(Cursor::new(buf)).unwrap(), info);

    let info = BundlePartInfo::new(0x12345678, "foobar")
        .set_param("name", "value")
        .set_param("name2", "value2")
        .set_param("name3", "value3");
    let mut buf = Vec::new();
    info.write_into(&mut buf).unwrap();
    assert_eq!(
        buf.as_bstr(),
        b"\x06FOOBAR\x12\x34\x56\x78\
          \x03\x00\
          \x04\x05\x05\x06\x05\x06\
          namevaluename2value2name3value3"
            .as_bstr()
    );
    assert_eq!(BundlePartInfo::read_from(Cursor::new(buf)).unwrap(), info);
}

#[derive(Deref)]
pub struct BundlePartReader<'a> {
    #[deref]
    info: BundlePartInfo,
    reader: &'a mut dyn Read,
    version: BundleVersion,
    remaining: Option<&'a mut u32>,
}

impl<'a> Read for BundlePartReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.version {
            BundleVersion::V1 => {
                assert!(self.remaining.is_none());
                self.reader.read(buf)
            }
            BundleVersion::V2 => {
                let remaining = self.remaining.as_mut().expect("Incoherent state");
                let mut total_read = 0;
                let mut dest = buf;
                while **remaining > 0 && !dest.is_empty() {
                    let read = match self.reader.take((**remaining).into()).read(dest) {
                        Ok(read) => read,
                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    total_read += read;
                    dest = &mut dest[read..];
                    **remaining -= read as u32;
                    if **remaining == 0 {
                        **remaining = self.reader.read_u32::<BigEndian>()?;
                    }
                    if read == 0 {
                        break;
                    }
                }
                Ok(total_read)
            }
        }
    }
}

pub struct BundleWriter<'a> {
    writer: Box<dyn Write + 'a>,
    version: BundleVersion,
    last_part_id: Option<u32>,
}

impl<'a> BundleWriter<'a> {
    pub fn new(spec: BundleSpec, mut writer: impl Write + 'a) -> io::Result<Self> {
        match spec {
            BundleSpec::ChangegroupV1 => { /* No header */ }
            BundleSpec::V1None => writer.write_all(b"HG10UN")?,
            BundleSpec::V1Gzip => writer.write_all(b"HG10GZ")?,
            BundleSpec::V1Bzip => writer.write_all(b"HG10")?, // The BzEncoder will add the "BZ".
            BundleSpec::V2None => writer.write_all(b"HG20\0\0\0\0")?,
            BundleSpec::V2Gzip => writer.write_all(b"HG20\0\0\0\x0eCompression=GZ")?,
            BundleSpec::V2Bzip => writer.write_all(b"HG20\0\0\0\x0eCompression=BZ")?,
            BundleSpec::V2Zstd => writer.write_all(b"HG20\0\0\0\x0eCompression=ZS")?,
        }
        let writer = match spec {
            BundleSpec::ChangegroupV1 | BundleSpec::V1None | BundleSpec::V2None => {
                Box::from(writer) as Box<dyn Write>
            }
            BundleSpec::V1Gzip | BundleSpec::V2Gzip => {
                Box::new(ZlibEncoder::new(writer, flate2::Compression::default()))
            }
            BundleSpec::V1Bzip | BundleSpec::V2Bzip => {
                Box::new(BzEncoder::new(writer, bzip2::Compression::default()))
            }
            BundleSpec::V2Zstd => Box::from(ZstdEncoder::new(writer, 0).unwrap()),
        };
        Ok(BundleWriter {
            writer,
            version: match spec {
                BundleSpec::ChangegroupV1
                | BundleSpec::V1None
                | BundleSpec::V1Gzip
                | BundleSpec::V1Bzip => BundleVersion::V1,
                BundleSpec::V2None
                | BundleSpec::V2Gzip
                | BundleSpec::V2Bzip
                | BundleSpec::V2Zstd => BundleVersion::V2,
            },
            last_part_id: None,
        })
    }

    pub fn new_part(&mut self, info: BundlePartInfo) -> io::Result<BundlePartWriter<32768>> {
        match self.version {
            BundleVersion::V1 => {
                assert!(self.last_part_id.is_none());
                assert_eq!(&*info.part_type, "changegroup");
                assert_eq!(info.get_param("version"), Some("01"));
                assert_eq!(info.params.len(), 1);
            }
            BundleVersion::V2 => {
                assert_ge!(
                    info.part_id,
                    self.last_part_id.as_ref().map_or(0, |i| i + 1)
                );
                let mut header = Vec::new();
                info.write_into(&mut header)?;
                write_bundle2_chunk(&mut *self.writer, &header)?;
            }
        };
        self.last_part_id = Some(info.part_id);
        Ok(BundlePartWriter::new(&mut self.writer, self.version))
    }
}

impl<'a> Drop for BundleWriter<'a> {
    fn drop(&mut self) {
        if self.version == BundleVersion::V2 {
            write_bundle2_chunk(&mut *self.writer, &[]).unwrap();
        }
        self.writer.flush().unwrap();
    }
}

pub struct BundlePartWriter<'a, const CHUNK_SIZE: usize> {
    writer: &'a mut dyn Write,
    bundle2_buf: Option<Vec<u8>>,
}

impl<'a, const CHUNK_SIZE: usize> BundlePartWriter<'a, CHUNK_SIZE> {
    fn new(writer: &'a mut dyn Write, version: BundleVersion) -> Self {
        BundlePartWriter {
            writer,
            bundle2_buf: match version {
                BundleVersion::V1 => None,
                BundleVersion::V2 => Some(Vec::new()),
            },
        }
    }

    fn flush_buf_as_chunk(&mut self) -> io::Result<()> {
        if let Some(bundle2_buf) = self.bundle2_buf.as_mut() {
            write_bundle2_chunk(&mut *self.writer, bundle2_buf)?;
            bundle2_buf.truncate(0);
        }
        Ok(())
    }
}

impl<'a, const CHUNK_SIZE: usize> Drop for BundlePartWriter<'a, CHUNK_SIZE> {
    fn drop(&mut self) {
        self.flush_buf_as_chunk().unwrap();
        if self.bundle2_buf.is_some() {
            write_bundle2_chunk(&mut *self.writer, &[]).unwrap();
        }
        self.writer.flush().unwrap();
    }
}

impl<'a, const CHUNK_SIZE: usize> Write for BundlePartWriter<'a, CHUNK_SIZE> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if let Some(bundle2_buf) = self.bundle2_buf.as_mut() {
            let full_len = buf.len();
            while bundle2_buf.len() + buf.len() >= CHUNK_SIZE {
                self.writer.write_u32::<BigEndian>(CHUNK_SIZE as u32)?;
                if !bundle2_buf.is_empty() {
                    self.writer.write_all(bundle2_buf)?;
                }
                let remaining = CHUNK_SIZE - bundle2_buf.len();
                bundle2_buf.truncate(0);
                self.writer.write_all(&buf[..remaining])?;
                buf = &buf[remaining..];
            }
            bundle2_buf.extend_from_slice(buf);
            Ok(full_len)
        } else {
            self.writer.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf_as_chunk()?;
        self.writer.flush()
    }
}

#[test]
fn test_bundle_part_writer() {
    fn fill<W: Write>(mut writer: W, flush: bool) {
        assert_eq!(writer.write(b"a").unwrap(), 1);
        if flush {
            writer.flush().unwrap();
        }
        assert_eq!(writer.write(b"bcd").unwrap(), 3);
        if flush {
            writer.flush().unwrap();
        }
        assert_eq!(writer.write(b"efg").unwrap(), 3);
        assert_eq!(writer.write(b"hijk").unwrap(), 4);
        assert_eq!(writer.write(b"lmnop").unwrap(), 5);
        if flush {
            writer.flush().unwrap();
        }
        assert_eq!(writer.write(b"qrstuvwxyz").unwrap(), 10);
        assert_eq!(writer.write(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap(), 26);
    }

    let mut buf = Vec::new();
    let writer = BundlePartWriter::<8>::new(&mut buf, BundleVersion::V1);
    fill(writer, true);

    assert_eq!(
        buf.as_bstr(),
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bstr(),
    );

    buf.truncate(0);
    let writer = BundlePartWriter::<8>::new(&mut buf, BundleVersion::V2);
    fill(writer, false);

    assert_eq!(
        buf.as_bstr(),
        b"\0\0\0\x08abcdefgh\
          \0\0\0\x08ijklmnop\
          \0\0\0\x08qrstuvwx\
          \0\0\0\x08yzABCDEF\
          \0\0\0\x08GHIJKLMN\
          \0\0\0\x08OPQRSTUV\
          \0\0\0\x04WXYZ\
          \0\0\0\0"
            .as_bstr()
    );

    buf.truncate(0);
    let writer = BundlePartWriter::<8>::new(&mut buf, BundleVersion::V2);
    fill(writer, true);

    assert_eq!(
        buf.as_bstr(),
        b"\0\0\0\x01a\
          \0\0\0\x03bcd\
          \0\0\0\x08efghijkl\
          \0\0\0\x04mnop\
          \0\0\0\x08qrstuvwx\
          \0\0\0\x08yzABCDEF\
          \0\0\0\x08GHIJKLMN\
          \0\0\0\x08OPQRSTUV\
          \0\0\0\x04WXYZ\
          \0\0\0\0"
            .as_bstr()
    );
}

pub struct BundleConnection<R: Read> {
    reader: R,
    buf: Vec<u8>,
    changesets: Option<ChangesetHeads>,
}

impl<R: Read> BundleConnection<R> {
    pub fn new(reader: R) -> Self {
        BundleConnection {
            reader,
            buf: Vec::new(),
            changesets: None,
        }
    }

    fn init_changesets(&mut self) {
        if self.changesets.is_some() {
            return;
        }
        let mut changesets = ChangesetHeads::new();
        let mut raw_changesets = BTreeMap::new();
        let tee = TeeReader::new(&mut self.reader, &mut self.buf);

        let mut bundle = BundleReader::new(tee).unwrap();
        while let Some(part) = bundle.next_part().unwrap() {
            if &*part.part_type != "changegroup" {
                continue;
            }
            let version = part
                .get_param("version")
                .map_or(1, |v| u8::from_str(v).unwrap());
            let empty_cs = RawHgChangeset(Box::new([]));
            // TODO: share more code with the equivalent loop in store.rs.
            for chunk in
                RevChunkIter::new(version, part).progress(|n| format!("Analyzing {n} changesets"))
            {
                let node = HgChangesetId::from_unchecked(HgObjectId::from(chunk.node().clone()));
                let parent1 =
                    HgChangesetId::from_unchecked(HgObjectId::from(chunk.parent1().clone()));
                let parent2 =
                    HgChangesetId::from_unchecked(HgObjectId::from(chunk.parent2().clone()));
                let delta_node =
                    HgChangesetId::from_unchecked(HgObjectId::from(chunk.delta_node().clone()));
                let parents = [parent1, parent2];
                let parents = parents
                    .iter()
                    .filter(|&p| *p != HgChangesetId::null())
                    .collect::<Vec<_>>();

                let reference_cs = if delta_node == HgChangesetId::null() {
                    &empty_cs
                } else {
                    raw_changesets.get(&delta_node).unwrap()
                };
                let mut last_end = 0;
                let mut raw_changeset = Vec::new();
                for diff in chunk.iter_diff() {
                    if diff.start > reference_cs.len() || diff.start < last_end {
                        die!("Malformed changeset chunk for {node}");
                    }
                    raw_changeset.extend_from_slice(&reference_cs[last_end..diff.start]);
                    raw_changeset.extend_from_slice(&diff.data);
                    last_end = diff.end;
                }
                if reference_cs.len() < last_end {
                    die!("Malformed changeset chunk for {node}");
                }
                raw_changeset.extend_from_slice(&reference_cs[last_end..]);
                let raw_changeset = RawHgChangeset(raw_changeset.into());
                let changeset = raw_changeset.parse().unwrap();
                let branch = changeset
                    .extra()
                    .and_then(|e| e.get(b"branch"))
                    .unwrap_or(b"default")
                    .as_bstr();

                changesets.add(&node, &parents, branch);
                raw_changesets.insert(node, raw_changeset);
            }
            break;
        }
        self.changesets = Some(changesets);
    }
}

impl<R: Read> HgConnectionBase for BundleConnection<R> {
    fn get_capability(&self, name: &[u8]) -> Option<&bstr::BStr> {
        match name {
            b"getbundle" | b"branchmap" => Some(b"".as_bstr()),
            _ => None,
        }
    }
}

impl<R: Read> HgConnection for BundleConnection<R> {
    fn getbundle<'a>(
        &'a mut self,
        _heads: &[HgChangesetId],
        common: &[HgChangesetId],
        _bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
        assert!(common.is_empty());

        Ok(Box::new(
            Cursor::new(mem::take(&mut self.buf)).chain(&mut self.reader),
        ))
    }
}

impl<R: Read> HgRepo for BundleConnection<R> {
    fn branchmap(&mut self) -> ImmutBString {
        self.init_changesets();
        let mut branchmap = Vec::new();
        if let Some(changesets) = &self.changesets {
            for (branch, group) in &changesets
                .branch_heads()
                .enumerate()
                .sorted_by_key(|(n, (_, branch))| (*branch, *n))
                .group_by(|(_, (_, branch))| *branch)
            {
                branchmap.extend_from_slice(branch);
                writeln!(
                    &mut branchmap,
                    " {}",
                    group.map(|(_, (cs, _))| cs).format(" ")
                )
                .unwrap();
            }
        }
        branchmap.into_boxed_slice()
    }

    fn heads(&mut self) -> ImmutBString {
        self.init_changesets();
        let mut heads = Vec::new();
        if let Some(changesets) = &self.changesets {
            writeln!(&mut heads, "{}", changesets.heads().format(" ")).unwrap();
        }
        heads.into_boxed_slice()
    }

    fn bookmarks(&mut self) -> ImmutBString {
        // TODO: For HG20 bundles, we could actually read the relevant part(s).
        Box::new([])
    }

    fn phases(&mut self) -> ImmutBString {
        Box::new([])
    }

    fn known(&mut self, _nodes: &[HgChangesetId]) -> Box<[bool]> {
        todo!()
    }
}

pub static BUNDLE_PATH: Lazy<Mutex<Option<tempfile::TempPath>>> = Lazy::new(|| Mutex::new(None));

fn create_chunk_data(a: &[u8], b: &[u8]) -> Box<[u8]> {
    let mut buf = Vec::new();
    for patch in textdiff(a, b) {
        buf.write_u32::<BigEndian>(patch.start.try_into().unwrap())
            .unwrap();
        buf.write_u32::<BigEndian>(patch.end.try_into().unwrap())
            .unwrap();
        buf.write_u32::<BigEndian>(patch.data.len().try_into().unwrap())
            .unwrap();
        buf.write_all(patch.data).unwrap();
    }
    buf.into_boxed_slice()
}

#[allow(clippy::too_many_arguments)]
fn write_chunk(
    mut writer: impl Write,
    version: u8,
    node: &HgObjectId,
    parent1: &HgObjectId,
    parent2: &HgObjectId,
    changeset: &HgChangesetId,
    previous: &mut Option<(HgObjectId, Box<[u8]>)>,
    mut f: impl FnMut(&HgObjectId) -> Box<[u8]>,
) -> io::Result<()> {
    let raw_object = f(node);
    let (previous_node, raw_previous) = match previous.take() {
        Some((a, b)) => (Some(a), Some(b)),
        None => (None, None),
    };
    let (delta_node, chunk) = if version == 1 {
        let previous =
            raw_previous.or_else(|| (parent1 != &HgObjectId::null()).then(|| f(parent1)));
        let previous = previous.as_deref().unwrap_or(b"");
        (None, create_chunk_data(previous, &raw_object))
    } else {
        let mut chunk_data = [parent1, parent2]
            .into_iter()
            .filter(|&p| p != &HgObjectId::null())
            .dedup()
            .map(|p| {
                if previous_node.as_ref() == Some(p) {
                    let previous = raw_previous.as_ref().unwrap();
                    (Some(p), create_chunk_data(previous, &raw_object))
                } else {
                    (Some(p), create_chunk_data(&f(p), &raw_object))
                }
            })
            .collect_vec();
        if chunk_data.is_empty() {
            chunk_data.push((None, create_chunk_data(b"", &raw_object)));
        }
        chunk_data.into_iter().min_by_key(|(_, d)| d.len()).unwrap()
    };
    *previous = Some((node.clone(), raw_object));
    writer.write_u32::<BigEndian>(
        (4 + chunk.len() + 80 + if version == 2 { 20 } else { 0 })
            .try_into()
            .unwrap(),
    )?;
    writer.write_all(node.as_raw_bytes())?;
    writer.write_all(parent1.as_raw_bytes())?;
    writer.write_all(parent2.as_raw_bytes())?;
    if version == 2 {
        writer.write_all(delta_node.unwrap_or(&HgObjectId::null()).as_raw_bytes())?;
    }
    writer.write_all(changeset.as_raw_bytes())?;
    writer.write_all(&chunk)
}

pub fn create_bundle(
    input: &mut dyn BufRead,
    mut out: impl Write,
    bundlespec: BundleSpec,
    version: u8,
    output: &File,
    replycaps: bool,
) -> ChangesetHeads {
    let mut part_id = 0;
    let mut buf = Vec::new();
    let mut bundle_writer = BundleWriter::new(bundlespec, output).unwrap();
    let mut changeset_heads = ChangesetHeads::new();

    if replycaps {
        let info = BundlePartInfo::new(part_id, "replycaps");
        let mut bundle_part_writer = bundle_writer.new_part(info).unwrap();
        bundle_part_writer
            .write_all(encodecaps([("error", Some(&["abort"]))]).as_bytes())
            .unwrap();
        part_id += 1;
    }

    let info = BundlePartInfo::new(part_id, "changegroup")
        .set_param("version", &format!("{:02}", version));
    let mut bundle_part_writer = bundle_writer.new_part(info).unwrap();
    let mut previous = None;
    let mut manifests = IndexMap::new();
    let mut progress = repeat(()).progress(|n| format!("Bundling {n} changesets"));
    loop {
        buf.truncate(0);
        input.read_until(b'\0', &mut buf).unwrap();
        if buf.ends_with(b"\0") {
            buf.pop();
        }
        if let Some([node, parent1, parent2, changeset]) = buf.splitn_exact(b' ') {
            progress.next();
            let node = HgChangesetId::from_bytes(node).unwrap();
            let parent1 = HgChangesetId::from_bytes(parent1).unwrap();
            let parent2 = HgChangesetId::from_bytes(parent2).unwrap();
            let changeset = HgChangesetId::from_bytes(changeset).unwrap();

            // TODO: add branch.
            changeset_heads.add(&node, &[&parent1, &parent2], b"".as_bstr());

            let _lock = HELPER_LOCK.lock().unwrap();
            write_chunk(
                &mut bundle_part_writer,
                version,
                &node,
                &parent1,
                &parent2,
                &changeset,
                &mut previous,
                |node| {
                    let node = HgChangesetId::from_unchecked(node.clone());
                    let changeset = RawHgChangeset::read(&node.to_git().unwrap()).unwrap();
                    changeset.0
                },
            )
            .unwrap();
            let get_manifest = |node: HgChangesetId| {
                let metadata = RawGitChangesetMetadata::read(&node.to_git().unwrap()).unwrap();
                let metadata = metadata.parse().unwrap();
                metadata.manifest_id().clone()
            };
            let manifest = get_manifest(node.clone());
            if manifest != HgManifestId::null() && !manifests.contains_key(&manifest) {
                let mn_parent1 = (parent1 != HgChangesetId::null())
                    .then(|| get_manifest(parent1))
                    .unwrap_or_else(HgManifestId::null);
                let mn_parent2 = (parent2 != HgChangesetId::null())
                    .then(|| get_manifest(parent2))
                    .unwrap_or_else(HgManifestId::null);
                if ![&mn_parent1, &mn_parent2].contains(&&manifest) {
                    manifests.insert(manifest, (mn_parent1, mn_parent2, node));
                }
            }
        } else {
            assert_eq!(buf, b"null");
            drop(progress);
            bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
            let files = bundle_manifest(&mut bundle_part_writer, version, manifests.drain(..));
            bundle_files(&mut bundle_part_writer, version, files);
            break;
        }
    }
    // The thread this is invoked from may be killed (it's dropped, not joined) because
    // we're not entirely sure the python side won't dead-lock us. If we communicate
    // we're done before flushing the bundle writer, the python side may actually close
    // before the function returns, and before the bundle writer is dropped.
    // So drop it manually first.
    drop(bundle_part_writer);
    drop(bundle_writer);
    writeln!(out, "done").unwrap();
    changeset_heads
}

fn bundle_manifest<const CHUNK_SIZE: usize>(
    bundle_part_writer: &mut BundlePartWriter<CHUNK_SIZE>,
    version: u8,
    manifests: impl IntoIterator<Item = (HgManifestId, (HgManifestId, HgManifestId, HgChangesetId))>,
) -> impl IntoIterator<
    Item = (
        Box<[u8]>,
        IndexMap<HgFileId, (HgFileId, HgFileId, HgChangesetId)>,
    ),
> {
    let mut previous = None;
    let mut files = HashMap::new();
    for (node, (parent1, parent2, changeset)) in manifests
        .into_iter()
        .progress(|n| format!("Bundling {n} manifests"))
    {
        write_chunk(
            &mut *bundle_part_writer,
            version,
            &node,
            &parent1,
            &parent2,
            &changeset,
            &mut previous,
            |node| {
                let node = HgManifestId::from_unchecked(node.clone());
                let manifest = RawHgManifest::read(&node.to_git().unwrap()).unwrap();
                manifest.0
            },
        )
        .unwrap();
        let git_node = node.to_git().unwrap();
        let git_parents = [parent1, parent2]
            .into_iter()
            .filter_map(|p| (p != HgManifestId::null()).then(|| (*p.to_git().unwrap()).clone()))
            .collect_vec();
        for (path, hg_file, hg_fileparents) in get_changes(&git_node, &git_parents, false) {
            if hg_file != GitObjectId::null() {
                files
                    .entry(path)
                    .or_insert_with(IndexMap::new)
                    .entry(HgFileId::from_bytes(format!("{}", hg_file).as_bytes()).unwrap())
                    .or_insert_with(|| {
                        (
                            HgFileId::from_bytes(
                                format!(
                                    "{}",
                                    hg_fileparents
                                        .get(0)
                                        .cloned()
                                        .unwrap_or_else(GitObjectId::null)
                                )
                                .as_bytes(),
                            )
                            .unwrap(),
                            HgFileId::from_bytes(
                                format!(
                                    "{}",
                                    hg_fileparents
                                        .get(1)
                                        .cloned()
                                        .unwrap_or_else(GitObjectId::null)
                                )
                                .as_bytes(),
                            )
                            .unwrap(),
                            changeset.clone(),
                        )
                    });
            }
        }
    }
    bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
    files
}

fn bundle_files<const CHUNK_SIZE: usize>(
    bundle_part_writer: &mut BundlePartWriter<CHUNK_SIZE>,
    version: u8,
    files: impl IntoIterator<
        Item = (
            Box<[u8]>,
            IndexMap<HgFileId, (HgFileId, HgFileId, HgChangesetId)>,
        ),
    >,
) {
    let count = Cell::new(0);
    let mut progress =
        repeat(()).progress(|n| format!("Bundling {n} revisions of {} files", count.get()));
    for (path, data) in files.into_iter().sorted_by(|a, b| a.0.cmp(&b.0)) {
        let path = manifest_path(&path);
        bundle_part_writer
            .write_u32::<BigEndian>((4 + path.len()).try_into().unwrap())
            .unwrap();
        bundle_part_writer.write_all(&path).unwrap();
        count.set(count.get() + 1);
        let mut previous = None;
        let empty_file = HgFileId::from_str("b80de5d138758541c5f05265ad144ab9fa86d1db").unwrap();
        for ((node, (parent1, parent2, changeset)), ()) in data.into_iter().zip(&mut progress) {
            let generate = |node: &HgObjectId| {
                let node = HgFileId::from_unchecked(node.clone());
                if node == empty_file {
                    vec![].into_boxed_slice()
                } else {
                    let metadata = unsafe { files_meta.get_note(&node) }
                        .map(|oid| GitFileMetadataId::from_unchecked(BlobId::from_unchecked(oid)));

                    let file = RawHgFile::read(&node.to_git().unwrap(), metadata.as_ref()).unwrap();
                    file.0
                }
            };
            let [parent1, parent2] =
                find_parents(&node, Some(&parent1), Some(&parent2), &generate(&node));
            write_chunk(
                &mut *bundle_part_writer,
                version,
                &node,
                parent1.unwrap_or(&HgObjectId::null()),
                parent2.unwrap_or(&HgObjectId::null()),
                &changeset,
                &mut previous,
                generate,
            )
            .unwrap();
        }
        bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
    }
    bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
}
