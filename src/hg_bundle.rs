/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::fs::File;
use std::io::{self, copy, Chain, Cursor, ErrorKind, Read, Write};
use std::iter::repeat;
use std::mem;
use std::os::raw::c_int;
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::str::FromStr;

use bstr::{BStr, ByteSlice};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use derive_more::Deref;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use indexmap::IndexMap;
use itertools::Itertools;
use tee::TeeReader;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::get_changes;
use crate::git::{CommitId, RawCommit};
use crate::hg::{HgChangesetId, HgFileId, HgManifestId, HgObjectId};
use crate::hg_connect::{encodecaps, HgConnection, HgConnectionBase, HgRepo};
use crate::hg_data::find_file_parents;
use crate::libcinnabar::{hg_object_id, strslice, AsStrSlice};
use crate::libgit::die;
use crate::oid::ObjectId;
use crate::progress::Progress;
use crate::store::{
    ChangesetHeads, RawGitChangesetMetadata, RawHgChangeset, RawHgFile, RawHgManifest, Store,
};
use crate::tree_util::{Empty, WithPath};
use crate::util::{assert_ge, assert_lt, FromBytes, ImmutBString, ReadExt, SliceExt, ToBoxed};
use crate::xdiff::textdiff;

#[no_mangle]
pub unsafe extern "C" fn rev_diff_start_iter(iterator: *mut strslice, chunk: *const rev_chunk) {
    ptr::write(
        iterator,
        chunk
            .as_ref()
            .unwrap()
            .revchunk
            .iter_diff()
            .0
            .as_str_slice(),
    );
}

#[no_mangle]
pub unsafe extern "C" fn rev_diff_iter_next(
    iterator: *mut strslice,
    part: *mut rev_diff_part,
) -> c_int {
    let mut diff_iter = RevDiffIter(iterator.as_mut().unwrap().as_bytes());
    let next = diff_iter.next();
    ptr::write(iterator, diff_iter.0.as_str_slice());
    if let Some(p) = next {
        ptr::write(
            part,
            mem::transmute::<rev_diff_part<'_>, rev_diff_part<'_>>(p.0),
        );
        1
    } else {
        0
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rev_chunk {
    node: NonNull<hg_object_id>,
    parent1: NonNull<hg_object_id>,
    parent2: NonNull<hg_object_id>,
    delta_node: NonNull<hg_object_id>,
    revchunk: RevChunk,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rev_diff_part<'a> {
    start: usize,
    end: usize,
    data: strslice<'a>,
}

pub struct RevChunk {
    raw: ImmutBString,
    delta_node: Option<Rc<HgObjectId>>,
}

impl RevChunk {
    pub fn node(&self) -> HgObjectId {
        HgObjectId::from_raw_bytes(&self.raw[0..20]).unwrap()
    }

    pub fn parent1(&self) -> HgObjectId {
        HgObjectId::from_raw_bytes(&self.raw[20..40]).unwrap()
    }

    pub fn parent2(&self) -> HgObjectId {
        HgObjectId::from_raw_bytes(&self.raw[40..60]).unwrap()
    }

    pub fn delta_node(&self) -> HgObjectId {
        self.delta_node.as_ref().map_or_else(
            || HgObjectId::from_raw_bytes(&self.raw[60..80]).unwrap(),
            |oid| **oid,
        )
    }

    pub fn iter_diff(&self) -> RevDiffIter {
        RevDiffIter(&self.raw[if self.delta_node.is_some() { 80 } else { 100 }..])
    }
}

impl From<RevChunk> for rev_chunk {
    fn from(mut chunk: RevChunk) -> Self {
        let buf = &mut chunk.raw[..];
        unsafe {
            rev_chunk {
                node: NonNull::new_unchecked(buf.as_mut_ptr()).cast(),
                parent1: NonNull::new_unchecked(buf.as_mut_ptr().add(20)).cast(),
                parent2: NonNull::new_unchecked(buf.as_mut_ptr().add(40)).cast(),
                delta_node: chunk
                    .delta_node
                    .as_ref()
                    .map_or_else(
                        || NonNull::new_unchecked(buf.as_mut_ptr().add(60)),
                        |oid| NonNull::new_unchecked(oid.as_raw_bytes() as *const _ as *mut _),
                    )
                    .cast(),
                revchunk: chunk,
            }
        }
    }
}

pub fn read_rev_chunk<R: Read>(mut r: R) -> ImmutBString {
    let mut buf = [0; 4];
    r.read_exact(&mut buf).unwrap();
    let len = BigEndian::read_u32(&buf) as u64;
    if len == 0 {
        return Box::new([]);
    }
    let mut result = Vec::with_capacity(len.try_into().unwrap());
    // TODO: should error out on short read
    copy(&mut r.take(len.checked_sub(4).unwrap()), &mut result).unwrap();
    result.into_boxed_slice()
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
    next_delta_node: Option<Rc<HgObjectId>>,
    reader: R,
}

impl<R: Read> RevChunkIter<R> {
    pub fn new(version: u8, reader: R) -> Self {
        RevChunkIter {
            version,
            next_delta_node: None,
            reader,
        }
    }
}

impl<R: Read> Iterator for RevChunkIter<R> {
    type Item = RevChunk;

    fn next(&mut self) -> Option<RevChunk> {
        let buf = read_rev_chunk(&mut self.reader);
        if buf.as_bytes().is_empty() {
            return None;
        }
        let data_offset = 80 + 20 * (if self.version == 1 { 0 } else { 1 });
        if buf.as_bytes().len() < data_offset {
            die!("Invalid revchunk");
        }

        let mut chunk = RevChunk {
            raw: buf,
            delta_node: None,
        };

        chunk.delta_node = (self.version == 1).then(|| {
            let delta_node = self
                .next_delta_node
                .take()
                .unwrap_or_else(|| chunk.parent1().into());

            let next_delta_node = if let Some(next_delta_node) = Rc::get_mut(
                self.next_delta_node
                    .get_or_insert_with(|| Rc::new(HgObjectId::NULL)),
            ) {
                next_delta_node
            } else {
                self.next_delta_node = Some(Rc::new(HgObjectId::NULL));
                Rc::get_mut(self.next_delta_node.as_mut().unwrap()).unwrap()
            };
            *next_delta_node = chunk.node();
            delta_node
        });

        Some(chunk)
    }
}

#[repr(transparent)]
pub struct RevDiffIter<'a>(&'a [u8]);

#[repr(transparent)]
pub struct RevDiffPart<'a>(rev_diff_part<'a>);

impl<'a> Iterator for RevDiffIter<'a> {
    type Item = RevDiffPart<'a>;

    fn next(&mut self) -> Option<RevDiffPart<'a>> {
        let slice = self.0.as_bytes();
        if slice.is_empty() {
            return None;
        }
        if slice.len() < 12 {
            die!("Invalid revchunk");
        }
        let start = usize::try_from(BigEndian::read_u32(&slice[0..4])).unwrap();
        let end = usize::try_from(BigEndian::read_u32(&slice[4..8])).unwrap();
        let len = usize::try_from(BigEndian::read_u32(&slice[8..12])).unwrap();
        let slice = &slice[12..];
        if slice.len() < len {
            die!("Invalid revchunk");
        }
        let (data, slice) = slice.split_at(len);
        unsafe {
            ptr::write(&mut self.0 as *mut _, slice);
        }
        Some(RevDiffPart(rev_diff_part {
            start,
            end,
            data: data.as_str_slice(),
        }))
    }
}

impl RevDiffPart<'_> {
    pub fn start(&self) -> usize {
        self.0.start
    }

    pub fn end(&self) -> usize {
        self.0.end
    }

    pub fn data(&self) -> &BStr {
        self.0.data.as_bytes().as_bstr()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleVersion {
    V1,
    V2,
}

#[derive(Clone)]
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
        let mandatory = part_type.chars().next().is_some_and(char::is_uppercase);
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

impl Read for BundlePartReader<'_> {
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

impl Drop for BundleWriter<'_> {
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

impl<const CHUNK_SIZE: usize> Drop for BundlePartWriter<'_, CHUNK_SIZE> {
    fn drop(&mut self) {
        self.flush_buf_as_chunk().unwrap();
        if self.bundle2_buf.is_some() {
            write_bundle2_chunk(&mut *self.writer, &[]).unwrap();
        }
        self.writer.flush().unwrap();
    }
}

impl<const CHUNK_SIZE: usize> Write for BundlePartWriter<'_, CHUNK_SIZE> {
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
            let empty_cs = RawHgChangeset::empty();
            // TODO: share more code with the equivalent loop in store.rs.
            for chunk in
                RevChunkIter::new(version, part).progress(|n| format!("Analyzing {n} changesets"))
            {
                let node = HgChangesetId::from_unchecked(chunk.node());
                let parent1 = HgChangesetId::from_unchecked(chunk.parent1());
                let parent2 = HgChangesetId::from_unchecked(chunk.parent2());
                let delta_node = HgChangesetId::from_unchecked(chunk.delta_node());
                let parents = [parent1, parent2];
                let parents = parents
                    .into_iter()
                    .filter(|p| !p.is_null())
                    .collect::<Vec<_>>();

                let reference_cs = if delta_node.is_null() {
                    &empty_cs
                } else {
                    raw_changesets.get(&delta_node).unwrap()
                };
                let mut last_end = 0;
                let mut raw_changeset = Vec::new();
                for diff in chunk.iter_diff() {
                    if diff.start() > reference_cs.len() || diff.start() < last_end {
                        die!("Malformed changeset chunk for {node}");
                    }
                    raw_changeset.extend_from_slice(&reference_cs[last_end..diff.start()]);
                    raw_changeset.extend_from_slice(diff.data());
                    last_end = diff.end();
                }
                if reference_cs.len() < last_end {
                    die!("Malformed changeset chunk for {node}");
                }
                raw_changeset.extend_from_slice(&reference_cs[last_end..]);
                let raw_changeset = RawHgChangeset::from(raw_changeset);
                let changeset = raw_changeset.parse().unwrap();
                let branch = changeset
                    .extra()
                    .and_then(|e| e.get(b"branch"))
                    .unwrap_or(b"default")
                    .as_bstr();

                changesets.add(node, &parents, branch);
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
                .chunk_by(|(_, (_, branch))| *branch)
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

pub fn create_chunk_data(a: &[u8], b: &[u8]) -> Box<[u8]> {
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
fn write_chunk<T: core::ops::Deref<Target = [u8]>>(
    mut writer: impl Write,
    version: u8,
    node: HgObjectId,
    parent1: HgObjectId,
    parent2: HgObjectId,
    changeset: HgChangesetId,
    previous: &mut Option<(HgObjectId, T)>,
    always_previous: bool,
    mut f: impl FnMut(HgObjectId) -> T,
) -> io::Result<()> {
    let raw_object = f(node);
    let (previous_node, raw_previous) = match previous.take() {
        Some((a, b)) => (Some(a), Some(b)),
        None => (None, None),
    };
    let (delta_node, chunk) = if version == 1 {
        let previous = raw_previous.or_else(|| (!parent1.is_null()).then(|| f(parent1)));
        let previous = previous.as_deref().unwrap_or(b"");
        (None, create_chunk_data(previous, &raw_object))
    } else {
        let mut chunk_data = [parent1, parent2]
            .into_iter()
            .filter(|p| !p.is_null())
            .dedup()
            .map(|p| {
                if let (true, Some(p)) = (always_previous, previous_node) {
                    let previous = raw_previous.as_ref().unwrap();
                    (Some(p), create_chunk_data(previous, &raw_object))
                } else {
                    (Some(p), create_chunk_data(&f(p), &raw_object))
                }
            })
            .collect_vec();
        if chunk_data.is_empty() {
            chunk_data.push((
                previous_node,
                create_chunk_data(raw_previous.as_deref().unwrap_or(b""), &raw_object),
            ));
        }
        chunk_data.into_iter().min_by_key(|(_, d)| d.len()).unwrap()
    };
    *previous = Some((node, raw_object));
    writer.write_u32::<BigEndian>(
        (4 + chunk.len() + 80 + if version == 2 { 20 } else { 0 })
            .try_into()
            .unwrap(),
    )?;
    writer.write_all(node.as_raw_bytes())?;
    writer.write_all(parent1.as_raw_bytes())?;
    writer.write_all(parent2.as_raw_bytes())?;
    if version == 2 {
        writer.write_all(delta_node.unwrap_or(HgObjectId::NULL).as_raw_bytes())?;
    }
    writer.write_all(changeset.as_raw_bytes())?;
    writer.write_all(&chunk)
}

pub fn create_bundle(
    store: &Store,
    changesets: impl Iterator<Item = [HgChangesetId; 3]>,
    bundlespec: BundleSpec,
    version: u8,
    output: &File,
    replycaps: bool,
) -> ChangesetHeads {
    let mut part_id = 0;
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

    for [node, parent1, parent2] in changesets.progress(|n| format!("Bundling {n} changesets")) {
        // TODO: add branch.
        changeset_heads.add(node, &[parent1, parent2], b"".as_bstr());

        write_chunk(
            &mut bundle_part_writer,
            version,
            node.into(),
            parent1.into(),
            parent2.into(),
            node,
            &mut previous,
            true,
            |node| {
                let node = HgChangesetId::from_unchecked(node);
                RawHgChangeset::read(store, node.to_git(store).unwrap()).unwrap()
            },
        )
        .unwrap();
        // We could derive the manifest parents from the parent changesets, but there
        // are cases where they are actually the opposites of the parent manifests,
        // so we have to go off the manifest dag.
        let get_manifest = |node: CommitId| {
            let manifest_commit = RawCommit::read(node).unwrap();
            let manifest_commit = manifest_commit.parse().unwrap();
            HgManifestId::from_bytes(manifest_commit.body()).unwrap()
        };
        let metadata = RawGitChangesetMetadata::read(store, node.to_git(store).unwrap()).unwrap();
        let metadata = metadata.parse().unwrap();
        let manifest = metadata.manifest_id();
        if !manifest.is_null() && !manifests.contains_key(&manifest) {
            let manifest_commit = RawCommit::read(manifest.to_git(store).unwrap().into()).unwrap();
            let manifest_commit = manifest_commit.parse().unwrap();
            let manifest_parents = manifest_commit.parents();
            let mn_parent1 = manifest_parents
                .first()
                .copied()
                .map_or(HgManifestId::NULL, get_manifest);
            let mn_parent2 = manifest_parents
                .get(1)
                .copied()
                .map_or(HgManifestId::NULL, get_manifest);
            if ![&mn_parent1, &mn_parent2].contains(&&manifest) {
                manifests.insert(manifest, (mn_parent1, mn_parent2, node));
            }
        }
    }
    bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
    let files = bundle_manifest(store, &mut bundle_part_writer, version, manifests.drain(..));
    bundle_files(store, &mut bundle_part_writer, version, files);
    changeset_heads
}

#[allow(clippy::type_complexity)]
fn bundle_manifest<const CHUNK_SIZE: usize>(
    store: &Store,
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
            node.into(),
            parent1.into(),
            parent2.into(),
            changeset,
            &mut previous,
            false,
            |node| {
                let node = HgManifestId::from_unchecked(node);
                RawHgManifest::read(node.to_git(store).unwrap()).unwrap()
            },
        )
        .unwrap();
        let git_node = node.to_git(store).unwrap();
        let git_parents = [parent1, parent2]
            .into_iter()
            .filter(|p| !p.is_null())
            .map(|p| (p.to_git(store).unwrap().into()))
            .collect_vec();
        for (path, (hg_file, hg_fileparents)) in
            get_changes(git_node.into(), &git_parents, false).map(WithPath::unzip)
        {
            if !hg_file.is_null() {
                files
                    .entry(path)
                    .or_insert_with(IndexMap::new)
                    .entry(hg_file)
                    .or_insert_with(|| {
                        (
                            hg_fileparents.first().copied().unwrap_or(HgFileId::NULL),
                            hg_fileparents.get(1).copied().unwrap_or(HgFileId::NULL),
                            changeset,
                        )
                    });
            }
        }
    }
    bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
    files
}

fn bundle_files<const CHUNK_SIZE: usize>(
    store: &Store,
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
        bundle_part_writer
            .write_u32::<BigEndian>((4 + path.len()).try_into().unwrap())
            .unwrap();
        bundle_part_writer.write_all(&path).unwrap();
        count.set(count.get() + 1);
        let mut previous = None;
        for ((node, (mut parent1, mut parent2, changeset)), ()) in
            data.into_iter().zip(&mut progress)
        {
            let data = RawHgFile::read_hg(store, node).unwrap();
            // Normalize parents so that the first parent isn't null (it's a corner case, see below).
            if parent1.is_null() {
                mem::swap(&mut parent1, &mut parent2);
            }
            let [parent1, parent2] = find_file_parents(node, Some(parent1), Some(parent2), &data)
                .expect("Failed to create file. Please open an issue with details");
            let mut parent1 = parent1.unwrap_or(HgFileId::NULL);
            let mut parent2 = parent2.unwrap_or(HgFileId::NULL);
            // On merges, a file with copy metadata has either not parent, or only one.
            // In that latter case, the parent is always set as second parent.
            // On non-merges, a file with copy metadata doesn't have a parent.
            if data.starts_with(b"\x01\n") {
                if !parent1.is_null() && !parent2.is_null() {
                    die!("Trying to create an invalid file. Please open an issue with details.");
                }
                if !parent1.is_null() {
                    mem::swap(&mut parent1, &mut parent2);
                }
            }
            write_chunk(
                &mut *bundle_part_writer,
                version,
                node.into(),
                parent1.into(),
                parent2.into(),
                changeset,
                &mut previous,
                false,
                |oid| RawHgFile::read_hg(store, HgFileId::from_unchecked(oid)).unwrap(),
            )
            .unwrap();
        }
        bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
    }
    bundle_part_writer.write_u32::<BigEndian>(0).unwrap();
}
