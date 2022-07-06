/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::{BTreeMap, HashMap};
use std::io::{self, copy, Chain, Cursor, ErrorKind, Read, Write};
use std::mem::{self, MaybeUninit};
use std::os::raw::c_int;
use std::ptr::NonNull;
use std::str::FromStr;

use bstr::ByteSlice;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use itertools::Itertools;
use replace_with::replace_with_or_abort;
use tee::TeeReader;
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::hg_connect::{HgConnection, HgConnectionBase};
use crate::progress::Progress;
use crate::store::{ChangesetHeads, HgChangesetId, RawHgChangeset};
use crate::{
    libcinnabar::hg_object_id,
    libgit::strbuf,
    oid::{HgObjectId, ObjectId},
    util::{ImmutBString, ReadExt, SliceExt},
};

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
            let initial_buf = initial_buf_.get_mut();
            if initial_buf.is_empty() {
                if (&mut self.inner).take(4).read_to_end(initial_buf)? != 4 {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        "Unrecognized mercurial bundle",
                    ));
                }
                let compression = match &initial_buf[..] {
                    b"HG20" => decompress_bundlev2_header(&mut self.inner, initial_buf)?,
                    b"HG10" => decompress_bundlev1_header(&mut self.inner, initial_buf)?,
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
    // TODO: should error out on short read
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

pub struct BundleSaver<R: Read, W: Write> {
    reader: R,
    writer: W,
}

impl<R: Read, W: Write> BundleSaver<R, W> {
    pub fn new(reader: R, mut writer: W, version: u8) -> Self {
        writer.write_all(b"HG20\0\0\0\0").unwrap();
        writer
            .write_all(b"\0\0\0\x1d\x0bCHANGEGROUP\0\0\0\0")
            .unwrap();
        writer.write_all(b"\x01\x00\x07\x02version").unwrap();
        writer
            .write_all(format!("{:02}", version).as_bytes())
            .unwrap();
        BundleSaver { reader, writer }
    }
}

impl<R: Read, W: Write> Drop for BundleSaver<R, W> {
    fn drop(&mut self) {
        self.writer.write_all(b"\0\0\0\0\0\0\0\0").unwrap();
    }
}

impl<R: Read, W: Write> Read for BundleSaver<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.writer.write_u32::<BigEndian>(n.try_into().unwrap())?;
        self.writer.write_all(&buf[..n]).unwrap();
        Ok(n)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleVersion {
    V1,
    V2,
}

pub struct BundleReader<R: Read> {
    reader: Chain<Cursor<ImmutBString>, R>,
    version: BundleVersion,
    remaining: Option<u32>,
}

impl<R: Read> BundleReader<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut header = [0; 4];
        reader.read_exact(&mut header)?;
        if &header == b"HG20" {
            // Read header
            let _header = read_bundle2_chunk(&mut reader)?;
            return Ok(BundleReader {
                reader: Cursor::new(vec![].into_boxed_slice()).chain(reader),
                version: BundleVersion::V2,
                remaining: Some(0),
            });
        }
        assert_ne!(&header, b"HG10");
        Ok(BundleReader {
            reader: Cursor::new(header.to_vec().into_boxed_slice()).chain(reader),
            version: BundleVersion::V1,
            remaining: Some(0),
        })
    }

    pub fn next_part(&mut self) -> io::Result<Option<BundlePart<impl Read>>> {
        match self.remaining.take() {
            None => return Ok(None),
            Some(0) => {}
            Some(len) => {
                assert_eq!(self.version, BundleVersion::V2);
                // Advance past last part if it was not read entirely.
                copy(&mut (&mut self.reader).take(len.into()), &mut io::sink())?;
                while copy_bundle2_chunk(&mut self.reader, &mut io::sink())? > 0 {}
            }
        }
        match self.version {
            BundleVersion::V1 => Ok(Some(BundlePart {
                mandatory: true,
                part_type: "changegroup".to_string().into_boxed_str(),
                part_id: 0,
                params: HashMap::new(),
                reader: &mut self.reader,
                version: self.version,
                remaining: self.remaining.as_mut(),
            })),
            BundleVersion::V2 => {
                let mut header = match read_bundle2_chunk(&mut self.reader) {
                    Err(e) => return Err(e),
                    Ok(header) if header.is_empty() => {
                        self.remaining = None;
                        return Ok(None);
                    }
                    Ok(header) => Cursor::new(header),
                };
                let part_type_len = header.read_u8()?;
                let part_type = header.read_exactly_to_string(part_type_len.into())?;
                let mandatory = part_type.chars().next().map_or(false, char::is_uppercase);
                let part_type = part_type.to_lowercase().into_boxed_str();
                let part_id = header.read_u32::<BigEndian>()?;
                let mandatory_params_num = header.read_u8()?;
                let advisory_params_num = header.read_u8()?;
                let param_lengths = (0..usize::from(mandatory_params_num + advisory_params_num))
                    .map(|_| Ok((header.read_u8()?, header.read_u8()?)))
                    .collect::<io::Result<Vec<(u8, u8)>>>()?;
                let params = param_lengths
                    .into_iter()
                    .map(|(name_len, value_len)| {
                        Ok((
                            header.read_exactly_to_string(name_len.into())?,
                            header.read_exactly_to_string(value_len.into())?,
                        ))
                    })
                    .collect::<io::Result<_>>()?;
                self.remaining = Some(self.reader.read_u32::<BigEndian>()?);
                Ok(Some(BundlePart {
                    mandatory,
                    part_type,
                    part_id,
                    params,
                    reader: &mut self.reader,
                    version: self.version,
                    remaining: self.remaining.as_mut(),
                }))
            }
        }
    }
}

pub struct BundlePart<'a, R: Read> {
    pub mandatory: bool,
    pub part_type: Box<str>,
    part_id: u32,
    pub params: HashMap<Box<str>, Box<str>>,
    reader: &'a mut R,
    version: BundleVersion,
    remaining: Option<&'a mut u32>,
}

impl<'a, R: Read> Read for BundlePart<'a, R> {
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
                .params
                .get("version")
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
    fn known(&mut self, _nodes: &[HgChangesetId]) -> Box<[bool]> {
        todo!()
    }

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

    fn listkeys(&mut self, _namespace: &str) -> ImmutBString {
        // TODO: For HG20 bundles, we could actually read the relevant part(s).
        Box::new([])
    }

    fn getbundle<'a>(
        &'a mut self,
        _heads: &[crate::store::HgChangesetId],
        common: &[crate::store::HgChangesetId],
        _bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
        assert!(common.is_empty());

        Ok(Box::new(
            Cursor::new(mem::take(&mut self.buf)).chain(&mut self.reader),
        ))
    }
}
