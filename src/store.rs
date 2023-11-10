/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::io::{copy, BufRead, BufReader, Read, Write};
use std::iter::{repeat, IntoIterator};
use std::mem;
use std::num::NonZeroU32;
use std::os::raw::c_int;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Mutex;

use bit_vec::BitVec;
use bstr::{BStr, BString, ByteSlice};
use derive_more::Deref;
use either::Either;
use getset::{CopyGetters, Getters};
use hex_literal::hex;
use indexmap::IndexMap;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use once_cell::sync::Lazy;
use percent_encoding::{percent_decode, percent_encode, NON_ALPHANUMERIC};
use tee::TeeReader;
use url::{Host, Url};

use crate::cinnabar::{
    GitChangesetId, GitChangesetMetadataId, GitFileId, GitFileMetadataId, GitManifestId,
    GitManifestTree, GitManifestTreeId,
};
use crate::git::{BlobId, CommitId, GitObjectId, GitOid, RecursedTreeEntry, TreeId, TreeIsh};
use crate::graft::{graft, grafted, replace_map_tablesize, GraftError};
use crate::hg::{HgChangesetId, HgFileId, HgManifestId, HgObjectId};
use crate::hg_bundle::{
    read_rev_chunk, rev_chunk, BundlePartInfo, BundleSpec, BundleWriter, RevChunkIter,
};
use crate::hg_connect_http::HttpRequest;
use crate::hg_data::{hash_data, GitAuthorship, HgAuthorship, HgCommitter};
use crate::libcinnabar::{
    files_meta, git2hg, git_notes_tree, hg2git, hg_notes_tree, store_metadata_notes, strslice,
    strslice_mut,
};
use crate::libgit::{
    commit, commit_oid, die, for_each_ref_in, get_oid_blob, object_id, strbuf, Commit, RawBlob,
    RawCommit, RawTree, RefTransaction, CHANGESETS_OID, FILES_META_OID, GIT2HG_OID, HG2GIT_OID,
    MANIFESTS_OID, METADATA_OID,
};
use crate::oid::ObjectId;
use crate::progress::{progress_enabled, Progress};
use crate::tree_util::{diff_by_path, Empty, ParseTree, RecurseTree, WithPath};
use crate::util::{
    FromBytes, ImmutBString, OsStrExt, RcExt, ReadExt, SliceExt, ToBoxed, Transpose,
};
use crate::xdiff::{apply, textdiff, PatchInfo};
use crate::{check_enabled, do_reload, Checks};

pub const REFS_PREFIX: &str = "refs/cinnabar/";
pub const REPLACE_REFS_PREFIX: &str = "refs/cinnabar/replace/";
pub const METADATA_REF: &str = "refs/cinnabar/metadata";
pub const CHECKED_REF: &str = "refs/cinnabar/checked";
pub const BROKEN_REF: &str = "refs/cinnabar/broken";
pub const NOTES_REF: &str = "refs/notes/cinnabar";

pub static mut METADATA_FLAGS: c_int = 0;

pub const FILES_META: c_int = 0x1;
pub const UNIFIED_MANIFESTS_V2: c_int = 0x2;

pub fn has_metadata() -> bool {
    unsafe { METADATA_FLAGS != 0 }
}

macro_rules! hg2git {
    ($h:ident => $g:ident) => {
        impl $h {
            pub fn to_git(self) -> Option<$g> {
                unsafe {
                    hg2git
                        .get_note(self.into())
                        .map(|o| $g::from_raw_bytes(o.as_raw_bytes()).unwrap())
                }
            }
        }
    };
}

hg2git!(HgChangesetId => GitChangesetId);
hg2git!(HgManifestId => GitManifestId);
hg2git!(HgFileId => GitFileId);

impl GitChangesetId {
    pub fn to_hg(self) -> Option<HgChangesetId> {
        //TODO: avoid repeatedly reading metadata for a given changeset.
        //The equivalent python code was keeping a LRU cache.
        let metadata = RawGitChangesetMetadata::read(self);
        metadata
            .as_ref()
            .and_then(RawGitChangesetMetadata::parse)
            .map(|m| m.changeset_id())
    }
}

pub struct RawGitChangesetMetadata(RawBlob);

impl RawGitChangesetMetadata {
    pub fn read(changeset_id: GitChangesetId) -> Option<Self> {
        Self::read_from_notes_tree(unsafe { &mut git2hg }, changeset_id)
    }

    pub fn read_from_notes_tree(
        notes: &mut git_notes_tree,
        changeset_id: GitChangesetId,
    ) -> Option<Self> {
        let note = notes
            .get_note(CommitId::from(changeset_id).into())
            .map(BlobId::from_unchecked)?;
        RawBlob::read(note).map(Self)
    }

    pub fn parse(&self) -> Option<ParsedGitChangesetMetadata> {
        let mut changeset = None;
        let mut manifest = None;
        let mut author = None;
        let mut extra = None;
        let mut files = None;
        let mut patch = None;
        for line in ByteSlice::lines(self.0.as_bytes()) {
            match line.splitn_exact(b' ')? {
                [b"changeset", c] => changeset = Some(HgChangesetId::from_bytes(c).ok()?),
                [b"manifest", m] => manifest = Some(HgManifestId::from_bytes(m).ok()?),
                [b"author", a] => author = Some(a),
                [b"extra", e] => extra = Some(e),
                [b"files", f] => files = Some(f),
                [b"patch", p] => patch = Some(p),
                _ => None?,
            }
        }

        Some(ParsedGitChangesetMetadata {
            changeset_id: changeset?,
            manifest_id: manifest.unwrap_or(HgManifestId::NULL),
            author,
            extra,
            files,
            patch,
        })
    }
}

#[derive(CopyGetters, Eq, Getters)]
pub struct GitChangesetMetadata<B: AsRef<[u8]>> {
    #[getset(get_copy = "pub")]
    changeset_id: HgChangesetId,
    #[getset(get_copy = "pub")]
    manifest_id: HgManifestId,
    author: Option<B>,
    extra: Option<B>,
    files: Option<B>,
    patch: Option<B>,
}

impl<B: AsRef<[u8]>, B2: AsRef<[u8]>> PartialEq<GitChangesetMetadata<B>>
    for GitChangesetMetadata<B2>
{
    fn eq(&self, other: &GitChangesetMetadata<B>) -> bool {
        self.changeset_id == other.changeset_id
            && self.manifest_id == other.manifest_id
            && self.author.as_ref().map(B2::as_ref) == other.author.as_ref().map(B::as_ref)
            && self.extra.as_ref().map(B2::as_ref) == other.extra.as_ref().map(B::as_ref)
            && self.files.as_ref().map(B2::as_ref) == other.files.as_ref().map(B::as_ref)
            && self.patch.as_ref().map(B2::as_ref) == other.patch.as_ref().map(B::as_ref)
    }
}

pub type ParsedGitChangesetMetadata<'a> = GitChangesetMetadata<&'a [u8]>;

impl<B: AsRef<[u8]>> GitChangesetMetadata<B> {
    pub fn author(&self) -> Option<&[u8]> {
        self.author.as_ref().map(B::as_ref)
    }

    pub fn extra(&self) -> Option<ChangesetExtra> {
        self.extra
            .as_ref()
            .map(|b| ChangesetExtra::from(b.as_ref()))
    }

    pub fn files(&self) -> impl Iterator<Item = &[u8]> {
        let mut split = self
            .files
            .as_ref()
            .map_or(&b""[..], B::as_ref)
            .split(|&b| b == b'\0');
        if self.files.is_none() {
            // b"".split() would return an empty first item, and we want to skip that.
            split.next();
        }
        split
    }

    pub fn patch(&self) -> Option<GitChangesetPatch> {
        self.patch.as_ref().map(|b| GitChangesetPatch(b.as_ref()))
    }

    pub fn serialize(&self) -> ImmutBString {
        // TODO: ideally, this would return a RawGitChangesetMetadata.
        let mut buf = Vec::new();
        writeln!(buf, "changeset {}", self.changeset_id()).unwrap();
        if !self.manifest_id().is_null() {
            writeln!(buf, "manifest {}", self.manifest_id()).unwrap();
        }
        for (key, value) in [
            (&b"author "[..], self.author.as_ref()),
            (&b"extra "[..], self.extra.as_ref()),
            (&b"files "[..], self.files.as_ref()),
            (&b"patch "[..], self.patch.as_ref()),
        ] {
            if let Some(value) = value {
                buf.extend_from_slice(key);
                buf.extend_from_slice(value.as_ref());
                buf.extend_from_slice(b"\n");
            }
        }
        // Remove final '\n'
        buf.pop();
        buf.into()
    }
}

pub type GeneratedGitChangesetMetadata = GitChangesetMetadata<ImmutBString>;

impl GeneratedGitChangesetMetadata {
    pub fn generate(
        commit: &Commit,
        changeset_id: HgChangesetId,
        raw_changeset: &RawHgChangeset,
    ) -> Option<Self> {
        let changeset = raw_changeset.parse()?;
        let manifest_id = changeset.manifest();
        let author = HgAuthorship::from(GitAuthorship(commit.author())).author;
        let author = if &*author != changeset.author() {
            Some(changeset.author().to_vec().into_boxed_slice())
        } else {
            None
        };
        let extra = changeset.extra().and_then(|mut e| {
            let mut buf = Vec::new();
            if e.get(b"committer") == Some(&HgCommitter::from(GitAuthorship(commit.committer())).0)
            {
                e.unset(b"committer");
                if e.is_empty() {
                    return None;
                }
            }
            e.dump_into(&mut buf);
            Some(buf.into_boxed_slice())
        });
        let files = changeset
            .files()
            .map(|files| bstr::join(b"\0", files).into_boxed_slice());
        let mut temp = GeneratedGitChangesetMetadata {
            changeset_id,
            manifest_id,
            author,
            extra,
            files,
            patch: None,
        };
        let new = RawHgChangeset::from_metadata(commit, &temp)?;
        if **raw_changeset != *new {
            // TODO: produce a better patch (byte_diff). In the meanwhile, we
            // do an approximation by taking the by-line diff from textdiff
            // and eliminating common parts, which is good enough.
            temp.patch = Some(GitChangesetPatch::from_patch_info(
                textdiff(&new, raw_changeset).map(|p| {
                    let orig = &new[p.start..p.end];
                    let patched = p.data;
                    let common_prefix = Iterator::zip(orig.iter(), patched.iter())
                        .take_while(|(&a, &b)| a == b)
                        .count();
                    let common_suffix = Iterator::zip(orig.iter().rev(), patched.iter().rev())
                        .take_while(|(&a, &b)| a == b)
                        .count();
                    PatchInfo {
                        start: p.start + common_prefix,
                        end: p.end - common_suffix,
                        data: &p.data[common_prefix..p.data.len() - common_suffix],
                    }
                }),
            ));
        }
        Some(temp)
    }
}

pub struct ChangesetExtra<'a> {
    data: BTreeMap<&'a BStr, &'a BStr>,
}

impl<'a> ChangesetExtra<'a> {
    fn from(buf: &'a [u8]) -> Self {
        if buf.is_empty() {
            ChangesetExtra::new()
        } else {
            ChangesetExtra {
                data: buf
                    .split(|&c| c == b'\0')
                    .map(|a| {
                        let [k, v] = a.splitn_exact(b':').unwrap();
                        (k.as_bstr(), v.as_bstr())
                    })
                    .collect(),
            }
        }
    }

    pub fn new() -> Self {
        ChangesetExtra {
            data: BTreeMap::new(),
        }
    }

    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.data.get(name.as_bstr()).map(|b| &***b)
    }

    pub fn unset(&mut self, name: &[u8]) {
        self.data.remove(name.as_bstr());
    }

    pub fn set(&mut self, name: &'a [u8], value: &'a [u8]) {
        self.data.insert(name.as_bstr(), value.as_bstr());
    }

    pub fn dump_into(&self, buf: &mut Vec<u8>) {
        for b in Itertools::intersperse(
            self.data.iter().map(|(&k, &v)| {
                let mut buf = Vec::new();
                buf.extend_from_slice(k);
                buf.push(b':');
                buf.extend_from_slice(v);
                Cow::Owned(buf)
            }),
            Cow::Borrowed(&b"\0"[..]),
        ) {
            buf.extend_from_slice(&b);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[test]
fn test_changeset_extra() {
    let mut extra = ChangesetExtra::new();
    extra.set(b"foo", b"bar");
    extra.set(b"bar", b"qux");
    let mut result = Vec::new();
    extra.dump_into(&mut result);
    assert_eq!(result.as_bstr(), b"bar:qux\0foo:bar".as_bstr());

    let mut extra = ChangesetExtra::from(&result);
    let mut result2 = Vec::new();
    extra.dump_into(&mut result2);
    assert_eq!(result.as_bstr(), result2.as_bstr());

    extra.set(b"aaaa", b"bbbb");
    result2.truncate(0);
    extra.dump_into(&mut result2);
    assert_eq!(result2.as_bstr(), b"aaaa:bbbb\0bar:qux\0foo:bar".as_bstr());
}

pub struct GitChangesetPatch<'a>(&'a [u8]);

impl<'a> GitChangesetPatch<'a> {
    pub fn iter(&self) -> Option<impl Iterator<Item = PatchInfo<Cow<'a, [u8]>>>> {
        self.0
            .split(|c| *c == b'\0')
            .map(|part| {
                let [start, end, data] = part.splitn_exact(b',')?;
                let start = usize::from_bytes(start).ok()?;
                let end = usize::from_bytes(end).ok()?;
                let data = Cow::from(percent_decode(data));
                Some(PatchInfo { start, end, data })
            })
            .collect::<Option<Vec<_>>>()
            .map(IntoIterator::into_iter)
    }

    pub fn apply(&self, input: &[u8]) -> Option<ImmutBString> {
        Some(apply(self.iter()?, input))
    }

    pub fn from_patch_info(
        iter: impl Iterator<Item = PatchInfo<impl AsRef<[u8]>>>,
    ) -> ImmutBString {
        let mut result = Vec::new();
        for (n, part) in iter.enumerate() {
            if n > 0 {
                result.push(b'\0');
            }
            write!(
                result,
                "{},{},{}",
                part.start,
                part.end,
                percent_encode(part.data.as_ref(), NON_ALPHANUMERIC)
            )
            .ok();
        }
        result.into_boxed_slice()
    }
}

#[derive(Deref)]
#[deref(forward)]
pub struct RawHgChangeset(pub ImmutBString);

impl RawHgChangeset {
    pub fn from_metadata<B: AsRef<[u8]>>(
        commit: &Commit,
        metadata: &GitChangesetMetadata<B>,
    ) -> Option<Self> {
        let HgAuthorship {
            author: mut hg_author,
            timestamp: hg_timestamp,
            utcoffset: hg_utcoffset,
        } = GitAuthorship(commit.author()).into();

        if let Some(author) = metadata.author() {
            hg_author = author.to_boxed();
        }
        let mut extra = metadata.extra();
        let hg_committer = (extra.as_ref().and_then(|e| e.get(b"committer")).is_none()
            && (commit.author() != commit.committer()))
        .then(|| HgCommitter::from(GitAuthorship(commit.committer())).0);

        if let Some(hg_committer) = hg_committer.as_ref() {
            extra
                .get_or_insert_with(ChangesetExtra::new)
                .set(b"committer", hg_committer);
        }

        let mut changeset = Vec::new();
        writeln!(changeset, "{}", metadata.manifest_id()).ok()?;
        changeset.extend_from_slice(&hg_author);
        changeset.push(b'\n');
        changeset.extend_from_slice(&hg_timestamp);
        changeset.push(b' ');
        changeset.extend_from_slice(&hg_utcoffset);
        if let Some(extra) = extra {
            changeset.push(b' ');
            extra.dump_into(&mut changeset);
        }
        let mut files = metadata.files().collect_vec();
        //TODO: probably don't actually need sorting.
        files.sort();
        for f in &files {
            changeset.push(b'\n');
            changeset.extend_from_slice(f);
        }
        changeset.extend_from_slice(b"\n\n");
        changeset.extend_from_slice(commit.body());

        if let Some(patch) = metadata.patch() {
            let mut patched = patch.apply(&changeset)?.to_vec();
            mem::swap(&mut changeset, &mut patched);
        }

        // Adjust for `handle_changeset_conflict`.
        // TODO: when creating the git2hg metadata moves to Rust, we can
        // create a patch instead, which would be handled above instead of
        // manually here.
        let node = metadata.changeset_id();
        if !node.is_null() {
            while changeset[changeset.len() - 1] == b'\0' {
                let mut hash = HgChangesetId::create();
                let mut parents = commit
                    .parents()
                    .iter()
                    .map(|p| GitChangesetId::from_unchecked(*p).to_hg())
                    .chain(repeat(Some(HgChangesetId::NULL)))
                    .take(2)
                    .collect::<Option<Vec<_>>>()?;
                parents.sort();
                for p in parents {
                    hash.update(p.as_raw_bytes());
                }
                hash.update(&changeset);
                if hash.finalize() == node {
                    break;
                }
                changeset.pop();
            }
        }
        Some(RawHgChangeset(changeset.into()))
    }

    pub fn read(oid: GitChangesetId) -> Option<Self> {
        let commit = RawCommit::read(oid.into())?;
        let commit = commit.parse()?;
        let metadata = RawGitChangesetMetadata::read(oid)?;
        let metadata = metadata.parse()?;
        Self::from_metadata(&commit, &metadata)
    }

    pub fn parse(&self) -> Option<HgChangeset> {
        let [header, body] = self.0.splitn_exact(&b"\n\n"[..])?;
        let mut lines = header.splitn(4, |&b| b == b'\n');
        let manifest = lines.next()?;
        let author = lines.next()?;
        let mut date = lines.next()?.splitn(3, |&b| b == b' ');
        let timestamp = date.next()?;
        let utcoffset = date.next()?;
        let extra = date.next();
        let files = lines.next();
        Some(HgChangeset {
            manifest: HgManifestId::from_bytes(manifest).ok()?,
            author,
            timestamp,
            utcoffset,
            extra,
            files,
            body,
        })
    }
}

#[derive(CopyGetters, Getters)]
pub struct HgChangeset<'a> {
    #[getset(get_copy = "pub")]
    manifest: HgManifestId,
    #[getset(get_copy = "pub")]
    author: &'a [u8],
    #[getset(get_copy = "pub")]
    timestamp: &'a [u8],
    #[getset(get_copy = "pub")]
    utcoffset: &'a [u8],
    extra: Option<&'a [u8]>,
    files: Option<&'a [u8]>,
    #[getset(get_copy = "pub")]
    body: &'a [u8],
}

impl<'a> HgChangeset<'a> {
    pub fn extra(&self) -> Option<ChangesetExtra> {
        self.extra.map(ChangesetExtra::from)
    }

    pub fn files(&self) -> Option<impl Iterator<Item = &[u8]>> {
        self.files.as_ref().map(|b| b.split(|&b| b == b'\n'))
    }
}

// Note: the C equivalent used to indirectly cache trees. This has not been
// replicated here. We'll see if it shows up in performance profiles.
struct ManifestCache {
    tree_id: GitManifestTreeId,
    content: Rc<[u8]>,
}

thread_local! {
    static MANIFESTCACHE: Cell<Option<ManifestCache>> = Cell::new(None);
}

#[derive(Deref)]
#[deref(forward)]
pub struct RawHgManifest(Rc<[u8]>);

impl Empty for RawHgManifest {
    fn empty() -> RawHgManifest {
        RawHgManifest(Rc::new([]))
    }
}

impl RawHgManifest {
    pub fn read(oid: GitManifestId) -> Option<Self> {
        Some(MANIFESTCACHE.with(|cache| {
            let last_manifest = cache.take();
            let tree_id = oid.get_tree_id();

            let mut manifest = Rc::<[u8]>::builder();
            if let Some(last_manifest) = last_manifest {
                let reference_manifest = last_manifest.content.clone();
                if last_manifest.tree_id == tree_id {
                    cache.set(Some(last_manifest));
                    return RawHgManifest(reference_manifest);
                }
                // Generously reserve memory for the new manifest to avoid reallocs.
                manifest.reserve(reference_manifest.as_ref().len() * 2);
                // TODO: ideally, we'd be able to use merge_join_by_path, but WithPath
                // using an owned string has a huge impact on performance.
                for entry in itertools::merge_join_by(
                    ByteSlice::lines_with_terminator(&*reference_manifest).map(ByteSlice::as_bstr),
                    diff_by_path(
                        GitManifestTree::read(last_manifest.tree_id).unwrap(),
                        GitManifestTree::read(tree_id).unwrap(),
                    )
                    .recurse(),
                    |manifest_line, diff| {
                        let [path, _] = manifest_line.splitn_exact(b'\0').unwrap();
                        path.cmp(diff.path())
                    },
                ) {
                    match entry {
                        // Entry from the last manifest, take that line verbatim ; no diff to apply
                        Left(entry) => manifest.extend_from_slice(entry),
                        // No entry in the last manifest, apply the diff
                        Right(diff) => RawHgManifest::write_one_entry(
                            &diff.map(|inner| {
                                // There isn't supposed to be a left side on the diff, matchin
                                // the manifest.
                                assert!(!inner.has_left());
                                inner.right().unwrap()
                            }),
                            &mut manifest,
                        )
                        .unwrap(),
                        // There was an entry in the last manifest, but the file was modified or removed
                        Both(_, diff) => {
                            if let Some(new_entry) = diff
                                .map(|inner| {
                                    match inner {
                                        // File was removed, do nothing.
                                        Left(_) => None,
                                        Both(_, b) => Some(b),
                                        // This shouldn't be possible
                                        Right(_) => unreachable!(),
                                    }
                                })
                                .transpose()
                            {
                                RawHgManifest::write_one_entry(&new_entry, &mut manifest).unwrap();
                            }
                        }
                    };
                }
            } else {
                for entry in GitManifestTree::read(tree_id)
                    .unwrap()
                    .into_iter()
                    .recurse()
                {
                    RawHgManifest::write_one_entry(&entry, &mut manifest).unwrap();
                }
            }
            let content = manifest.into_rc();

            cache.set(Some(ManifestCache {
                tree_id,
                content: content.clone(),
            }));

            RawHgManifest(content)
        }))
    }
}

#[derive(Deref)]
#[deref(forward)]
pub struct RawHgFile(pub ImmutBString);

impl RawHgFile {
    pub const EMPTY_OID: HgFileId =
        HgFileId::from_raw_bytes_array(hex!("b80de5d138758541c5f05265ad144ab9fa86d1db"));

    pub fn read(oid: GitFileId, metadata: Option<GitFileMetadataId>) -> Option<Self> {
        let mut result = Vec::new();
        if let Some(metadata) = metadata {
            result.extend_from_slice(b"\x01\n");
            result.extend_from_slice(RawBlob::read(metadata.into())?.as_bytes());
            result.extend_from_slice(b"\x01\n");
        }
        result.extend_from_slice(RawBlob::read(oid.into())?.as_bytes());
        Some(Self(result.into()))
    }

    pub fn read_hg(oid: HgFileId) -> Option<Self> {
        if oid == Self::EMPTY_OID {
            Some(Self(vec![].into()))
        } else {
            let metadata = unsafe { files_meta.get_note(oid.into()) }
                .map(BlobId::from_unchecked)
                .map(GitFileMetadataId::from_unchecked);
            Self::read(oid.to_git().unwrap(), metadata)
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct DagNodeId(NonZeroU32);

impl DagNodeId {
    fn try_from_offset(offset: usize) -> Option<Self> {
        u32::try_from(offset + 1)
            .ok()
            .and_then(NonZeroU32::new)
            .map(Self)
    }

    fn to_offset(self) -> usize {
        self.0.get() as usize - 1
    }
}

#[derive(Debug)]
struct DagNode<N, T> {
    node: N,
    parent1: Option<DagNodeId>,
    parent2: Option<DagNodeId>,
    data: T,
}

#[derive(Debug)]
struct ChangesetInfo {
    has_children: bool,
    branch: BString,
}

#[derive(Debug)]
pub struct Dag<N, T> {
    // 4 billion nodes ought to be enough for anybody.
    ids: BTreeMap<N, DagNodeId>,
    dag: Vec<DagNode<N, T>>,
}

pub enum Traversal {
    Parents,
    Children,
}

impl<N: Ord + Copy, T> Dag<N, T> {
    pub fn new() -> Self {
        Dag {
            ids: BTreeMap::new(),
            dag: Vec::new(),
        }
    }

    pub fn add<F: FnMut(DagNodeId, &mut T)>(
        &mut self,
        node: N,
        parents: &[N],
        data: T,
        mut cb: F,
    ) -> DagNodeId {
        assert!(parents.len() <= 2);
        let parents = parents
            .iter()
            .filter_map(|&p| {
                self.get_mut(p).map(|(id, data)| {
                    cb(id, data);
                    id
                })
            })
            .collect_vec();
        let id = DagNodeId::try_from_offset(self.dag.len()).unwrap();
        assert!(self.ids.insert(node, id).is_none());
        self.dag.push(DagNode {
            node,
            parent1: parents.get(0).copied(),
            parent2: parents.get(1).copied(),
            data,
        });
        id
    }

    pub fn get(&self, node: N) -> Option<(DagNodeId, &T)> {
        self.ids
            .get(&node)
            .map(|id| (*id, &self.dag[id.to_offset()].data))
    }

    pub fn get_mut(&mut self, node: N) -> Option<(DagNodeId, &mut T)> {
        self.ids
            .get(&node)
            .map(|id| (*id, &mut self.dag[id.to_offset()].data))
    }

    pub fn get_by_id(&self, id: DagNodeId) -> (&N, &T) {
        let node = &self.dag[id.to_offset()];
        (&node.node, &node.data)
    }

    pub fn traverse_mut(
        &mut self,
        start: N,
        direction: Traversal,
        cb: impl FnMut(N, &mut T) -> bool,
    ) {
        match (direction, self.ids.get(&start)) {
            (Traversal::Parents, Some(&start)) => self.traverse_parents_mut(start, cb),
            (Traversal::Children, Some(&start)) => self.traverse_children_mut(start, cb),
            _ => {}
        }
    }

    fn traverse_parents_mut(&mut self, start: DagNodeId, mut cb: impl FnMut(N, &mut T) -> bool) {
        let mut queue = VecDeque::from([start]);
        let mut seen = BitVec::from_elem(self.ids.len(), false);
        while let Some(id) = queue.pop_front() {
            seen.set(id.to_offset(), true);
            let node = &mut self.dag[id.to_offset()];
            if cb(node.node, &mut node.data) {
                for id in [node.parent1, node.parent2].into_iter().flatten() {
                    if !seen[id.to_offset()] {
                        queue.push_back(id);
                    }
                }
            }
        }
    }

    fn traverse_children_mut(&mut self, start: DagNodeId, mut cb: impl FnMut(N, &mut T) -> bool) {
        let mut seen = BitVec::from_elem(self.ids.len() - start.to_offset(), false);
        for (idx, node) in self.dag[start.to_offset()..].iter_mut().enumerate() {
            if (idx == 0
                || [node.parent1, node.parent2]
                    .into_iter()
                    .flatten()
                    .any(|id| id >= start && seen[id.to_offset() - start.to_offset()]))
                && cb(node.node, &mut node.data)
            {
                seen.set(idx, true);
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&N, &T)> {
        self.dag.iter().map(|node| (&node.node, &node.data))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&N, &mut T)> {
        self.dag.iter_mut().map(|node| (&node.node, &mut node.data))
    }
}

#[derive(Debug)]
pub struct ChangesetHeads {
    dag: Dag<HgChangesetId, ChangesetInfo>,
    heads: BTreeSet<DagNodeId>,
}

impl ChangesetHeads {
    pub fn new() -> Self {
        ChangesetHeads {
            dag: Dag::new(),
            heads: BTreeSet::new(),
        }
    }

    fn from_stored_metadata() -> Self {
        let changesets_cid =
            CommitId::from_raw_bytes(unsafe { CHANGESETS_OID.as_raw_bytes() }).unwrap();
        if changesets_cid.is_null() {
            ChangesetHeads::new()
        } else {
            ChangesetHeads::from_metadata(changesets_cid)
        }
    }

    pub fn from_metadata(cid: CommitId) -> Self {
        let mut result = ChangesetHeads::new();

        let commit = RawCommit::read(cid).unwrap();
        let commit = commit.parse().unwrap();
        for l in ByteSlice::lines(commit.body()) {
            let [h, b] = l.splitn_exact(b' ').unwrap();
            let cs = HgChangesetId::from_bytes(h).unwrap();
            result.add(cs, &[], b.as_bstr());
        }
        result
    }

    pub fn add(&mut self, cs: HgChangesetId, parents: &[HgChangesetId], branch: &BStr) {
        let data = ChangesetInfo {
            has_children: false,
            branch: BString::from(branch),
        };
        let id = self.dag.add(cs, parents, data, |parent_id, parent_data| {
            parent_data.has_children = true;
            if parent_data.branch == branch {
                self.heads.remove(&parent_id);
            }
        });
        self.heads.insert(id);
    }

    pub fn branch_heads(&self) -> impl Iterator<Item = (&HgChangesetId, &BStr)> {
        self.heads.iter().map(|id| {
            let (node, data) = self.dag.get_by_id(*id);
            (node, data.branch.as_bstr())
        })
    }

    pub fn heads(&self) -> impl Iterator<Item = &HgChangesetId> {
        self.heads.iter().filter_map(|id| {
            let (node, data) = self.dag.get_by_id(*id);
            // Branch heads can have children in other branches, in which case
            // they are not heads.
            (!data.has_children).then_some(node)
        })
    }

    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }
}

pub static CHANGESET_HEADS: Lazy<Mutex<ChangesetHeads>> =
    Lazy::new(|| Mutex::new(ChangesetHeads::from_stored_metadata()));

#[derive(Debug)]
pub struct ManifestHeads {
    heads: BTreeSet<GitManifestId>,
}

impl ManifestHeads {
    pub fn new() -> Self {
        ManifestHeads {
            heads: BTreeSet::new(),
        }
    }

    fn from_stored_metadata() -> Self {
        let manifests_cid =
            CommitId::from_raw_bytes(unsafe { MANIFESTS_OID.as_raw_bytes() }).unwrap();
        if manifests_cid.is_null() {
            ManifestHeads::new()
        } else {
            ManifestHeads::from_metadata(manifests_cid)
        }
    }

    pub fn from_metadata(cid: CommitId) -> Self {
        let mut result = ManifestHeads::new();

        let commit = RawCommit::read(cid).unwrap();
        let commit = commit.parse().unwrap();
        for p in commit.parents() {
            result.heads.insert(GitManifestId::from_unchecked(*p));
        }
        result
    }

    pub fn add(&mut self, head: GitManifestId) {
        let commit = RawCommit::read(head.into()).unwrap();
        let commit = commit.parse().unwrap();
        for p in commit.parents() {
            self.heads.remove(&GitManifestId::from_unchecked(*p));
        }
        self.heads.insert(head);
    }

    pub fn heads(&self) -> impl Iterator<Item = &GitManifestId> {
        self.heads.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }
}

pub static MANIFEST_HEADS: Lazy<Mutex<ManifestHeads>> =
    Lazy::new(|| Mutex::new(ManifestHeads::from_stored_metadata()));

#[derive(Default)]
pub struct TagSet {
    tags: IndexMap<Box<[u8]>, (HgChangesetId, HashSet<HgChangesetId>)>,
}

impl TagSet {
    pub fn from_buf(buf: &[u8]) -> Option<Self> {
        let mut tags = IndexMap::new();
        for line in ByteSlice::lines(buf) {
            if line.is_empty() {
                continue;
            }
            let [node, tag] = line.splitn_exact(b' ')?;
            let tag = tag.trim_with(|b| b.is_ascii_whitespace());
            let node = HgChangesetId::from_bytes(node).ok()?;
            tags.entry(tag.to_boxed())
                .and_modify(|e: &mut (HgChangesetId, HashSet<HgChangesetId>)| {
                    let mut node = node;
                    mem::swap(&mut e.0, &mut node);
                    e.1.insert(node);
                })
                .or_insert_with(|| (node, HashSet::new()));
        }
        Some(TagSet { tags })
    }

    pub fn merge(&mut self, other: TagSet) {
        if self.tags.is_empty() {
            self.tags = other.tags;
            return;
        }
        for (tag, (anode, ahist)) in other.tags.into_iter() {
            // Derived from mercurial's _updatetags.
            self.tags
                .entry(tag)
                .and_modify(|(bnode, bhist)| {
                    if !(bnode != &anode
                        && bhist.contains(&anode)
                        && (!ahist.contains(bnode) || bhist.len() > ahist.len()))
                    {
                        *bnode = anode;
                    }
                    bhist.extend(ahist.iter().copied());
                })
                .or_insert((anode, ahist));
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &HgChangesetId)> {
        self.tags
            .iter()
            .filter_map(|(tag, (node, _))| (!node.is_null()).then_some((&**tag, node)))
    }
}

impl PartialEq for TagSet {
    fn eq(&self, other: &Self) -> bool {
        self.iter().sorted().collect_vec() == other.iter().sorted().collect_vec()
    }
}

pub fn get_tags() -> TagSet {
    let mut tags = TagSet::default();
    let mut tags_files = HashSet::new();
    for head in CHANGESET_HEADS.lock().unwrap().heads() {
        (|| -> Option<()> {
            let head = head.to_git()?;
            let tags_file = get_oid_blob(format!("{}:.hgtags", head).as_bytes())?;
            if tags_files.insert(tags_file) {
                let tags_blob = RawBlob::read(tags_file).unwrap();
                tags.merge(TagSet::from_buf(tags_blob.as_bytes())?);
            }
            Some(())
        })();
    }
    tags
}

static BUNDLE_BLOBS: Mutex<Vec<object_id>> = Mutex::new(Vec::new());

fn store_changesets_metadata() -> CommitId {
    let mut tree = strbuf::new();
    for (n, blob) in BUNDLE_BLOBS
        .lock()
        .unwrap()
        .drain(..)
        .enumerate()
        .map(|(n, blob)| ((n + 1).to_string(), blob))
        .sorted_by(|(n, _), (n2, _)| Ord::cmp(n, n2))
    {
        let blob = BlobId::from_unchecked(GitObjectId::from(blob));
        tree.extend_from_slice(b"100644 bundle");
        if n != "1" {
            tree.extend_from_slice(n.as_bytes());
        }
        tree.extend_from_slice(b"\0");
        tree.extend_from_slice(blob.as_raw_bytes());
    }
    let mut tid = object_id::default();
    unsafe {
        store_git_tree(&tree, std::ptr::null(), &mut tid);
    }
    drop(tree);
    let mut commit = strbuf::new();
    writeln!(commit, "tree {}", GitObjectId::from(tid)).ok();
    let heads = CHANGESET_HEADS.lock().unwrap();
    for (head, _) in heads.branch_heads() {
        writeln!(commit, "parent {}", head.to_git().unwrap()).ok();
    }
    writeln!(commit, "author  <cinnabar@git> 0 +0000").ok();
    writeln!(commit, "committer  <cinnabar@git> 0 +0000").ok();
    for (head, branch) in heads.branch_heads() {
        write!(commit, "\n{} {}", head, branch).ok();
    }
    let mut result = object_id::default();
    unsafe {
        store_git_commit(&commit, &mut result);
    }
    CommitId::from_unchecked(result.into())
}

#[no_mangle]
pub unsafe extern "C" fn reset_changeset_heads() {
    let mut heads = CHANGESET_HEADS.lock().unwrap();
    *heads = ChangesetHeads::from_stored_metadata();
}

fn store_manifests_metadata() -> CommitId {
    let mut commit = strbuf::new();
    writeln!(commit, "tree {}", RawTree::EMPTY_OID).ok();
    let heads = MANIFEST_HEADS.lock().unwrap();
    for head in heads.heads() {
        writeln!(commit, "parent {}", head).ok();
    }
    writeln!(commit, "author  <cinnabar@git> 0 +0000").ok();
    writeln!(commit, "committer  <cinnabar@git> 0 +0000\n").ok();
    let mut result = object_id::default();
    unsafe {
        store_git_commit(&commit, &mut result);
    }
    CommitId::from_unchecked(result.into())
}

#[no_mangle]
pub unsafe extern "C" fn add_manifest_head(mn: *const object_id) {
    let mut heads = MANIFEST_HEADS.lock().unwrap();
    heads.add(GitManifestId::from_unchecked(CommitId::from_unchecked(
        mn.as_ref().unwrap().clone().into(),
    )));
}

#[no_mangle]
pub unsafe extern "C" fn reset_manifest_heads() {
    let mut heads = MANIFEST_HEADS.lock().unwrap();
    *heads = ManifestHeads::from_stored_metadata();
}

#[no_mangle]
pub unsafe extern "C" fn clear_manifest_heads() {
    let mut heads = MANIFEST_HEADS.lock().unwrap();
    *heads = ManifestHeads::new();
}

pub fn set_changeset_heads(new_heads: ChangesetHeads) {
    let mut heads = CHANGESET_HEADS.lock().unwrap();
    *heads = new_heads;
}

extern "C" {
    pub fn ensure_store_init();
    pub fn store_git_blob(blob_buf: *const strbuf, result: *mut object_id);
    fn store_git_tree(tree_buf: *const strbuf, reference: *const object_id, result: *mut object_id);
    pub fn store_git_commit(commit_buf: *const strbuf, result: *mut object_id);
    pub fn do_set_replace(replaced: *const object_id, replace_with: *const object_id);
    fn create_git_tree(
        tree_id: *const object_id,
        ref_tree: *const object_id,
        result: *mut object_id,
    );
}

pub enum SetWhat {
    Changeset,
    ChangesetMeta,
    Manifest,
    File,
    FileMeta,
}

pub fn do_set(what: SetWhat, hg_id: HgObjectId, git_id: GitObjectId) {
    fn set<T: TryFrom<GitObjectId>>(
        notes: &mut hg_notes_tree,
        hg_id: HgObjectId,
        git_id: GitObjectId,
    ) {
        if git_id.is_null() {
            notes.remove_note(hg_id);
        } else if T::try_from(git_id).is_err() {
            die!("Invalid object");
        } else {
            notes.add_note(hg_id, git_id);
        }
    }
    match what {
        SetWhat::Changeset => {
            if git_id.is_null() {
                unsafe { &mut hg2git }.remove_note(hg_id);
            } else if let Ok(ref mut commit) = CommitId::try_from(git_id) {
                handle_changeset_conflict(HgChangesetId::from_unchecked(hg_id), commit);
                unsafe { &mut hg2git }.add_note(hg_id, (*commit).into());
            } else {
                die!("Invalid object");
            }
        }
        SetWhat::ChangesetMeta => {
            let csid = HgChangesetId::from_unchecked(hg_id);
            if let Some(cid) = csid.to_git() {
                if git_id.is_null() {
                    unsafe {
                        git2hg.remove_note(cid.into());
                    }
                } else if BlobId::try_from(git_id).is_err() {
                    die!("Invalid object");
                } else {
                    unsafe {
                        git2hg.add_note(cid.into(), git_id);
                    }
                }
            } else if !git_id.is_null() {
                die!("Invalid sha1");
            }
        }
        SetWhat::Manifest => {
            if !git_id.is_null() {
                MANIFEST_HEADS
                    .lock()
                    .unwrap()
                    .add(GitManifestId::from_unchecked(CommitId::from_unchecked(
                        git_id,
                    )));
            }
            set::<CommitId>(unsafe { &mut hg2git }, hg_id, git_id);
        }
        SetWhat::File => {
            set::<BlobId>(unsafe { &mut hg2git }, hg_id, git_id);
        }
        SetWhat::FileMeta => {
            set::<BlobId>(unsafe { &mut files_meta }, hg_id, git_id);
        }
    }
}

fn store_changeset(
    changeset_id: HgChangesetId,
    parents: &[HgChangesetId],
    raw_changeset: &RawHgChangeset,
) -> Result<(CommitId, Option<CommitId>), GraftError> {
    let git_parents = parents
        .iter()
        .copied()
        .map(HgChangesetId::to_git)
        .collect::<Option<Vec<_>>>()
        .ok_or(GraftError::NoGraft)?;
    let changeset = raw_changeset.parse().unwrap();
    let manifest_tree_id = match changeset.manifest() {
        m if m.is_null() => unsafe {
            let mut tid = object_id::default();
            store_git_tree(&strbuf::new(), std::ptr::null(), &mut tid);
            TreeId::from_unchecked(GitObjectId::from(tid))
        },
        m => {
            let git_manifest_id = m.to_git().unwrap();
            let manifest_commit = RawCommit::read(git_manifest_id.into()).unwrap();
            let manifest_commit = manifest_commit.parse().unwrap();
            manifest_commit.tree()
        }
    };

    let ref_tree = git_parents.get(0).map(|&p| {
        let ref_commit = RawCommit::read(p.into()).unwrap();
        let ref_commit = ref_commit.parse().unwrap();
        object_id::from(ref_commit.tree())
    });

    let mut tree_id = object_id::default();
    unsafe {
        create_git_tree(
            &object_id::from(manifest_tree_id),
            ref_tree
                .as_ref()
                .map_or(std::ptr::null(), |t| t as *const _),
            &mut tree_id,
        );
    }
    let tree_id = TreeId::from_unchecked(GitObjectId::from(tree_id));

    let (commit_id, metadata_id, transition) =
        match graft(changeset_id, raw_changeset, tree_id, &git_parents) {
            Ok(Some(commit_id)) => {
                let metadata = GeneratedGitChangesetMetadata::generate(
                    &RawCommit::read(commit_id).unwrap().parse().unwrap(),
                    changeset_id,
                    raw_changeset,
                )
                .unwrap();
                if !grafted() && metadata.patch().is_some() {
                    (Some(commit_id), None, true)
                } else {
                    let mut buf = strbuf::new();
                    buf.extend_from_slice(&metadata.serialize());
                    let mut cs_metadata_oid = object_id::default();
                    unsafe {
                        store_git_blob(&buf, &mut cs_metadata_oid);
                    }
                    let metadata_id = GitChangesetMetadataId::from_unchecked(
                        BlobId::from_unchecked(GitObjectId::from(cs_metadata_oid)),
                    );
                    (Some(commit_id), Some(metadata_id), false)
                }
            }
            Ok(None) | Err(GraftError::NoGraft) => (None, None, false),
            Err(e) => return Err(e),
        };

    let (commit_id, metadata_id, replace) = if commit_id.is_none() || transition {
        let replace = commit_id;
        let result = raw_commit_for_changeset(&changeset, tree_id, &git_parents);
        let mut result_oid = object_id::default();
        unsafe {
            store_git_commit(&result, &mut result_oid);
        }
        let commit_id = CommitId::from_unchecked(GitObjectId::from(result_oid));

        let metadata = GeneratedGitChangesetMetadata::generate(
            &RawCommit::read(commit_id).unwrap().parse().unwrap(),
            changeset_id,
            raw_changeset,
        )
        .unwrap();
        let mut buf = strbuf::new();
        buf.extend_from_slice(&metadata.serialize());
        let mut cs_metadata_oid = object_id::default();
        unsafe {
            store_git_blob(&buf, &mut cs_metadata_oid);
        }
        let metadata_id = GitChangesetMetadataId::from_unchecked(BlobId::from_unchecked(
            GitObjectId::from(cs_metadata_oid),
        ));

        (commit_id, metadata_id, replace)
    } else {
        (
            unsafe { commit_id.unwrap_unchecked() },
            metadata_id.unwrap(),
            None,
        )
    };

    let result = (commit_id, replace);
    if let Some(replace) = result.1 {
        let replace = object_id::from(replace);
        unsafe {
            do_set_replace(&replace, &commit_id.into());
        }
    }
    do_set(SetWhat::Changeset, changeset_id.into(), commit_id.into());
    do_set(
        SetWhat::ChangesetMeta,
        changeset_id.into(),
        metadata_id.into(),
    );

    let mut heads = CHANGESET_HEADS.lock().unwrap();
    let branch = changeset
        .extra()
        .and_then(|e| e.get(b"branch"))
        .unwrap_or(b"default")
        .as_bstr();
    heads.add(changeset_id, parents, branch);
    Ok(result)
}

fn handle_changeset_conflict(hg_id: HgChangesetId, git_id: &mut CommitId) {
    // There are cases where two changesets would map to the same git
    // commit because their differences are not in information stored in
    // the git commit (different manifest node, but identical tree ;
    // different branches ; etc.)
    // In that case, add invisible characters to the commit message until
    // we find a commit that doesn't map to another changeset.

    let mut commit_data = None;
    while let Some(existing_hg_id) = GitChangesetId::from_unchecked(*git_id).to_hg() {
        // We might just already have the changeset in store.
        if existing_hg_id == hg_id {
            break;
        }

        let commit_data = commit_data.get_or_insert_with(|| {
            let mut buf = strbuf::new();
            buf.extend_from_slice(RawCommit::read(*git_id).unwrap().as_bytes());
            buf
        });
        commit_data.extend_from_slice(b"\0");
        let mut new_git_id = object_id::default();
        unsafe {
            store_git_commit(commit_data, &mut new_git_id);
        }
        *git_id = CommitId::from_unchecked(new_git_id.into());
    }
}

pub fn raw_commit_for_changeset(
    changeset: &HgChangeset,
    tree_id: TreeId,
    parents: &[GitChangesetId],
) -> strbuf {
    let mut result = strbuf::new();
    let author = HgAuthorship {
        author: changeset.author(),
        timestamp: changeset.timestamp(),
        utcoffset: changeset.utcoffset(),
    };
    let git_author = GitAuthorship::from(author.clone());
    let git_committer = changeset
        .extra()
        .and_then(|extra| extra.get(b"committer"))
        .map(|committer| {
            if committer.ends_with(b">") {
                GitAuthorship::from(HgAuthorship {
                    author: committer,
                    timestamp: author.timestamp,
                    utcoffset: author.utcoffset,
                })
            } else {
                GitAuthorship::from(HgCommitter(committer))
            }
        });
    let git_committer = git_committer.as_ref().unwrap_or(&git_author);
    result.extend_from_slice(format!("tree {}\n", tree_id).as_bytes());
    for parent in parents {
        result.extend_from_slice(format!("parent {}\n", parent).as_bytes());
    }
    result.extend_from_slice(b"author ");
    result.extend_from_slice(&git_author.0);
    result.extend_from_slice(b"\ncommitter ");
    result.extend_from_slice(&git_committer.0);
    result.extend_from_slice(b"\n\n");
    result.extend_from_slice(changeset.body());
    result
}

pub fn create_changeset(
    commit_id: CommitId,
    manifest_id: HgManifestId,
    files: Option<Box<[u8]>>,
) -> (HgChangesetId, GitChangesetMetadataId) {
    let mut metadata = GitChangesetMetadata {
        changeset_id: HgChangesetId::NULL,
        manifest_id,
        author: None,
        extra: None,
        files: files.and_then(|f| (!f.is_empty()).then_some(f)),
        patch: None,
    };
    let commit = RawCommit::read(commit_id).unwrap();
    let commit = commit.parse().unwrap();
    let branch = commit.parents().get(0).and_then(|p| {
        let metadata = RawGitChangesetMetadata::read(GitChangesetId::from_unchecked(*p)).unwrap();
        let metadata = metadata.parse().unwrap();
        metadata
            .extra()
            .and_then(|e| e.get(b"branch").map(ToBoxed::to_boxed))
    });
    if let Some(branch) = &branch {
        let mut extra = ChangesetExtra::new();
        extra.set(b"branch", branch);
        let mut buf = Vec::new();
        extra.dump_into(&mut buf);
        metadata.extra = Some(buf.into_boxed_slice());
    }
    let changeset = RawHgChangeset::from_metadata(&commit, &metadata).unwrap();
    let mut hash = HgChangesetId::create();
    let parents = commit
        .parents()
        .iter()
        .map(|p| GitChangesetId::from_unchecked(*p).to_hg())
        .collect::<Option<Vec<_>>>()
        .unwrap();
    for p in parents
        .iter()
        .copied()
        .chain(repeat(HgChangesetId::NULL))
        .take(2)
        .sorted()
        .collect_vec()
    {
        hash.update(p.as_raw_bytes());
    }
    hash.update(&changeset.0);
    metadata.changeset_id = hash.finalize();
    let mut buf = strbuf::new();
    buf.extend_from_slice(&metadata.serialize());
    let mut blob_oid = object_id::default();
    unsafe {
        store_git_blob(&buf, &mut blob_oid);
        do_set(
            SetWhat::Changeset,
            metadata.changeset_id.into(),
            commit_id.into(),
        );
        do_set(
            SetWhat::ChangesetMeta,
            metadata.changeset_id.into(),
            blob_oid.clone().into(),
        );
    }
    let mut heads = CHANGESET_HEADS.lock().unwrap();
    let branch = branch.as_deref().unwrap_or(b"default").as_bstr();
    heads.add(metadata.changeset_id, &parents, branch);
    let metadata_id =
        GitChangesetMetadataId::from_unchecked(BlobId::from_unchecked(GitObjectId::from(blob_oid)));
    (metadata.changeset_id, metadata_id)
}

// The rev_chunk has a non-FFI-safe field that is not exposed to C.
#[allow(improper_ctypes)]
extern "C" {
    pub fn store_manifest(chunk: *const rev_chunk, reference_mn: strslice, stored_mn: strslice_mut);
    fn store_file(chunk: *const rev_chunk);
}

#[no_mangle]
pub unsafe extern "C" fn check_manifest(oid: *const object_id) -> c_int {
    let git_manifest_id =
        GitManifestId::from_raw_bytes(oid.as_ref().unwrap().as_raw_bytes()).unwrap();
    let manifest_commit = RawCommit::read(git_manifest_id.into()).unwrap();
    let manifest_commit = manifest_commit.parse().unwrap();
    let manifest_id = HgManifestId::from_bytes(manifest_commit.body()).unwrap();

    let parents = manifest_commit
        .parents()
        .iter()
        .map(|p| {
            let manifest_commit = RawCommit::read(*p).unwrap();
            let manifest_commit = manifest_commit.parse().unwrap();
            HgManifestId::from_bytes(manifest_commit.body()).unwrap()
        })
        .collect_vec();
    let manifest = RawHgManifest::read(git_manifest_id).unwrap();

    let computed = hash_data(
        parents.get(0).copied().map(Into::into),
        parents.get(1).copied().map(Into::into),
        manifest.as_ref(),
    );

    if computed == manifest_id {
        1
    } else {
        0
    }
}

static STORED_FILES: Mutex<BTreeMap<HgFileId, [HgFileId; 2]>> = Mutex::new(BTreeMap::new());

pub fn check_file(node: HgFileId, p1: HgFileId, p2: HgFileId) -> bool {
    let data = RawHgFile::read_hg(node).unwrap();
    crate::hg_data::find_file_parents(node, Some(p1), Some(p2), &data).is_some()
}

pub fn do_check_files() -> bool {
    // Try to detect issue #207 as early as possible.
    let mut busted = false;
    for (&node, &[p1, p2]) in STORED_FILES
        .lock()
        .unwrap()
        .iter()
        .progress(|n| format!("Checking {n} imported file root and head revisions"))
    {
        if !check_file(node, p1, p2) {
            error!(target: "root", "Error in file {node}");
            busted = true;
        }
    }
    if busted {
        let mut transaction = RefTransaction::new().unwrap();
        transaction
            .update(
                BROKEN_REF,
                unsafe { crate::libgit::METADATA_OID },
                None,
                "post-pull check",
            )
            .unwrap();
        transaction.commit().unwrap();
        error!(
            target: "root",
            "It seems you have hit a known, rare, and difficult to \
             reproduce issue.\n\
             Your help would be appreciated.\n\
             Please try either `git cinnabar rollback` followed by \
             the same command that just\n\
             failed, or `git cinnabar reclone`.\n\
             Please open a new issue \
             (https://github.com/glandium/git-cinnabar/issues/new)\n\
             mentioning issue #207 and reporting whether the second \
             attempt succeeded.\n\n\
             Please read all the above and keep a copy of this \
             repository."
        );
    }
    !busted
}

pub fn store_changegroup<R: Read>(input: R, version: u8) {
    unsafe {
        ensure_store_init();
    }
    let mut bundle = strbuf::new();
    let mut bundle_writer = None;
    let mut input = if check_enabled(Checks::UNBUNDLER)
        && CHANGESET_HEADS.lock().unwrap().heads().next().is_some()
    {
        bundle_writer = Some(BundleWriter::new(BundleSpec::V2Zstd, &mut bundle).unwrap());
        let bundle_writer = bundle_writer.as_mut().unwrap();
        let info =
            BundlePartInfo::new(0, "changegroup").set_param("version", &format!("{:02}", version));
        let part = bundle_writer.new_part(info).unwrap();
        Box::new(TeeReader::new(input, part)) as Box<dyn Read>
    } else {
        Box::from(input)
    };
    let mut changesets = RevChunkIter::new(version, &mut input)
        .progress(|n| format!("Reading {n} changesets"))
        .collect_vec();
    for manifest in RevChunkIter::new(version, &mut input)
        .progress(|n| format!("Reading and importing {n} manifests"))
    {
        let mid = HgManifestId::from_unchecked(manifest.node());
        let delta_node = HgManifestId::from_unchecked(manifest.delta_node());
        let reference_mn = if delta_node.is_null() {
            RawHgManifest::empty()
        } else {
            RawHgManifest::read(delta_node.to_git().unwrap()).unwrap()
        };
        let mut last_end = 0;
        let mut mn_size = 0;
        for diff in manifest.iter_diff() {
            if diff.start() > reference_mn.len() || diff.start() < last_end {
                die!("Malformed changeset chunk for {mid}");
            }
            mn_size += diff.start() - last_end;
            mn_size += diff.data().len();
            last_end = diff.end();
        }
        if reference_mn.len() < last_end {
            die!("Malformed changeset chunk for {mid}");
        }
        mn_size += reference_mn.len() - last_end;

        let mut stored_manifest = Rc::builder_with_capacity(mn_size);
        unsafe {
            store_manifest(
                &manifest.into(),
                (&reference_mn).into(),
                (&mut stored_manifest.spare_capacity_mut()[..mn_size]).into(),
            );
            stored_manifest.set_len(mn_size);
        }

        let tree_id = mid.to_git().unwrap().get_tree_id();
        MANIFESTCACHE.with(|cache| {
            cache.set(Some(ManifestCache {
                tree_id,
                content: stored_manifest.into_rc(),
            }));
        });
    }
    let files = Cell::new(0);
    let mut progress = repeat(()).progress(|n| {
        format!(
            "Reading and importing {n} revisions of {} files",
            files.get()
        )
    });
    let mut stored_files = STORED_FILES.lock().unwrap();
    let null_parents = [HgFileId::NULL; 2];
    while {
        let buf = read_rev_chunk(&mut input);
        !buf.is_empty()
    } {
        files.set(files.get() + 1);
        for (file, ()) in RevChunkIter::new(version, &mut input).zip(&mut progress) {
            let node = HgFileId::from_unchecked(file.node());
            let parents = [
                HgFileId::from_unchecked(file.parent1()),
                HgFileId::from_unchecked(file.parent2()),
            ];
            // Try to detect issue #207 as early as possible.
            // Keep track of file roots of files with metadata and at least
            // one head that can be traced back to each of those roots.
            // Or, in the case of updates, all heads.
            if has_metadata()
                || stored_files.contains_key(&parents[0])
                || stored_files.contains_key(&parents[1])
            {
                stored_files.insert(node, parents);
                for p in parents.into_iter() {
                    if p.is_null() {
                        continue;
                    }
                    if stored_files.get(&p) != Some(&null_parents) {
                        stored_files.remove(&p);
                    }
                }
            } else if parents == null_parents {
                if let Some(diff) = file.iter_diff().next() {
                    if diff.start() == 0 && diff.data().get(..2) == Some(b"\x01\n") {
                        stored_files.insert(node, parents);
                    }
                }
            }
            unsafe {
                store_file(&file.into());
            }
        }
    }
    drop(progress);

    let mut previous = (HgChangesetId::NULL, RawHgChangeset(Box::new([])));
    for changeset in changesets
        .drain(..)
        .progress(|n| format!("Importing {n} changesets"))
    {
        let delta_node = HgChangesetId::from_unchecked(changeset.delta_node());
        let changeset_id = HgChangesetId::from_unchecked(changeset.node());
        let parents = [changeset.parent1(), changeset.parent2()]
            .into_iter()
            .filter_map(|p| {
                let p = HgChangesetId::from_unchecked(p);
                (!p.is_null()).then_some(p)
            })
            .collect::<Vec<_>>();

        let reference_cs = if delta_node == previous.0 {
            previous.1
        } else if delta_node.is_null() {
            RawHgChangeset(Box::new([]))
        } else {
            RawHgChangeset::read(delta_node.to_git().unwrap()).unwrap()
        };

        let mut last_end = 0;
        let mut raw_changeset = Vec::new();
        for diff in changeset.iter_diff() {
            if diff.start() > reference_cs.len() || diff.start() < last_end {
                die!("Malformed changeset chunk for {changeset_id}");
            }
            raw_changeset.extend_from_slice(&reference_cs[last_end..diff.start()]);
            raw_changeset.extend_from_slice(diff.data());
            last_end = diff.end();
        }
        if reference_cs.len() < last_end {
            die!("Malformed changeset chunk for {changeset_id}");
        }
        raw_changeset.extend_from_slice(&reference_cs[last_end..]);
        let raw_changeset = RawHgChangeset(raw_changeset.into());
        match store_changeset(changeset_id, &parents, &raw_changeset) {
            Ok(_) => {}
            Err(GraftError::NoGraft) => {
                // TODO: ideally this should instead hard-error when not grafting,
                // but NoGraft can theoretically still be emitted in that case.
                debug!("Cannot graft changeset {changeset_id}, not importing");
            }
            Err(GraftError::Ambiguous(candidates)) => die!(
                "Cannot graft {changeset_id}. Candidates: {}",
                itertools::join(candidates.iter(), ", ")
            ),
        }
        previous = (changeset_id, raw_changeset);
    }
    drop(input);
    drop(bundle_writer);
    if !bundle.as_bytes().is_empty() {
        let mut bundle_blob = object_id::default();
        unsafe {
            store_git_blob(&bundle, &mut bundle_blob);
        }
        BUNDLE_BLOBS.lock().unwrap().push(bundle_blob);
    }
}

fn branches_for_url(url: Url) -> Vec<Box<BStr>> {
    let mut parts = url.path_segments().unwrap().rev().collect_vec();
    if let Some(Host::Domain(host)) = url.host() {
        parts.push(host);
    }
    let mut branches = parts.into_iter().fold(Vec::<Box<BStr>>::new(), |mut v, p| {
        if !p.is_empty() {
            v.push(
                bstr::join(
                    b"/",
                    Some(p.as_bytes().as_bstr())
                        .into_iter()
                        .chain(v.last().map(|s| &**s)),
                )
                .as_bstr()
                .to_boxed(),
            );
        }
        v
    });
    branches.push(b"metadata".as_bstr().to_boxed());
    branches
}

#[test]
fn test_branches_for_url() {
    assert_eq!(
        branches_for_url(Url::parse("https://server/").unwrap()),
        vec![
            b"server".as_bstr().to_boxed(),
            b"metadata".as_bstr().to_boxed()
        ]
    );
    assert_eq!(
        branches_for_url(Url::parse("https://server:443/").unwrap()),
        vec![
            b"server".as_bstr().to_boxed(),
            b"metadata".as_bstr().to_boxed()
        ]
    );
    assert_eq!(
        branches_for_url(Url::parse("https://server:443/repo").unwrap()),
        vec![
            b"repo".as_bstr().to_boxed(),
            b"server/repo".as_bstr().to_boxed(),
            b"metadata".as_bstr().to_boxed()
        ]
    );
    assert_eq!(
        branches_for_url(Url::parse("https://server:443/dir_a/repo").unwrap()),
        vec![
            b"repo".as_bstr().to_boxed(),
            b"dir_a/repo".as_bstr().to_boxed(),
            b"server/dir_a/repo".as_bstr().to_boxed(),
            b"metadata".as_bstr().to_boxed()
        ]
    );
    assert_eq!(
        branches_for_url(Url::parse("https://server:443/dir_a/dir_b/repo").unwrap()),
        vec![
            b"repo".as_bstr().to_boxed(),
            b"dir_b/repo".as_bstr().to_boxed(),
            b"dir_a/dir_b/repo".as_bstr().to_boxed(),
            b"server/dir_a/dir_b/repo".as_bstr().to_boxed(),
            b"metadata".as_bstr().to_boxed()
        ]
    );
}

pub fn merge_metadata(git_url: Url, hg_url: Option<Url>, branch: Option<&[u8]>) -> bool {
    // Eventually we'll want to handle a full merge, but for now, we only
    // handle the case where we don't have metadata to begin with.
    // The caller should avoid calling this function otherwise.
    assert!(!has_metadata());
    let mut remote_refs = Command::new("git")
        .arg("ls-remote")
        .arg(OsStr::new(git_url.as_ref()))
        .stderr(Stdio::null())
        .output()
        .unwrap()
        .stdout
        .split(|&b| b == b'\n')
        .filter_map(|l| {
            let [sha1, refname] = l.splitn_exact(|&b: &u8| b == b'\t')?;
            Some((
                refname.as_bstr().to_boxed(),
                CommitId::from_bytes(sha1).unwrap(),
            ))
        })
        .collect::<HashMap<_, _>>();
    let mut bundle = if remote_refs.is_empty() && ["http", "https"].contains(&git_url.scheme()) {
        let mut req = HttpRequest::new(git_url.clone());
        req.follow_redirects(true);
        // We let curl handle Content-Encoding: gzip via Accept-Encoding.
        let mut bundle = match req.execute() {
            Ok(bundle) => bundle,
            Err(e) => {
                error!(target: "root", "{}", e);
                return false;
            }
        };
        const BUNDLE_SIGNATURE: &str = "# v2 git bundle\n";
        let signature = (&mut bundle)
            .take(BUNDLE_SIGNATURE.len() as u64)
            .read_all()
            .unwrap();
        if &*signature != BUNDLE_SIGNATURE.as_bytes() {
            error!(target: "root", "Could not find cinnabar metadata");
            return false;
        }
        let mut bundle = BufReader::new(bundle);
        let mut line = Vec::new();
        loop {
            line.truncate(0);
            bundle.read_until(b'\n', &mut line).unwrap();
            if line.ends_with(b"\n") {
                line.pop();
            }
            if line.is_empty() {
                break;
            }
            let [sha1, refname] = line.splitn_exact(b' ').unwrap();
            remote_refs.insert(
                refname.as_bstr().to_boxed(),
                CommitId::from_bytes(sha1).unwrap(),
            );
        }
        Some(bundle)
    } else {
        None
    };

    let branches = branch.map_or_else(
        || hg_url.map(branches_for_url).unwrap_or_default(),
        |b| vec![b.as_bstr().to_boxed()],
    );

    let (refname, metadata_cid) = if let Some((refname, metadata_cid)) =
        branches.into_iter().find_map(|branch| {
            if let Some(cid) = remote_refs.get(&*branch) {
                return Some((branch, cid));
            }
            let cinnabar_refname = bstr::join(b"", [b"refs/cinnabar/".as_bstr(), &branch])
                .as_bstr()
                .to_boxed();
            if let Some(cid) = remote_refs.get(&cinnabar_refname) {
                return Some((cinnabar_refname, cid));
            }
            let head_refname = bstr::join(b"", [b"refs/heads/".as_bstr(), &branch])
                .as_bstr()
                .to_boxed();
            if let Some(cid) = remote_refs.get(&head_refname) {
                return Some((head_refname, cid));
            }
            None
        }) {
        (refname, *metadata_cid)
    } else {
        error!(target: "root", "Could not find cinnabar metadata");
        return false;
    };

    let commit = if let Some(commit) = RawCommit::read(metadata_cid) {
        commit
    } else {
        let mut proc = if let Some(mut bundle) = bundle.as_mut() {
            let mut command = Command::new("git");
            command
                .arg("index-pack")
                .arg("--stdin")
                .arg("--fix-thin")
                .stdout(Stdio::null())
                .stdin(Stdio::piped());
            if progress_enabled() {
                command.arg("-v");
            }
            let mut proc = command.spawn().unwrap();
            let stdin = proc.stdin.as_mut().unwrap();
            copy(&mut bundle, stdin).unwrap();
            proc
        } else {
            let mut command = Command::new("git");
            command
                .arg("fetch")
                .arg("--no-tags")
                .arg("--no-recurse-submodules")
                .arg("-q");
            if progress_enabled() {
                command.arg("--progress");
            } else {
                command.arg("--no-progress");
            }
            command.arg(OsStr::new(git_url.as_ref()));
            command.arg(OsStr::from_bytes(&bstr::join(
                b":",
                [&**refname, b"refs/cinnabar/fetch"],
            )));
            command.spawn().unwrap()
        };
        if !proc.wait().unwrap().success() {
            error!(target: "root", "Failed to fetch cinnabar metadata.");
            return false;
        }
        RawCommit::read(metadata_cid).unwrap()
    };

    // Do some basic validation on the metadata we just got.
    let commit = commit.parse().unwrap();
    if !commit.author().contains_str("cinnabar@git")
        || !String::from_utf8_lossy(commit.body())
            .split_ascii_whitespace()
            .sorted()
            .eq(["files-meta", "unified-manifests-v2"].into_iter())
    {
        error!(target: "root", "Invalid cinnabar metadata.");
        return false;
    }

    // At this point, we'll just assume this is good enough.

    // Get replace refs.
    if commit.tree() != RawTree::EMPTY_OID {
        let mut errors = false;
        let by_sha1 = remote_refs
            .into_iter()
            .map(|(a, b)| (b, a))
            .collect::<BTreeMap<_, _>>();
        let mut needed = Vec::new();
        for item in RawTree::read(commit.tree()).unwrap().into_iter().recurse() {
            let cid = item.inner().oid.try_into().unwrap();
            if RawCommit::read(cid).is_none() {
                if let Some(refname) = by_sha1.get(&cid) {
                    let replace_ref = bstr::join(b"/", [b"refs/cinnabar/replace", &**item.path()]);
                    needed.push(
                        bstr::join(b":", [&**refname, replace_ref.as_bstr()])
                            .as_bstr()
                            .to_boxed(),
                    );
                } else {
                    error!(target: "root", "Missing commit: {}", cid);
                    errors = true;
                }
            }
        }
        if errors {
            return false;
        }

        if !needed.is_empty() && bundle.is_none() {
            let mut command = Command::new("git");
            command
                .arg("fetch")
                .arg("--no-tags")
                .arg("--no-recurse-submodules")
                .arg("-q");
            if progress_enabled() {
                command.arg("--progress");
            } else {
                command.arg("--no-progress");
            }
            command.arg(OsStr::new(git_url.as_ref()));
            command.args(needed.iter().map(|n| OsStr::from_bytes(n)));
            if !command.status().unwrap().success() {
                error!(target: "root", "Failed to fetch cinnabar metadata.");
                return false;
            }
        }
    }

    unsafe {
        do_reload(&object_id::from(metadata_cid));
    }
    true
}

extern "C" {
    fn init_replace_map();
    fn reset_replace_map();
    fn store_replace_map(result: *mut object_id);
}

fn old_metadata() {
    die!(
        "Metadata from git-cinnabar versions older than 0.5.0 is not supported.\n\
          Please run `git cinnabar upgrade` with version 0.5.x first."
    );
}

fn new_metadata() {
    die!(
        "It looks like this repository was used with a newer version of git-cinnabar. \
          Cannot use this version."
    );
}

#[allow(dead_code)]
fn need_upgrade() {
    die!("Git-cinnabar metadata needs upgrade. Please run `git cinnabar upgrade` first.");
}

#[no_mangle]
pub unsafe extern "C" fn init_metadata(c: *const commit) {
    let cid = if let Some(c) = c.as_ref() {
        CommitId::from_unchecked(GitObjectId::from(commit_oid(c).as_ref().unwrap().clone()))
    } else {
        METADATA_OID = CommitId::NULL;
        CHANGESETS_OID = CommitId::NULL;
        MANIFESTS_OID = CommitId::NULL;
        HG2GIT_OID = CommitId::NULL;
        GIT2HG_OID = CommitId::NULL;
        FILES_META_OID = CommitId::NULL;
        return;
    };
    let c = RawCommit::read(cid).unwrap();
    let c = c.parse().unwrap();
    if !(5..=6).contains(&c.parents().len()) {
        die!("Invalid metadata?");
    }
    for (cid, field) in Some(cid).iter().chain(c.parents()[..5].iter()).zip([
        &mut METADATA_OID,
        &mut CHANGESETS_OID,
        &mut MANIFESTS_OID,
        &mut HG2GIT_OID,
        &mut GIT2HG_OID,
        &mut FILES_META_OID,
    ]) {
        *field = *cid;
    }
    for flag in c.body().split(|&b| b == b' ') {
        match flag {
            b"files-meta" => {
                METADATA_FLAGS |= FILES_META;
            }
            b"unified-manifests" => old_metadata(),
            b"unified-manifests-v2" => {
                METADATA_FLAGS |= UNIFIED_MANIFESTS_V2;
            }
            _ => new_metadata(),
        }
    }
    if METADATA_FLAGS != FILES_META | UNIFIED_MANIFESTS_V2 {
        old_metadata();
    }
    let mut count = 0;
    for_each_ref_in("refs/cinnabar/branches/", |_, _| -> Result<(), ()> {
        count += 1;
        Ok(())
    })
    .ok();
    if count > 0 {
        old_metadata();
    }

    reset_replace_map();

    let tree = RawTree::read(c.tree()).unwrap();
    let mut replaces = BTreeMap::new();
    for (path, oid) in tree.into_iter().map(WithPath::unzip) {
        match oid {
            Either::Right(RecursedTreeEntry {
                oid: GitOid::Commit(replace_with),
                ..
            }) => {
                if let Ok(original) = CommitId::from_bytes(&path) {
                    if original == replace_with {
                        warn!("self-referencing graft: {}", original);
                    } else {
                        replaces
                            .entry(original)
                            .and_modify(|_| die!("duplicate replace: {}", original))
                            .or_insert_with(|| replace_with);
                    }
                } else {
                    warn!("bad replace name: {}", path.as_bstr());
                }
            }
            _ => die!("Invalid metadata"),
        }
    }
    init_replace_map();
    for (original, replace_with) in replaces.into_iter() {
        do_set_replace(&original.into(), &replace_with.into());
    }
    if replace_map_tablesize() == 0 {
        let mut count = 0;
        for_each_ref_in("refs/cinnabar/replace/", |_, _| -> Result<(), ()> {
            count += 1;
            Ok(())
        })
        .ok();
        if count > 0 {
            old_metadata();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn done_metadata() {
    git2hg.done();
    hg2git.done();
    files_meta.done();
}

pub fn do_store_metadata() -> CommitId {
    let hg2git_;
    let git2hg_;
    let files_meta_;
    let manifests;
    let changesets;
    let mut tree = object_id::default();
    let mut previous = None;
    unsafe {
        hg2git_ = store_metadata_notes(&mut *hg2git, HG2GIT_OID);
        git2hg_ = store_metadata_notes(&mut *git2hg, GIT2HG_OID);
        files_meta_ = store_metadata_notes(&mut *files_meta, FILES_META_OID);
        manifests = store_manifests_metadata();
        changesets = store_changesets_metadata();
        if !METADATA_OID.is_null() {
            previous = Some(METADATA_OID);
        }
        store_replace_map(&mut tree);
    }
    let new_metadata = [changesets, manifests, hg2git_, git2hg_, files_meta_]
        .into_iter()
        .map(|o| CommitId::from_unchecked(GitObjectId::from(o)))
        .collect_vec();
    if let Some(previous) = previous {
        let c = RawCommit::read(previous).unwrap();
        let c = c.parse().unwrap();
        if !(5..=6).contains(&c.parents().len()) {
            die!("Invalid metadata?");
        }
        if c.parents()[..5] == new_metadata {
            return previous;
        }
    }
    let mut buf = strbuf::new();
    writeln!(buf, "tree {}", GitObjectId::from(tree)).ok();
    for p in new_metadata.into_iter().chain(previous) {
        writeln!(buf, "parent {}", p).ok();
    }
    buf.extend_from_slice(
        b"author  <cinnabar@git> 0 +0000\n\
          committer  <cinnabar@git> 0 +0000\n\
          \n\
          files-meta unified-manifests-v2",
    );
    unsafe {
        let mut result = object_id::default();
        store_git_commit(&buf, &mut result);
        CommitId::from_unchecked(result.into())
    }
}
