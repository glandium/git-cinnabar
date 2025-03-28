/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::cell::{Cell, OnceCell, Ref, RefCell, RefMut};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::hash::Hash;
use std::io::{copy, BufRead, BufReader, Read, Write};
use std::iter::{repeat, IntoIterator};
use std::mem;
use std::num::NonZeroU32;
use std::os::raw::{c_char, c_int, c_ulong};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::Mutex;

use bit_vec::BitVec;
use bitflags::bitflags;
use bstr::{BStr, BString, ByteSlice};
use derive_more::Deref;
use either::Either;
use getset::{CopyGetters, Getters};
use hex_literal::hex;
use indexmap::IndexMap;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use percent_encoding::{percent_decode, percent_encode, NON_ALPHANUMERIC};
use tee::TeeReader;
use url::{Host, Url};

use crate::cinnabar::{
    GitChangesetId, GitChangesetMetadataId, GitFileId, GitFileMetadataId, GitManifestId,
    GitManifestTree, GitManifestTreeId,
};
use crate::git::{
    BlobId, Commit, CommitId, GitObjectId, GitOid, RawBlob, RawCommit, RawTree, RecursedTreeEntry,
    TreeId, TreeIsh,
};
use crate::graft::{graft, grafted, replace_map_tablesize, GraftError};
use crate::hg::{HgChangesetId, HgFileAttr, HgFileId, HgManifestId, HgObjectId};
use crate::hg_bundle::{
    read_rev_chunk, rev_chunk, BundlePartInfo, BundleSpec, BundleWriter, RevChunkIter,
};
use crate::hg_connect::get_reader;
use crate::hg_data::{hash_data, GitAuthorship, HgAuthorship, HgCommitter};
use crate::libcinnabar::{git_notes_tree, hg_notes_tree, strslice, strslice_mut, AsStrSlice};
use crate::libgit::{
    config_get_value, die, for_each_ref_in, get_oid_blob, object_entry, object_id, object_type,
    resolve_ref, FfiBox, FileMode, RefTransaction,
};
use crate::oid::ObjectId;
use crate::progress::{progress_enabled, Progress};
use crate::tree_util::{diff_by_path, merge_join_by_path, Empty, ParseTree, RecurseTree, WithPath};
use crate::util::{
    FromBytes, ImmutBString, IteratorExt, OsStrExt, RcExt, RcSlice, RcSliceBuilder, ReadExt,
    SliceExt, ToBoxed, Transpose,
};
use crate::xdiff::{apply, bytediff, PatchInfo};
use crate::{check_enabled, experiment, has_compat, Checks, Compat, Experiments};

pub const REFS_PREFIX: &str = "refs/cinnabar/";
pub const REPLACE_REFS_PREFIX: &str = "refs/cinnabar/replace/";
pub const METADATA_REF: &str = "refs/cinnabar/metadata";
pub const CHECKED_REF: &str = "refs/cinnabar/checked";
pub const BROKEN_REF: &str = "refs/cinnabar/broken";
pub const NOTES_REF: &str = "refs/notes/cinnabar";

bitflags! {
    #[derive(Debug, Copy, Clone)]
    pub struct MetadataFlags: i32 {
        const FILES_META = 0x1;
        const UNIFIED_MANIFESTS_V2 = 0x2;

    }
}

pub struct Store {
    pub metadata_cid: CommitId,
    pub changesets_cid: CommitId,
    pub manifests_cid: CommitId,
    pub hg2git_cid: CommitId,
    pub git2hg_cid: CommitId,
    pub files_meta_cid: CommitId,
    hg2git_: OnceCell<RefCell<hg_notes_tree>>,
    git2hg_: OnceCell<RefCell<git_notes_tree>>,
    files_meta_: OnceCell<RefCell<hg_notes_tree>>,
    pub flags: MetadataFlags,
    changeset_heads_: OnceCell<RefCell<ChangesetHeads>>,
    manifest_heads_: OnceCell<RefCell<ManifestHeads>>,
    tree_cache_: RefCell<BTreeMap<GitManifestTreeId, TreeId>>,
    reverse_replace: RefCell<BTreeMap<GitChangesetId, GitChangesetId>>,
}

impl Store {
    const fn default() -> Store {
        Store {
            metadata_cid: CommitId::NULL,
            changesets_cid: CommitId::NULL,
            manifests_cid: CommitId::NULL,
            git2hg_cid: CommitId::NULL,
            hg2git_cid: CommitId::NULL,
            files_meta_cid: CommitId::NULL,
            git2hg_: OnceCell::new(),
            hg2git_: OnceCell::new(),
            files_meta_: OnceCell::new(),
            flags: MetadataFlags::empty(),
            changeset_heads_: OnceCell::new(),
            manifest_heads_: OnceCell::new(),
            tree_cache_: RefCell::new(BTreeMap::new()),
            reverse_replace: RefCell::new(BTreeMap::new()),
        }
    }
}

impl Store {
    pub fn changeset_heads(&self) -> Ref<ChangesetHeads> {
        self.changeset_heads_
            .get_or_init(|| {
                RefCell::new(if self.changesets_cid.is_null() {
                    ChangesetHeads::new()
                } else {
                    ChangesetHeads::from_metadata(self.changesets_cid)
                })
            })
            .borrow()
    }

    pub fn changeset_heads_mut(&self) -> RefMut<ChangesetHeads> {
        self.changeset_heads();
        self.changeset_heads_.get().unwrap().borrow_mut()
    }

    pub fn manifest_heads(&self) -> Ref<ManifestHeads> {
        self.manifest_heads_
            .get_or_init(|| {
                RefCell::new(if self.manifests_cid.is_null() {
                    ManifestHeads::new()
                } else {
                    ManifestHeads::from_metadata(self.manifests_cid)
                })
            })
            .borrow()
    }

    pub fn manifest_heads_mut(&self) -> RefMut<ManifestHeads> {
        self.manifest_heads();
        self.manifest_heads_.get().unwrap().borrow_mut()
    }

    pub fn hg2git(&self) -> Ref<hg_notes_tree> {
        self.hg2git_
            .get_or_init(|| RefCell::new(hg_notes_tree::new_with(self.hg2git_cid)))
            .borrow()
    }

    pub fn hg2git_mut(&self) -> RefMut<hg_notes_tree> {
        self.hg2git();
        self.hg2git_.get().unwrap().borrow_mut()
    }

    pub fn git2hg(&self) -> Ref<git_notes_tree> {
        self.git2hg_
            .get_or_init(|| RefCell::new(git_notes_tree::new_with(self.git2hg_cid)))
            .borrow()
    }

    pub fn git2hg_mut(&self) -> RefMut<git_notes_tree> {
        self.git2hg();
        self.git2hg_.get().unwrap().borrow_mut()
    }

    pub fn files_meta(&self) -> Ref<hg_notes_tree> {
        self.files_meta_
            .get_or_init(|| RefCell::new(hg_notes_tree::new_with(self.files_meta_cid)))
            .borrow()
    }

    pub fn files_meta_mut(&self) -> RefMut<hg_notes_tree> {
        self.files_meta();
        self.files_meta_.get().unwrap().borrow_mut()
    }
}

pub fn has_metadata(store: &Store) -> bool {
    !store.flags.is_empty()
}

macro_rules! hg2git {
    ($h:ident => $g:ident) => {
        impl $h {
            pub fn to_git(self, store: &Store) -> Option<$g> {
                store
                    .hg2git_mut()
                    .get_note(self.into())
                    .map(|o| $g::from_raw_bytes(o.as_raw_bytes()).unwrap())
            }
        }

        impl crate::oid::Abbrev<$h> {
            pub fn to_git(self, store: &Store) -> Option<$g> {
                store
                    .hg2git_mut()
                    .get_note_abbrev(self.into())
                    .map(|o| $g::from_raw_bytes(o.as_raw_bytes()).unwrap())
            }
        }
    };
}

hg2git!(HgChangesetId => GitChangesetId);
hg2git!(HgManifestId => GitManifestId);
hg2git!(HgFileId => GitFileId);

impl GitChangesetId {
    pub fn to_hg(self, store: &Store) -> Option<HgChangesetId> {
        //TODO: avoid repeatedly reading metadata for a given changeset.
        //The equivalent python code was keeping a LRU cache.
        let metadata = RawGitChangesetMetadata::read(store, self);
        metadata
            .as_ref()
            .and_then(RawGitChangesetMetadata::parse)
            .map(|m| m.changeset_id())
    }
}

pub struct RawGitChangesetMetadata(RawBlob);

impl RawGitChangesetMetadata {
    pub fn read(store: &Store, changeset_id: GitChangesetId) -> Option<Self> {
        let note = store
            .git2hg_mut()
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
        store: &Store,
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
        let new = RawHgChangeset::from_metadata_(store, commit, &temp, false)?;
        if **raw_changeset != *new {
            temp.patch = Some(GitChangesetPatch::from_patch_info(bytediff(
                &new,
                raw_changeset,
            )));
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
pub struct RawHgChangeset(ImmutBString);

impl Empty for RawHgChangeset {
    fn empty() -> RawHgChangeset {
        RawHgChangeset(Box::new([]))
    }
}

impl From<Vec<u8>> for RawHgChangeset {
    fn from(v: Vec<u8>) -> RawHgChangeset {
        RawHgChangeset(v.into_boxed_slice())
    }
}

impl RawHgChangeset {
    pub fn from_metadata<B: AsRef<[u8]>>(
        store: &Store,
        commit: &Commit,
        metadata: &GitChangesetMetadata<B>,
    ) -> Option<Self> {
        Self::from_metadata_(store, commit, metadata, true)
    }

    fn from_metadata_<B: AsRef<[u8]>>(
        store: &Store,
        commit: &Commit,
        metadata: &GitChangesetMetadata<B>,
        handle_changeset_conflict: bool,
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

        // Adjust for old commits created by now removed
        // `handle_changeset_conflict`.
        if handle_changeset_conflict {
            let node = metadata.changeset_id();
            if !node.is_null() {
                while changeset[changeset.len() - 1] == b'\0' {
                    let mut hash = HgChangesetId::create();
                    let mut parents = commit
                        .parents()
                        .iter()
                        .map(|p| GitChangesetId::from_unchecked(*p).to_hg(store))
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
        }
        Some(RawHgChangeset(changeset.into()))
    }

    pub fn read(store: &Store, oid: GitChangesetId) -> Option<Self> {
        let commit = RawCommit::read(oid.into())?;
        let commit = commit.parse()?;
        let metadata = RawGitChangesetMetadata::read(store, oid)?;
        let metadata = metadata.parse()?;
        Self::from_metadata(store, &commit, &metadata)
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

impl HgChangeset<'_> {
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
    content: RcSlice<u8>,
}

thread_local! {
    static MANIFESTCACHE: Cell<Option<ManifestCache>> = const { Cell::new(None) };
}

#[derive(Deref)]
#[deref(forward)]
pub struct RawHgManifest(RcSlice<u8>);

impl Empty for RawHgManifest {
    fn empty() -> RawHgManifest {
        RawHgManifest(RcSlice::new())
    }
}

impl RawHgManifest {
    pub fn read(oid: GitManifestId) -> Option<Self> {
        Some(MANIFESTCACHE.with(|cache| {
            let last_manifest = cache.take();
            let tree_id = oid.get_tree_id();

            let mut manifest = RcSlice::<u8>::builder();
            if let Some(last_manifest) = last_manifest {
                let reference_manifest = last_manifest.content.clone();
                if last_manifest.tree_id == tree_id {
                    cache.set(Some(last_manifest));
                    return RawHgManifest(reference_manifest);
                }
                manifest.reserve(reference_manifest.len());
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
pub struct RawHgFile(RcSlice<u8>);

impl RawHgFile {
    pub const EMPTY_OID: HgFileId =
        HgFileId::from_raw_bytes_array(hex!("b80de5d138758541c5f05265ad144ab9fa86d1db"));

    pub fn read(oid: GitFileId, metadata: Option<GitFileMetadataId>) -> Option<Self> {
        let mut result = RcSliceBuilder::new();
        if let Some(metadata) = metadata {
            result.extend_from_slice(b"\x01\n");
            result.extend_from_slice(RawBlob::read(metadata.into())?.as_bytes());
            result.extend_from_slice(b"\x01\n");
        }
        result.extend_from_slice(RawBlob::read(oid.into())?.as_bytes());
        Some(Self(result.into_rc()))
    }

    pub fn read_hg(store: &Store, oid: HgFileId) -> Option<Self> {
        if oid == Self::EMPTY_OID {
            Some(Self(RcSlice::new()))
        } else {
            let metadata = store
                .files_meta_mut()
                .get_note(oid.into())
                .map(BlobId::from_unchecked)
                .map(GitFileMetadataId::from_unchecked);
            Self::read(oid.to_git(store).unwrap(), metadata)
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
    ids: HashMap<N, DagNodeId>,
    dag: Vec<DagNode<N, T>>,
}

impl<N: Hash + Eq + Copy, T> Dag<N, T> {
    pub fn new() -> Self {
        Dag {
            ids: HashMap::new(),
            dag: Vec::new(),
        }
    }

    pub fn add(&mut self, node: N, parents: &[N], data: T) -> DagNodeId {
        assert!(parents.len() <= 2);
        let parents = parents
            .iter()
            .filter_map(|&p| self.get_mut(p).map(|(id, _)| id))
            .collect_vec();
        let id = DagNodeId::try_from_offset(self.dag.len()).unwrap();
        assert!(self.ids.insert(node, id).is_none());
        self.dag.push(DagNode {
            node,
            parent1: parents.first().copied(),
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

    pub fn traverse_parents(
        &self,
        starts: &[N],
        mut follow_parents: impl FnMut(N, &T) -> bool,
    ) -> impl Iterator<Item = (&N, &T)> {
        let starts = starts
            .iter()
            .filter_map(|n| self.ids.get(n).map(|x| x.to_offset()))
            .sorted()
            .collect_vec();
        let limit = starts.last().map_or(0, |x| x + 1);
        let mut smallest = starts.first().copied().unwrap_or(0);
        let mut parents = BitVec::from_elem(limit, false);
        for start in starts {
            parents.set(start, true);
        }
        self.dag[..limit]
            .iter()
            .enumerate()
            .rev()
            .filter_map_while(move |(idx, node)| {
                if parents[idx] {
                    if follow_parents(node.node, &node.data) {
                        for id in [node.parent1, node.parent2].into_iter().flatten() {
                            let idx = id.to_offset();
                            parents.set(idx, true);
                            if idx < smallest {
                                smallest = idx;
                            }
                        }
                    }
                    Ok((&node.node, &node.data))
                } else if idx < smallest {
                    // Short-circuit when there aren't any new parents to find.
                    Err(true)
                } else {
                    Err(false)
                }
            })
    }

    pub fn traverse_children(
        &self,
        starts: &[N],
        mut follow_children: impl FnMut(N, &T) -> bool,
    ) -> impl Iterator<Item = (&N, &T)> {
        let mut starts = starts
            .iter()
            .map(|n| self.ids.get(n).copied())
            .sorted_by(|x, y| y.cmp(x))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        let first = starts
            .last()
            .map_or_else(|| self.ids.len(), |start| start.to_offset());
        let mut seen = BitVec::from_elem(self.ids.len() - first, false);
        self.dag
            .iter()
            .enumerate()
            .skip(first)
            .filter_map(move |(idx, node)| {
                let is_start = starts
                    .last()
                    .filter(|next_start| idx == next_start.to_offset())
                    .is_some();
                if is_start {
                    starts.pop();
                }
                if is_start
                    || [node.parent1, node.parent2]
                        .into_iter()
                        .flatten()
                        .any(|id| id.to_offset() >= first && seen[id.to_offset() - first])
                {
                    if follow_children(node.node, &node.data) {
                        seen.set(idx - first, true);
                    }
                    Some((&node.node, &node.data))
                } else {
                    None
                }
            })
    }

    pub fn heads(
        &self,
        mut interesting: impl FnMut(N, &T) -> bool,
    ) -> impl Iterator<Item = (&N, &T)> {
        let mut parents = BitVec::from_elem(self.ids.len(), false);
        self.dag
            .iter()
            .enumerate()
            .rev()
            .filter_map(move |(idx, node)| {
                if interesting(node.node, &node.data) {
                    for id in [node.parent1, node.parent2].into_iter().flatten() {
                        parents.set(id.to_offset(), true);
                    }
                    (!parents[idx]).then_some((&node.node, &node.data))
                } else {
                    None
                }
            })
    }

    pub fn roots(
        &self,
        mut interesting: impl FnMut(N, &T) -> bool,
    ) -> impl Iterator<Item = (&N, &T)> {
        let mut seen = BitVec::from_elem(self.ids.len(), false);
        self.dag.iter().enumerate().filter_map(move |(idx, node)| {
            if interesting(node.node, &node.data) {
                seen.set(idx, true);
                if [node.parent1, node.parent2]
                    .into_iter()
                    .flatten()
                    .filter(|id| seen[id.to_offset()])
                    .count()
                    == 0
                {
                    return Some((&node.node, &node.data));
                }
            }
            None
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = (&N, &T)> {
        self.dag.iter().map(|node| (&node.node, &node.data))
    }
}

#[test]
fn test_dag() {
    let mut dag = Dag::new();
    dag.add("a", &[], ());
    dag.add("b", &["a"], ());
    dag.add("c", &["b"], ());
    dag.add("d", &["c"], ());
    dag.add("e", &[], ());
    dag.add("f", &["e"], ());
    dag.add("g", &["f"], ());
    dag.add("h", &["d", "g"], ());
    dag.add("i", &["c", "g"], ());
    dag.add("j", &["c", "g"], ());

    let result = dag
        .traverse_children(&["a"], |_, ()| false)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "a");

    let result = dag
        .traverse_children(&["a"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "abcdhij");

    let result = dag
        .traverse_children(&["c"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "cdhij");

    let result = dag
        .traverse_children(&["d"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "dh");

    let result = dag
        .traverse_children(&["e"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "efghij");

    let result = dag
        .traverse_children(&["f"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "fghij");

    let result = dag
        .traverse_children(&["a"], |node, ()| node <= "g")
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "abcdhij");

    let result = dag
        .traverse_children(&["a", "e"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "abcdefghij");

    let result = dag
        .traverse_children(&["a", "e"], |node, ()| node <= "g")
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "abcdefghij");

    let result = dag
        .traverse_children(&["a", "f"], |node, ()| "abcf".contains(node))
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "abcdfgij");

    let result = dag
        .traverse_parents(&["j"], |_, ()| false)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "j");

    let result = dag
        .traverse_parents(&["j"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "jgfecba");

    let result = dag
        .traverse_parents(&["a"], |_, ()| true)
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "a");

    let result = dag
        .traverse_parents(&["j"], |node, ()| node >= "d")
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "jgfec");

    let result = dag
        .traverse_parents(&["j"], |node, ()| node >= "c")
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "jgfecb");

    let result = dag
        .traverse_parents(&["j", "h"], |node, ()| node >= "c")
        .map(|(n, _)| n)
        .join("");
    assert_eq!(result, "jhgfedcb");

    let result = dag.heads(|_, _| true).map(|(n, _)| n).join("");
    assert_eq!(result, "jih");

    let result = dag.heads(|node, _| node <= "i").map(|(n, _)| n).join("");
    assert_eq!(result, "ih");

    let result = dag.heads(|node, _| node <= "h").map(|(n, _)| n).join("");
    assert_eq!(result, "h");

    let result = dag.heads(|node, _| node <= "g").map(|(n, _)| n).join("");
    assert_eq!(result, "gd");

    let result = dag.roots(|_, _| true).map(|(n, _)| n).join("");
    assert_eq!(result, "ae");

    let result = dag.roots(|node, _| node >= "b").map(|(n, _)| n).join("");
    assert_eq!(result, "be");

    let result = dag.roots(|node, _| node >= "e").map(|(n, _)| n).join("");
    assert_eq!(result, "e");

    let result = dag.roots(|node, _| node >= "h").map(|(n, _)| n).join("");
    assert_eq!(result, "hij");
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
        let id = self.dag.add(cs, parents, data);
        self.heads.insert(id);
        for parent in parents {
            if let Some((parent_id, parent_data)) = self.dag.get_mut(*parent) {
                parent_data.has_children = true;
                if parent_data.branch == branch {
                    self.heads.remove(&parent_id);
                }
            }
        }
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

    pub fn ever_contained(&self, tag: &[u8]) -> bool {
        self.tags.contains_key(tag)
    }

    pub fn get(&self, tag: &[u8]) -> Option<HgChangesetId> {
        self.tags
            .get(tag)
            .filter(|(node, _)| !node.is_null())
            .map(|(node, _)| *node)
    }
}

impl PartialEq for TagSet {
    fn eq(&self, other: &Self) -> bool {
        self.iter().sorted().collect_vec() == other.iter().sorted().collect_vec()
    }
}

impl Store {
    pub fn get_tags(&self) -> TagSet {
        let mut tags = TagSet::default();
        let mut tags_files = HashSet::new();
        for head in self.changeset_heads().heads() {
            (|| -> Option<()> {
                let head = head.to_git(self)?;
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
}

static BUNDLE_BLOBS: Mutex<Vec<BlobId>> = Mutex::new(Vec::new());

fn store_changesets_metadata(store: &Store) -> CommitId {
    let mut tree = Vec::new();
    for (n, blob) in BUNDLE_BLOBS
        .lock()
        .unwrap()
        .drain(..)
        .enumerate()
        .map(|(n, blob)| ((n + 1).to_string(), blob))
        .sorted_by(|(n, _), (n2, _)| Ord::cmp(n, n2))
    {
        tree.extend_from_slice(b"100644 bundle");
        if n != "1" {
            tree.extend_from_slice(n.as_bytes());
        }
        tree.extend_from_slice(b"\0");
        tree.extend_from_slice(blob.as_raw_bytes());
    }
    let tid = store_git_tree(&tree, None);
    let mut commit = Vec::new();
    writeln!(commit, "tree {}", tid).ok();
    let heads = store.changeset_heads();
    for (head, _) in heads.branch_heads() {
        writeln!(commit, "parent {}", head.to_git(store).unwrap()).ok();
    }
    writeln!(commit, "author  <cinnabar@git> 0 +0000").ok();
    writeln!(commit, "committer  <cinnabar@git> 0 +0000").ok();
    for (head, branch) in heads.branch_heads() {
        write!(commit, "\n{} {}", head, branch).ok();
    }
    store_git_commit(&commit)
}

fn store_manifests_metadata(store: &Store) -> CommitId {
    let mut commit = Vec::new();
    writeln!(commit, "tree {}", RawTree::EMPTY_OID).ok();
    let heads = store.manifest_heads();
    for head in heads.heads() {
        writeln!(commit, "parent {}", head).ok();
    }
    writeln!(commit, "author  <cinnabar@git> 0 +0000").ok();
    writeln!(commit, "committer  <cinnabar@git> 0 +0000\n").ok();
    store_git_commit(&commit)
}

#[no_mangle]
pub unsafe extern "C" fn add_manifest_head(store: &Store, mn: *const object_id) {
    let mut heads = store.manifest_heads_mut();
    heads.add(GitManifestId::from_unchecked(CommitId::from_unchecked(
        mn.as_ref().unwrap().clone().into(),
    )));
}

pub fn clear_manifest_heads(store: &Store) {
    let mut heads = store.manifest_heads_mut();
    *heads = ManifestHeads::new();
}

pub fn set_changeset_heads(store: &Store, new_heads: ChangesetHeads) {
    let mut heads = store.changeset_heads_mut();
    *heads = new_heads;
}

extern "C" {
    pub fn ensure_store_init();
    fn store_git_object(
        typ: object_type,
        buf: strslice,
        result: *mut object_id,
        reference: *const strslice,
        reference_entry: *const object_entry,
    );
    pub fn do_set_replace(replaced: *const object_id, replace_with: *const object_id);
    fn get_object_entry(oid: *const object_id) -> *const object_entry;
    fn unpack_object_entry(oe: *const object_entry, buf: *mut *mut c_char, len: *mut c_ulong);
}

pub fn store_git_blob(blob_buf: &[u8]) -> BlobId {
    unsafe {
        let mut result = object_id::default();
        store_git_object(
            object_type::OBJ_BLOB,
            blob_buf.as_str_slice(),
            &mut result,
            ptr::null(),
            ptr::null(),
        );
        BlobId::from_unchecked(result.into())
    }
}

pub fn store_git_tree(tree_buf: &[u8], reference: Option<TreeId>) -> TreeId {
    unsafe {
        let mut oe = ptr::null();
        let mut ref_tree = None;
        if let Some(reference) = reference {
            oe = get_object_entry(&reference.into());
            if !oe.is_null() {
                let mut reftree_buf = ptr::null_mut();
                let mut len = 0;
                unpack_object_entry(oe, &mut reftree_buf, &mut len);
                ref_tree = Some(FfiBox::from_raw_parts(reftree_buf as *mut _, len as usize));
            }
        }
        let mut result = object_id::default();
        let ref_tree = ref_tree.as_ref().map(|x| x.as_str_slice());
        store_git_object(
            object_type::OBJ_TREE,
            tree_buf.as_str_slice(),
            &mut result,
            ref_tree.as_ref().map_or(ptr::null(), |x| x as *const _),
            oe,
        );
        TreeId::from_unchecked(result.into())
    }
}

pub fn store_git_commit(commit_buf: &[u8]) -> CommitId {
    unsafe {
        let mut result = object_id::default();
        store_git_object(
            object_type::OBJ_COMMIT,
            commit_buf.as_str_slice(),
            &mut result,
            ptr::null(),
            ptr::null(),
        );
        CommitId::from_unchecked(result.into())
    }
}

pub enum SetWhat {
    Changeset,
    ChangesetMeta,
    Manifest,
    File,
    FileMeta,
}

impl Store {
    pub fn set(&self, what: SetWhat, hg_id: HgObjectId, git_id: GitObjectId) {
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
                    self.hg2git_mut().remove_note(hg_id);
                } else if let Ok(ref mut commit) = CommitId::try_from(git_id) {
                    self.hg2git_mut().add_note(hg_id, (*commit).into());
                } else {
                    die!("Invalid object");
                }
            }
            SetWhat::ChangesetMeta => {
                let csid = HgChangesetId::from_unchecked(hg_id);
                if let Some(cid) = csid.to_git(self) {
                    if git_id.is_null() {
                        self.git2hg_mut().remove_note(cid.into());
                    } else if BlobId::try_from(git_id).is_err() {
                        die!("Invalid object");
                    } else {
                        self.git2hg_mut().add_note(cid.into(), git_id);
                    }
                } else if !git_id.is_null() {
                    die!("Invalid sha1");
                }
            }
            SetWhat::Manifest => {
                if !git_id.is_null() {
                    self.manifest_heads_mut().add(GitManifestId::from_unchecked(
                        CommitId::from_unchecked(git_id),
                    ));
                }
                set::<CommitId>(&mut self.hg2git_mut(), hg_id, git_id);
            }
            SetWhat::File => {
                set::<BlobId>(&mut self.hg2git_mut(), hg_id, git_id);
            }
            SetWhat::FileMeta => {
                set::<BlobId>(&mut self.files_meta_mut(), hg_id, git_id);
            }
        }
    }
}

fn corrupted_metata() -> ! {
    die!("Corrupt mercurial metadata");
}

// The git storage for a mercurial manifest used to be a commit with two
// directories at its root:
// - a git directory, matching the git tree in the git commit corresponding to
//   the mercurial changeset using the manifest.
// - a hg directory, containing the same file paths, but where all pointed
//   objects are commits (mode 160000 in the git tree) whose sha1 is actually
//   the mercurial sha1 for the corresponding mercurial file.
// Reconstructing the mercurial manifest required file paths, mercurial sha1
// for each file, and the corresponding attribute ("l" for symlinks, "x" for
// executables"). The hg directory alone was not enough for that, because it
// lacked the attribute information.
fn create_git_tree(
    store: &Store,
    manifest_tree_id: GitManifestTreeId,
    ref_tree_id: Option<TreeId>,
    merge_tree_id: Option<GitManifestTreeId>,
) -> TreeId {
    let cached = merge_tree_id
        .is_none()
        .then(|| store.tree_cache_.borrow().get(&manifest_tree_id).copied())
        .flatten();
    if let Some(cached) = cached {
        return cached;
    }
    let manifest_tree = GitManifestTree::read(manifest_tree_id).unwrap();
    let merge_tree = merge_tree_id.map_or(GitManifestTree::EMPTY, |tid| {
        GitManifestTree::read(tid).unwrap()
    });
    let mut tree_buf = Vec::with_capacity(manifest_tree.as_ref().len());
    let mut ref_tree = None;
    for (path, entries) in
        merge_join_by_path(manifest_tree.iter(), merge_tree.iter()).map(WithPath::unzip)
    {
        let entry = entries
            .as_ref()
            .left()
            .or_else(|| entries.as_ref().right())
            .unwrap();
        // In some edge cases, presumably all related to the use of
        // `hg convert` before Mercurial 2.0.1, manifest trees have
        // double slashes, which end up as "_" directories in the
        // corresponding git cinnabar metadata.
        // With further changes in the subsequent Mercurial manifests,
        // those entries with double slashes are superseded with entries
        // with single slash, while still being there. So to create
        // the corresponding git commit, we need to merge both in some
        // manner.
        // Mercurial doesn't actually guarantee which of the paths would
        // actually be checked out when checking out such manifests,
        // but we always choose the single slash path. Most of the time,
        // though, both will have the same contents. At least for files.
        // Sub-directories may differ in what paths they contain, but
        // again, the files they contain are usually identical.
        if path.len() == 0 {
            if entry.is_right() {
                corrupted_metata();
            }
            if merge_tree_id.is_some() {
                continue;
            }
            let result =
                create_git_tree(store, manifest_tree_id, ref_tree_id, entry.clone().left());
            store
                .tree_cache_
                .borrow_mut()
                .insert(manifest_tree_id, result);
            return result;
        }
        let (oid, mode): (GitObjectId, _) = match entry {
            Either::Left(subtree_id) => {
                let ref_entry_oid = ref_tree_id
                    .and_then(|tid| {
                        ref_tree
                            .get_or_insert_with(|| RawTree::read(tid).unwrap().into_iter())
                            .find(|e| e.path() == path.as_bstr())
                    })
                    .and_then(|e| e.into_inner().left());
                (
                    create_git_tree(
                        store,
                        *subtree_id,
                        ref_entry_oid,
                        entries.right().and_then(Either::left),
                    )
                    .into(),
                    FileMode::DIRECTORY,
                )
            }
            Either::Right(entry) => {
                let oid = if entry.fid == RawHgFile::EMPTY_OID {
                    let empty_blob_id = store_git_blob(&[]);
                    assert_eq!(empty_blob_id, RawBlob::EMPTY_OID);
                    RawBlob::EMPTY_OID
                } else if let Some(bid) = entry.fid.to_git(store) {
                    BlobId::from(bid)
                } else {
                    corrupted_metata();
                };
                (
                    oid.into(),
                    match entry.attr {
                        HgFileAttr::Regular => FileMode::REGULAR | FileMode::RW,
                        HgFileAttr::Executable => FileMode::REGULAR | FileMode::RWX,
                        HgFileAttr::Symlink => FileMode::SYMLINK,
                    },
                )
            }
        };
        write!(tree_buf, "{:o} ", u16::from(mode)).ok();
        tree_buf.extend_from_slice(&path);
        tree_buf.extend_from_slice(b"\0");
        tree_buf.extend_from_slice(oid.as_raw_bytes());
    }
    let result = store_git_tree(&tree_buf, ref_tree_id);
    if merge_tree_id.is_none() {
        store
            .tree_cache_
            .borrow_mut()
            .insert(manifest_tree_id, result);
    }
    result
}

fn store_changeset(
    store: &Store,
    changeset_id: HgChangesetId,
    parents: &[HgChangesetId],
    raw_changeset: &RawHgChangeset,
) -> Result<(CommitId, Option<CommitId>), GraftError> {
    let git_parents = parents
        .iter()
        .copied()
        .map(|p| {
            p.to_git(store)
                .map(|p| store.reverse_replace.borrow().get(&p).copied().unwrap_or(p))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(GraftError::NoGraft)?;
    let changeset = raw_changeset.parse().unwrap();
    let manifest_tree_id = GitManifestTreeId::from_unchecked(match changeset.manifest() {
        m if m.is_null() => store_git_tree(&[], None),
        m => {
            let git_manifest_id = m.to_git(store).unwrap();
            let manifest_commit = RawCommit::read(git_manifest_id.into()).unwrap();
            let manifest_commit = manifest_commit.parse().unwrap();
            manifest_commit.tree()
        }
    });

    let ref_tree = git_parents.first().map(|&p| {
        let ref_commit = RawCommit::read(p.into()).unwrap();
        let ref_commit = ref_commit.parse().unwrap();
        ref_commit.tree()
    });

    let tree_id = create_git_tree(store, manifest_tree_id, ref_tree, None);

    let (commit_id, metadata_id, transition) =
        match graft(store, changeset_id, raw_changeset, tree_id, &git_parents) {
            Ok(Some(commit_id)) => {
                let metadata = GeneratedGitChangesetMetadata::generate(
                    store,
                    &RawCommit::read(commit_id).unwrap().parse().unwrap(),
                    changeset_id,
                    raw_changeset,
                )
                .unwrap();
                if !grafted() && metadata.patch().is_some() {
                    (Some(commit_id), None, true)
                } else {
                    let buf = metadata.serialize();
                    let cs_metadata_oid = store_git_blob(&buf);
                    let metadata_id = GitChangesetMetadataId::from_unchecked(cs_metadata_oid);
                    (Some(commit_id), Some(metadata_id), false)
                }
            }
            Ok(None) | Err(GraftError::NoGraft) => (None, None, false),
            Err(e) => return Err(e),
        };

    let (commit_id, metadata_id, replace) = if commit_id.is_none() || transition {
        let replace = commit_id;
        let mut raw_commit = Vec::from(raw_commit_for_changeset(&changeset, tree_id, &git_parents));
        let commit_id = loop {
            let commit_id = store_git_commit(&raw_commit);
            // There are cases where two changesets would map to the same git
            // commit because their differences are not in information stored in
            // the git commit (different manifest node, but identical tree ;
            // different branches ; etc.)
            // In that case, add invisible characters to the commit message until
            // we find a commit that doesn't map to another changeset.
            match GitChangesetId::from_unchecked(commit_id).to_hg(store) {
                Some(existing_hg_id) if existing_hg_id != changeset_id => {
                    if has_compat(Compat::CHANGESET_CONFLICT_NUL) {
                        raw_commit.push(b'\0');
                    } else {
                        raw_commit.push(b'\n');
                    }
                }
                _ => {
                    break commit_id;
                }
            }
        };

        let metadata = GeneratedGitChangesetMetadata::generate(
            store,
            &RawCommit::read(commit_id).unwrap().parse().unwrap(),
            changeset_id,
            raw_changeset,
        )
        .unwrap();
        let buf = metadata.serialize();
        let cs_metadata_oid = store_git_blob(&buf);
        let metadata_id = GitChangesetMetadataId::from_unchecked(cs_metadata_oid);

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
        unsafe {
            do_set_replace(&object_id::from(replace), &commit_id.into());
        }
        store.reverse_replace.borrow_mut().insert(
            GitChangesetId::from_unchecked(commit_id),
            GitChangesetId::from_unchecked(replace),
        );
    }
    store.set(SetWhat::Changeset, changeset_id.into(), commit_id.into());
    store.set(
        SetWhat::ChangesetMeta,
        changeset_id.into(),
        metadata_id.into(),
    );

    let mut heads = store.changeset_heads_mut();
    let branch = changeset
        .extra()
        .and_then(|e| e.get(b"branch"))
        .unwrap_or(b"default")
        .as_bstr();
    heads.add(changeset_id, parents, branch);
    Ok(result)
}

pub fn raw_commit_for_changeset(
    changeset: &HgChangeset,
    tree_id: TreeId,
    parents: &[GitChangesetId],
) -> Box<[u8]> {
    let mut result = Vec::new();
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
    result.into_boxed_slice()
}

pub fn create_changeset(
    store: &Store,
    commit_id: CommitId,
    manifest_id: HgManifestId,
    files: Option<Box<[u8]>>,
    branch: Option<&BStr>,
) -> (HgChangesetId, GitChangesetMetadataId) {
    let mut cs_metadata = GitChangesetMetadata {
        changeset_id: HgChangesetId::NULL,
        manifest_id,
        author: None,
        extra: None,
        files: files.and_then(|f| (!f.is_empty()).then_some(f)),
        patch: None,
    };
    let commit = RawCommit::read(commit_id).unwrap();
    let commit = commit.parse().unwrap();
    let branch = branch.map(ToBoxed::to_boxed).or_else(|| {
        commit.parents().first().and_then(|p| {
            let cs_metadata =
                RawGitChangesetMetadata::read(store, GitChangesetId::from_unchecked(*p)).unwrap();
            let cs_metadata = cs_metadata.parse().unwrap();
            cs_metadata
                .extra()
                .and_then(|e| e.get(b"branch").map(|b| b.as_bstr().to_boxed()))
        })
    });
    let mut extra = None;
    if let Some(branch) = &branch {
        let extra = extra.get_or_insert_with(ChangesetExtra::new);
        extra.set(b"branch", branch);
    }
    let git_commit_extra = experiment(Experiments::GIT_COMMIT).then(|| commit_id.to_string());
    if let Some(git_commit_extra) = &git_commit_extra {
        let extra = extra.get_or_insert_with(ChangesetExtra::new);
        extra.set(b"git_commit", git_commit_extra.as_bytes());
    }
    if let Some(extra) = extra {
        let mut buf = Vec::new();
        extra.dump_into(&mut buf);
        cs_metadata.extra = Some(buf.into_boxed_slice());
    }
    let changeset = RawHgChangeset::from_metadata(store, &commit, &cs_metadata).unwrap();
    let mut hash = HgChangesetId::create();
    let parents = commit
        .parents()
        .iter()
        .map(|p| GitChangesetId::from_unchecked(*p).to_hg(store))
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
    cs_metadata.changeset_id = hash.finalize();
    let buf = cs_metadata.serialize();
    let blob_oid = store_git_blob(&buf);
    store.set(
        SetWhat::Changeset,
        cs_metadata.changeset_id.into(),
        commit_id.into(),
    );
    store.set(
        SetWhat::ChangesetMeta,
        cs_metadata.changeset_id.into(),
        blob_oid.into(),
    );
    let mut heads = store.changeset_heads_mut();
    let branch = branch.as_deref().unwrap_or(b"default".as_bstr());
    heads.add(cs_metadata.changeset_id, &parents, branch);
    let cs_metadata_id =
        GitChangesetMetadataId::from_unchecked(BlobId::from_unchecked(GitObjectId::from(blob_oid)));
    (cs_metadata.changeset_id, cs_metadata_id)
}

// The rev_chunk has a non-FFI-safe field that is not exposed to C.
#[allow(improper_ctypes)]
extern "C" {
    pub fn store_manifest(
        store: &Store,
        chunk: *const rev_chunk,
        reference_mn: strslice,
        stored_mn: strslice_mut,
    );
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
        parents.first().copied().map(Into::into),
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

pub fn check_file(store: &Store, node: HgFileId, p1: HgFileId, p2: HgFileId) -> bool {
    let data = RawHgFile::read_hg(store, node).unwrap();
    crate::hg_data::find_file_parents(node, Some(p1), Some(p2), &data).is_some()
}

pub fn do_check_files(store: &Store) -> bool {
    // Try to detect issue #207 as early as possible.
    let mut busted = false;
    for (&node, &[p1, p2]) in STORED_FILES
        .lock()
        .unwrap()
        .iter()
        .progress(|n| format!("Checking {n} imported file root and head revisions"))
    {
        if !check_file(store, node, p1, p2) {
            error!(target: "root", "Error in file {node}");
            busted = true;
        }
    }
    if busted {
        let mut transaction = RefTransaction::new().unwrap();
        transaction
            .update(BROKEN_REF, store.metadata_cid, None, "post-pull check")
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

pub fn store_changegroup<R: Read>(store: &Store, input: R, version: u8) {
    unsafe {
        ensure_store_init();
    }
    let mut bundle = Vec::new();
    let mut bundle_writer = None;
    let mut input =
        if check_enabled(Checks::UNBUNDLER) && store.changeset_heads().heads().next().is_some() {
            bundle_writer = Some(BundleWriter::new(BundleSpec::V2Zstd, &mut bundle).unwrap());
            let bundle_writer = bundle_writer.as_mut().unwrap();
            let info = BundlePartInfo::new(0, "changegroup")
                .set_param("version", &format!("{:02}", version));
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
        .filter(|m| store.hg2git_mut().get_note(m.node()).is_none())
    {
        let mid = HgManifestId::from_unchecked(manifest.node());
        let delta_node = HgManifestId::from_unchecked(manifest.delta_node());
        let reference_mn = if delta_node.is_null() {
            RawHgManifest::empty()
        } else {
            RawHgManifest::read(delta_node.to_git(store).unwrap()).unwrap()
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

        let mut stored_manifest = RcSlice::builder_with_capacity(mn_size);
        unsafe {
            store_manifest(
                store,
                &manifest.into(),
                reference_mn.as_str_slice(),
                (&mut stored_manifest.spare_capacity_mut()[..mn_size]).into(),
            );
            stored_manifest.set_len(mn_size);
        }

        let tree_id = mid.to_git(store).unwrap().get_tree_id();
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
        let mut previous_file = None;
        for (file, ()) in RevChunkIter::new(version, &mut input)
            .zip(&mut progress)
            .filter(|(f, ())| store.hg2git_mut().get_note(f.node()).is_none())
        {
            let node = HgFileId::from_unchecked(file.node());
            let delta_node = HgFileId::from_unchecked(file.delta_node());
            let parents = [
                HgFileId::from_unchecked(file.parent1()),
                HgFileId::from_unchecked(file.parent2()),
            ];
            // Try to detect issue #207 as early as possible.
            // Keep track of file roots of files with metadata and at least
            // one head that can be traced back to each of those roots.
            // Or, in the case of updates, all heads.
            if has_metadata(store)
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
            if node == RawHgFile::EMPTY_OID {
                // Creating the empty blob is handled when creating the git tree for
                // the corresponding changeset. We have nothing to associate the blob
                // with here.
                continue;
            }
            let reference_file = previous_file
                .take()
                .and_then(|(fid, file)| (fid == delta_node).then_some(file))
                .unwrap_or_else(|| {
                    RawHgFile::read_hg(
                        store,
                        if delta_node.is_null() {
                            RawHgFile::EMPTY_OID
                        } else {
                            delta_node
                        },
                    )
                    .unwrap()
                });

            let mut raw_file = RcSliceBuilder::new();
            let mut last_end = 0;
            for diff in file.iter_diff() {
                if diff.start() > reference_file.len() || diff.start() < last_end {
                    die!("Malformed file chunk for {node}");
                }
                raw_file.extend_from_slice(&reference_file[last_end..diff.start()]);
                raw_file.extend_from_slice(diff.data());
                last_end = diff.end();
            }
            if reference_file.len() < last_end {
                die!("Malformed file chunk for {node}");
            }
            raw_file.extend_from_slice(&reference_file[last_end..]);
            let mut content = &raw_file[..];
            if content.starts_with(b"\x01\n") {
                let [file_metadata, file_content] =
                    content[2..].splitn_exact(&b"\x01\n"[..]).unwrap();
                let metadata_oid = store_git_blob(file_metadata);
                store
                    .files_meta_mut()
                    .add_note(node.into(), metadata_oid.into());
                content = file_content;
            }
            unsafe {
                let file_oid = if let Some(reference_entry) = (!delta_node.is_null())
                    .then(|| {
                        delta_node.to_git(store).and_then(|delta_node| {
                            get_object_entry(&GitObjectId::from(delta_node).into()).as_ref()
                        })
                    })
                    .flatten()
                {
                    let reference_offset = store
                        .files_meta_mut()
                        .get_note(delta_node.into())
                        .map(BlobId::from_unchecked)
                        .map_or(0, |b| RawBlob::read(b).unwrap().as_bytes().len() + 4);

                    let mut file_oid = object_id::default();
                    store_git_object(
                        object_type::OBJ_BLOB,
                        content.as_str_slice(),
                        &mut file_oid,
                        &reference_file[reference_offset..].as_str_slice(),
                        reference_entry,
                    );
                    BlobId::from_unchecked(file_oid.into())
                } else {
                    store_git_blob(content)
                };
                store.hg2git_mut().add_note(node.into(), file_oid.into());
            }
            previous_file = Some((node, RawHgFile(raw_file.into_rc())));
        }
    }
    drop(progress);

    let mut previous = (HgChangesetId::NULL, RawHgChangeset(Box::new([])));
    for changeset in changesets
        .drain(..)
        .progress(|n| format!("Importing {n} changesets"))
        .filter(|cs| store.hg2git_mut().get_note(cs.node()).is_none())
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
            RawHgChangeset::read(store, delta_node.to_git(store).unwrap()).unwrap()
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
        match store_changeset(store, changeset_id, &parents, &raw_changeset) {
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
    if !bundle.is_empty() {
        let bundle_blob = store_git_blob(&bundle);
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

pub fn merge_metadata(
    store: &mut Store,
    git_url: Url,
    hg_url: Option<Url>,
    branch: Option<&[u8]>,
) -> bool {
    // Eventually we'll want to handle a full merge, but for now, we only
    // handle the case where we don't have metadata to begin with.
    // The caller should avoid calling this function otherwise.
    assert!(!has_metadata(store));
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
    let mut bundle =
        if remote_refs.is_empty() && ["http", "https", "file"].contains(&git_url.scheme()) {
            let mut bundle = match get_reader(&git_url, "cinnabarclone") {
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
                    let replace_ref = bstr::join(
                        b"/",
                        [
                            REPLACE_REFS_PREFIX.strip_suffix('/').unwrap().as_bytes(),
                            &**item.path(),
                        ],
                    );
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

    *store = Store::new(Some(metadata_cid));
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

impl Store {
    pub fn new(c: Option<CommitId>) -> Self {
        if let Some(objectformat) = config_get_value("extensions.objectformat") {
            if objectformat != OsStr::new("sha1") {
                // Ideally, we'd return error code 65 (Data format error).
                die!(
                    "Git repository uses unsupported {} object format",
                    objectformat.to_string_lossy()
                );
            }
        }
        let mut result = Store::default();
        let cid = if let Some(c) = c {
            c
        } else {
            unsafe {
                reset_replace_map();
                init_replace_map();
            }
            return result;
        };
        let c = RawCommit::read(cid).unwrap();
        let c = c.parse().unwrap();
        if !(5..=6).contains(&c.parents().len()) {
            die!("Invalid metadata?");
        }
        for (cid, field) in Some(cid).iter().chain(c.parents()[..5].iter()).zip([
            &mut result.metadata_cid,
            &mut result.changesets_cid,
            &mut result.manifests_cid,
            &mut result.hg2git_cid,
            &mut result.git2hg_cid,
            &mut result.files_meta_cid,
        ]) {
            *field = *cid;
        }
        for flag in c.body().split(|&b| b == b' ') {
            match flag {
                b"files-meta" => {
                    result.flags.insert(MetadataFlags::FILES_META);
                }
                b"unified-manifests" => old_metadata(),
                b"unified-manifests-v2" => {
                    result.flags.insert(MetadataFlags::UNIFIED_MANIFESTS_V2);
                }
                _ => new_metadata(),
            }
        }
        if !result
            .flags
            .difference(MetadataFlags::FILES_META | MetadataFlags::UNIFIED_MANIFESTS_V2)
            .is_empty()
        {
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

        unsafe {
            reset_replace_map();
        }

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
        unsafe {
            init_replace_map();
            for (original, replace_with) in replaces.into_iter() {
                do_set_replace(&original.into(), &replace_with.into());
                result.reverse_replace.borrow_mut().insert(
                    GitChangesetId::from_unchecked(replace_with),
                    GitChangesetId::from_unchecked(original),
                );
            }
        }
        if unsafe { replace_map_tablesize() } == 0 {
            let mut count = 0;
            for_each_ref_in(REPLACE_REFS_PREFIX, |_, _| -> Result<(), ()> {
                count += 1;
                Ok(())
            })
            .ok();
            if count > 0 {
                old_metadata();
            }
        }
        // Delete new-type tag_cache, we don't use it anymore. Old-type
        // tag-cache is expected to have been removed by versions >= 0.5.x,
        // which is a required first step if upgrading from < 0.5.0.
        let tag_cache = "refs/cinnabar/tag_cache";
        if let Some(cid) = resolve_ref(tag_cache) {
            let mut transaction = RefTransaction::new().unwrap();
            transaction.delete(tag_cache, Some(cid), "cleanup").unwrap();
            transaction.commit().unwrap();
        }
        result
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if has_metadata(self) {
            unsafe {
                reset_replace_map();
            }
        }
    }
}

pub fn do_store_metadata(store: &Store) -> CommitId {
    if progress_enabled() {
        eprint!("Updating metadata...");
    }
    let result = (|| {
        let mut tree = object_id::default();
        let mut previous = None;
        let hg2git_cid = store.hg2git_cid;
        let hg2git_ = store.hg2git_mut().store(hg2git_cid, FileMode::GITLINK);
        let git2hg_cid = store.git2hg_cid;
        let git2hg_ = store
            .git2hg_mut()
            .store(git2hg_cid, FileMode::REGULAR | FileMode::RW);
        let files_meta_cid = store.files_meta_cid;
        let files_meta_ = store
            .files_meta_mut()
            .store(files_meta_cid, FileMode::REGULAR | FileMode::RW);
        let manifests = store_manifests_metadata(store);
        let changesets = store_changesets_metadata(store);
        if !store.metadata_cid.is_null() {
            previous = Some(store.metadata_cid);
        }
        unsafe {
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
        let mut buf = Vec::new();
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
        store_git_commit(&buf)
    })();
    if progress_enabled() {
        eprintln!();
    }
    result
}
