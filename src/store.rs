/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::iter::{repeat, IntoIterator};
use std::mem;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::sync::Mutex;

use bstr::{BStr, BString, ByteSlice};
use cstr::cstr;
use derive_more::{Deref, Display};
use getset::{CopyGetters, Getters};
use itertools::Itertools;
use once_cell::sync::Lazy;
use percent_encoding::{percent_decode, percent_encode, NON_ALPHANUMERIC};

use crate::graft::{graft, grafted, GraftError};
use crate::hg_bundle::{read_rev_chunk, rev_chunk, RevChunkIter};
use crate::hg_data::{GitAuthorship, HgAuthorship, HgCommitter};
use crate::libc::FdFile;
use crate::libcinnabar::{generate_manifest, git2hg, hg2git, hg_object_id, send_buffer_to};
use crate::libgit::{
    get_oid_committish, lookup_replace_commit, object_id, object_type, strbuf, BlobId, Commit,
    CommitId, RawBlob, RawCommit, TreeId,
};
use crate::oid::{GitObjectId, HgObjectId, ObjectId};
use crate::oid_type;
use crate::util::{FromBytes, ImmutBString, ReadExt, SliceExt, ToBoxed};
use crate::xdiff::{apply, textdiff, PatchInfo};

pub const REFS_PREFIX: &str = "refs/cinnabar/";
pub const REPLACE_REFS_PREFIX: &str = "refs/cinnabar/replace/";
pub const METADATA_REF: &str = "refs/cinnabar/metadata";
pub const CHECKED_REF: &str = "refs/cinnabar/checked";
pub const BROKEN_REF: &str = "refs/cinnabar/broken";
pub const NOTES_REF: &str = "refs/notes/cinnabar";

macro_rules! hg2git {
    ($h:ident => $g:ident($i:ident)) => {
        oid_type!($g($i));
        oid_type!($h(HgObjectId));

        impl $h {
            pub fn to_git(&self) -> Option<$g> {
                unsafe {
                    hg2git
                        .get_note(&self)
                        .map(|o| $g::from_unchecked($i::from_unchecked(o)))
                }
            }
        }
    };
}

hg2git!(HgChangesetId => GitChangesetId(CommitId));
hg2git!(HgManifestId => GitManifestId(CommitId));
hg2git!(HgFileId => GitFileId(BlobId));

oid_type!(GitChangesetMetadataId(BlobId));
oid_type!(GitFileMetadataId(BlobId));

impl GitChangesetId {
    pub fn to_hg(&self) -> Option<HgChangesetId> {
        //TODO: avoid repeatedly reading metadata for a given changeset.
        //The equivalent python code was keeping a LRU cache.
        let metadata = RawGitChangesetMetadata::read(self);
        metadata
            .as_ref()
            .and_then(RawGitChangesetMetadata::parse)
            .map(|m| m.changeset_id().clone())
    }
}

pub struct RawGitChangesetMetadata(RawBlob);

impl RawGitChangesetMetadata {
    pub fn read(changeset_id: &GitChangesetId) -> Option<Self> {
        let note = unsafe {
            git2hg
                .get_note(changeset_id)
                .map(|o| BlobId::from_unchecked(o))?
        };
        RawBlob::read(&note).map(Self)
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
            manifest_id: manifest.unwrap_or_else(HgManifestId::null),
            author,
            extra,
            files,
            patch,
        })
    }
}

#[derive(CopyGetters, Getters)]
pub struct GitChangesetMetadata<B: AsRef<[u8]>> {
    #[getset(get = "pub")]
    changeset_id: HgChangesetId,
    #[getset(get = "pub")]
    manifest_id: HgManifestId,
    author: Option<B>,
    extra: Option<B>,
    files: Option<B>,
    patch: Option<B>,
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
        if self.manifest_id() != &HgManifestId::null() {
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
        changeset_id: &HgChangesetId,
        raw_changeset: &RawHgChangeset,
    ) -> Option<Self> {
        let changeset = raw_changeset.parse()?;
        let changeset_id = changeset_id.clone();
        let manifest_id = changeset.manifest().clone();
        let author = HgAuthorship::from(GitAuthorship(commit.author())).author;
        let author = if &*author != changeset.author() {
            Some(changeset.author().to_vec().into_boxed_slice())
        } else {
            None
        };
        let extra = changeset.extra.map(|b| b.to_vec().into_boxed_slice());
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
                        data: &p.data[common_prefix..][..common_suffix],
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

    pub fn get(&self, name: &'a [u8]) -> Option<&'a [u8]> {
        self.data.get(name.as_bstr()).map(|b| &***b)
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
        let hg_committer = if commit.author() != commit.committer() {
            Some(HgCommitter::from(GitAuthorship(commit.committer())).0)
        } else {
            None
        };
        let hg_committer = hg_committer.as_ref();

        if let Some(author) = metadata.author() {
            hg_author = author.to_boxed();
        }
        let mut extra = metadata.extra();
        if let Some(hg_committer) = hg_committer {
            extra
                .get_or_insert_with(ChangesetExtra::new)
                .set(b"committer", hg_committer);
        };
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
        while changeset[changeset.len() - 1] == b'\0' {
            let mut hash = HgChangesetId::create();
            let mut parents = commit
                .parents()
                .iter()
                .map(|p| unsafe { GitChangesetId::from_unchecked(p.clone()) }.to_hg())
                .chain(repeat(Some(HgChangesetId::null())))
                .take(2)
                .collect::<Option<Vec<_>>>()?;
            parents.sort();
            for p in parents {
                hash.update(p.as_raw_bytes());
            }
            hash.update(&changeset);
            if hash.finalize() == *node {
                break;
            }
            changeset.pop();
        }
        Some(RawHgChangeset(changeset.into()))
    }

    pub fn read(oid: &GitChangesetId) -> Option<Self> {
        let commit = RawCommit::read(oid)?;
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
    #[getset(get = "pub")]
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

#[derive(Deref)]
#[deref(forward)]
pub struct RawHgManifest(ImmutBString);

impl RawHgManifest {
    pub fn read(oid: &GitManifestId) -> Option<Self> {
        unsafe {
            generate_manifest(&(&***oid).clone().into())
                .as_ref()
                .map(|b| Self(b.as_bytes().to_owned().into()))
        }
    }
}

#[derive(Deref)]
#[deref(forward)]
pub struct RawHgFile(ImmutBString);

impl RawHgFile {
    pub fn read(oid: &GitFileId, metadata: Option<&GitFileMetadataId>) -> Option<Self> {
        let mut result = Vec::new();
        if let Some(metadata) = metadata {
            result.extend_from_slice(b"\x01\n");
            result.extend_from_slice(RawBlob::read(metadata)?.as_bytes());
            result.extend_from_slice(b"\x01\n");
        }
        result.extend_from_slice(RawBlob::read(oid)?.as_bytes());
        Some(Self(result.into()))
    }
}

#[derive(Debug)]
struct ChangesetHeads {
    generation: usize,
    heads: BTreeMap<HgChangesetId, (BString, usize)>,
}

impl ChangesetHeads {
    fn new() -> Self {
        get_oid_committish(b"refs/cinnabar/metadata^1").map_or_else(
            || ChangesetHeads {
                generation: 0,
                heads: BTreeMap::new(),
            },
            |cid| {
                let commit = RawCommit::read(&cid).unwrap();
                let commit = commit.parse().unwrap();
                let heads = ByteSlice::lines(commit.body())
                    .enumerate()
                    .map(|(n, l)| {
                        let [h, b] = l.splitn_exact(b' ').unwrap();
                        (HgChangesetId::from_bytes(h).unwrap(), (BString::from(b), n))
                    })
                    .collect::<BTreeMap<_, _>>();
                ChangesetHeads {
                    generation: heads.len(),
                    heads,
                }
            },
        )
    }
}

static CHANGESET_HEADS: Lazy<Mutex<ChangesetHeads>> =
    Lazy::new(|| Mutex::new(ChangesetHeads::new()));

#[no_mangle]
pub unsafe extern "C" fn add_changeset_head(cs: *const hg_object_id, oid: *const object_id) {
    let cs = HgChangesetId::from_unchecked(HgObjectId::from(cs.as_ref().unwrap().clone()));

    // Because we don't keep track of many of these things in the rust side right now,
    // we do extra work here. Eventually, this will be simplified.
    let mut heads = CHANGESET_HEADS.lock().unwrap();
    let oid = GitObjectId::from(oid.as_ref().unwrap().clone());
    if oid == GitObjectId::null() {
        heads.heads.remove(&cs);
    } else {
        let blob = BlobId::from_unchecked(oid);
        let cs_meta = RawGitChangesetMetadata(RawBlob::read(&blob).unwrap());
        let meta = cs_meta.parse().unwrap();
        assert_eq!(meta.changeset_id, cs);
        let branch = meta
            .extra()
            .and_then(|e| e.get(b"branch"))
            .unwrap_or(b"default");
        let cid = cs.to_git().unwrap();
        let commit = RawCommit::read(&cid).unwrap();
        let commit = commit.parse().unwrap();
        for parent in commit.parents() {
            let parent = lookup_replace_commit(parent);
            let parent_cs_meta =
                RawGitChangesetMetadata::read(&GitChangesetId::from_unchecked(parent.into_owned()))
                    .unwrap();
            let parent_meta = parent_cs_meta.parse().unwrap();
            let parent_branch = parent_meta
                .extra()
                .and_then(|e| e.get(b"branch"))
                .unwrap_or(b"default");
            if parent_branch == branch {
                if let Some((b, _)) = heads.heads.get(&parent_meta.changeset_id) {
                    assert_eq!(b.as_bstr(), parent_branch.as_bstr());
                    heads.heads.remove(&parent_meta.changeset_id);
                }
            }
        }
        let generation = heads.generation;
        heads.generation += 1;
        heads.heads.insert(cs, (BString::from(branch), generation));
    }
}

#[no_mangle]
pub unsafe extern "C" fn changeset_heads(output: c_int) {
    let mut output = FdFile::from_raw_fd(output);
    let heads = CHANGESET_HEADS.lock().unwrap();

    let mut buf = Vec::new();
    for (_, h, b) in heads.heads.iter().map(|(h, (b, g))| (g, h, b)).sorted() {
        writeln!(buf, "{} {}", h, b).ok();
    }
    send_buffer_to(&*buf, &mut output);
}

extern "C" {
    fn write_object_file_flags(
        buf: *const c_void,
        len: usize,
        typ: object_type,
        oid: *mut object_id,
        flags: c_uint,
    ) -> c_int;
}

#[no_mangle]
pub unsafe extern "C" fn store_changesets_metadata(blob: *const object_id, result: *mut object_id) {
    let result = result.as_mut().unwrap();
    let mut tree = vec![];
    if let Some(blob) = blob.as_ref() {
        let blob = BlobId::from_unchecked(GitObjectId::from(blob.clone()));
        tree.extend_from_slice(b"100644 bundle\0");
        tree.extend_from_slice(blob.as_raw_bytes());
    }
    let mut tid = object_id::default();
    write_object_file_flags(
        tree.as_ptr() as *const c_void,
        tree.len(),
        object_type::OBJ_TREE,
        &mut tid,
        0,
    );
    drop(tree);
    let mut commit = vec![];
    writeln!(commit, "tree {}", GitObjectId::from(tid)).ok();
    let heads = CHANGESET_HEADS.lock().unwrap();
    for (_, head) in heads.heads.iter().map(|(h, (_, g))| (g, h)).sorted() {
        writeln!(commit, "parent {}", head.to_git().unwrap()).ok();
    }
    writeln!(commit, "author  <cinnabar@git> 0 +0000").ok();
    writeln!(commit, "committer  <cinnabar@git> 0 +0000").ok();
    for (_, head, branch) in heads.heads.iter().map(|(h, (b, g))| (g, h, b)).sorted() {
        write!(commit, "\n{} {}", head, branch).ok();
    }
    write_object_file_flags(
        commit.as_ptr() as *const c_void,
        commit.len(),
        object_type::OBJ_COMMIT,
        result,
        0,
    );
}

#[no_mangle]
pub unsafe extern "C" fn reset_changeset_heads() {
    let mut heads = CHANGESET_HEADS.lock().unwrap();
    *heads = ChangesetHeads::new();
}

extern "C" {
    fn ensure_store_init();
    pub fn store_git_blob(blob_buf: *const strbuf, result: *mut object_id);
    fn store_git_commit(commit_buf: *const strbuf, result: *mut object_id);
    fn do_set_(what: *const c_char, hg_id: *const hg_object_id, git_id: *const object_id);
    fn do_set_replace(replaced: *const object_id, replace_with: *const object_id);
    fn create_git_tree(
        tree_id: *const object_id,
        ref_tree: *const object_id,
        result: *mut object_id,
    );
    fn ensure_empty_tree() -> *const object_id;
}

pub fn do_store_changeset(mut input: &mut dyn BufRead, mut output: impl Write, args: &[&[u8]]) {
    unsafe {
        ensure_store_init();
    }
    if args.len() < 2 || args.len() > 4 {
        die!("store-changeset takes between 2 and 4 arguments");
    }

    let changeset_id = HgChangesetId::from_bytes(args[0]).unwrap();
    let parents = &args[1..args.len() - 1]
        .iter()
        .map(|p| HgChangesetId::from_bytes(p).unwrap().to_git().unwrap())
        .collect::<Vec<_>>();
    let size = usize::from_bytes(args[args.len() - 1]).unwrap();
    let buf = input.read_exactly(size).unwrap();
    let raw_changeset = RawHgChangeset(buf);

    let changeset = raw_changeset.parse().unwrap();
    let manifest_tree_id = match changeset.manifest() {
        m if m == &HgManifestId::null() => unsafe {
            TreeId::from_unchecked(GitObjectId::from(
                ensure_empty_tree().as_ref().unwrap().clone(),
            ))
        },
        m => {
            let git_manifest_id = m.to_git().unwrap();
            let manifest_commit = RawCommit::read(&git_manifest_id).unwrap();
            let manifest_commit = manifest_commit.parse().unwrap();
            manifest_commit.tree().clone()
        }
    };

    let ref_tree = parents.get(0).map(|p| {
        let ref_commit = RawCommit::read(p).unwrap();
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
    let tree_id = unsafe { TreeId::from_unchecked(GitObjectId::from(tree_id)) };

    let (commit_id, metadata_id, transition) =
        match graft(&changeset_id, &raw_changeset, &tree_id, parents) {
            Ok(Some(commit_id)) => {
                let metadata = GeneratedGitChangesetMetadata::generate(
                    &RawCommit::read(&commit_id).unwrap().parse().unwrap(),
                    &changeset_id,
                    &raw_changeset,
                )
                .unwrap();
                if !grafted() && metadata.patch().is_some() {
                    (Some(commit_id), None, true)
                } else {
                    let mut buf = strbuf::new();
                    buf.extend_from_slice(&metadata.serialize());
                    let mut metadata_oid = object_id::default();
                    unsafe {
                        store_git_blob(&buf, &mut metadata_oid);
                    }
                    let metadata_id = unsafe {
                        GitChangesetMetadataId::from_unchecked(BlobId::from_unchecked(
                            GitObjectId::from(metadata_oid),
                        ))
                    };
                    (Some(commit_id), Some(metadata_id), false)
                }
            }
            Ok(None) | Err(GraftError::NoGraft) => (None, None, false),
            Err(GraftError::Ambiguous(candidates)) => {
                writeln!(
                    output,
                    "ambiguous {}",
                    itertools::join(candidates.iter(), " ")
                )
                .unwrap();
                return;
            }
        };

    let (commit_id, metadata_id, replace) = if commit_id.is_none() || transition {
        let replace = commit_id;
        let mut result = strbuf::new();
        let author = HgAuthorship {
            author: changeset.author(),
            timestamp: changeset.timestamp(),
            utcoffset: changeset.utcoffset(),
        };
        // TODO: reduce the amount of cloning.
        let git_author = GitAuthorship::from(author.clone());
        let git_committer = if let Some(extra) = changeset.extra() {
            if let Some(committer) = extra.get(b"committer") {
                if committer.ends_with(b">") {
                    GitAuthorship::from(HgAuthorship {
                        author: committer,
                        timestamp: author.timestamp,
                        utcoffset: author.utcoffset,
                    })
                } else {
                    GitAuthorship::from(HgCommitter(committer))
                }
            } else {
                git_author.clone()
            }
        } else {
            git_author.clone()
        };
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

        let mut result_oid = object_id::default();
        unsafe {
            store_git_commit(&result, &mut result_oid);
        }
        let commit_id = unsafe { CommitId::from_unchecked(GitObjectId::from(result_oid)) };

        let metadata = GeneratedGitChangesetMetadata::generate(
            &RawCommit::read(&commit_id).unwrap().parse().unwrap(),
            &changeset_id,
            &raw_changeset,
        )
        .unwrap();
        let mut buf = strbuf::new();
        buf.extend_from_slice(&metadata.serialize());
        let mut metadata_oid = object_id::default();
        unsafe {
            store_git_blob(&buf, &mut metadata_oid);
        }
        let metadata_id = unsafe {
            GitChangesetMetadataId::from_unchecked(BlobId::from_unchecked(GitObjectId::from(
                metadata_oid,
            )))
        };
        (commit_id, metadata_id, replace)
    } else {
        (
            unsafe { commit_id.unwrap_unchecked() },
            metadata_id.unwrap(),
            None,
        )
    };

    if let Some(replace) = &replace {
        writeln!(output, "{} {}", commit_id, replace).unwrap();
    } else {
        writeln!(output, "{}", commit_id).unwrap();
    }
    let changeset_id = hg_object_id::from(changeset_id);
    let commit_id = object_id::from(commit_id);
    let blob_id = object_id::from((*metadata_id).clone());
    unsafe {
        if let Some(replace) = replace {
            let replace = object_id::from(replace);
            do_set_replace(&replace, &commit_id);
        }
        do_set_(cstr!("changeset").as_ptr(), &changeset_id, &commit_id);
        do_set_(
            cstr!("changeset-metadata").as_ptr(),
            &changeset_id,
            &blob_id,
        );
        do_set_(cstr!("changeset-head").as_ptr(), &changeset_id, &blob_id);
    }
}

pub fn do_create(input: &mut dyn BufRead, output: impl Write, args: &[&[u8]]) {
    match args.split_first() {
        Some((&b"changeset", args)) => do_create_changeset(input, output, args),
        Some((typ, _)) => die!("unknown create type: {}", typ.as_bstr()),
        None => die!("create expects a type"),
    }
}

pub fn do_create_changeset(mut input: &mut dyn BufRead, mut output: impl Write, args: &[&[u8]]) {
    unsafe {
        ensure_store_init();
    }
    if args.len() != 3 {
        die!("create changeset takes 3 arguments");
    }
    let commit_id = CommitId::from_bytes(args[0]).unwrap();
    let manifest_id = HgManifestId::from_bytes(args[1]).unwrap();
    let size = usize::from_bytes(args[2]).unwrap();
    let files = (size != 0).then(|| input.read_exactly(size).unwrap());
    let mut metadata = GitChangesetMetadata {
        changeset_id: HgChangesetId::null(),
        manifest_id,
        author: None,
        extra: None,
        files,
        patch: None,
    };
    let commit = RawCommit::read(&commit_id).unwrap();
    let commit = commit.parse().unwrap();
    let changeset = RawHgChangeset::from_metadata(&commit, &metadata).unwrap();
    let mut hash = HgChangesetId::create();
    let mut parents = commit
        .parents()
        .iter()
        .map(|p| unsafe { GitChangesetId::from_unchecked(p.clone()) }.to_hg())
        .chain(repeat(Some(HgChangesetId::null())))
        .take(2)
        .collect::<Option<Vec<_>>>()
        .unwrap();
    parents.sort();
    for p in parents {
        hash.update(p.as_raw_bytes());
    }
    hash.update(&changeset.0);
    metadata.changeset_id = hash.finalize();
    let mut buf = strbuf::new();
    buf.extend_from_slice(&metadata.serialize());
    let mut blob_oid = object_id::default();
    unsafe {
        store_git_blob(&buf, &mut blob_oid);
    }
    let metadata_id = unsafe {
        GitChangesetMetadataId::from_unchecked(BlobId::from_unchecked(GitObjectId::from(blob_oid)))
    };
    writeln!(output, "{} {}", metadata.changeset_id, metadata_id).unwrap();
}

extern "C" {
    fn store_manifest(chunk: *const rev_chunk);
    fn store_file(chunk: *const rev_chunk);
}

pub fn do_store_changegroup(input: &mut dyn BufRead, args: &[&[u8]]) {
    unsafe {
        ensure_store_init();
    }
    let version = match args {
        [b"1"] => 1,
        [b"2"] => 2,
        _ => die!("store-changegroup only takes one argument that is either 1 or 2"),
    };
    for _changeset in RevChunkIter::new(version, &mut *input) {}
    for manifest in RevChunkIter::new(version, &mut *input) {
        unsafe {
            store_manifest(&manifest);
        }
    }
    while {
        let mut buf = strbuf::new();
        read_rev_chunk(&mut *input, &mut buf);
        !buf.as_bytes().is_empty()
    } {
        for file in RevChunkIter::new(version, &mut *input) {
            unsafe {
                store_file(&file);
            }
        }
    }
}
