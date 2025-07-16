/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(renamed_and_removed_lints)]
#![allow(clippy::borrowed_box)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::new_without_default)]
#![deny(clippy::clone_on_ref_ptr)]
#![deny(clippy::cloned_instead_of_copied)]
#![deny(clippy::default_trait_access)]
#![deny(clippy::flat_map_option)]
#![deny(clippy::from_iter_instead_of_collect)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::inconsistent_struct_constructor)]
#![deny(clippy::large_types_passed_by_value)]
#![deny(clippy::let_underscore_drop)]
#![deny(clippy::let_unit_value)]
#![deny(clippy::manual_ok_or)]
#![deny(clippy::map_flatten)]
#![deny(clippy::map_unwrap_or)]
#![deny(clippy::needless_bitwise_bool)]
#![deny(clippy::needless_continue)]
#![deny(clippy::needless_for_each)]
#![deny(clippy::option_option)]
#![deny(clippy::range_minus_one)]
#![deny(clippy::range_plus_one)]
#![deny(clippy::redundant_closure_for_method_calls)]
#![deny(clippy::redundant_else)]
#![deny(clippy::redundant_slicing)]
#![deny(clippy::ref_binding_to_reference)]
#![deny(clippy::ref_option_ref)]
#![deny(clippy::semicolon_if_nothing_returned)]
#![deny(clippy::trait_duplication_in_bounds)]
#![deny(clippy::transmute_ptr_to_ptr)]
#![deny(clippy::type_repetition_in_bounds)]
#![deny(clippy::unicode_not_nfc)]
#![deny(clippy::unnecessary_wraps)]
#![deny(clippy::unnested_or_patterns)]
#![deny(clippy::unused_self)]
#![allow(unknown_lints)]

#[macro_use]
extern crate log;

mod cinnabar;
mod git;
mod graft;
mod hg;
mod libc;
mod libcinnabar;
pub mod libgit;
mod logging;
mod oid;
mod progress;
pub mod store;
pub mod tree_util;
mod util;
mod version;
mod xdiff;

pub(crate) mod hg_bundle;
pub mod hg_connect;
pub(crate) mod hg_connect_http;
pub(crate) mod hg_connect_stdio;
pub(crate) mod hg_data;

use std::borrow::{Borrow, Cow};
use std::cell::{Cell, OnceCell, RefCell};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::hash::Hash;
use std::io::{stderr, stdin, stdout, BufRead, BufReader, BufWriter, IsTerminal, Write};
use std::iter::repeat;
use std::os::raw::{c_char, c_int};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, from_utf8, FromStr};
use std::sync::Mutex;
#[cfg(feature = "version-check")]
use std::time::Duration;
use std::time::Instant;
use std::{cmp, fmt};

use bitflags::bitflags;
use bstr::io::BufReadExt;
use bstr::{BStr, ByteSlice};
use byteorder::{BigEndian, WriteBytesExt};
use cinnabar::{
    GitChangesetId, GitFileMetadataId, GitManifestId, GitManifestTree, GitManifestTreeId,
};
use clap::error::ErrorKind;
use clap::{CommandFactory, FromArgMatches, Parser};
use cstr::cstr;
use digest::OutputSizeUser;
use either::Either;
use git::{BlobId, CommitId, GitObjectId, RawBlob, RawCommit, RawTree, RecursedTreeEntry, TreeIsh};
use graft::{graft_finish, grafted, init_graft, maybe_init_graft};
use hg::{HgChangesetId, HgFileId, HgManifestId, ManifestEntry};
use hg_bundle::{create_bundle, create_chunk_data, read_rev_chunk, BundleSpec, RevChunkIter};
use hg_connect::{
    get_bundle, get_bundle_connection, get_clonebundle_url, get_connection, get_store_bundle,
    HgConnection, HgConnectionBase, HgRepo,
};
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::{EitherOrBoth, Itertools};
use libgit::{
    commit, config_get_value, die, diff_tree_with_copies, for_each_ref_in, for_each_remote,
    get_oid_committish, get_unique_abbrev, git_author_info, git_committer_info, lookup_commit,
    lookup_replace_commit, object_id, reachable_subset, remote, repository, resolve_ref, rev_list,
    rev_list_with_boundaries, rev_list_with_parents, the_repository, DiffTreeItem, FileMode,
    MaybeBoundary, RefTransaction,
};
use logging::{LoggingReader, LoggingWriter};
use oid::{Abbrev, ObjectId};
use once_cell::sync::Lazy;
use percent_encoding::percent_decode;
use progress::Progress;
use sha1::{Digest, Sha1};
use store::{
    check_file, check_manifest, create_changeset, do_check_files, do_store_metadata,
    ensure_store_init, has_metadata, raw_commit_for_changeset, store_git_blob, store_git_tree,
    store_manifest, ChangesetHeads, GeneratedGitChangesetMetadata, RawGitChangesetMetadata,
    RawHgChangeset, RawHgFile, RawHgManifest, SetWhat, Store, BROKEN_REF, CHECKED_REF,
    METADATA_REF, NOTES_REF, REFS_PREFIX, REPLACE_REFS_PREFIX,
};
use tee::TeeReader;
use tree_util::{diff_by_path, merge_join_by_path, NoRecurse, RecurseTree};
use url::Url;
use util::{CStrExt, IteratorExt, OsStrExt, SliceExt, Transpose};
#[cfg(windows)]
use windows_sys::Win32;

use crate::hg_bundle::BundleReader;
use crate::hg_connect::{decodecaps, find_common, UnbundleResponse};
use crate::libcinnabar::AsStrSlice;
use crate::progress::set_progress;
use crate::store::{clear_manifest_heads, do_set_replace, set_changeset_heads, Dag};
use crate::tree_util::{Empty, ParseTree, WithPath};
use crate::util::{FromBytes, ToBoxed};
use crate::version::{FULL_VERSION, SHORT_VERSION};

#[cfg(any(feature = "version-check", feature = "self-update"))]
mod version_check;

#[cfg(feature = "version-check")]
use version_check::VersionChecker;

#[cfg(not(feature = "version-check"))]
pub struct VersionChecker;

#[cfg(not(feature = "version-check"))]
impl VersionChecker {
    pub fn new() -> Self {
        VersionChecker
    }
}

#[cfg(feature = "self-update")]
use version::Version;
#[cfg(feature = "self-update")]
use version_check::{find_version, VersionInfo, VersionRequest};

pub const CARGO_PKG_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

#[allow(improper_ctypes)]
extern "C" {
    fn do_cleanup(rollback: c_int);

    #[cfg(windows)]
    fn wmain(argc: c_int, argv: *const *const u16) -> c_int;

    fn init_cinnabar(argv0: *const c_char) -> c_int;
}

static REF_UPDATES: Lazy<Mutex<HashMap<Box<BStr>, CommitId>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn dump_ref_updates() {
    let mut ref_updates = REF_UPDATES.lock().unwrap();
    if !ref_updates.is_empty() {
        let mut transaction = RefTransaction::new().unwrap();
        for (refname, oid) in ref_updates.drain() {
            let refname = OsStr::from_bytes(&refname);
            if oid.is_null() {
                transaction.delete(refname, None, "update").unwrap();
            } else {
                transaction.update(refname, oid, None, "update").unwrap();
            }
        }
        transaction.commit().unwrap();
    }
}

fn the_store() -> Result<Store, &'static str> {
    unsafe { HAS_GIT_REPO }
        .then(|| {
            let c = resolve_ref(METADATA_REF);
            Store::new(c)
        })
        .ok_or("not a git repository")
}

fn do_done_and_check(store: &mut Store, args: &[&[u8]]) -> bool {
    unsafe {
        if graft_finish() == Some(false) {
            // Rollback
            do_cleanup(1);
            error!(target: "root", "Nothing to graft");
            return false;
        }
        let new_metadata = do_store_metadata(store);
        do_cleanup(0);
        set_metadata_to(
            Some(new_metadata),
            SetMetadataFlags::FORCE | SetMetadataFlags::KEEP_REFS,
            "update",
        )
        .unwrap();
        if args.contains(&CHECKED_REF.as_bytes()) {
            let mut transaction = RefTransaction::new().unwrap();
            transaction
                .update(CHECKED_REF, new_metadata, None, "fsck")
                .unwrap();
            transaction.commit().unwrap();
        }
        *store = Store::new(Some(new_metadata));
    }
    do_check_files(store)
}

#[cfg(unix)]
pub fn prepare_arg(arg: OsString) -> CString {
    arg.to_cstring()
}

#[cfg(windows)]
pub fn prepare_arg(arg: OsString) -> Vec<u16> {
    let mut arg = arg.encode_wide().collect_vec();
    arg.push(0);
    arg
}

fn do_one_hg2git(store: &Store, sha1: Abbrev<HgChangesetId>) -> String {
    format!("{}", sha1.to_git(store).unwrap_or(GitChangesetId::NULL))
}

fn do_one_git2hg(store: &Store, committish: OsString) -> String {
    let note = get_oid_committish(committish.as_bytes())
        .map(lookup_replace_commit)
        .and_then(|oid| GitChangesetId::from_unchecked(oid).to_hg(store));
    format!("{}", note.unwrap_or(HgChangesetId::NULL))
}

fn do_conversion<T, I: Iterator<Item = T>, F: FnMut(T) -> Result<String, String>, W: Write>(
    abbrev: Option<usize>,
    input: I,
    mut f: F,
    mut output: W,
) -> Result<(), String> {
    let abbrev = abbrev.unwrap_or(40);
    for i in input {
        let out = f(i)?;
        writeln!(output, "{}", &out[..abbrev]).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn do_conversion_cmd<T, I, F>(
    store: &Store,
    abbrev: Option<usize>,
    input: I,
    batch: bool,
    f: F,
) -> Result<(), String>
where
    T: FromStr,
    <T as FromStr>::Err: fmt::Display,
    I: Iterator<Item = T>,
    F: Fn(&Store, T) -> String,
{
    let f = &f;
    let out = stdout();
    let mut out = BufWriter::new(out.lock());
    do_conversion(abbrev, input, |t| Ok(f(store, t)), &mut out)?;
    if batch {
        out.flush().map_err(|e| e.to_string())?;
        let input = stdin();
        for line in input.lock().lines() {
            let line = line.map_err(|e| e.to_string())?;
            do_conversion(
                abbrev,
                line.split_whitespace(),
                |i| {
                    let t = T::from_str(i).map_err(|e| e.to_string())?;
                    Ok(f(store, t))
                },
                &mut out,
            )?;
            out.flush().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn do_data_changeset(store: &Store, rev: Abbrev<HgChangesetId>) -> Result<(), String> {
    let changeset = RawHgChangeset::read(
        store,
        rev.to_git(store)
            .ok_or_else(|| format!("Unknown changeset id: {rev}"))?,
    )
    .unwrap();
    stdout().write_all(&changeset).map_err(|e| e.to_string())
}

fn do_data_manifest(store: &Store, rev: Abbrev<HgManifestId>) -> Result<(), String> {
    let manifest = RawHgManifest::read(
        rev.to_git(store)
            .ok_or_else(|| format!("Unknown manifest id: {rev}"))?,
    )
    .unwrap();
    stdout().write_all(&manifest).map_err(|e| e.to_string())
}

fn hg_url(url: impl AsRef<OsStr>) -> Option<Url> {
    let url = url.as_ref().strip_prefix("hg:")?;
    if let Some(url) = url.strip_prefix(":") {
        // hg:: prefix
        match url.to_str().and_then(|s| Url::parse(s).ok()) {
            Some(parsed_url)
                // On Windows, assume that a one-letter scheme and no host
                // means we originally had something like c:/foo.
                if !(cfg!(windows)
                    && parsed_url.scheme().len() == 1
                    && parsed_url.host_str().is_none()) =>
            {
                Some(parsed_url)
            }
            _ => {
                let path = Path::new(url);
                let path = if path.is_relative() {
                    #[cfg(not(test))]
                    let curdir = std::env::current_dir().ok()?;
                    #[cfg(all(test, windows))]
                    let curdir = Path::new("c:/foo");
                    #[cfg(all(test, unix))]
                    let curdir = Path::new("/foo");
                    Cow::from(curdir.join(path))
                } else {
                    Cow::from(path)
                };
                Url::from_file_path(path).ok()
            }
        }
    } else if let Some(remainder) = url.strip_prefix("//") {
        // hg:// prefix
        let remainder = remainder.as_bytes();
        let mut in_brackets = false;
        let mut bytes = 0;
        for b in remainder {
            match b {
                b':' if !in_brackets => break,
                b'/' | b'?' | b'#' => break,
                b'[' => in_brackets = true,
                b']' => in_brackets = false,
                _ => {}
            }
            bytes += 1;
        }
        let (userhost, remainder) = remainder.split_at(bytes);
        let (scheme, port, remainder) = remainder.strip_prefix(b":").map_or_else(
            || (&b"https"[..], &b""[..], remainder),
            |remainder| {
                let mut bytes = 0;
                for b in remainder {
                    match b {
                        b'/' | b'?' | b'#' => break,
                        _ => {}
                    }
                    bytes += 1;
                }
                let (port, remainder) = remainder.split_at(bytes);
                let [port, scheme] = port.splitn_exact(b'.').unwrap_or_else(|| {
                    if port.iter().all(u8::is_ascii_digit) {
                        [port, b"https"]
                    } else {
                        [b"", port]
                    }
                });
                (scheme, port, remainder)
            },
        );
        let mut url = scheme.to_owned();
        if scheme == b"tags" && userhost.is_empty() && port.is_empty() && remainder.is_empty() {
            url.push(b':');
        } else {
            url.extend_from_slice(b"://");
            url.extend_from_slice(userhost);
            if !port.is_empty() {
                url.push(b':');
                url.extend_from_slice(port);
            }
            url.extend_from_slice(remainder);
        }

        Url::parse(url.to_str().ok()?).ok()
    } else {
        None
    }
}

#[test]
fn test_hg_url() {
    assert_eq!(hg_url("http://foo.com/foo"), None);
    assert_eq!(
        hg_url("hg::https://foo.com/foo"),
        Url::parse("https://foo.com/foo").ok()
    );
    assert_eq!(hg_url("hg::tags:"), Url::parse("tags:").ok());
    assert_eq!(hg_url("hg://:tags"), Url::parse("tags:").ok());
    assert_eq!(
        hg_url("hg://:tags").unwrap().as_str(),
        Url::parse("tags:").unwrap().as_str()
    );
    assert_eq!(hg_url("/foo/bar"), None);
    assert_eq!(
        hg_url("hg::file:///foo/bar"),
        Url::parse("file:///foo/bar").ok()
    );
    assert_eq!(
        hg_url("hg://:file/foo/bar"),
        Url::parse("file:///foo/bar").ok()
    );
    #[cfg(unix)]
    {
        assert_eq!(hg_url("hg::/foo/bar"), Url::parse("file:///foo/bar").ok());
        assert_eq!(hg_url("hg::bar"), Url::parse("file:///foo/bar").ok());
    }
    #[cfg(windows)]
    {
        assert_eq!(hg_url("c:/foo/bar"), None);
        assert_eq!(
            hg_url("hg::c:/foo/bar"),
            Url::parse("file:///C:/foo/bar").ok()
        );
        assert_eq!(hg_url("hg::bar"), Url::parse("file:///C:/foo/bar").ok());
        assert_eq!(
            hg_url("hg::file://c:/foo/bar"),
            Url::parse("file:///c:/foo/bar").ok()
        );
        assert_eq!(
            hg_url("hg::file:///c:/foo/bar"),
            Url::parse("file:///c:/foo/bar").ok()
        );
        assert_eq!(
            hg_url("hg://:file/c:/foo/bar"),
            Url::parse("file:///c:/foo/bar").ok()
        );
    }
    assert_eq!(
        hg_url("hg://foo.com/foo"),
        Url::parse("https://foo.com/foo").ok()
    );
    assert_eq!(
        hg_url("hg://foo.com:8443/foo"),
        Url::parse("https://foo.com:8443/foo").ok()
    );
    assert_eq!(
        hg_url("hg://foo.com:http/foo"),
        Url::parse("http://foo.com/foo").ok()
    );
    assert_eq!(
        hg_url("hg://foo.com:8080.http/foo"),
        Url::parse("http://foo.com:8080/foo").ok()
    );
}

extern "C" {
    fn git_path_fetch_head(repos: *mut repository) -> *const c_char;
}

struct BundleSaverConnection(Box<dyn HgRepo>);

impl HgConnectionBase for BundleSaverConnection {
    fn get_url(&self) -> Option<&Url> {
        self.0.get_url()
    }

    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        self.0.get_capability(name)
    }

    fn require_capability(&self, name: &[u8]) -> &BStr {
        self.0.require_capability(name)
    }

    fn sample_size(&self) -> usize {
        self.0.sample_size()
    }
}
impl HgConnection for BundleSaverConnection {
    fn getbundle<'a>(
        &'a mut self,
        heads: &[HgChangesetId],
        common: &[HgChangesetId],
        bundle2caps: Option<&str>,
    ) -> Result<Box<dyn std::io::Read + 'a>, util::ImmutBString> {
        let reader = self.0.getbundle(heads, common, bundle2caps)?;
        let mut stdout = std::io::stdout();
        let mut bundle = BundleReader::new(TeeReader::new(reader, &mut stdout)).unwrap();
        while let Some(part) = bundle.next_part().unwrap() {
            if &*part.part_type == "changegroup" {
                let version = part
                    .get_param("version")
                    .map_or(1, |v| u8::from_str(v).unwrap());
                let mut part = BufReader::new(part);
                RevChunkIter::new(version, &mut part)
                    .progress(|n| format!("Reading {n} changesets"))
                    .for_each(drop);
                RevChunkIter::new(version, &mut part)
                    .progress(|n| format!("Reading {n} manifests"))
                    .for_each(drop);
                let files = Cell::new(0);
                let mut progress = repeat(())
                    .progress(|n| format!("Reading {n} revisions of {} files", files.get()));
                while {
                    let buf = read_rev_chunk(&mut part);
                    !buf.is_empty()
                } {
                    files.set(files.get() + 1);
                    RevChunkIter::new(version, &mut part)
                        .zip(&mut progress)
                        .for_each(drop);
                }
            } else if &*part.part_type == "stream2" {
                return Err(b"Stream bundles are not supported."
                    .to_vec()
                    .into_boxed_slice());
            }
        }
        drop(bundle);
        stdout.flush().map_err(|e| e.to_string().into_boxed_str())?;
        Ok(Box::new(&b"HG20\0\0\0\0\0\0\0\0"[..]))
    }

    fn unbundle(&mut self, _heads: Option<&[HgChangesetId]>, _input: File) -> UnbundleResponse {
        unimplemented!()
    }

    fn pushkey(
        &mut self,
        _namespace: &str,
        _key: &str,
        _old: &str,
        _new: &str,
    ) -> util::ImmutBString {
        unimplemented!();
    }

    fn lookup(&mut self, key: &str) -> util::ImmutBString {
        self.0.lookup(key)
    }

    fn clonebundles(&mut self) -> util::ImmutBString {
        unimplemented!();
    }

    fn cinnabarclone(&mut self) -> util::ImmutBString {
        unimplemented!();
    }
}

impl HgRepo for BundleSaverConnection {
    fn branchmap(&mut self) -> util::ImmutBString {
        self.0.branchmap()
    }

    fn heads(&mut self) -> util::ImmutBString {
        self.0.heads()
    }

    fn bookmarks(&mut self) -> util::ImmutBString {
        self.0.bookmarks()
    }

    fn phases(&mut self) -> util::ImmutBString {
        self.0.phases()
    }

    fn known(&mut self, nodes: &[HgChangesetId]) -> Box<[bool]> {
        self.0.known(nodes)
    }
}

extern "C" {
    fn check_pager_config(repo: *mut repository, cmd: *const c_char) -> c_int;
    fn setup_pager(repo: *mut repository);
}

// https://github.com/rust-lang/rust-clippy/issues/10599
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum TagFormatItem {
    TagName,
    ObjectName,
    HgObjectName,
}

fn do_tag_list(store: &mut Store, format: Option<String>) -> Result<(), String> {
    unsafe {
        if check_pager_config(the_repository, cstr!("tag").as_ptr()) != 0 {
            setup_pager(the_repository);
        }
    }
    // Crude imitation of `git tag -l`'s `--format`, with a limited set of field names.
    // (and `%(tagname)` corresponding to `%(refname:strip=2)`).
    let format = format.as_deref().unwrap_or("%(tagname)");
    let format = format
        .split(' ')
        .map(|item| match item {
            "%(tagname)" => Some(TagFormatItem::TagName),
            "%(objectname)" => Some(TagFormatItem::ObjectName),
            "%(hg::objectname)" => Some(TagFormatItem::HgObjectName),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| format!("Invalid format: {format}"))?;
    let mut stdout = stdout();
    for (tag, c) in store.get_tags().iter().sorted() {
        for (n, format_item) in format.iter().enumerate() {
            if n > 0 {
                stdout.write_all(b" ").unwrap();
            }
            match format_item {
                TagFormatItem::TagName => stdout.write_all(tag).unwrap(),
                TagFormatItem::ObjectName => write!(
                    stdout,
                    "{}",
                    c.to_git(store).unwrap_or(GitChangesetId::NULL)
                )
                .unwrap(),
                TagFormatItem::HgObjectName => write!(stdout, "{c}").unwrap(),
            }
        }
        stdout.write_all(b"\n").unwrap();
    }
    Ok(())
}

fn validate_label(label: &[u8], typ: &str) -> Result<(), String> {
    const RESERVED_CHARS: [u8; 4] = [b':', b'\0', b'\n', b'\r'];
    match label {
        b"tip" | b"." | b"null" => Err(format!(
            "Cannot use reserved name '{}' as a {} name",
            label.as_bstr(),
            typ
        )),
        _ if label.iter().any(|x| RESERVED_CHARS.contains(x)) => Err(format!(
            "Cannot use character '{}' in a {} name",
            label[label
                .iter()
                .position(|x| RESERVED_CHARS.contains(x))
                .unwrap()] as char,
            typ
        )),
        _ if label.iter().all(u8::is_ascii_digit) => {
            Err(format!("Cannot use an integer as a {typ} name"))
        }
        _ if label.trim_with(|x| x.is_ascii_whitespace()) != label => {
            Err(format!("Leading or trailing whitespace in {typ} name"))
        }
        _ => Ok(()),
    }
}

fn do_tag(
    store: &mut Store,
    force: bool,
    delete: bool,
    onto: Option<OsString>,
    message: Option<OsString>,
    tag: Option<OsString>,
    committish: Option<OsString>,
) -> Result<(), String> {
    // TODO: `hg tag`` doesn't allow to create a tag on a non-head without `-f`.
    let tags = store.get_tags();
    let tag = tag.expect("clap should have ensured it's Some at this point");
    let tag = tag.as_bytes();
    validate_label(tag, "tag")?;
    let (current_csid, new_csid) = if delete {
        (
            Some(
                tags.get(tag)
                    .ok_or_else(|| format!("tag '{}' not found", tag.as_bstr()))?,
            ),
            HgChangesetId::NULL,
        )
    } else {
        let current_csid = tags.get(tag);
        if current_csid.is_some() && !force {
            return Err(format!("tag '{}' already exists", tag.as_bstr()));
        }
        let committish = committish.as_deref().map_or(&b"HEAD"[..], OsStr::as_bytes);
        let commit = get_oid_committish(committish)
            .or_else(|| {
                Abbrev::<HgChangesetId>::from_bytes(committish)
                    .ok()
                    .and_then(|cs| cs.to_git(store).map(Into::into))
            })
            .map(lookup_replace_commit)
            .map(GitChangesetId::from_unchecked)
            .ok_or_else(|| format!("bad revision '{}'", committish.as_bstr()))?;
        let csid = commit
            .to_hg(store)
            .ok_or_else(|| format!("{commit} is not on a Mercurial repository (yet?)"))?;
        (
            current_csid.or_else(|| tags.ever_contained(tag).then_some(HgChangesetId::NULL)),
            csid,
        )
    };
    let head = if let Some(onto) = &onto {
        resolve_ref(onto)
    } else {
        Some(resolve_ref("HEAD").expect("We shouldn't be reaching here without a HEAD"))
    };
    let tree = if let Some(head) = head {
        RawTree::read_treeish(head).unwrap()
    } else {
        [].into_iter().collect::<RawTree>()
    };
    let new_tree = merge_join_by_path(
        tree,
        [WithPath::new(
            *b".hgtags",
            NoRecurse((current_csid, new_csid)),
        )],
    )
    .map(|merged| {
        merged.map(|merged| {
            let (hgtags, current_csid, new_csid) = match merged {
                EitherOrBoth::Left(l) => return l,
                EitherOrBoth::Right(r) => (None, r.0 .0, r.0 .1),
                EitherOrBoth::Both(l, r) => {
                    // TODO: what to do if it's not a blob?
                    let hgtags = l
                        .right()
                        .and_then(|e| BlobId::try_from(e.oid).ok())
                        .and_then(RawBlob::read);
                    (hgtags, r.0 .0, r.0 .1)
                }
            };
            let hgtags = hgtags.as_ref().map_or(&b""[..], RawBlob::as_bytes);
            let oid_len =
                <<HgChangesetId as ObjectId>::Digest as OutputSizeUser>::output_size() * 2;
            let mut needed_size = oid_len + /* one space */ 1 + tag.len() + /* newline */ 1;
            if current_csid.is_some() {
                needed_size *= 2;
            }
            let missing_newline = hgtags.last().is_some_and(|c| *c != b'\n');
            if missing_newline {
                needed_size += 1;
            }
            let mut new_hgtags = Vec::with_capacity(hgtags.len() + needed_size);
            new_hgtags.extend_from_slice(hgtags);
            if missing_newline {
                new_hgtags.push(b'\n');
            }
            if let Some(current_csid) = current_csid {
                write!(&mut new_hgtags, "{current_csid}").unwrap();
                new_hgtags.push(b' ');
                new_hgtags.extend_from_slice(tag);
                new_hgtags.push(b'\n');
            }
            write!(&mut new_hgtags, "{new_csid}").unwrap();
            new_hgtags.push(b' ');
            new_hgtags.extend_from_slice(tag);
            new_hgtags.push(b'\n');

            let oid = store_git_blob(&new_hgtags);
            Either::Right(RecursedTreeEntry {
                oid: oid.into(),
                mode: FileMode::REGULAR | FileMode::RW,
            })
        })
    })
    .collect::<RawTree>();
    // Giving a reference is not useful, as the original tree is not
    // going to be in the same pack.
    let tree_id = store_git_tree(new_tree.as_bytes(), None);

    let mut buf = Vec::new();
    buf.extend_from_slice(b"tree ");
    buf.extend_from_slice(tree_id.to_string().as_bytes());
    if let Some(head) = head {
        buf.extend_from_slice(b"\nparent ");
        buf.extend_from_slice(head.to_string().as_bytes());
    }
    buf.extend_from_slice(b"\nauthor ");
    buf.extend_from_slice(&git_author_info());
    buf.extend_from_slice(b"\ncommitter ");
    buf.extend_from_slice(&git_committer_info());
    buf.extend_from_slice(b"\n\n");
    buf.extend_from_slice(&message.as_deref().map_or_else(
        || {
            let mut buf = Vec::new();
            buf.extend_from_slice(if delete {
                b"Removed tag "
            } else {
                b"Added tag "
            });
            buf.extend_from_slice(tag);
            if !delete {
                buf.extend_from_slice(b" for changeset ");
                buf.extend_from_slice(new_csid.abbrev(12).to_string().as_bytes());
            }
            buf.into()
        },
        |m| Cow::Borrowed(m.as_bytes()),
    ));
    let new_cid = store::store_git_commit(&buf);

    unsafe {
        do_cleanup(0);
    }

    if let Some(onto) = onto {
        // TODO: check that the branch is not checked out anywhere.
        let mut transaction = RefTransaction::new().unwrap();
        transaction
            .update(onto, new_cid, head, "git cinnabar tag")
            .unwrap();
        transaction.commit().unwrap();
        Ok(())
    } else {
        Command::new("git")
            .arg("merge")
            .arg(new_cid.to_string())
            .status()
            .expect("Failed to execute `git merge`")
            .success()
            .then_some(())
            .ok_or_else(|| "git merge failed".to_string())
    }
}
fn do_fetch(
    store: &mut Store,
    remote: &OsStr,
    revs: &[OsString],
    bundle: bool,
) -> Result<(), String> {
    set_progress(bundle || stdout().is_terminal());
    let url = remote::get(remote).get_url();
    let hg_url =
        hg_url(url).ok_or_else(|| format!("Invalid mercurial url: {}", url.to_string_lossy()))?;
    let mut conn = hg_connect::get_connection(&hg_url)
        .ok_or_else(|| format!("Failed to connect to {hg_url}"))?;
    if bundle {
        conn = Box::new(BundleSaverConnection(conn));
    }
    let supports_lookup = OnceCell::new();
    let revs = revs
        .iter()
        .map(|rev| match rev.to_string_lossy() {
            Cow::Borrowed(s) => match HgChangesetId::from_str(s) {
                Ok(h) => Ok(Either::Left(h)),
                Err(_)
                    if *supports_lookup
                        .get_or_init(|| conn.get_capability(b"lookup").is_some()) =>
                {
                    let result = conn.lookup(s);
                    let [success, data] = result
                        .trim_end_with(|b| b.is_ascii_whitespace())
                        .splitn_exact(b' ')
                        .expect("lookup command result is malformed");
                    if success == b"0" {
                        return Err(data.to_str_lossy().into_owned());
                    }
                    Ok(Either::Right(
                        data.to_str()
                            .ok()
                            .and_then(|d| HgChangesetId::from_str(d).ok())
                            .expect("lookup command result is malformed"),
                    ))
                }
                Err(_) => Err(format!(
                    "Remote repository does not support the \"lookup\" command. \
                    Cannot fetch {s}."
                )),
            },
            Cow::Owned(s) => Err(format!("Invalid character in revision: {s}")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let unknown = revs
        .iter()
        .filter_map(|r| r.left())
        .chunks(conn.sample_size())
        .into_iter()
        .find_map(|chunk| {
            let chunk = chunk.collect_vec();
            conn.known(&chunk)
                .iter()
                .zip(&chunk)
                .filter(|(known, _)| !**known)
                .map(|(_, h)| *h)
                .next()
        });
    if let Some(unknown) = unknown {
        return Err(format!("Unknown revision: {unknown}"));
    }
    let full_revs = revs.iter().map(|r| r.either(|h| h, |h| h)).collect_vec();

    check_graft_refs();

    let remote = Some(remote.to_str().unwrap())
        .and_then(|r| (!r.starts_with("hg://") && !r.starts_with("hg::")).then_some(r));

    maybe_init_graft(store, remote)?;

    let unknown_full_revs = full_revs
        .iter()
        .filter(|h| h.to_git(store).is_none())
        .copied()
        .collect_vec();

    if !unknown_full_revs.is_empty() {
        get_bundle(
            store,
            &mut *conn,
            &unknown_full_revs,
            None,
            &HashSet::new(),
            remote,
        )?;

        if !bundle {
            do_done_and_check(store, &[])
                .then_some(())
                .ok_or_else(|| "Fatal error".to_string())?;
        }
    }

    if !bundle {
        let url = url.to_string_lossy();
        let mut fetch_head = Vec::new();
        let width = full_revs
            .iter()
            .map(|rev| {
                let git_rev = rev.to_git(store).unwrap();
                writeln!(fetch_head, "{git_rev}\t\t'hg/revs/{rev}' of {url}").unwrap();
                get_unique_abbrev(git_rev).len()
            })
            .max()
            .unwrap()
            * 2
            + 3;
        let path = unsafe { CStr::from_ptr(git_path_fetch_head(the_repository)).to_osstr() };
        File::create(path)
            .and_then(|mut f| f.write(&fetch_head))
            .map_err(|e| e.to_string())?;

        eprintln!("From {url}");
        for rev in full_revs {
            eprintln!(" * {:width$} hg/revs/{} -> FETCH_HEAD", "branch", rev);
        }
    }
    Ok(())
}

fn do_fetch_tags() -> Result<(), String> {
    let cmd = Command::new("git")
        .arg("fetch")
        .arg("--tags")
        .arg("hg::tags:")
        .arg("tag")
        .arg("*")
        .status()
        .map_err(|e| e.to_string())?;
    if cmd.success() {
        Ok(())
    } else {
        Err("fetch failed".to_owned())
    }
}

fn get_previous_metadata(metadata: CommitId) -> Option<CommitId> {
    // TODO: fully parse the metadata commit.
    let commit = RawCommit::read(metadata)?;
    let commit = commit.parse()?;
    let num_parents = if commit
        .body()
        .split(|b| *b == b' ')
        .any(|f| f == b"files-meta")
    {
        6
    } else {
        5
    };
    let parents = commit.parents();
    if parents.len() == num_parents {
        Some(parents[num_parents - 1])
    } else {
        None
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct SetMetadataFlags: i32 {
        const FORCE = 0x1;
        const KEEP_REFS = 0x2;
    }
}

fn set_metadata_to(
    new_metadata: Option<CommitId>,
    flags: SetMetadataFlags,
    msg: &str,
) -> Result<Option<CommitId>, String> {
    let mut refs = HashMap::new();
    for_each_ref_in(REFS_PREFIX, |r, oid| {
        if flags.contains(SetMetadataFlags::KEEP_REFS)
            && (r.as_bytes().starts_with_str("refs/")
                || r.as_bytes().starts_with_str("hg/")
                || r == "HEAD")
        {
            return Ok(());
        }
        let mut full_ref = OsString::from(REFS_PREFIX);
        full_ref.push(r);
        if refs.insert(full_ref, oid).is_some() {
            return Err("Shouldn't have had conflicts in refs hashmap");
        }
        Ok(())
    })
    .map_err(|_| "Failed to enumerate refs/cinnabar/*")
    .unwrap();

    let mut broken = None;
    let mut checked = None;
    let mut metadata = None;

    let mut transaction = RefTransaction::new().unwrap();
    let mut replace_refs = HashMap::new();
    for (r, oid) in refs.into_iter() {
        match (new_metadata, &r) {
            (Some(_), _) if r == METADATA_REF => metadata = Some(oid),
            (Some(_), _) if r == CHECKED_REF => checked = Some(oid),
            (Some(_), _) if r == BROKEN_REF => broken = Some(oid),
            (Some(_), _) if r.as_bytes().starts_with(REPLACE_REFS_PREFIX.as_bytes()) => {
                replace_refs.insert(r, oid);
            }
            _ => {
                transaction.delete(r, Some(oid), msg)?;
            }
        }
    }

    let broken = broken;
    let checked = checked;
    let metadata = metadata;

    let notes = resolve_ref(NOTES_REF);

    if let Some(new) = new_metadata {
        #[derive(Debug, PartialEq)]
        enum MetadataState {
            Unknown,
            Broken,
            Checked,
        }

        let mut state = match metadata {
            Some(ref m) if Some(m) == broken.as_ref() => MetadataState::Broken,
            Some(ref m) if Some(m) == checked.as_ref() => MetadataState::Checked,
            _ => MetadataState::Unknown,
        };

        let mut m = metadata;
        let found = flags
            .contains(SetMetadataFlags::FORCE)
            .then(|| {
                state = MetadataState::Unknown;
                new
            })
            .or_else(|| {
                std::iter::from_fn(move || {
                    m = m.and_then(get_previous_metadata);
                    m
                })
                .try_find_(|&m| -> Result<_, String> {
                    if Some(m) == broken {
                        state = MetadataState::Broken;
                    } else if Some(m) == checked {
                        state = MetadataState::Checked;
                    } else if state == MetadataState::Broken {
                        // We don't know whether ancestors of broken metadata are broken.
                        state = MetadataState::Unknown;
                    }
                    Ok(m == new)
                })
                .ok()
                .flatten()
            })
            .ok_or_else(|| {
                format!("Cannot rollback to {new}, it is not in the ancestry of current metadata.")
            })?;
        // And just in case, check we got what we were looking for. Any error
        // should already have been returned by the `?` above.
        assert_eq!(found, new);

        match state {
            MetadataState::Checked => {
                transaction.update(CHECKED_REF, new, checked, msg)?;
            }
            MetadataState::Broken => transaction.update(BROKEN_REF, new, broken, msg)?,
            MetadataState::Unknown => {}
        }

        // TODO: fully parse the metadata commit. Also check earlier
        // (ideally before calling this function).
        let commit = RawCommit::read(new).unwrap();
        let commit = commit.parse().unwrap();
        if commit.author() != b" <cinnabar@git> 0 +0000" {
            return Err(format!("Invalid cinnabar metadata: {new}"));
        }
        transaction.update(METADATA_REF, new, metadata, msg)?;
        transaction.update(NOTES_REF, commit.parents()[3], notes, msg)?;
        for (path, item) in RawTree::read(commit.tree())
            .ok_or_else(|| format!("Failed to read metadata: {new}"))?
            .into_iter()
            .recurse()
            .map(WithPath::unzip)
        {
            // TODO: Check mode.
            // TODO: Check oid is valid.
            let mut replace_ref = REPLACE_REFS_PREFIX.to_owned();
            replace_ref.push_str(from_utf8(&path).unwrap());
            let replace_ref = OsString::from(replace_ref);
            transaction.update(
                &replace_ref,
                item.oid.try_into().unwrap(),
                replace_refs.remove(&replace_ref),
                msg,
            )?;
        }
        // Remove any remaining replace ref.
        for (r, oid) in replace_refs.into_iter() {
            transaction.delete(r, Some(oid), msg)?;
        }
    } else if let Some(notes) = notes {
        transaction.delete(NOTES_REF, Some(notes), msg)?;
    }
    transaction.commit()?;
    Ok(metadata)
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct r#ref([u8; 0]);

extern "C" {
    fn add_ref(tail: *mut *mut *mut r#ref, name: *const c_char, oid: *const object_id);

    fn add_symref(tail: *mut *mut *mut r#ref, name: *const c_char, sym: *const c_char);

    fn get_ref_map(remote: *const remote, remote_refs: *const r#ref) -> *mut r#ref;

    fn free_refs(r: *mut r#ref);

    fn get_next_ref(r: *const r#ref) -> *const r#ref;

    fn get_ref_name(r: *const r#ref) -> *const c_char;

    fn get_ref_peer_ref(r: *const r#ref) -> *const r#ref;

    fn get_stale_refs(r: *const remote, fetch_map: *const r#ref) -> *mut r#ref;

    fn repo_in_merge_bases(
        r: *mut repository,
        commit: *const commit,
        reference: *const commit,
    ) -> c_int;
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct worktree([u8; 0]);

extern "C" {
    fn term_columns() -> c_int;

    fn get_worktrees() -> *const *const worktree;

    fn free_worktrees(wt: *const *const worktree);

    fn get_worktree_git_dir(wt: *const worktree) -> *const c_char;

    fn get_worktree_path(wt: *const worktree) -> *const c_char;

    fn get_worktree_is_current(wt: *const worktree) -> c_int;

    fn get_worktree_is_detached(wt: *const worktree) -> c_int;

    fn get_worktree_head_oid(wt: *const worktree) -> *const object_id;

    fn get_worktree_ref_store(wr: *const worktree) -> *const libgit::ref_store;
}

fn do_reclone(store: &mut Store, rebase: bool) -> Result<(), String> {
    let mut heads = Vec::new();
    if rebase {
        for prefix in ["refs/tags/", "refs/heads/"] {
            // TODO: this doesn't handle tag objects, only tags that point directly to commits.
            // Ideally, we'd print out that we can't update those, but at the moment we can't
            // even enumerate them. We don't expect tag objects on cinnabar-produced commits,
            // though.
            for_each_ref_in(prefix, |refname, cid| -> Result<(), String> {
                let mut full_ref = OsString::from(prefix);
                full_ref.push(refname);
                heads.push((Either::Left(full_ref), cid));
                Ok(())
            })?;
        }
        unsafe {
            let worktrees = get_worktrees();
            let mut wt = worktrees;
            while !(*wt).is_null() {
                let git_dir = Path::new(CStr::from_ptr(get_worktree_git_dir(*wt)).to_osstr());
                if git_dir.join("BISECT_LOG").exists() {
                    let err = if get_worktree_is_current(*wt) != 0 {
                        "Can't reclone: bisect in progress.".to_string()
                    } else {
                        let path = PathBuf::from(CStr::from_ptr(get_worktree_path(*wt)).to_osstr());
                        format!("Can't reclone: bisect in progress in {}.", path.display())
                    };
                    free_worktrees(worktrees);
                    return Err(err);
                }
                if git_dir.join("rebase-apply").exists() || git_dir.join("rebase-merge").exists() {
                    let err = if get_worktree_is_current(*wt) != 0 {
                        "Can't reclone: rebase in progress.".to_string()
                    } else {
                        let path = PathBuf::from(CStr::from_ptr(get_worktree_path(*wt)).to_osstr());
                        format!("Can't reclone: rebase in progress in {}.", path.display())
                    };
                    free_worktrees(worktrees);
                    return Err(err);
                }
                if get_worktree_is_detached(*wt) == 1 {
                    heads.push((
                        Either::Right((get_worktree_is_current(*wt) == 0).then(|| {
                            (
                                get_worktree_ref_store(*wt).as_ref().unwrap(),
                                PathBuf::from(CStr::from_ptr(get_worktree_path(*wt)).to_osstr()),
                            )
                        })),
                        CommitId::from_raw_bytes((*get_worktree_head_oid(*wt)).as_raw_bytes())
                            .unwrap(),
                    ));
                }
                wt = wt.add(1);
            }

            free_worktrees(worktrees);
        }
    }

    let old_changesets_oid = store.changesets_cid;
    let current_metadata_oid = store.metadata_cid;
    let old_store = store;
    let mut store = Store::new(None);
    store.metadata_cid = current_metadata_oid;

    check_graft_refs();

    maybe_init_graft(&store, None)?;

    let old_to_hg = |cid| GitChangesetId::from_unchecked(cid).to_hg(old_store);

    let mut update_refs_by_category = Vec::new();

    for_each_remote(|remote| {
        if remote.skip_default_update() {
            return Ok(());
        }
        let url = match hg_url(remote.get_url()) {
            Some(url) if url.scheme() == "tags" => return Ok(()),
            Some(url) => url,
            None => return Ok(()),
        };
        println!("Fetching {}", remote.name().unwrap().to_string_lossy());
        let mut conn = get_connection(&url).unwrap();
        let info = repo_list(
            Some(&store),
            &mut *conn,
            remote.name().and_then(|s| s.to_str()),
            false,
        );

        let mut ref_map: *mut r#ref = std::ptr::null_mut();
        let mut tail = &mut ref_map as *mut _;

        for (refname, (_, cid)) in info.refs.iter() {
            let refname = CString::new(refname.to_vec()).unwrap();
            unsafe {
                add_ref(
                    &mut tail,
                    refname.as_ptr(),
                    cid.map(object_id::from)
                        .as_ref()
                        .map_or(std::ptr::null(), |cid| cid as *const _),
                );
            }
        }
        let mut wanted_refs = Vec::new();
        let mut update_refs = Vec::new();

        unsafe {
            if let Some(head_ref) = &info.head_ref {
                let symref = CString::new(head_ref.to_vec()).unwrap();
                add_symref(&mut tail, cstr!("HEAD").as_ptr(), symref.as_ptr());
            }

            let refs = get_ref_map(remote, ref_map);
            free_refs(ref_map);
            let mut r = refs as *const r#ref;

            while !r.is_null() {
                let refname = CStr::from_ptr(get_ref_name(r)).to_bytes().as_bstr();
                let peer_ref = get_ref_peer_ref(r);
                if !peer_ref.is_null() {
                    let peer_ref = CStr::from_ptr(get_ref_name(peer_ref))
                        .to_bytes()
                        .as_bstr()
                        .to_boxed();
                    let (csid, cid) = info.refs.get(refname).unwrap();
                    wanted_refs.push((refname.to_boxed(), peer_ref, *csid, *cid));
                }
                r = get_next_ref(r);
            }
            let stale_refs = get_stale_refs(remote, refs);
            r = stale_refs;
            while !r.is_null() {
                let refname = CStr::from_ptr(get_ref_name(r)).to_bytes().as_bstr();
                update_refs.push((Either::Left(refname.to_boxed()), None, None, None));
                r = get_next_ref(r);
            }
            free_refs(refs);
        }
        let unknown_wanted_heads = wanted_refs
            .iter()
            .filter(|(_, _, _, cid)| cid.is_none())
            .map(|(_, _, csid, _)| *csid)
            .unique()
            .collect_vec();

        if !unknown_wanted_heads.is_empty() {
            get_bundle(
                &mut store,
                &mut *conn,
                &unknown_wanted_heads,
                Some(&info.topological_heads),
                &info.branch_names,
                remote.name().and_then(|n| n.to_str()),
            )?;
        }

        for (refname, peer_ref, csid, cid) in wanted_refs.into_iter().unique() {
            let old_cid = resolve_ref(OsStr::from_bytes(&peer_ref));
            let cid = Some(CommitId::from(
                cid.unwrap_or_else(|| csid.to_git(&store).unwrap()),
            ));
            if old_cid != cid {
                update_refs.push((Either::Left(peer_ref), Some(refname), cid, old_cid));
            }
        }
        if !update_refs.is_empty() {
            update_refs_by_category.push((
                format!("From {}", remote.get_url().to_string_lossy()),
                update_refs,
            ));
        }
        Ok(())
    })
    .and_then(|()| {
        // If all the changesets we had in store weren't pulled from the remotes
        // above, try fetching them from skip-default-update remotes.
        if old_changesets_oid.is_null() {
            return Ok(());
        }
        let old_changeset_heads = RawCommit::read(old_changesets_oid).unwrap();
        let old_changeset_heads = old_changeset_heads.parse().unwrap();
        let mut unknowns = old_changeset_heads
            .parents()
            .iter()
            .copied()
            .zip(
                // Yes, this reads the commit one more time. We need better APIs.
                ChangesetHeads::from_metadata(old_changesets_oid)
                    .heads()
                    .copied(),
            )
            .filter(|(_, csid)| csid.to_git(&store).is_none())
            .collect_vec();

        for_each_remote(|remote| {
            if unknowns.is_empty() || !remote.skip_default_update() {
                return Ok(());
            }
            let url = match hg_url(remote.get_url()) {
                Some(url) if url.scheme() == "tags" => return Ok(()),
                Some(url) => url,
                None => return Ok(()),
            };
            println!("Fetching {}", remote.name().unwrap().to_string_lossy());
            let mut conn = get_connection(&url).unwrap();

            let knowns = unknowns
                .chunks(conn.sample_size())
                .map(|unknowns| {
                    conn.known(&unknowns.iter().map(|(_, csid)| *csid).collect_vec())
                        .into_vec()
                        .into_iter()
                })
                .collect_vec();

            let (knowns, u): (Vec<_>, Vec<_>) = unknowns
                .drain(..)
                .zip(knowns.into_iter().flatten())
                .partition_map(|(ids, known)| {
                    if known {
                        Either::Left(ids)
                    } else {
                        Either::Right(ids)
                    }
                });
            unknowns = u;
            if !knowns.is_empty() {
                get_bundle(
                    &mut store,
                    &mut *conn,
                    &knowns.iter().map(|(_, csid)| *csid).collect_vec(),
                    None,
                    &HashSet::new(),
                    Some(remote.name().unwrap().to_str().unwrap()),
                )?;
                let update_refs = knowns
                    .into_iter()
                    .filter_map(|(old_cid, csid)| {
                        csid.to_git(&store)
                            .and_then(|cid| (cid != old_cid).then(|| (old_cid, cid.into(), csid)))
                    })
                    .map(|(old_cid, cid, csid)| {
                        (
                            Either::Left(b"(none)".as_bstr().to_boxed()),
                            Some(
                                format!("hg/revs/{csid}")
                                    .into_bytes()
                                    .into_boxed_slice()
                                    .into(),
                            ),
                            Some(cid),
                            Some(old_cid),
                        )
                    })
                    .collect_vec();
                if !update_refs.is_empty() {
                    update_refs_by_category.push((
                        format!("From {}", remote.get_url().to_string_lossy()),
                        update_refs,
                    ));
                }
            }
            Ok(())
        })
    })
    .and_then(|()| {
        let mut to_rewrite = if rebase && !old_changesets_oid.is_null() {
            let mut args = vec!["--full-history".to_string(), "--topo-order".to_string()];
            for (_, cid) in &heads {
                args.push(cid.to_string());
            }
            args.push("--not".to_string());
            args.push(old_changesets_oid.to_string());
            rev_list(args).collect_vec()
        } else {
            Vec::new()
        };

        let mut rewritten = BTreeMap::new();

        while let Some(cid) = to_rewrite.pop() {
            let commit = RawCommit::read(cid).unwrap();
            let commit = commit.parse().unwrap();
            let (new_parents, need_parents): (Vec<_>, Vec<_>) = commit
                .parents()
                .iter()
                .map(|p| {
                    if let Some(p) = rewritten.get(p) {
                        (*p, None)
                    } else {
                        old_to_hg(*p).map_or((None, Some(*p)), |csid| {
                            let new_cid =
                                csid.to_git(&store).map(CommitId::from).filter(|new_cid| {
                                    p == new_cid || p.get_tree_id() == new_cid.get_tree_id()
                                });
                            (new_cid, None)
                        })
                    }
                })
                .unzip();
            let new_parents = new_parents.into_iter().flatten().collect_vec();
            let need_parents = need_parents.into_iter().flatten().collect_vec();
            if !need_parents.is_empty() {
                to_rewrite.push(cid);
                for p in need_parents.into_iter() {
                    to_rewrite.push(p);
                }
                continue;
            }
            if new_parents == commit.parents() {
                assert!(rewritten.insert(cid, Some(cid)).is_none());
            } else if new_parents.len() == commit.parents().len() {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"tree ");
                buf.extend_from_slice(commit.tree().to_string().as_bytes());
                for p in new_parents {
                    buf.extend_from_slice(b"\nparent ");
                    buf.extend_from_slice(p.to_string().as_bytes());
                }
                buf.extend_from_slice(b"\nauthor ");
                buf.extend_from_slice(commit.author());
                buf.extend_from_slice(b"\ncommitter ");
                buf.extend_from_slice(commit.committer());
                buf.extend_from_slice(b"\n\n");
                buf.extend_from_slice(commit.body());
                let new_cid = store::store_git_commit(&buf);
                assert!(rewritten.insert(cid, Some(new_cid)).is_none());
            } else {
                assert!(rewritten.insert(cid, None).is_none());
            }
        }

        let (update_refs, cant_update_refs): (Vec<_>, Vec<_>) = heads
            .into_iter()
            .filter_map(|(refname_or_head, old_cid)| {
                let cid = rewritten.get(&old_cid).and_then(Clone::clone).or_else(|| {
                    old_to_hg(old_cid)
                        .and_then(|cid| cid.to_git(&store))
                        .map(Into::into)
                });
                (Some(old_cid) != cid).then_some((refname_or_head, old_cid, cid))
            })
            .partition_map(|(refname_or_head, old_cid, cid)| {
                if let Some(cid) = cid {
                    Either::Left((refname_or_head, old_cid, cid))
                } else {
                    Either::Right(refname_or_head)
                }
            });
        for (category, update_refs) in
            &update_refs.into_iter().chunk_by(|(refname_or_head, _, _)| {
                if let Either::Left(refname) = refname_or_head {
                    if refname.as_bytes().starts_with(b"refs/tags/") {
                        "Rebased tags"
                    } else if refname.as_bytes().starts_with(b"refs/heads/") {
                        "Rebase branches"
                    } else {
                        unreachable!();
                    }
                } else {
                    "Rebased detached heads"
                }
            })
        {
            let update_refs = update_refs
                .map(|(refname_or_head, old_cid, cid)| {
                    let peer_ref =
                        refname_or_head.map_left(|refname| refname.as_bytes().as_bstr().to_boxed());
                    let refname = peer_ref
                        .as_ref()
                        .either(Clone::clone, |_| b"HEAD".as_bstr().to_boxed());
                    (peer_ref, Some(refname), Some(cid), Some(old_cid))
                })
                .collect_vec();
            update_refs_by_category.push((category.to_string(), update_refs));
        }

        store.metadata_cid = current_metadata_oid;

        do_done_and_check(&mut store, &[])
            .then_some(())
            .ok_or_else(|| "Fatal error".to_string())?;
        let mut transaction = RefTransaction::new().unwrap();
        let mut other_transactions = Vec::new();
        let mut out = Vec::new();
        for (category, update_refs) in update_refs_by_category {
            writeln!(out, "{category}").unwrap();
            let update_refs = update_refs
                .into_iter()
                .sorted_by(|(peer_ref_a, _, _, _), (peer_ref_b, _, _, _)| {
                    match (peer_ref_a, peer_ref_b) {
                        (Either::Left(refname_a), Either::Left(refname_b)) => {
                            Ord::cmp(refname_a, refname_b)
                        }
                        (Either::Left(_), Either::Right(_)) => Ordering::Less,
                        (Either::Right(_), Either::Left(_)) => Ordering::Greater,
                        (Either::Right(None), Either::Right(None)) => Ordering::Equal,
                        (Either::Right(Some(_)), Either::Right(None)) => Ordering::Less,
                        (Either::Right(None), Either::Right(Some(_))) => Ordering::Greater,
                        (Either::Right(Some((_, path_a))), Either::Right(Some((_, path_b)))) => {
                            Ord::cmp(path_a, path_b)
                        }
                    }
                })
                .map(|(peer_ref, refname, cid, old_cid)| {
                    fn get_pretty_refname(r: &BStr) -> Box<str> {
                        r.strip_prefix(b"refs/heads/")
                            .or_else(|| r.strip_prefix(b"refs/tags/"))
                            .or_else(|| r.strip_prefix(b"refs/remotes/"))
                            .unwrap_or(r)
                            .to_str_lossy()
                            .into()
                    }
                    let pretty_refname = refname.as_ref().map(|r| get_pretty_refname(r).to_boxed());
                    let pretty_peer_ref = peer_ref.as_ref().either(
                        |peer_ref| get_pretty_refname(peer_ref).to_boxed(),
                        |head| {
                            if let Some((_, path)) = head {
                                format!("HEAD [{}]", path.display()).to_boxed()
                            } else {
                                "HEAD".to_boxed()
                            }
                        },
                    );
                    let abbrev_cid = cid.map(get_unique_abbrev);
                    let abbrev_old_cid = old_cid.map(get_unique_abbrev);
                    (
                        (peer_ref, pretty_peer_ref),
                        (refname, pretty_refname),
                        (cid, abbrev_cid),
                        (old_cid, abbrev_old_cid),
                    )
                })
                .collect_vec();
            let width = update_refs
                .iter()
                .filter_map(|(_, _, (_, cid), (_, old_cid))| {
                    cid.map(|c| c.len())
                        .into_iter()
                        .chain((old_cid.map(|c| c.len())).into_iter())
                        .max()
                })
                .max()
                .unwrap_or(7)
                * 2
                + 3;
            let term_columns = unsafe { term_columns() as usize };
            let refwidth = update_refs
                .iter()
                .filter_map(|((_, p), (_, r), _, _)| {
                    let width = r.as_ref().map_or(0, |r| r.len());
                    (width <= term_columns.saturating_sub(width + p.len() + 25)).then_some(width)
                })
                .max()
                .unwrap_or(0);
            for (
                (peer_ref, pretty_peer_ref),
                (refname, pretty_refname),
                (cid, abbrev_cid),
                (old_cid, abbrev_old_cid),
            ) in update_refs
            {
                if let Some(pretty_refname) = &pretty_refname {
                    let abbrev_cid = abbrev_cid.unwrap();
                    let cid = cid.unwrap();
                    let (code, from_to, extra, msg) = if let Some(abbrev_old_cid) = abbrev_old_cid {
                        let old_cid = old_cid.unwrap();
                        let old_commit = unsafe { lookup_commit(the_repository, &old_cid.into()) };
                        let commit = unsafe { lookup_commit(the_repository, &cid.into()) };
                        if unsafe { repo_in_merge_bases(the_repository, commit, old_commit) } == 0 {
                            (
                                '+',
                                format!("{abbrev_old_cid}...{abbrev_cid}"),
                                "  (forced update)",
                                "forced-update",
                            )
                        } else {
                            (
                                ' ',
                                format!("{abbrev_old_cid}..{abbrev_cid}"),
                                "",
                                "fast-forward",
                            )
                        }
                    } else {
                        ('*', "[new branch]".to_string(), "", "storing head")
                    };
                    writeln!(
                        out,
                        " {code} {from_to:width$} {pretty_refname:refwidth$} -> {pretty_peer_ref}{extra}"
                    )
                    .unwrap();
                    let msg = format!("cinnabar reclone: {msg}");
                    match &peer_ref {
                        Either::Left(peer_ref) => {
                            if !refname.unwrap().starts_with(b"hg/revs/") {
                                transaction
                                    .update(OsStr::from_bytes(peer_ref), cid, old_cid, &msg)
                                    .unwrap();
                            }
                        }
                        Either::Right(None) => {
                            transaction.update("HEAD", cid, old_cid, &msg).unwrap();
                        }
                        Either::Right(Some((rs, _))) => {
                            let mut transaction = RefTransaction::new_with_ref_store(rs).unwrap();
                            transaction.update("HEAD", cid, old_cid, &msg).unwrap();
                            other_transactions.push(transaction);
                        }
                    }
                } else {
                    writeln!(
                        out,
                        " - {:width$} {:refwidth$} -> {}",
                        "[deleted]", "(none)", pretty_peer_ref
                    )
                    .unwrap();
                    transaction
                        .delete(
                            OsStr::from_bytes(&peer_ref.left().unwrap()),
                            old_cid,
                            "cinnabar reclone: prune",
                        )
                        .unwrap();
                };
            }
        }
        transaction.commit().unwrap();
        for transaction in other_transactions {
            transaction.commit().unwrap();
        }
        stderr().write_all(&out).unwrap();
        if !cant_update_refs.is_empty() {
            eprintln!("Could not rewrite the following refs:");
            for refname_or_head in cant_update_refs {
                match refname_or_head {
                    Either::Left(refname) => eprintln!("   {}", refname.as_bytes().as_bstr()),
                    Either::Right(None) => eprintln!("   HEAD"),
                    Either::Right(Some((_, path))) => eprintln!("   HEAD [{}]", path.display()),
                }
            }
            eprintln!("They may still be based on the old remote branches.");
        }
        Ok(())
    })
    .map(|()| {
        *old_store = store;
        if !rebase {
            // TODO: Avoid showing this message when we detect there is nothing
            // to rebase.
            println!("Please note that reclone left your local branches untouched.");
            println!("They may be based on entirely different commits.");
            println!("If that is the case, you can try to fix them automatically by running");
            println!("the two following commands:");
            println!("  git cinnabar rollback");
            println!("  git cinnabar reclone --rebase");
        }
    })
}

fn do_rollback(
    candidates: bool,
    fsck: bool,
    force: bool,
    committish: Option<OsString>,
) -> Result<(), String> {
    let metadata = resolve_ref(METADATA_REF);
    if candidates {
        assert!(committish.is_none());
        assert!(!fsck);
        assert!(!force);
        let labels = [
            ("current", metadata),
            ("checked", resolve_ref(CHECKED_REF)),
            ("broken", resolve_ref(BROKEN_REF)),
        ];
        let labels = labels
            .iter()
            .filter_map(|(name, cid)| Some((*name, (*cid)?)))
            .collect_vec();
        let mut metadata = metadata;
        while let Some(m) = metadata {
            print!("{m}");
            let matched_labels = labels
                .iter()
                .filter_map(|(name, cid)| (*cid == m).then_some(*name))
                .collect_vec()
                .join(", ");
            if !matched_labels.is_empty() {
                print!(" ({matched_labels})");
            }
            println!();
            metadata = get_previous_metadata(m);
        }
        return Ok(());
    }

    let wanted_metadata = if fsck {
        assert!(committish.is_none());
        if let Some(oid) = resolve_ref(CHECKED_REF) {
            Some(oid)
        } else {
            return Err("No successful fsck has been recorded. Cannot rollback.".to_string());
        }
    } else if let Some(committish) = committish {
        if *committish == *CommitId::NULL.to_string() {
            None
        } else {
            Some(
                get_oid_committish(committish.as_bytes())
                    .ok_or_else(|| format!("Invalid revision: {}", committish.to_string_lossy()))?,
            )
        }
    } else if let Some(oid) = metadata {
        get_previous_metadata(oid)
    } else {
        return Err("Nothing to rollback.".to_string());
    };
    let flags = if force {
        SetMetadataFlags::FORCE
    } else {
        SetMetadataFlags::empty()
    };
    set_metadata_to(wanted_metadata, flags, "rollback").map(|_| ())
}

#[allow(clippy::unnecessary_wraps)]
fn do_strip(store: &mut Store, committish: Vec<OsString>) -> Result<(), String> {
    if committish.is_empty() {
        return Ok(());
    }
    let committish = committish
        .into_iter()
        .map(|c| {
            get_oid_committish(c.as_bytes())
                .or_else(|| {
                    Abbrev::<HgChangesetId>::from_bytes(c.as_bytes())
                        .ok()
                        .and_then(|cs| cs.to_git(store).map(Into::into))
                })
                .map(lookup_replace_commit)
                .map(GitChangesetId::from_unchecked)
                .ok_or_else(|| format!("bad revision '{}'", c.as_bytes().as_bstr()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let args = ["--ancestry-path".to_string(), format!("{METADATA_REF}^^@")]
        .into_iter()
        .chain(committish.iter().map(|c| format!("^{c}")));

    for (c, boundary) in rev_list_with_boundaries(args) {
        let cid = GitChangesetId::from_unchecked(c);
        if let Some(csid) = cid.to_hg(store) {
            let strip = match boundary {
                MaybeBoundary::Boundary => committish.contains(&cid),
                MaybeBoundary::Commit => true,
                _ => false,
            };
            if strip {
                store.set(SetWhat::ChangesetMeta, csid.into(), GitObjectId::NULL);
                store.set(SetWhat::Changeset, csid.into(), GitObjectId::NULL);
            }
        }
    }

    let mut changeset_heads = ChangesetHeads::new();

    for (c, parents) in rev_list_with_parents([
        "--full-history".to_string(),
        "--reverse".to_string(),
        "--topo-order".to_string(),
        format!("{METADATA_REF}^^@"),
    ]) {
        let cid = GitChangesetId::from_unchecked(c);
        if let Some(metadata) = RawGitChangesetMetadata::read(store, cid) {
            let metadata = metadata.parse().unwrap();
            let csid = metadata.changeset_id();

            let parents = parents
                .iter()
                .map(|p| {
                    GitChangesetId::from_unchecked(lookup_replace_commit(*p))
                        .to_hg(store)
                        .unwrap()
                })
                .collect_vec();
            changeset_heads.add(
                csid,
                &parents,
                metadata
                    .extra()
                    .and_then(|e| e.get(b"branch"))
                    .unwrap_or(b"default")
                    .as_bstr(),
            );
        }
    }

    set_changeset_heads(store, changeset_heads);

    do_done_and_check(store, &[])
        .then_some(())
        .ok_or_else(|| "Fatal error".to_string())
}

#[allow(clippy::unnecessary_wraps)]
fn do_upgrade() -> Result<(), String> {
    // If we got here, init_cinnabar_2/init_metadata went through,
    // which means we didn't die because of unusable metadata.
    // There are currently no conditions that will require an upgrade.
    warn!(target: "root", "No metadata to upgrade");
    Ok(())
}

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        const REMOTE_HG_BINARY: &str = "git-remote-hg.exe";
    } else {
        const REMOTE_HG_BINARY: &str = "git-remote-hg";
    }
}

#[cfg(all(feature = "self-update", windows))]
const BINARY: &str = "git-cinnabar.exe";
#[cfg(all(feature = "self-update", not(windows)))]
const BINARY: &str = "git-cinnabar";

#[cfg(feature = "self-update")]
fn do_self_update(
    branch: Option<String>,
    exact: Option<VersionInfo>,
    url: bool,
) -> Result<(), String> {
    assert!(!(branch.is_some() && exact.is_some()));
    #[cfg(windows)]
    const FINISH_SELF_UPDATE: &str = "GIT_CINNABAR_FINISH_SELF_UPDATE";
    #[cfg(windows)]
    const FINISH_SELF_UPDATE_PARENT: &str = "GIT_CINNABAR_FINISH_SELF_UPDATE_PARENT";

    #[cfg(windows)]
    if let Some(old_path) = std::env::var_os(FINISH_SELF_UPDATE) {
        use Win32::Foundation::HANDLE;
        let handle =
            usize::from_str(&std::env::var(FINISH_SELF_UPDATE_PARENT).unwrap()).unwrap() as HANDLE;
        unsafe {
            Win32::System::Threading::WaitForSingleObject(
                handle,
                Win32::System::Threading::INFINITE,
            );
        }
        std::fs::remove_file(old_path).ok();
        return Ok(());
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_dir = exe.parent().unwrap();
    let version = if let Some(exact) = exact {
        let v0_6 = Version::parse("0.6.0-rc.1").unwrap();
        find_version(exact.clone())
            .or_else(|| matches!(exact, VersionInfo::Commit(_)).then_some(exact))
            .filter(|info| match info {
                VersionInfo::Tagged(v, _) => v >= &v0_6,
                _ => true,
            })
    } else {
        version_check::check_new_version(
            branch
                .as_ref()
                .map_or_else(VersionRequest::default, |b| VersionRequest::from(&**b)),
        )
    };
    if url {
        if let Some(version) = version {
            println!("{}", GitCinnabarBuild::url(version));
        }
        return Ok(());
    }
    if let Some(version) = version {
        let mut tmpbuilder = tempfile::Builder::new();
        tmpbuilder.prefix(BINARY);
        let mut tmpfile = tmpbuilder.tempfile_in(exe_dir).map_err(|e| e.to_string())?;
        download_build(version, &mut tmpfile)?;
        tmpfile.flush().map_err(|e| e.to_string())?;
        let old_exe = tmpbuilder.tempfile_in(exe_dir).map_err(|e| e.to_string())?;
        let old_exe_path = old_exe.path().to_path_buf();
        old_exe.close().map_err(|e| e.to_string())?;
        std::fs::rename(&exe, &old_exe_path).map_err(|e| e.to_string())?;
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = tmpfile.as_file_mut();
            let mut perms = file.metadata().map_err(|e| e.to_string())?.permissions();
            let mode = perms.mode();
            perms.set_mode(mode | ((mode & 0o444) >> 2));
            file.set_permissions(perms).map_err(|e| e.to_string())?;
        }
        tmpfile.persist(&exe).map_err(|e| e.to_string())?;
        let remote_hg_exe = exe_dir.join(REMOTE_HG_BINARY);
        if let Ok(metadata) = std::fs::symlink_metadata(&remote_hg_exe) {
            if !metadata.is_symlink() {
                std::fs::copy(&exe, &remote_hg_exe).map_err(|e| e.to_string())?;
            }
        }
        #[cfg(windows)]
        {
            use Win32::Foundation::HANDLE;
            let mut handle: HANDLE = std::ptr::null_mut();
            let curproc = unsafe { Win32::System::Threading::GetCurrentProcess() };
            if unsafe {
                Win32::Foundation::DuplicateHandle(
                    curproc,
                    curproc,
                    curproc,
                    &mut handle,
                    /* dwDesiredAccess */ 0,
                    /* bInheritHandle */ 1,
                    Win32::Foundation::DUPLICATE_SAME_ACCESS,
                )
            } != 0
            {
                std::mem::forget(
                    Command::new(exe)
                        .arg("self-update")
                        .env(FINISH_SELF_UPDATE, old_exe_path)
                        .env(FINISH_SELF_UPDATE_PARENT, format!("{}", handle as usize))
                        .spawn(),
                );
            }
        }
        #[cfg(not(windows))]
        std::fs::remove_file(old_exe_path).ok();
    } else {
        warn!(target: "root", "Did not find an update to install.");
    }
    Ok(())
}

#[cfg(feature = "self-update")]
enum GitCinnabarBuild {
    Executable(String),
    Archive(String),
}

#[cfg(feature = "self-update")]
impl GitCinnabarBuild {
    fn new(version: VersionInfo) -> Self {
        use concat_const::concat as cat;
        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "x86_64", target_os = "linux"))] {
                const SYSTEM_MACHINE: &str = "linux.x86_64";
            } else if #[cfg(all(target_arch = "aarch64", target_os = "linux"))] {
                const SYSTEM_MACHINE: &str = "linux.arm64";
            } else if #[cfg(all(target_arch = "x86_64", target_os = "macos"))] {
                const SYSTEM_MACHINE: &str = "macos.x86_64";
            } else if #[cfg(all(target_arch = "aarch64", target_os = "macos"))] {
                const SYSTEM_MACHINE: &str = "macos.arm64";
            } else if #[cfg(all(target_arch = "x86_64", target_os = "windows"))] {
                const SYSTEM_MACHINE: &str = "windows.x86_64";
            } else {
                compile_error!("self-update is not supported on this platform");
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(windows)] {
                const ARCHIVE_EXT: &str = "zip";
            } else {
                const ARCHIVE_EXT: &str = "tar.xz";
            }
        }

        match version {
            VersionInfo::Commit(cid) => {
                const URL_BASE: &str =
                "https://community-tc.services.mozilla.com/api/index/v1/task/project.git-cinnabar.build.";
                const URL_TAIL: &str = cat!(".", SYSTEM_MACHINE, "/artifacts/public/", BINARY);
                GitCinnabarBuild::Executable(format!("{URL_BASE}{cid}{URL_TAIL}"))
            }
            VersionInfo::Tagged(version, _) => {
                let tag = version.as_tag();
                const URL_BASE: &str = cat!(CARGO_PKG_REPOSITORY, "/releases/download/");
                const URL_TAIL: &str = cat!("/git-cinnabar.", SYSTEM_MACHINE, ".", ARCHIVE_EXT);
                GitCinnabarBuild::Archive(format!("{URL_BASE}{tag}{URL_TAIL}"))
            }
        }
    }

    fn url(version: VersionInfo) -> String {
        match Self::new(version) {
            GitCinnabarBuild::Archive(url) => url,
            GitCinnabarBuild::Executable(url) => url,
        }
    }
}

#[cfg(feature = "self-update")]
fn download_build(version: VersionInfo, tmpfile: &mut impl Write) -> Result<(), String> {
    use crate::hg_connect_http::HttpRequest;

    let request = |url: &str| {
        eprintln!("Installing update from {url}");
        let mut req = HttpRequest::new(Url::parse(url).map_err(|e| e.to_string())?);
        req.follow_redirects(true);
        req.set_log_target("raw-wire::self-update".to_string());
        req.execute()
    };

    match GitCinnabarBuild::new(version) {
        GitCinnabarBuild::Executable(url) => {
            let mut response = request(&url)?;
            std::io::copy(&mut response, tmpfile)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        GitCinnabarBuild::Archive(url) => {
            let mut extracted = false;
            #[cfg(windows)]
            {
                let mut response = request(&url)?;
                while let Some(ref mut file) =
                    zip::read::read_zipfile_from_stream(&mut response).map_err(|e| e.to_string())?
                {
                    if file.is_file()
                        && file
                            .enclosed_name()
                            .is_some_and(|p| p.file_name().unwrap() == BINARY)
                    {
                        std::io::copy(file, tmpfile).map_err(|e| e.to_string())?;
                        extracted = true;
                        break;
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let mut archive = tar::Archive::new(xz2::read::XzDecoder::new(request(&url)?));
                for file in archive.entries().map_err(|e| e.to_string())? {
                    let mut file = file.map_err(|e| e.to_string())?;
                    let header = file.header();
                    if header.entry_type() == tar::EntryType::Regular
                        && header
                            .path()
                            .map_err(|e| e.to_string())?
                            .file_name()
                            .unwrap()
                            == BINARY
                    {
                        std::io::copy(&mut file, tmpfile).map_err(|e| e.to_string())?;
                        extracted = true;
                        break;
                    }
                }
            }
            if extracted {
                Ok(())
            } else {
                use concat_const::concat as cat;
                Err(cat!(
                    "Could not find the ",
                    BINARY,
                    " executable in the downloaded archive."
                )
                .to_string())
            }
        }
    }
}

fn do_setup() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let remote_hg_exe = exe.with_file_name(REMOTE_HG_BINARY);
    if let Ok(metadata) = std::fs::symlink_metadata(&remote_hg_exe) {
        if !metadata.is_symlink() {
            std::fs::copy(&exe, &remote_hg_exe).map_err(|e| e.to_string())?;
        }
    } else {
        cfg_if::cfg_if! {
            if #[cfg(windows)] {
                use std::os::windows::fs::symlink_file;
                use Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;
                match symlink_file(&exe, &remote_hg_exe) {
                    Err(e) if e.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD as i32) => {
                        std::fs::copy(&exe, &remote_hg_exe).map(|_| ())
                    }
                    x => x,
                }
                .map_err(|e| e.to_string())?;
            } else {
                use std::os::unix::fs::symlink;
                symlink(&exe, &remote_hg_exe).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn do_data_file(store: &Store, rev: Abbrev<HgFileId>) -> Result<(), String> {
    let mut stdout = stdout();
    let file_id = rev
        .to_git(store)
        .ok_or_else(|| format!("Unknown file id: {rev}"))?;
    let metadata_id = store
        .files_meta_mut()
        .get_note_abbrev(rev)
        .map(|oid| GitFileMetadataId::from_unchecked(BlobId::from_unchecked(oid)));
    let file = RawHgFile::read(file_id, metadata_id).unwrap();
    stdout.write_all(&file).map_err(|e| e.to_string())
}

pub fn graft_config_enabled(remote: Option<&str>) -> Result<Option<Either<bool, Url>>, String> {
    get_config_remote("graft", remote)
        .map(|v| {
            v.into_string().and_then(|v| {
                bool::from_str(&v)
                    .map(Either::Left)
                    .or_else(|_| Url::parse(&v).map(Either::Right))
                    .map_err(|_| v.into())
            })
        })
        .transpose()
        // TODO: This should report the environment variable is that's what was used.
        .map_err(|e| format!("Invalid value for cinnabar.graft: {}", e.to_string_lossy()))
}

fn do_unbundle(store: &mut Store, clonebundle: bool, mut url: OsString) -> Result<(), String> {
    if !url.as_bytes().starts_with(b"hg:") {
        let mut new_url = OsString::from("hg::");
        new_url.push(url);
        url = new_url;
    }
    let mut url = hg_url(&url).unwrap();
    if !["http", "https", "file"].contains(&url.scheme()) {
        Err(format!("{} urls are not supported.", url.scheme()))?;
    }
    maybe_init_graft(store, None)?;
    let mut conn = if clonebundle {
        let mut conn = get_connection(&url).unwrap();
        if conn.get_capability(b"clonebundles").is_none() {
            Err("Repository does not support clonebundles")?;
        }
        url = get_clonebundle_url(&mut *conn).ok_or("Repository didn't provide a clonebundle")?;
        // Release the connection now, so that its cleanup doesn't conflict
        // with get_bundle_connection.  Yes, this API sucks.
        std::mem::drop(conn);
        eprintln!("Getting clone bundle from {url}");
        get_bundle_connection(&url).unwrap()
    } else {
        get_connection(&url).unwrap()
    };

    if !has_metadata(store) && matches!(graft_config_enabled(None), Ok(Some(Either::Right(_)))) {
        init_graft(store, true);
    }

    get_store_bundle(store, &mut *conn, &[], &[])
        .map_err(|e| String::from_utf8_lossy(&e).into_owned())?;

    do_done_and_check(store, &[])
        .then_some(())
        .ok_or_else(|| "Fatal error".to_string())
}

fn do_bundle(
    store: &Store,
    version: u8,
    bundlespec: Option<BundleSpec>,
    path: PathBuf,
    mut revs: Vec<OsString>,
) -> Result<i32, String> {
    let bundlespec = bundlespec.unwrap_or(match version {
        1 => BundleSpec::V1None,
        2 => BundleSpec::V2None,
        v => return Err(format!("Unknown version {v}")),
    });
    let version = match bundlespec {
        BundleSpec::ChangegroupV1
        | BundleSpec::V1None
        | BundleSpec::V1Gzip
        | BundleSpec::V1Bzip => 1,
        BundleSpec::V2None | BundleSpec::V2Gzip | BundleSpec::V2Bzip | BundleSpec::V2Zstd => 2,
    };
    revs.extend([
        "--topo-order".into(),
        "--full-history".into(),
        "--reverse".into(),
    ]);
    let commits = rev_list(revs).map(|c| {
        let commit = RawCommit::read(c).unwrap();
        let commit = commit.parse().unwrap();
        (c, commit.parents().to_boxed(), None)
    });
    let file = File::create(path).unwrap();
    let result = do_create_bundle(store, commits, bundlespec, version, &file, false).map(|_| 0);
    unsafe {
        do_cleanup(1);
    }
    result
}

fn create_file(store: &Store, blobid: BlobId, parents: &[HgFileId]) -> HgFileId {
    let blob = RawBlob::read(blobid).unwrap();
    let mut hash = HgFileId::create();
    if parents.len() < 2 {
        hash.update(HgFileId::NULL.as_raw_bytes());
        hash.update(parents.first().unwrap_or(&HgFileId::NULL).as_raw_bytes());
    } else {
        assert_eq!(parents.len(), 2);
        for parent in parents.iter().sorted() {
            hash.update(parent.as_raw_bytes());
        }
    }
    hash.update(blob.as_bytes());
    let fid = hash.finalize();
    store.set(SetWhat::File, fid.into(), blobid.into());
    fid
}

fn create_copy(
    store: &Store,
    blobid: BlobId,
    source_path: &BStr,
    source_fid: HgFileId,
) -> HgFileId {
    let blob = RawBlob::read(blobid).unwrap();
    let mut metadata = Vec::new();
    metadata.extend_from_slice(b"copy: ");
    metadata.extend_from_slice(source_path);
    metadata.extend_from_slice(b"\ncopyrev: ");
    write!(metadata, "{source_fid}").unwrap();
    metadata.extend_from_slice(b"\n");

    let mut hash = HgFileId::create();
    hash.update(HgFileId::NULL.as_raw_bytes());
    hash.update(HgFileId::NULL.as_raw_bytes());
    hash.update(b"\x01\n");
    hash.update(metadata.as_bytes());
    hash.update(b"\x01\n");
    hash.update(blob.as_bytes());
    let fid = hash.finalize();

    let oid = store_git_blob(&metadata);
    store.set(SetWhat::FileMeta, fid.into(), oid.into());
    store.set(SetWhat::File, fid.into(), blobid.into());
    fid
}

// content is &mut but is only going to be overwritten with the same content.
// This is an inconvenience from the way store_manifest currently works, and
// it will remain this way until it moves to Rust.
fn create_manifest(store: &Store, content: &mut [u8], parents: &[HgManifestId]) -> HgManifestId {
    let parent_manifest = parents.first().map_or_else(RawHgManifest::empty, |p| {
        RawHgManifest::read(p.to_git(store).unwrap()).unwrap()
    });
    let parent1 = parents.first().copied().unwrap_or(HgManifestId::NULL);
    let mut hash = HgManifestId::create();
    if parents.len() < 2 {
        hash.update(HgManifestId::NULL.as_raw_bytes());
        hash.update(parent1.as_raw_bytes());
    } else {
        assert_eq!(parents.len(), 2);
        for parent in parents.iter().sorted() {
            hash.update(parent.as_raw_bytes());
        }
    }
    hash.update(&*content);
    let mid = hash.finalize();
    let data = create_chunk_data(&parent_manifest, content);
    let mut manifest_chunk = Vec::new();
    manifest_chunk.extend_from_slice(b"\0\0\0\0");
    manifest_chunk.extend_from_slice(mid.as_raw_bytes());
    manifest_chunk.extend_from_slice(parent1.as_raw_bytes());
    manifest_chunk.extend_from_slice(parents.get(1).unwrap_or(&HgManifestId::NULL).as_raw_bytes());
    manifest_chunk.extend_from_slice(parent1.as_raw_bytes());
    manifest_chunk.extend_from_slice(HgManifestId::NULL.as_raw_bytes());
    manifest_chunk.extend_from_slice(&data);
    let len = manifest_chunk.len();
    (&mut manifest_chunk[..4])
        .write_u32::<BigEndian>(len as u32)
        .unwrap();
    manifest_chunk.extend_from_slice(b"\0\0\0\0");
    for chunk in RevChunkIter::new(2, manifest_chunk.as_bytes()) {
        unsafe {
            store_manifest(
                store,
                &chunk.into(),
                parent_manifest.as_str_slice(),
                content.into(),
            );
        }
    }
    mid
}

fn create_root_changeset(store: &Store, cid: CommitId, branch: Option<&BStr>) -> HgChangesetId {
    // TODO: this is all very suboptimal in what it does, how it does it,
    // and what the code looks like.
    unsafe {
        ensure_store_init();
    }
    let mut manifest = Vec::new();
    let mut paths = Vec::new();
    for entry in RawTree::read_treeish(cid)
        .unwrap()
        .into_iter()
        .recurse()
        .map_map(|item| ManifestEntry {
            fid: create_file(store, item.oid.try_into().unwrap(), &[]),
            attr: item.mode.try_into().unwrap(),
        })
    {
        RawHgManifest::write_one_entry(&entry, &mut manifest).unwrap();
        paths.extend_from_slice(entry.path());
        paths.push(b'\0');
    }
    paths.pop();
    let mid = create_manifest(store, &mut manifest, &[]);
    let (csid, _) = create_changeset(store, cid, mid, Some(paths.to_boxed()), branch);
    csid
}

#[derive(Debug, PartialEq, Eq)]
struct ManifestLine<'a> {
    line: &'a BStr,
    path_len: usize,
}

impl ManifestLine<'_> {
    fn path(&self) -> &[u8] {
        &self.line[..self.path_len]
    }

    fn fid(&self) -> HgFileId {
        HgFileId::from_bytes(&self.line[self.path_len + 1..self.path_len + 41]).unwrap()
    }
}

impl<'a> From<&'a [u8]> for ManifestLine<'a> {
    fn from(line: &'a [u8]) -> ManifestLine<'a> {
        ManifestLine {
            line: line.as_bstr(),
            path_len: line.find_byte(b'\0').unwrap(),
        }
    }
}

impl PartialOrd for ManifestLine<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ManifestLine<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path().cmp(other.path())
    }
}

impl Borrow<[u8]> for ManifestLine<'_> {
    fn borrow(&self) -> &[u8] {
        self.path()
    }
}

fn create_simple_manifest(
    store: &Store,
    cid: CommitId,
    parent: CommitId,
) -> (HgManifestId, Option<Box<[u8]>>) {
    // TODO: this is all very suboptimal in what it does, how it does it,
    // and what the code looks like. And code should be shared with
    // `create_root_changeset`.
    let parent = GitChangesetId::from_unchecked(parent);
    let parent_metadata = RawGitChangesetMetadata::read(store, parent).unwrap();
    let parent_mid = parent_metadata.parse().unwrap().manifest_id();
    let parent_manifest = RawHgManifest::read(parent_mid.to_git(store).unwrap()).unwrap();
    let mut extra_diff = Vec::new();
    let mut diff = diff_tree_with_copies(parent.into(), cid)
        .inspect(|item| {
            if let DiffTreeItem::Renamed { from, .. } = item.inner() {
                extra_diff.push(from.clone().map(DiffTreeItem::Deleted));
            }
        })
        .map_map(|item| match item {
            DiffTreeItem::Renamed { to, .. } | DiffTreeItem::Copied { to, .. }
                if to.oid == RawBlob::EMPTY_OID =>
            {
                DiffTreeItem::Added(to)
            }
            item => item,
        })
        .collect_vec();
    if diff.is_empty() {
        return (parent_mid, None);
    }
    diff.append(&mut extra_diff);
    diff.sort_by(|a, b| a.path().cmp(b.path()));
    let parent_lines = parent_manifest
        .lines_with_terminator()
        .map(ManifestLine::from)
        .collect::<Vec<_>>();
    let mut manifest = Vec::new();
    let mut paths = Vec::new();
    for (path, either_or_both) in parent_lines
        .iter()
        .merge_join_by(diff, |parent_line, diff_item| {
            (parent_line.path()).cmp(diff_item.path())
        })
        .map(|item| match item {
            EitherOrBoth::Left(left) => (left.path().to_boxed(), EitherOrBoth::Left(left)),
            EitherOrBoth::Right(right) => {
                let (path, inner) = right.unzip();
                (path, EitherOrBoth::Right(inner))
            }
            EitherOrBoth::Both(left, right) => {
                let (path, inner) = right.unzip();
                (path, EitherOrBoth::Both(left, inner))
            }
        })
    {
        let (fid, mode) = match either_or_both {
            EitherOrBoth::Left(line) => {
                manifest.extend_from_slice(line.line);
                continue;
            }
            EitherOrBoth::Both(_, DiffTreeItem::Deleted { .. }) => {
                paths.extend_from_slice(&path);
                paths.push(b'\0');
                continue;
            }
            EitherOrBoth::Both(line, DiffTreeItem::Modified { from, to }) => {
                let mut fid = line.fid();
                if from.oid != to.oid {
                    fid = create_file(store, to.oid.try_into().unwrap(), &[fid]);
                }
                (fid, to.mode)
            }
            EitherOrBoth::Both(
                _,
                DiffTreeItem::Renamed { from, to } | DiffTreeItem::Copied { from, to },
            )
            | EitherOrBoth::Right(
                DiffTreeItem::Renamed { from, to } | DiffTreeItem::Copied { from, to },
            ) => (
                create_copy(
                    store,
                    to.oid.try_into().unwrap(),
                    from.path(),
                    parent_lines[parent_lines
                        .binary_search_by_key(&&**from.path(), |e| e.path())
                        .unwrap()]
                    .fid(),
                ),
                to.mode,
            ),
            EitherOrBoth::Right(DiffTreeItem::Added(added)) => (
                create_file(store, added.oid.try_into().unwrap(), &[]),
                added.mode,
            ),

            thing => die!("Something went wrong {:?}", thing),
        };
        let entry = WithPath::new(
            path,
            ManifestEntry {
                fid,
                attr: mode.try_into().unwrap(),
            },
        );
        RawHgManifest::write_one_entry(&entry, &mut manifest).unwrap();
        paths.extend_from_slice(entry.path());
        paths.push(b'\0');
    }
    paths.pop();
    let mid = create_manifest(store, &mut manifest, &[parent_mid]);
    (mid, Some(paths.into_boxed_slice()))
}

fn create_simple_changeset(
    store: &Store,
    cid: CommitId,
    parent: CommitId,
    branch: Option<&BStr>,
) -> [HgChangesetId; 2] {
    unsafe {
        ensure_store_init();
    }
    let parent_csid = GitChangesetId::from_unchecked(parent).to_hg(store).unwrap();
    let (mid, paths) = create_simple_manifest(store, cid, parent);
    let (csid, _) = create_changeset(store, cid, mid, paths, branch);
    [csid, parent_csid]
}

fn create_merge_changeset(
    store: &Store,
    cid: CommitId,
    parent1: CommitId,
    parent2: CommitId,
    branch: Option<&BStr>,
) -> [HgChangesetId; 3] {
    static EXPERIMENTAL: std::sync::Once = std::sync::Once::new();

    EXPERIMENTAL.call_once(|| {
        if experiment(Experiments::MERGE) {
            warn!(target: "root", "Pushing merges is experimental.");
            warn!(target: "root", "This may irremediably push bad state to the mercurial server!");
        } else {
            die!("Pushing merges is not supported yet");
        }
    });
    unsafe {
        ensure_store_init();
    }
    let cs_mn = |c: CommitId| {
        let csid = GitChangesetId::from_unchecked(c);
        let metadata = RawGitChangesetMetadata::read(store, csid).unwrap();
        let metadata = metadata.parse().unwrap();
        (metadata.changeset_id(), metadata.manifest_id())
    };
    let (parent1_csid, parent1_mid) = cs_mn(parent1);
    let (parent2_csid, parent2_mid) = cs_mn(parent2);
    if parent1_mid == parent2_mid {
        let (mid, paths) = create_simple_manifest(store, cid, parent1);
        let (csid, _) = create_changeset(store, cid, mid, paths, branch);
        [csid, parent1_csid, parent2_csid]
    } else {
        let parent1_mn_cid = parent1_mid.to_git(store).unwrap();
        let parent2_mn_cid = parent2_mid.to_git(store).unwrap();
        let range = format!("{}...{}", &parent1_mn_cid, &parent2_mn_cid);
        let mut file_dags = HashMap::new();
        for cid in rev_list(["--topo-order", "--full-history", "--reverse", &range]) {
            let commit = RawCommit::read(cid).unwrap();
            let commit = commit.parse().unwrap();
            for (path, (oid, parents)) in
                get_changes(cid, commit.parents(), false).map(WithPath::unzip)
            {
                let parents = parents
                    .iter()
                    .copied()
                    .filter(|p| !p.is_null())
                    .collect_vec();
                let dag = file_dags.entry(path).or_insert_with(Dag::new);
                for &parent in &parents {
                    if dag.get(parent).is_none() {
                        dag.add(parent, &[], ());
                    }
                }
                if dag.get(oid).is_none() {
                    dag.add(oid, &parents, ());
                }
            }
        }

        let files = RawTree::read_treeish(cid).unwrap().into_iter().recurse();
        let raw_parent1_manifest = RawHgManifest::read(parent1_mn_cid).unwrap();
        let parent1_manifest = raw_parent1_manifest.iter();
        let parent2_manifest = RawHgManifest::read(parent2_mn_cid).unwrap().into_iter();
        let manifests =
            parent1_manifest.merge_join_by(parent2_manifest, |a, b| a.path().cmp(b.path()));

        let mut manifest = Vec::new();
        let mut paths = Vec::new();
        for item in files.merge_join_by(manifests, |a, b| {
            a.path().cmp(match b {
                EitherOrBoth::Both(b, _) | EitherOrBoth::Left(b) | EitherOrBoth::Right(b) => {
                    b.path()
                }
            })
        }) {
            let (path, item) = item
                .map_right(|r| r.transpose().unwrap())
                .transpose()
                .unwrap()
                .unzip();
            let (l, parents, p1_attr) = match item {
                EitherOrBoth::Right(EitherOrBoth::Both(_, _) | EitherOrBoth::Left(_)) => {
                    // File was removed and was on the first parent, it's marked
                    // as affecting the changeset.
                    paths.extend_from_slice(&path);
                    paths.push(b'\0');
                    continue;
                }
                EitherOrBoth::Right(EitherOrBoth::Right(_)) => {
                    // File was removed, but was only on the second parent, it's
                    // not marked.
                    continue;
                }
                EitherOrBoth::Left(l) => {
                    // Weird case, where the file was added in the merge (it's in
                    // neither parents).
                    (l, Vec::new().into_boxed_slice(), None)
                }
                EitherOrBoth::Both(l, EitherOrBoth::Left(p1)) => {
                    (l, vec![p1.clone()].into_boxed_slice(), Some(p1.attr))
                }
                EitherOrBoth::Both(l, EitherOrBoth::Right(p2)) => {
                    (l, vec![p2].into_boxed_slice(), None)
                }
                EitherOrBoth::Both(l, EitherOrBoth::Both(p1, p2)) => {
                    if p1.fid == p2.fid {
                        (l, vec![p1.clone()].into_boxed_slice(), Some(p1.attr))
                    } else {
                        static WARN: std::sync::Once = std::sync::Once::new();
                        WARN.call_once(|| warn!(target: "root", "This may take a while..."));
                        let parents = file_dags
                            .remove(&path)
                            .and_then(|dag| {
                                let is_ancestor = |a: HgFileId, b| {
                                    dag.traverse_parents(&[b], |_, _| true)
                                        .any(|(&p, _)| p == a)
                                };
                                if is_ancestor(p1.fid, p2.fid) {
                                    Some(vec![p2.clone()])
                                } else if is_ancestor(p2.fid, p1.fid) {
                                    Some(vec![p1.clone()])
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| vec![p1.clone(), p2]);
                        (l, parents.into_boxed_slice(), Some(p1.attr))
                    }
                }
            };
            // empty file needs to be checked separately because hg2git metadata
            // doesn't store empty files because of the conflict with empty manifests.
            let unchanged = parents.len() == 1
                && ((parents[0].fid == RawHgFile::EMPTY_OID && l.oid == RawBlob::EMPTY_OID)
                    || parents[0].fid.to_git(store).unwrap() == l.oid);
            let fid = if unchanged {
                parents[0].fid
            } else {
                let parents = parents.iter().map(|p| p.fid).collect_vec();
                create_file(store, l.oid.try_into().unwrap(), &parents)
            };

            let line = WithPath::new(
                path,
                ManifestEntry {
                    fid,
                    attr: l.mode.try_into().unwrap(),
                },
            );
            RawHgManifest::write_one_entry(&line, &mut manifest).unwrap();
            if !unchanged
                || p1_attr
                    .map(|attr| attr != line.inner().attr)
                    .unwrap_or_default()
            {
                paths.extend_from_slice(line.path());
                paths.push(b'\0');
            }
        }
        paths.pop();
        let (mid, paths) = if *manifest == *raw_parent1_manifest {
            (parent1_mid, None)
        } else {
            (
                create_manifest(store, &mut manifest, &[parent1_mid, parent2_mid]),
                Some(paths.into_boxed_slice()),
            )
        };
        let (csid, _) = create_changeset(store, cid, mid, paths, branch);
        [csid, parent1_csid, parent2_csid]
    }
}

pub fn do_create_bundle(
    store: &Store,
    commits: impl Iterator<Item = (CommitId, Box<[CommitId]>, Option<Box<BStr>>)>,
    bundlespec: BundleSpec,
    version: u8,
    output: &File,
    replycaps: bool,
) -> Result<ChangesetHeads, String> {
    let changesets = commits.map(move |(cid, parents, branch)| {
        let branch = branch.as_deref();
        if let Some(csid) = GitChangesetId::from_unchecked(cid).to_hg(store) {
            let mut parents = parents.iter().copied();
            let parent1 = parents.next().map_or(HgChangesetId::NULL, |p| {
                GitChangesetId::from_unchecked(p).to_hg(store).unwrap()
            });
            let parent2 = parents.next().map_or(HgChangesetId::NULL, |p| {
                GitChangesetId::from_unchecked(p).to_hg(store).unwrap()
            });
            assert!(parents.next().is_none());
            [csid, parent1, parent2]
        } else if parents.is_empty() {
            [
                create_root_changeset(store, cid, branch),
                HgChangesetId::NULL,
                HgChangesetId::NULL,
            ]
        } else if parents.len() == 1 {
            let [csid, parent1] = create_simple_changeset(store, cid, parents[0], branch);
            [csid, parent1, HgChangesetId::NULL]
        } else if parents.len() == 2 {
            create_merge_changeset(
                store,
                cid,
                *parents.first().unwrap(),
                *parents.get(1).unwrap(),
                branch,
            )
        } else {
            die!("Pushing octopus merges to mercurial is not supported");
        }
    });
    Ok(create_bundle(
        store, changesets, bundlespec, version, output, replycaps,
    ))
}

fn do_fsck(
    store: &mut Store,
    force: bool,
    full: bool,
    commits: Vec<OsString>,
) -> Result<i32, String> {
    if !has_metadata(store) {
        eprintln!(
            "There does not seem to be any git-cinnabar metadata.\n\
             Is this a git-cinnabar clone?"
        );
        return Ok(1);
    }
    let metadata_cid = store.metadata_cid;
    let checked_cid = if force {
        None
    } else {
        let broken_cid = resolve_ref(BROKEN_REF);
        let checked_cid = match resolve_ref(CHECKED_REF) {
            checked_cid if checked_cid == broken_cid => None,
            checked_cid => checked_cid,
        };
        if checked_cid.as_ref() == Some(&metadata_cid) {
            eprintln!(
                "The git-cinnabar metadata was already checked and is \
                 presumably clean.\n\
                 Try `--force` if you want to check anyway."
            );
            return Ok(0);
        }
        checked_cid
    };
    let commit = RawCommit::read(metadata_cid).unwrap();
    let commit = commit.parse().unwrap();
    if !String::from_utf8_lossy(commit.body())
        .split_ascii_whitespace()
        .sorted()
        .eq(["files-meta", "unified-manifests-v2"].into_iter())
    {
        eprintln!(
            "The git-cinnabar metadata is incompatible with this version.\n\
             Please use the git-cinnabar version it was used with last."
        );
        return Ok(1);
    }
    if !(5..=6).contains(&commit.parents().len()) {
        return Err(
            "The git-cinnabar metadata seems to be corrupted in unexpected ways.".to_string(),
        );
    }
    let [changesets_cid, manifests_cid] = <[_; 2]>::try_from(&commit.parents()[..2]).unwrap();
    let commit = RawCommit::read(changesets_cid).unwrap();
    let commit = commit.parse().unwrap();
    let heads = commit
        .body()
        .split(|&b| b == b'\n')
        .filter_map(|l| {
            l.splitn_exact(b' ').and_then(|[node, branch]| {
                Some((HgChangesetId::from_bytes(node).ok()?, branch.as_bstr()))
            })
        })
        .collect::<Vec<_>>();
    if heads.len() != commit.parents().len() {
        return Err(
            "The git-cinnabar metadata seems to be corrupted in unexpected ways.".to_string(),
        );
    }

    if full || !commits.is_empty() {
        return do_fsck_full(store, commits, metadata_cid, changesets_cid, manifests_cid);
    }

    let [checked_changesets_cid, checked_manifests_cid] =
        checked_cid.as_ref().map_or([None, None], |&c| {
            let commit = RawCommit::read(c).unwrap();
            let commit = commit.parse().unwrap();
            let mut parents = commit.parents().iter();
            [parents.next().copied(), parents.next().copied()]
        });
    let raw_checked = array_init::from_iter::<_, _, 2>(
        [&checked_changesets_cid, &checked_manifests_cid]
            .iter()
            .map(|c| c.and_then(RawCommit::read)),
    )
    .unwrap();
    let [checked_changesets, checked_manifests] = array_init::from_iter(
        raw_checked
            .iter()
            .map(|r| r.as_ref().and_then(RawCommit::parse)),
    )
    .unwrap();

    let broken = Cell::new(false);
    let report = |s| {
        eprintln!("\r{s}");
        broken.set(true);
    };

    let mut heads_set = None;
    let mut parents = None;
    let mut manifest_nodes = Vec::new();

    for (&c, &(changeset_node, branch)) in commit
        .parents()
        .iter()
        .zip(heads.iter())
        .filter(|(c, _)| match &checked_changesets {
            Some(checked) => !checked.parents().contains(c),
            None => true,
        })
        .progress(|n| format!("Checking {n} changeset heads"))
    {
        let git_cid = changeset_node.to_git(store);
        let git_cid = if let Some(git_cid) = git_cid {
            git_cid
        } else {
            report(format!(
                "Missing hg2git metadata for changeset {changeset_node}"
            ));
            continue;
        };
        if git_cid != c {
            let parents = parents.get_or_insert_with(|| BTreeSet::from_iter(commit.parents()));
            if !parents.contains(&CommitId::from(git_cid)) {
                report(format!(
                    "Inconsistent metadata:\n\
                     \x20 Head metadata says changeset {changeset_node} maps to {c}\n
                     \x20 but hg2git metadata says it maps to {git_cid}"
                ));
                continue;
            }
        }
        let commit = RawCommit::read(c).unwrap();
        let commit = commit.parse().unwrap();
        let metadata = if let Some(metadata) = RawGitChangesetMetadata::read(store, git_cid) {
            metadata
        } else {
            report(format!("Missing git2hg metadata for git commit {c}"));
            continue;
        };
        let metadata = metadata.parse().unwrap();
        if metadata.changeset_id() != changeset_node {
            let heads_map = heads_set
                .get_or_insert_with(|| heads.iter().map(|(a, _)| a).collect::<BTreeSet<_>>());
            if !heads_map.contains(&metadata.changeset_id()) {
                report(format!(
                    "Inconsistent metadata:\n\
                     \x20 Head metadata says {} maps to changeset {}\n
                     \x20 but git2hg metadata says it maps to changeset {}",
                    c,
                    changeset_node,
                    metadata.changeset_id()
                ));
                continue;
            }
        }
        let raw_changeset = RawHgChangeset::from_metadata(store, &commit, &metadata).unwrap();
        let mut sha1 = Sha1::new();
        commit
            .parents()
            .iter()
            .copied()
            .map(|p| {
                GitChangesetId::from_unchecked(lookup_replace_commit(p))
                    .to_hg(store)
                    .unwrap()
            })
            .chain(repeat(HgChangesetId::NULL))
            .take(2)
            .sorted()
            .for_each(|p| sha1.update(p.as_raw_bytes()));
        sha1.update(&*raw_changeset);
        let sha1 = sha1.finalize();
        if changeset_node.as_raw_bytes() != sha1.as_slice() {
            report(format!("Sha1 mismatch for changeset {changeset_node}",));
            continue;
        }
        let changeset = raw_changeset.parse().unwrap();
        let changeset_branch = changeset
            .extra()
            .and_then(|e| e.get(b"branch"))
            .unwrap_or(b"default")
            .as_bstr();
        if branch != changeset_branch {
            report(format!(
                "Inconsistent metadata:\n\
                 \x20 Head metadata says changeset {changeset_node} is in branch {branch}\n\
                 \x20 but git2hg metadata says it is in branch {changeset_branch}"
            ));
            continue;
        }
        manifest_nodes.push(changeset.manifest());
    }

    if broken.get() {
        return Ok(1);
    }

    // Rebuilding manifests benefits from limiting the difference with
    // the last rebuilt manifest. Similarly, building the list of unique
    // files in all manifests benefits from that too.
    // Unfortunately, the manifest heads are not ordered in a topological
    // relevant manner, and the differences between two consecutive manifests
    // can be much larger than they could be. The consequence is spending a
    // large amount of time rebuilding the manifests and gathering the files
    // list. It's actually faster to attempt to reorder them according to
    // some heuristics first, such that the differences are smaller.
    // Here, we use the depth from the root node(s) to reorder the manifests.
    // This doesn't give the most optimal ordering, but it's already much
    // faster. On a clone of multiple mozilla-* repositories with > 1400 heads,
    // it's close to an order of magnitude difference on the "Checking
    // manifests" loop.
    let mut depths = BTreeMap::new();
    let mut roots = BTreeSet::new();
    let mut manifest_queue = Vec::new();
    let manifests_arg = format!("{manifests_cid}^@");
    let checked_manifests_arg = checked_manifests_cid.map(|c| format!("^{c}^@"));
    let mut args = vec![
        "--topo-order",
        "--reverse",
        "--full-history",
        &manifests_arg,
    ];
    if let Some(a) = &checked_manifests_arg {
        args.push(a);
    }
    for mid in rev_list(args).progress(|n| format!("Loading {n} manifests")) {
        let commit = RawCommit::read(mid).unwrap();
        let commit = commit.parse().unwrap();
        manifest_queue.push((mid, commit.parents().to_boxed()));
        for p in commit.parents() {
            if !depths.contains_key(p) {
                roots.insert(*p);
            }
            depths.insert(
                mid,
                cmp::max(
                    depths.get(p).copied().unwrap_or(0) + 1,
                    depths.get(&mid).copied().unwrap_or(0),
                ),
            );
        }
    }

    // TODO: check that all manifest_nodes gathered above are available in the
    // manifests dag, and that the dag heads are the recorded heads.
    let commit = RawCommit::read(manifests_cid).unwrap();
    let commit = commit.parse().unwrap();

    let mut previous = None;
    let mut all_interesting = BTreeSet::new();
    for mid in commit
        .parents()
        .iter()
        .copied()
        .filter(|p| match &checked_manifests {
            Some(checked) => !checked.parents().contains(p),
            None => true,
        })
        .sorted_by_key(|p| depths.get(p).copied().unwrap_or(0))
        .progress(|n| format!("Checking {n} manifest heads"))
    {
        let commit = RawCommit::read(mid).unwrap();
        let commit = commit.parse().unwrap();
        let hg_manifest_id = if let Ok(id) = HgManifestId::from_bytes(commit.body()) {
            id
        } else {
            report(format!("Invalid manifest metadata in git commit {mid}"));
            continue;
        };
        let git_mid = if let Some(id) = hg_manifest_id.to_git(store) {
            id
        } else {
            report(format!(
                "Missing hg2git metadata for manifest {hg_manifest_id}"
            ));
            continue;
        };
        if mid != git_mid {
            report(format!(
                "Inconsistent metadata:\n\
                 \x20 Manifest DAG contains {mid} for manifest {hg_manifest_id}\n
                 \x20 but hg2git metadata says the manifest maps to {git_mid}"
            ));
        }
        if unsafe { check_manifest(&object_id::from(git_mid)) } != 1 {
            report(format!("Sha1 mismatch for manifest {git_mid}"));
        }
        let files: Vec<(_, HgFileId)> = if let Some(previous) = previous {
            let a = GitManifestTree::read_treeish(GitManifestId::from_unchecked(previous)).unwrap();
            let b = GitManifestTree::read_treeish(GitManifestId::from_unchecked(mid)).unwrap();
            diff_by_path(a, b)
                .recurse()
                .map_map(|entry| match entry {
                    Right(added) => Some(added.fid),
                    Both(from, to) if from.fid != to.fid => Some(to.fid),
                    _ => None,
                })
                .filter_map(Transpose::transpose)
                .map(WithPath::unzip)
                .filter(|pair| !all_interesting.contains(pair))
                .collect_vec()
        } else {
            GitManifestTree::read(GitManifestTreeId::from_unchecked(commit.tree()))
                .unwrap()
                .into_iter()
                .recurse()
                .map_map(|item| item.fid)
                .map(WithPath::unzip)
                .filter(|pair| !all_interesting.contains(pair))
                .collect_vec()
        };
        all_interesting.extend(files);
        previous = Some(mid);
    }

    // Don't check files that were already there in the previously checked
    // manifests.
    let mut previous = None;
    for r in roots {
        if let Some(previous) = previous {
            let a = GitManifestTree::read_treeish(GitManifestId::from_unchecked(previous)).unwrap();
            let b = GitManifestTree::read_treeish(GitManifestId::from_unchecked(r)).unwrap();
            diff_by_path(a, b)
                .recurse()
                .map_map(|entry| match entry {
                    Right(added) => Some(added.fid),
                    Both(from, to) if from.fid != to.fid => Some(to.fid),
                    _ => None,
                })
                .filter_map(Transpose::transpose)
                .map(WithPath::unzip)
                .for_each(|item| {
                    all_interesting.remove(&item);
                });
        } else {
            for item in GitManifestTree::read_treeish(GitManifestId::from_unchecked(r))
                .unwrap()
                .into_iter()
                .recurse()
                .map_map(|item| item.fid)
                .map(WithPath::unzip)
            {
                all_interesting.remove(&item);
            }
        }
        previous = Some(r);
    }

    let mut progress = repeat(()).progress(|n| format!("Checking {n} files"));
    while !all_interesting.is_empty() && !manifest_queue.is_empty() {
        let (mid, parents) = manifest_queue.pop().unwrap();
        for (path, (hg_file, hg_fileparents)) in
            get_changes(mid, &parents, true).map(WithPath::unzip)
        {
            if hg_fileparents.contains(&hg_file) {
                continue;
            }
            // Reaching here means the file received a modification compared
            // to its parents. If it's a file we're going to check below,
            // it means we don't need to check its parents if somehow they were
            // going to be checked. If it's not a file we're going to check
            // below, it's because it's either a file we weren't interested in
            // in the first place, or it's the parent of a file we have checked.
            // Either way, we aren't interested in the parents.
            for p in hg_fileparents.iter() {
                all_interesting.remove(&(path.clone(), *p));
            }
            if let Some((path, hg_file)) = all_interesting.take(&(path, hg_file)) {
                if !check_file(
                    store,
                    hg_file,
                    hg_fileparents.first().copied().unwrap_or(HgFileId::NULL),
                    hg_fileparents.get(1).copied().unwrap_or(HgFileId::NULL),
                ) {
                    report(format!(
                        "Sha1 mismatch for file {}\n\
                         \x20 revision {}",
                        path.as_bstr(),
                        hg_file
                    ));
                    let print_parents = hg_fileparents.iter().filter(|p| !p.is_null()).join(" ");
                    if !print_parents.is_empty() {
                        report(format!(
                            "  with parent{} {}",
                            if print_parents.len() > 41 { "s" } else { "" },
                            print_parents
                        ));
                    }
                }
                progress.next();
            }
        }
    }
    drop(progress);
    if !all_interesting.is_empty() {
        eprintln!("\rCould not find the following files:");
        for (path, oid) in all_interesting.iter().sorted() {
            eprintln!(" . {} {}", oid, path.as_bstr());
        }
        eprintln!(
            "This might be a bug in `git cinnabar fsck`. Please open \
             an issue, with the message above, on\n\
             {CARGO_PKG_REPOSITORY}/issues"
        );
        return Ok(1);
    }

    check_replace(metadata_cid);

    if broken.get() {
        eprintln!(
            "\rYour git-cinnabar repository appears to be corrupted.\n\
             Please open an issue, with the information above, on\n\
             {CARGO_PKG_REPOSITORY}/issues"
        );
        let mut transaction = RefTransaction::new().unwrap();
        transaction
            .update(BROKEN_REF, metadata_cid, None, "fsck")
            .unwrap();
        transaction.commit().unwrap();
        if checked_cid.is_some() {
            eprintln!(
                "\nThen please try to run `git cinnabar rollback --fsck` to \
                 restore last known state, and to update from the mercurial \
                 repository."
            );
        } else {
            eprintln!("\nThen please try to run `git cinnabar reclone`.");
        }
        eprintln!(
            "\nPlease note this may affect the commit sha1s of mercurial \
             changesets, and may require to rebase your local branches."
        );
        eprintln!(
            "\nAlternatively, you may start afresh with a new clone. In any \
             case, please keep this corrupted repository around for further \
             debugging."
        );
        return Ok(1);
    }

    if do_done_and_check(store, &[CHECKED_REF.as_bytes()]) {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn do_fsck_full(
    store: &mut Store,
    commits: Vec<OsString>,
    metadata_cid: CommitId,
    changesets_cid: CommitId,
    manifests_cid: CommitId,
) -> Result<i32, String> {
    let full_fsck = commits.is_empty();
    let commit_queue = if full_fsck {
        let changesets_arg = format!("{changesets_cid}^@");

        Box::new(rev_list([
            "--topo-order",
            "--full-history",
            "--reverse",
            &changesets_arg,
        ])) as Box<dyn Iterator<Item = _>>
    } else {
        Box::new(
            commits
                .into_iter()
                .map(|c| {
                    let git_cs = GitChangesetId::from_bytes(c.as_bytes()).map_err(|_| {
                        format!("Invalid commit or changeset: {}", c.to_string_lossy())
                    })?;
                    if git_cs.to_hg(store).is_some() {
                        return Ok(git_cs.into());
                    }
                    let cs = HgChangesetId::from_bytes(c.as_bytes()).map_err(|_| {
                        format!("Invalid commit or changeset: {}", c.to_string_lossy())
                    })?;

                    if let Some(git_cs) = cs.to_git(store) {
                        Ok(git_cs.into())
                    } else {
                        Err(format!(
                            "Unknown commit or changeset: {}",
                            c.to_str().unwrap()
                        ))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter(),
        )
    };

    let broken = Cell::new(false);
    let report = |s| {
        eprintln!("\r{s}");
        broken.set(true);
    };
    let fixed = Cell::new(false);
    let fix = |s| {
        eprintln!("\r{s}");
        fixed.set(true);
    };

    let mut seen_git2hg = BTreeSet::new();
    let mut seen_changesets = BTreeSet::new();
    let mut seen_manifests = BTreeSet::new();
    let mut seen_files = BTreeSet::new();
    let mut changeset_heads = ChangesetHeads::new();
    let mut manifest_heads = BTreeSet::new();

    for cid in commit_queue.progress(|n| format!("Checking {n} changesets")) {
        let cid = lookup_replace_commit(cid);
        let cid = GitChangesetId::from_unchecked(cid);
        let metadata = if let Some(metadata) = RawGitChangesetMetadata::read(store, cid) {
            metadata
        } else {
            report(format!("Missing note for git commit: {cid}"));
            continue;
        };
        seen_git2hg.insert(cid);

        let commit = RawCommit::read(cid.into()).unwrap();
        let commit = commit.parse().unwrap();
        let metadata = if let Some(metadata) = metadata.parse() {
            metadata
        } else {
            report(format!("Cannot parse note for git commit: {cid}"));
            continue;
        };
        let changeset_id = metadata.changeset_id();
        match changeset_id.to_git(store) {
            Some(oid) if oid == cid => {}
            Some(oid) => {
                report(format!(
                    "Commit mismatch for changeset {changeset_id}\n\
                     \x20 hg2git: {oid}\n\
                     \x20 commit: {cid}"
                ));
            }
            None => {
                report(format!(
                    "Missing changeset in hg2git branch: {changeset_id}"
                ));
                continue;
            }
        }
        seen_changesets.insert(changeset_id);
        let raw_changeset =
            if let Some(raw_changeset) = RawHgChangeset::from_metadata(store, &commit, &metadata) {
                raw_changeset
            } else {
                report(format!(
                    "Failed to recreate changeset {} from git commit {}",
                    metadata.changeset_id(),
                    cid
                ));
                continue;
            };
        let mut sha1 = Sha1::new();
        let hg_parents = commit
            .parents()
            .iter()
            .copied()
            .map(|p| {
                GitChangesetId::from_unchecked(lookup_replace_commit(p))
                    .to_hg(store)
                    .unwrap()
            })
            .collect_vec();
        hg_parents
            .iter()
            .copied()
            .chain(repeat(HgChangesetId::NULL))
            .take(2)
            .sorted()
            .for_each(|p| sha1.update(p.as_raw_bytes()));
        sha1.update(&*raw_changeset);
        let sha1 = sha1.finalize();
        if changeset_id.as_raw_bytes() != sha1.as_slice() {
            report(format!("Sha1 mismatch for changeset {changeset_id}"));
            continue;
        }

        let changeset = raw_changeset.parse().unwrap();

        if !grafted() {
            let fresh_commit = raw_commit_for_changeset(
                &changeset,
                commit.tree(),
                &commit
                    .parents()
                    .iter()
                    .copied()
                    .map(GitChangesetId::from_unchecked)
                    .collect_vec(),
            );
            let mut hash = GitChangesetId::create();
            hash.update(format!("commit {}\0", fresh_commit.as_bytes().len()));
            hash.update(fresh_commit.as_bytes());
            let fresh_cid = hash.finalize();
            if cid != fresh_cid {
                eprintln!(
                    "\nCommit mismatch for changeset {changeset_id}\n\
                     \x20 it is commit {cid} here\n\
                     \x20 but would be {fresh_cid} on a fresh clone"
                );
            }
        }

        let branch = metadata
            .extra()
            .and_then(|e| e.get(b"branch"))
            .unwrap_or(b"default");
        changeset_heads.add(changeset_id, &hg_parents, branch.as_bstr());

        let fresh_metadata =
            GeneratedGitChangesetMetadata::generate(store, &commit, changeset_id, &raw_changeset)
                .unwrap();
        if fresh_metadata != metadata {
            fix(format!("Adjusted changeset metadata for {changeset_id}"));
            store.set(SetWhat::Changeset, changeset_id.into(), GitObjectId::NULL);
            store.set(SetWhat::Changeset, changeset_id.into(), cid.into());
            let buf = fresh_metadata.serialize();
            let metadata_id = store_git_blob(&buf);
            store.set(
                SetWhat::ChangesetMeta,
                changeset_id.into(),
                GitObjectId::NULL,
            );
            store.set(
                SetWhat::ChangesetMeta,
                changeset_id.into(),
                metadata_id.into(),
            );
        }

        let manifest_id = changeset.manifest();
        if !seen_manifests.insert(manifest_id) {
            // We've already seen the manifest.
            continue;
        }
        let manifest_cid = if let Some(manifest_cid) = manifest_id.to_git(store) {
            manifest_cid
        } else {
            report(format!("Missing manifest in hg2git branch: {manifest_id}"));
            continue;
        };

        let checked = unsafe {
            let manifest_cid = object_id::from(manifest_cid);
            check_manifest(&manifest_cid) == 1
        };
        if !checked {
            report(format!("Sha1 mismatch for manifest {manifest_id}"));
        }

        let hg_manifest_parents = hg_parents
            .iter()
            .map(|p| {
                let metadata =
                    RawGitChangesetMetadata::read(store, p.to_git(store).unwrap()).unwrap();
                let metadata = metadata.parse().unwrap();
                metadata.manifest_id()
            })
            .collect_vec();
        let git_manifest_parents = hg_manifest_parents
            .into_iter()
            .filter_map(|p| p.to_git(store).map(Into::into))
            .sorted()
            .collect_vec();

        let manifest_commit = RawCommit::read(manifest_cid.into()).unwrap();
        let manifest_commit = manifest_commit.parse().unwrap();
        if manifest_commit
            .parents()
            .iter()
            .sorted()
            .ne(git_manifest_parents.iter())
        {
            // TODO: better error
            report(format!(
                "{}({}) [{}] != [{}]",
                manifest_id,
                manifest_cid,
                manifest_commit.parents().iter().join(", "),
                git_manifest_parents.iter().join(", ")
            ));
        }

        if full_fsck {
            manifest_heads.insert(manifest_cid.into());
            for p in manifest_commit.parents() {
                manifest_heads.remove(p);
            }
        }

        // TODO: check that manifest content matches changeset content.
        for (path, (hg_file, hg_fileparents)) in
            get_changes(manifest_cid.into(), &git_manifest_parents, false).map(WithPath::unzip)
        {
            if hg_file.is_null() || hg_file == RawHgFile::EMPTY_OID || !seen_files.insert(hg_file) {
                continue;
            }
            if
            // TODO: add FileFindParents logging.
            !check_file(
                store,
                hg_file,
                hg_fileparents.first().copied().unwrap_or(HgFileId::NULL),
                hg_fileparents.get(1).copied().unwrap_or(HgFileId::NULL),
            ) {
                report(format!(
                    "Sha1 mismatch for file {}\n\
                     \x20 revision {}",
                    path.as_bstr(),
                    hg_file
                ));
                let print_parents = hg_fileparents.iter().filter(|p| !p.is_null()).join(" ");
                if !print_parents.is_empty() {
                    report(format!(
                        "  with parent{} {}",
                        if print_parents.len() > 41 { "s" } else { "" },
                        print_parents
                    ));
                }
            }
        }
    }

    if full_fsck && !broken.get() {
        let manifests_commit = RawCommit::read(manifests_cid).unwrap();
        let manifests_commit = manifests_commit.parse().unwrap();
        let store_manifest_heads = manifests_commit
            .parents()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();

        if manifest_heads != store_manifest_heads {
            let args = ["--topo-order", "--full-history", "--reverse"];

            fn iter_manifests<'a>(
                a: &'a BTreeSet<CommitId>,
                b: &'a BTreeSet<CommitId>,
            ) -> impl Iterator<Item = String> + 'a {
                a.difference(b)
                    .map(|x| format!("{x}"))
                    .chain(b.iter().map(|x| format!("^{x}")))
            }
            let all_args = args
                .into_iter()
                .map(str::to_string)
                .chain(iter_manifests(&manifest_heads, &store_manifest_heads));
            for m in rev_list(all_args) {
                fix(format!("Missing manifest commit in manifest branch: {m}"));
            }

            let all_args = args
                .into_iter()
                .map(str::to_string)
                .chain(iter_manifests(&store_manifest_heads, &manifest_heads));
            for m in rev_list(all_args) {
                fix(format!(
                    "Removing manifest commit {m} with no corresponding changeset"
                ));
            }

            for &h in store_manifest_heads.difference(&manifest_heads) {
                // TODO: This is gross.
                let m = RawCommit::read(h).unwrap();
                let m = m.parse().unwrap();
                let m = HgManifestId::from_bytes(m.body()).unwrap();
                if seen_manifests.contains(&m) {
                    fix(format!(
                        "Remove non-head reference to {h} in manifests metadata"
                    ));
                }
            }

            clear_manifest_heads(store);
            for h in manifest_heads {
                // TODO: This is gross.
                let m = RawCommit::read(h).unwrap();
                let m = m.parse().unwrap();
                let m = HgManifestId::from_bytes(m.body()).unwrap();
                store.set(SetWhat::Manifest, m.into(), h.into());
            }
        }
    }

    if full_fsck && !broken.get() {
        let mut dangling = Vec::new();
        store.hg2git_mut().for_each(|h, _| {
            if seen_changesets.contains(&HgChangesetId::from_unchecked(h))
                || seen_manifests.contains(&HgManifestId::from_unchecked(h))
                || seen_files.contains(&HgFileId::from_unchecked(h))
            {
                return;
            }
            dangling.push(h);
        });
        for h in dangling {
            fix(format!("Removing dangling metadata for {h}"));
            // Theoretically, we should figure out if they are files, manifests
            // or changesets and set the right variable accordingly, but in
            // practice, it makes no difference. Reevaluate when refactoring,
            // though.
            store.set(SetWhat::File, h, GitObjectId::NULL);
            store.set(SetWhat::FileMeta, h, GitObjectId::NULL);
        }
        let mut dangling = Vec::new();
        store.git2hg_mut().for_each(|g, _| {
            // TODO: this is gross.
            let cid = GitChangesetId::from_unchecked(CommitId::from_unchecked(g));
            if seen_git2hg.contains(&cid) {
                return;
            }
            dangling.push(cid);
        });
        for cid in dangling {
            fix(format!("Removing dangling note for commit {cid}"));
            let metadata = RawGitChangesetMetadata::read(store, cid).unwrap();
            let metadata = metadata.parse().unwrap();
            store.set(
                SetWhat::ChangesetMeta,
                metadata.changeset_id().into(),
                GitObjectId::NULL,
            );
        }
    }

    check_replace(metadata_cid);

    if full_fsck {
        eprintln!("\rChecking head references...");
        let original_heads = ChangesetHeads::from_metadata(changesets_cid);
        let original_heads = original_heads.branch_heads().collect::<BTreeSet<_>>();
        let computed_heads = changeset_heads.branch_heads().collect::<BTreeSet<_>>();
        for (cid, branch) in computed_heads
            .difference(&original_heads)
            .sorted_by_key(|(_, branch)| branch)
        {
            fix(format!("Adding missing head {cid} in branch {branch}"));
        }
        for (cid, branch) in original_heads
            .difference(&computed_heads)
            .sorted_by_key(|(_, branch)| branch)
        {
            fix(format!(
                "Removing non-head reference to {cid} in branch {branch}"
            ));
        }
        if original_heads != computed_heads {
            set_changeset_heads(store, changeset_heads);
        }
    }

    if broken.get() {
        eprintln!(
            "\rYour git-cinnabar repository appears to be corrupted. There\n\
             are known issues in older revisions that have been fixed.\n\
             Please try running the following command to reset:\n\
             \x20  git cinnabar reclone\n\n\
             Please note this command may change the commit sha1s. Your\n\
             local branches will however stay untouched.\n\
             Please report any corruption that fsck would detect after a\n\
             reclone."
        );
        let mut transaction = RefTransaction::new().unwrap();
        transaction
            .update(BROKEN_REF, metadata_cid, None, "fsck")
            .unwrap();
        transaction.commit().unwrap();
        return Ok(1);
    }

    if do_done_and_check(store, &[CHECKED_REF.as_bytes()]) {
        if fixed.get() {
            Ok(2)
        } else {
            Ok(0)
        }
    } else {
        Ok(1)
    }
}

fn check_replace(metadata_cid: CommitId) {
    for r in RawTree::read_treeish(metadata_cid)
        .unwrap()
        .into_iter()
        .recurse()
        .filter_map(|item| {
            let r = GitObjectId::from_bytes(item.path()).unwrap();
            (item.inner().oid == r).then_some(r)
        })
        .progress(|n| format!("Removing {n} self-referencing grafts"))
    {
        unsafe {
            do_set_replace(&object_id::from(r), &object_id::default());
        }
    }
}

#[allow(clippy::type_complexity)]
fn get_changes(
    cid: CommitId,
    parents: &[CommitId],
    all: bool,
) -> Box<dyn Iterator<Item = WithPath<(HgFileId, Box<[HgFileId]>)>>> {
    if parents.is_empty() {
        Box::new(
            GitManifestTree::read_treeish(GitManifestId::from_unchecked(cid))
                .unwrap()
                .into_iter()
                .recurse()
                .map_map(|item| (item.fid, [].to_boxed())),
        )
    } else if parents.len() == 1 {
        Box::new(
            manifest_diff(parents[0], cid).map_map(|(node, parent)| (node, [parent].to_boxed())),
        )
    } else {
        Box::new(
            manifest_diff2(parents[0], parents[1], cid, all)
                .map_map(|(node, parents)| (node, parents.to_boxed())),
        )
    }
}

fn manifest_diff(a: CommitId, b: CommitId) -> impl Iterator<Item = WithPath<(HgFileId, HgFileId)>> {
    let a = GitManifestTree::read_treeish(GitManifestId::from_unchecked(a)).unwrap();
    let b = GitManifestTree::read_treeish(GitManifestId::from_unchecked(b)).unwrap();
    diff_by_path(a, b)
        .recurse()
        .map_map(|entry| match entry {
            Right(added) => Some((added.fid, HgFileId::NULL)),
            Both(from, to) if from.fid != to.fid => Some((to.fid, from.fid)),
            Left(deleted) => Some((HgFileId::NULL, deleted.fid)),
            _ => None,
        })
        .filter_map(Transpose::transpose)
}

fn manifest_diff2(
    a: CommitId,
    b: CommitId,
    c: CommitId,
    all: bool,
) -> impl Iterator<Item = WithPath<(HgFileId, [HgFileId; 2])>> {
    Itertools::merge_join_by(manifest_diff(a, c), manifest_diff(b, c), |x, y| {
        x.path().cmp(y.path())
    })
    .map(|item| item.transpose().unwrap())
    .map_map(move |y| match y {
        Left((c, a)) if all => Some((c, [a, c])),
        Right((c, b)) if all => Some((c, [c, b])),
        Both((c, a), (c2, b)) => {
            assert_eq!(c, c2);
            Some((c, [a, b]))
        }
        _ => None,
    })
    .filter_map(Transpose::transpose)
}

#[derive(Clone, Debug)]
struct AbbrevSize(usize);

impl FromStr for AbbrevSize {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = usize::from_str(s).map_err(|e| format!("{e}"))?;
        match value {
            3..=40 => Ok(AbbrevSize(value)),
            41..=usize::MAX => Err(format!("value too large: {value}")),
            _ => Err(format!("value too small: {value}")),
        }
    }
}

#[derive(Parser)]
#[command(
    name = "git-cinnabar",
    version=SHORT_VERSION.as_ref(),
    long_version=FULL_VERSION.as_ref(),
    arg_required_else_help = true,
    dont_collapse_args_in_usage = true,
    subcommand_required = true,
)]
enum CinnabarCommand {
    #[command(name = "remote-hg", hide = true)]
    RemoteHg { remote: OsString, url: OsString },
    /// Dump the contents of a mercurial revision
    #[command(name = "data")]
    #[group(id = "input", multiple = false, required = true)]
    Data {
        /// Open changelog
        #[arg(short = 'c', group = "input")]
        changeset: Option<Abbrev<HgChangesetId>>,
        /// Open manifest
        #[arg(short = 'm', group = "input")]
        manifest: Option<Abbrev<HgManifestId>>,
        /// Open file
        #[arg(group = "input")]
        file: Option<Abbrev<HgFileId>>,
    },
    /// Convert mercurial sha1 to corresponding git sha1
    #[command(name = "hg2git")]
    #[group(id = "input", multiple = true, required = true)]
    Hg2Git {
        /// Show a partial prefix
        #[arg(long, require_equals = true, num_args = ..=1)]
        abbrev: Option<Vec<AbbrevSize>>,
        /// Mercurial sha1
        #[arg(group = "input")]
        sha1: Vec<Abbrev<HgChangesetId>>,
        /// Read sha1s on stdin
        #[arg(long, group = "input")]
        batch: bool,
    },
    /// Convert git sha1 to corresponding mercurial sha1
    #[command(name = "git2hg")]
    #[group(id = "input", multiple = true, required = true)]
    Git2Hg {
        /// Show a partial prefix
        #[arg(long, require_equals = true, num_args = ..=1)]
        abbrev: Option<Vec<AbbrevSize>>,
        /// Git sha1/committish
        #[arg(group = "input", value_parser)]
        committish: Vec<OsString>,
        /// Read sha1/committish on stdin
        #[arg(long)]
        #[arg(long, group = "input")]
        batch: bool,
    },
    #[command(skip)]
    Tag(TagCommand),
    /// Fetch a changeset from a mercurial remote
    #[command(name = "fetch")]
    Fetch {
        /// Mercurial remote name or url
        #[arg(required_unless_present = "tags", value_parser)]
        remote: Option<OsString>,
        /// Mercurial changeset to fetch
        #[arg(required_unless_present = "tags", value_parser)]
        revs: Vec<OsString>,
        /// Don't import, but send the bundle to stdout
        #[arg(long)]
        bundle: bool,
        /// Fetch tags
        #[arg(long, exclusive = true)]
        tags: bool,
    },
    /// Reclone all mercurial remotes
    #[command(name = "reclone")]
    Reclone {
        /// Rebase local branches
        #[arg(long)]
        rebase: bool,
    },
    /// Remove cinnabar metadata
    #[command(name = "clear")]
    Clear,
    #[command(name = "rollback")]
    /// Rollback cinnabar metadata state
    Rollback {
        /// Show a list of candidates for rollback
        #[arg(long, conflicts_with = "committish")]
        candidates: bool,
        /// Rollback to the last successful fsck state
        #[arg(long, conflicts_with = "committish", conflicts_with = "candidates")]
        fsck: bool,
        /// Force to use the given committish even if it is not in the current metadata's ancestry
        #[arg(long, conflicts_with = "candidates")]
        force: bool,
        /// Git sha1/committish of the state to rollback to
        #[arg(value_parser)]
        committish: Option<OsString>,
    },
    #[command(skip)]
    Strip(StripCommand),
    /// Check cinnabar metadata consistency
    #[command(name = "fsck")]
    Fsck {
        /// Force check, even when metadata was already checked. Also disables incremental fsck
        #[arg(long)]
        force: bool,
        /// Check more thoroughly
        #[arg(long, conflicts_with = "commit")]
        full: bool,
        /// Specific commit or changeset to check
        #[arg(value_parser)]
        commit: Vec<OsString>,
    },
    /// Create a mercurial bundle
    #[command(name = "bundle")]
    Bundle {
        /// Bundle version
        #[arg(long, default_value = "2", value_parser = clap::value_parser!(u8).range(1..=2))]
        version: u8,
        /// Type of bundle (bundlespec)
        #[arg(long, short, conflicts_with = "version")]
        r#type: Option<BundleSpec>,
        /// Path of the bundle
        #[arg(value_parser)]
        path: PathBuf,
        /// Git revision range (see the Specifying Ranges section of gitrevisions(7))
        #[arg(value_parser)]
        revs: Vec<OsString>,
    },
    /// Apply a mercurial bundle to the repository
    #[command(name = "unbundle")]
    Unbundle {
        /// Get clone bundle from given repository
        #[arg(long)]
        clonebundle: bool,
        /// Url/Location of the bundle
        url: OsString,
    },
    /// Upgrade cinnabar metadata
    #[command(name = "upgrade")]
    Upgrade,
    /// Update git-cinnabar
    #[cfg(feature = "self-update")]
    #[command(name = "self-update")]
    SelfUpdate {
        /// Branch to get updates from
        #[arg(long)]
        branch: Option<String>,
        /// Exact commit to get a version from
        #[arg(long, value_parser = self_update_exact, conflicts_with = "branch")]
        exact: Option<VersionInfo>,
        /// Show where the self-update would be downloaded from
        #[arg(long, hide = true)]
        url: bool,
    },
    /// Setup git-cinnabar
    #[command(name = "setup", hide = true)]
    Setup,
}

#[cfg(feature = "self-update")]
fn self_update_exact(arg: &str) -> Result<VersionInfo, String> {
    CommitId::from_str(arg)
        .map(VersionInfo::Commit)
        .or_else(|_| Version::parse(arg).map(|v| VersionInfo::Tagged(v, CommitId::NULL)))
        .map_err(|e| e.to_string())
}

/// Create, list, delete tags
#[derive(Parser)]
#[command(name = "tag")]
struct TagCommand {
    /// List tags
    #[arg(short = 'l', long, conflicts_with_all = ["delete", "onto", "message", "force", "tag", "committish"])]
    list: bool,
    #[arg(long, conflicts_with_all = ["delete", "onto", "message", "force", "tag", "committish"])]
    format: Option<String>,
    /// Force tag operation
    #[arg(short = 'f', long)]
    force: bool,
    /// Delete existing tag
    #[arg(short = 'd', long, conflicts_with = "committish")]
    delete: bool,
    /// Record changes on the given branch (without checking it out)
    #[arg(long)]
    onto: Option<OsString>,
    /// Use text as commit message
    #[arg(short = 'm', long)]
    message: Option<OsString>,
    /// Tag name
    #[arg(required = true)]
    tag: Option<OsString>,
    /// Object to tag (can be either a git commit or a mercurial changeset)
    committish: Option<OsString>,
}

/// Strip cinnabar metadata for commits and their descendants
#[derive(Parser)]
#[command(name = "strip")]
struct StripCommand {
    /// Commits to strip (can be either git commits or a mercurial changesets)
    committish: Vec<OsString>,
}

struct AllCommand(CinnabarCommand);

impl CommandFactory for AllCommand {
    fn command() -> clap::Command {
        let mut command = CinnabarCommand::command();
        if experiment(Experiments::TAG) {
            command = command.subcommand(TagCommand::command());
        }
        if experiment(Experiments::STRIP) {
            command = command.subcommand(StripCommand::command());
        }
        command
    }

    fn command_for_update() -> clap::Command {
        unimplemented!()
    }
}

impl FromArgMatches for AllCommand {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        CinnabarCommand::from_arg_matches(matches)
            .or_else(|e| {
                if e.kind() == ErrorKind::InvalidSubcommand {
                    if let Some((name, matches)) = matches.subcommand() {
                        if name == "tag" && experiment(Experiments::TAG) {
                            return TagCommand::from_arg_matches(matches).map(CinnabarCommand::Tag);
                        }
                        if name == "strip" && experiment(Experiments::STRIP) {
                            return StripCommand::from_arg_matches(matches)
                                .map(CinnabarCommand::Strip);
                        }
                    }
                }
                Err(e)
            })
            .map(Self)
    }

    fn update_from_arg_matches(&mut self, _matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        unimplemented!()
    }
}

impl Parser for AllCommand {}

fn git_cinnabar(args: Option<&[&OsStr]>) -> Result<c_int, String> {
    use CinnabarCommand::*;

    let command = if let Some(args) = args {
        AllCommand::try_parse_from(args)
    } else {
        AllCommand::try_parse()
    };
    let command = match command {
        Ok(c) => c.0,
        Err(e) => {
            e.print().unwrap();
            #[cfg(feature = "version-check")]
            if e.kind() == ErrorKind::DisplayVersion
                && e.render()
                    .to_string()
                    .strip_suffix('\n')
                    .and_then(|s| s.strip_prefix("git-cinnabar "))
                    .unwrap_or("")
                    != *SHORT_VERSION
            {
                if let Some(mut checker) = VersionChecker::for_dashdash_version() {
                    checker.wait(Duration::from_secs(1));
                }
            }
            return if e.use_stderr() { Ok(1) } else { Ok(0) };
        }
    };
    #[cfg(feature = "self-update")]
    if let SelfUpdate { branch, exact, url } = command {
        return do_self_update(branch, exact, url).map(|()| 0);
    }
    if let Setup = command {
        return do_setup().map(|()| 0);
    }
    let _v = VersionChecker::new();
    if let RemoteHg { remote, url } = command {
        return git_remote_hg(remote, url);
    }
    let mut store = the_store().unwrap_or_else(|e| panic!("{}", e));
    let ret = match command {
        #[cfg(feature = "self-update")]
        SelfUpdate { .. } => unreachable!(),
        RemoteHg { .. } => unreachable!(),
        Setup => unreachable!(),
        Data {
            changeset: Some(c), ..
        } => do_data_changeset(&store, c),
        Data {
            manifest: Some(m), ..
        } => do_data_manifest(&store, m),
        Data { file: Some(f), .. } => do_data_file(&store, f),
        Data { .. } => unreachable!(),
        Hg2Git {
            abbrev,
            sha1,
            batch,
        } => do_conversion_cmd(
            &store,
            abbrev.map(|v| v.first().map_or(12, |a| a.0)),
            sha1.into_iter(),
            batch,
            do_one_hg2git,
        ),
        Git2Hg {
            abbrev,
            committish,
            batch,
        } => do_conversion_cmd(
            &store,
            abbrev.map(|v| v.first().map_or(12, |a| a.0)),
            committish.into_iter(),
            batch,
            do_one_git2hg,
        ),
        Tag(TagCommand {
            list: true, format, ..
        }) => do_tag_list(&mut store, format),
        Tag(TagCommand {
            list: false,
            force,
            delete,
            onto,
            message,
            tag,
            committish,
            ..
        }) => do_tag(&mut store, force, delete, onto, message, tag, committish),
        Fetch {
            remote: Some(remote),
            revs,
            bundle,
            tags: false,
        } => do_fetch(&mut store, &remote, &revs, bundle),
        Fetch { tags: true, .. } => do_fetch_tags(),
        Fetch { remote: None, .. } => unreachable!(),
        Reclone { rebase } => do_reclone(&mut store, rebase),
        Clear => do_rollback(false, false, false, Some(CommitId::NULL.to_string().into())),
        Rollback {
            candidates,
            fsck,
            force,
            committish,
        } => do_rollback(candidates, fsck, force, committish),
        Strip(StripCommand { committish }) => do_strip(&mut store, committish),
        Upgrade => do_upgrade(),
        Unbundle { clonebundle, url } => do_unbundle(&mut store, clonebundle, url),
        Fsck {
            force,
            full,
            commit,
        } => match do_fsck(&mut store, force, full, commit) {
            Ok(code) => return Ok(code),
            Err(e) => Err(e),
        },
        Bundle {
            version,
            r#type,
            path,
            revs,
        } => match do_bundle(&store, version, r#type, path, revs) {
            Ok(code) => return Ok(code),
            Err(e) => Err(e),
        },
    };
    ret.map(|_| 0)
}

pub fn main() {
    let args: Vec<_> = std::env::args_os().map(prepare_arg).collect();
    let argc = args.len();
    #[cfg_attr(windows, allow(clippy::redundant_closure_for_method_calls))]
    let mut argv: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    // This is circumvoluted, but we need the initialization from wmain.
    #[cfg(unix)]
    use cinnabar_main as cinnabar_main_;
    #[cfg(windows)]
    use wmain as cinnabar_main_;

    let ret = unsafe { cinnabar_main_(argc.try_into().unwrap(), &argv[0]) };
    drop(args);
    std::process::exit(ret);
}

fn remote_helper_tags_list(store: &Store, mut stdout: impl Write) {
    let tags = store.get_tags();
    let tags = tags
        .iter()
        .filter_map(|(t, h)| h.to_git(store).map(|g| (t, g)))
        .sorted()
        .collect_vec();
    // git fetch does a check-connection that calls
    // `git rev-list --objects --stdin --not --all` with the list of
    // sha1s from the list we're about to give it. With no refs on these
    // exact sha1s, the rev-list can take a long time on large repos.
    // So we temporarily create refs to make that rev-list faster.
    let mut ref_updates = REF_UPDATES.lock().unwrap();
    let mut transaction = RefTransaction::new().unwrap();
    for &(tag, cid) in &tags {
        let mut buf = b"refs/cinnabar/refs/tags/".to_vec();
        buf.extend_from_slice(tag);
        transaction
            .update(OsStr::from_bytes(&buf), cid.into(), None, "tags")
            .unwrap();
        // Queue the deletions for after the helper closes, by which time git
        // will have finished with check-connection.
        ref_updates.insert(buf.as_bstr().to_boxed(), CommitId::NULL);
    }
    transaction.commit().unwrap();

    for &(tag, cid) in &tags {
        let mut buf = format!("{cid} refs/tags/").into_bytes();
        buf.extend_from_slice(tag);
        buf.push(b'\n');
        stdout.write_all(&buf).unwrap();
    }
    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();
}

bitflags! {
    #[derive(Debug)]
    pub struct RefsStyle: i32 {
        const HEADS = 0x1;
        const BOOKMARKS = 0x2;
        const TIPS = 0x4;
    }
}

impl RefsStyle {
    fn from_config(name: &str, remote: Option<&str>) -> Option<Self> {
        match get_config_remote(name, remote)
            .as_deref()
            .map(OsStrExt::as_bytes)
        {
            Some(b"") => None,
            None => None,
            Some(config) => {
                let mut styles = RefsStyle::empty();
                for c in config.split(|&b| b == b',') {
                    match c {
                        b"true" | b"all" => styles = RefsStyle::all(),
                        b"heads" => styles.set(RefsStyle::HEADS, true),
                        b"bookmarks" => styles.set(RefsStyle::BOOKMARKS, true),
                        b"tips" => styles.set(RefsStyle::TIPS, true),
                        _ => die!(
                            "`{}` is not one of `heads`, `bookmarks` or `tips`",
                            c.as_bstr()
                        ),
                    }
                }
                Some(styles)
            }
        }
    }
}

#[derive(Debug)]
struct RemoteInfo {
    head_ref: Option<Box<BStr>>,
    refs: BTreeMap<Box<BStr>, (HgChangesetId, Option<GitChangesetId>)>,
    topological_heads: Vec<HgChangesetId>,
    branch_names: HashSet<Box<BStr>>,
    bookmarks: HashMap<Box<BStr>, HgChangesetId>,
    refs_style: RefsStyle,
}

fn repo_list(
    store: Option<&Store>,
    conn: &mut dyn HgRepo,
    remote: Option<&str>,
    for_push: bool,
) -> RemoteInfo {
    let refs_style = (for_push)
        .then(|| RefsStyle::from_config("pushrefs", remote))
        .flatten()
        .or_else(|| RefsStyle::from_config("refs", remote))
        .unwrap_or(RefsStyle::all());

    let mut refs = BTreeMap::new();

    let apply_template = |template: &[&str], values: &[&BStr]| {
        let mut buf = Vec::new();
        let mut values = values.iter();
        for part in template {
            if part.is_empty() {
                buf.extend_from_slice(values.next().unwrap());
            } else {
                buf.extend_from_slice(part.as_bytes());
            }
        }
        buf.as_bstr().to_boxed()
    };

    let mut add_ref = |template: Option<&[&str]>, values: &[&BStr], csid: HgChangesetId| {
        if let Some(template) = template {
            let cid = store.as_ref().and_then(|store| csid.to_git(store));
            refs.insert(apply_template(template, values), (csid, cid));
        }
    };

    let branchmap = ByteSlice::lines(&*conn.branchmap())
        .map(|l| {
            let [b, h] = l.splitn_exact(b' ').unwrap();
            (
                b.as_bstr().to_boxed(),
                h.split(|&b| b == b' ')
                    .map(HgChangesetId::from_bytes)
                    .collect::<Result<Box<[_]>, _>>()
                    .unwrap(),
            )
        })
        .collect::<HashMap<_, _>>();
    let bookmarks = ByteSlice::lines(&*conn.bookmarks())
        .map(|l| {
            let [b, h] = l.splitn_exact(b'\t').unwrap();
            (
                b.as_bstr().to_boxed(),
                HgChangesetId::from_bytes(h).unwrap(),
            )
        })
        .collect::<HashMap<_, _>>();

    let mut head_template = None;
    let mut tip_template = None;
    let mut default_tip = None;
    if refs_style.intersects(RefsStyle::HEADS | RefsStyle::TIPS) {
        if refs_style.contains(RefsStyle::HEADS | RefsStyle::TIPS) {
            if refs_style.contains(RefsStyle::BOOKMARKS) {
                head_template = Some(&["refs/heads/branches/", "", "/", ""][..]);
                tip_template = Some(&["refs/heads/branches/", "", "/tip"][..]);
            } else {
                head_template = Some(&["refs/heads/", "", "/", ""][..]);
                tip_template = Some(&["refs/heads/", "", "/tip"][..]);
            }
        } else if refs_style.contains(RefsStyle::HEADS | RefsStyle::BOOKMARKS) {
            head_template = Some(&["refs/heads/branches/", "", "/", ""]);
        } else if refs_style.contains(RefsStyle::HEADS) {
            head_template = Some(&["refs/heads/", "", "/", ""]);
        } else if refs_style.contains(RefsStyle::TIPS | RefsStyle::BOOKMARKS) {
            tip_template = Some(&["refs/heads/branches/", ""]);
        } else if refs_style.contains(RefsStyle::TIPS) {
            tip_template = Some(&["refs/heads/", ""]);
        }

        for (branch, heads) in branchmap.iter() {
            // Use the last non-closed head as tip if there's more than one head.
            // Caveat: we don't know a head is closed until we've pulled it.
            let mut tip = None;
            for head in heads.iter().rev() {
                tip = Some(head);
                if let Some(store) = store {
                    if let Some(git_head) = head.to_git(store) {
                        let metadata = RawGitChangesetMetadata::read(store, git_head).unwrap();
                        let metadata = metadata.parse().unwrap();
                        if metadata.extra().and_then(|e| e.get(b"close")).is_some() {
                            continue;
                        }
                    }
                }
                break;
            }
            if let Some(tip) = tip {
                if &***branch == b"default" {
                    default_tip = Some(tip);
                }
                add_ref(tip_template, &[branch], *tip);
            }

            for head in heads.iter() {
                if tip_template.is_none() || Some(head) != tip {
                    add_ref(
                        head_template,
                        &[branch, head.to_string().as_bytes().as_bstr()],
                        *head,
                    );
                }
            }
        }
    }

    let mut bookmark_template = None;
    if refs_style.contains(RefsStyle::BOOKMARKS) {
        bookmark_template = Some(
            if refs_style.intersects(RefsStyle::HEADS | RefsStyle::TIPS) {
                &["refs/heads/bookmarks/", ""][..]
            } else {
                &["refs/heads/", ""]
            },
        );
        for (name, cid) in bookmarks.iter() {
            if !cid.is_null() {
                add_ref(bookmark_template, &[&**name], *cid);
            }
        }
    }

    let head_ref = if let Some(bookmark_template) = bookmarks
        .contains_key(b"@".as_bstr())
        .then_some(())
        .and(bookmark_template)
    {
        Some(apply_template(bookmark_template, &[b"@".as_bstr()]))
    } else if let Some(tip_template) = tip_template {
        Some(apply_template(tip_template, &[b"default".as_bstr()]))
    } else if let Some((head_template, default_tip)) = head_template.zip(default_tip) {
        Some(apply_template(
            head_template,
            &[
                b"default".as_bstr(),
                format!("{default_tip}").as_bytes().as_bstr(),
            ],
        ))
    } else {
        None
    };

    RemoteInfo {
        head_ref,
        refs,
        topological_heads: conn
            .heads()
            .trim_end_with(|c| c == '\n')
            .split(|&b| b == b' ')
            .map(HgChangesetId::from_bytes)
            .collect::<Result<_, _>>()
            .unwrap(),
        branch_names: branchmap.into_keys().collect(),
        bookmarks,
        refs_style,
    }
}

fn remote_helper_repo_list(
    store: Option<&Store>,
    conn: &mut dyn HgRepo,
    remote: Option<&str>,
    mut stdout: impl Write,
    for_push: bool,
) -> RemoteInfo {
    let info = repo_list(store, conn, remote, for_push);
    if let Some(head_ref) = &info.head_ref {
        if info.refs.contains_key(head_ref) {
            let mut buf = b"@".to_vec();
            buf.extend_from_slice(head_ref);
            buf.push(b' ');
            buf.extend_from_slice(b"HEAD\n");
            stdout.write_all(&buf).unwrap();
        }
    }

    for (refname, (_, cid)) in info.refs.iter() {
        let mut buf = cid
            .as_ref()
            .map_or_else(|| "?".to_string(), ToString::to_string)
            .into_bytes();
        buf.push(b' ');
        buf.extend_from_slice(refname);
        buf.push(b'\n');
        stdout.write_all(&buf).unwrap();
    }

    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();
    info
}

fn remote_helper_import(
    store: &mut Store,
    conn: &mut dyn HgRepo,
    remote: Option<&str>,
    wanted_refs: &[&BStr],
    info: RemoteInfo,
    mut stdout: impl Write,
) -> Result<(), String> {
    if let Some(metadata) = resolve_ref(METADATA_REF) {
        if Some(metadata) == resolve_ref(BROKEN_REF) {
            return Err(
                "Cannot fetch with broken metadata. Please fix your clone first.".to_string(),
            );
        }
    }

    // If anything wrong happens at any time, we risk git picking the existing
    // refs/cinnabar refs, so remove them preventively.
    let mut transaction = RefTransaction::new().unwrap();
    for_each_ref_in(REFS_PREFIX, |r, cid| {
        if r.as_bytes().starts_with_str("refs/")
            || r.as_bytes().starts_with_str("hg/")
            || r == "HEAD"
        {
            let mut full_ref = OsString::from(REFS_PREFIX);
            full_ref.push(r);
            transaction.delete(full_ref, Some(cid), "pre-import")
        } else {
            Ok(())
        }
    })?;
    transaction.commit()?;

    check_graft_refs();

    let wanted_refs = wanted_refs
        .iter()
        .map(|refname| {
            let refname = (*refname == b"HEAD".as_bstr())
                .then_some(info.head_ref.as_deref())
                .flatten()
                .unwrap_or(*refname);
            info.refs
                .get_key_value(refname)
                .map(|(k, (h, g))| (k.as_bstr(), h, g.as_ref()))
                .ok_or(refname)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|refname| format!("couldn't find remote ref {refname}"))?;

    let mut tags = None;
    let unknown_wanted_heads = wanted_refs
        .iter()
        .filter(|(_, _, cid)| cid.is_none())
        .map(|(_, csid, _)| **csid)
        .unique()
        .collect_vec();
    if !unknown_wanted_heads.is_empty() {
        tags = Some(store.get_tags());
        maybe_init_graft(store, remote)?;
        get_bundle(
            store,
            conn,
            &unknown_wanted_heads,
            Some(&info.topological_heads),
            &info.branch_names,
            remote,
        )?;
    }

    do_done_and_check(store, &[])
        .then_some(())
        .ok_or_else(|| "Fatal error".to_string())?;

    let mut transaction = RefTransaction::new().unwrap();
    for (refname, csid, cid) in wanted_refs.iter().unique() {
        let mut buf = Vec::new();
        buf.extend_from_slice(REFS_PREFIX.as_bytes());
        buf.extend(&***refname);
        transaction
            .update(
                OsStr::from_bytes(&buf),
                cid.copied()
                    .unwrap_or_else(|| csid.to_git(store).unwrap())
                    .into(),
                None,
                "import",
            )
            .unwrap();
    }
    transaction.commit().unwrap();

    conn.sync();
    writeln!(stdout, "done").unwrap();
    stdout.flush().unwrap();

    if info.refs_style.contains(RefsStyle::HEADS) {
        if let Some(remote) = remote {
            let remote_prune = format!("remote.{remote}.prune");
            if config_get_value("fetch.prune")
                .or_else(|| config_get_value(&remote_prune))
                .as_deref()
                != Some(OsStr::new("true"))
            {
                eprintln!(
                    "It is recommended that you set \"{remote_prune}\" or \
                     \"fetch.prune\" to \"true\".\n\
                     \x20 git config {remote_prune} true\n\
                     or\n\
                     \x20 git config fetch.prune true"
                );
            }
        }
    }

    if let Some(old_tags) = tags {
        if old_tags != store.get_tags() {
            eprintln!(
                "\nRun the following command to update tags:\n\
                 \x20 git cinnabar fetch --tags"
            );
        }
    }
    Ok(())
}

fn check_graft_refs() {
    if get_config("graft-refs").is_some() {
        warn!(
            target: "root",
            "The cinnabar.graft-refs configuration is deprecated.\n\
             Please unset it."
        );
    }
}

#[derive(PartialEq, Eq)]
enum RecordMetadata {
    Never,
    Phase,
    Always,
    // Like Always, but also applies to dry-run
    Force,
}

impl TryFrom<&OsStr> for RecordMetadata {
    type Error = String;

    fn try_from(value: &OsStr) -> Result<RecordMetadata, String> {
        value
            .to_str()
            .and_then(|s| {
                Some(match s {
                    "never" => RecordMetadata::Never,
                    "phase" => RecordMetadata::Phase,
                    "always" => RecordMetadata::Always,
                    "force" => RecordMetadata::Force,
                    _ => return None,
                })
            })
            .ok_or_else(|| {
                format!(
                    "`{}` is not one of `never`, `phase`, `always` or `force`",
                    value.as_bytes().as_bstr()
                )
            })
    }
}

fn remote_helper_push(
    store: &mut Store,
    conn: &mut dyn HgRepo,
    remote: Option<&str>,
    push_refs: &[&BStr],
    info: RemoteInfo,
    mut stdout: impl Write,
    dry_run: bool,
) -> Result<(), String> {
    let push_refs = push_refs
        .iter()
        .map(|p| {
            let [source, dest] = p.splitn_exact(b':').unwrap();
            let (source, force) = source
                .strip_prefix(b"+")
                .map_or((source, false), |s| (s, true));
            (
                (!source.is_empty()).then(|| get_oid_committish(source).unwrap()),
                dest.as_bstr(),
                force,
            )
        })
        .collect_vec();

    let broken = resolve_ref(METADATA_REF).map(|m| resolve_ref(BROKEN_REF) == Some(m));
    if broken == Some(true) || conn.get_capability(b"unbundle").is_none() {
        for (_, dest, _) in &push_refs {
            let mut buf = b"error ".to_vec();
            buf.extend_from_slice(dest);
            buf.extend_from_slice(if broken == Some(true) {
                b" Cannot push with broken metadata. Please fix your clone first.\n"
            } else {
                b" Remote does not support the \"unbundle\" capability.\n"
            });
            stdout.write_all(&buf).unwrap();
        }
        stdout.write_all(b"\n").unwrap();
        stdout.flush().unwrap();
        return Ok(());
    }

    let bookmark_prefix = info.refs_style.contains(RefsStyle::BOOKMARKS).then(|| {
        if info
            .refs_style
            .intersects(RefsStyle::HEADS | RefsStyle::TIPS)
        {
            b"refs/heads/bookmarks/".as_bstr()
        } else {
            b"refs/heads/".as_bstr()
        }
    });

    let data = get_config_remote("data", remote)
        .filter(|d| !d.is_empty())
        .as_deref()
        .map_or(Ok(RecordMetadata::Phase), RecordMetadata::try_from)?;

    let mut pushed = ChangesetHeads::new();
    let result = (|| {
        let push_commits = push_refs.iter().filter_map(|(c, _, _)| *c).collect_vec();
        let local_bases = rev_list_with_boundaries(
            store
                .changeset_heads()
                .branch_heads()
                .filter(|(_, b)| info.branch_names.contains(*b))
                .map(|(h, _)| format!("^{}", h.to_git(store).unwrap()))
                .chain(push_commits.iter().map(ToString::to_string))
                .chain(["--topo-order".to_string(), "--full-history".to_string()]),
        )
        .filter_map(|(c, b)| match b {
            MaybeBoundary::Boundary => Some(Ok(c)),
            MaybeBoundary::Shallow => Some(Err(
                "Pushing git shallow clones is not supported".to_string()
            )),
            MaybeBoundary::Commit => None,
        })
        .chain(push_commits.into_iter().map(Ok))
        .map_ok(GitChangesetId::from_unchecked)
        .filter_map_ok(|c| c.to_hg(store))
        .unique()
        .collect::<Result<Vec<_>, _>>()?;

        let pushing_anything = push_refs.iter().any(|(c, _, _)| c.is_some());
        let force = push_refs.iter().all(|(_, _, force)| *force);
        let no_topological_heads = info.topological_heads.iter().all(ObjectId::is_null);
        if pushing_anything && local_bases.is_empty() && !no_topological_heads {
            let mut fail = true;
            if has_metadata(store) && force {
                let cinnabar_roots = rev_list([
                    "--topo-order",
                    "--full-history",
                    "--max-parents=0",
                    "refs/cinnabar/metadata^",
                ])
                .filter_map(|c| GitChangesetId::from_unchecked(c).to_hg(store))
                .collect_vec();
                fail = !conn.known(&cinnabar_roots).iter().any(|k| *k);
            }
            if fail {
                return Err("Cannot push to this remote without pulling/updating first".to_string());
            }
        }

        let common = find_common(store, conn, local_bases, remote);

        let mut push_commits = rev_list_with_parents(
            ["--topo-order", "--full-history", "--reverse"]
                .iter()
                .map(ToString::to_string)
                .chain(
                    common
                        .into_iter()
                        .map(|c| format!("^{}", c.to_git(store).unwrap())),
                )
                .chain(
                    push_refs
                        .iter()
                        .filter_map(|(c, _, _)| c.as_ref().map(ToString::to_string)),
                ),
        )
        .map(|(c, p)| (c, p, None))
        .collect_vec();

        if experiment(Experiments::BRANCH)
            && info
                .refs_style
                .intersects(RefsStyle::HEADS | RefsStyle::TIPS)
        {
            #[derive(Clone, Debug)]
            enum BranchInfo {
                Known(Option<Box<BStr>>),
                Inferred(Option<Box<BStr>>),
                Set(Option<Box<BStr>>),
            }

            impl BranchInfo {
                fn unwrap(self) -> Option<Box<BStr>> {
                    match self {
                        BranchInfo::Known(b) | BranchInfo::Inferred(b) | BranchInfo::Set(b) => b,
                    }
                }
            }

            let get_branch = |c| {
                let cs_metadata =
                    RawGitChangesetMetadata::read(store, GitChangesetId::from_unchecked(c))?;
                let cs_metadata = cs_metadata.parse().unwrap();
                Some(BranchInfo::Known(cs_metadata.extra().and_then(|e| {
                    e.get(b"branch").map(|b| b.as_bstr().to_boxed())
                })))
            };

            let mut dag: Dag<CommitId, RefCell<Option<BranchInfo>>> = Dag::new();
            for (c, p, _) in &push_commits {
                dag.add(
                    *c,
                    p,
                    RefCell::new(get_branch(*c).or_else(|| {
                        p.first().and_then(|p| {
                            dag.get(*p)
                                .and_then(|(_, b)| {
                                    b.clone().into_inner().map(|b| match b {
                                        BranchInfo::Inferred(b) => BranchInfo::Inferred(b),
                                        BranchInfo::Known(b) => BranchInfo::Inferred(b),
                                        BranchInfo::Set(_) => unreachable!(),
                                    })
                                })
                                .or_else(|| {
                                    get_branch(*p).map(|b| BranchInfo::Inferred(b.unwrap()))
                                })
                        })
                    })),
                );
            }

            let prefix = if info.refs_style.contains(RefsStyle::BOOKMARKS) {
                &b"refs/heads/branches/"[..]
            } else {
                &b"refs/heads/"[..]
            };
            for (c, branch) in push_refs.iter().filter_map(|(c, remote_ref, _)| {
                c.and_then(|c| {
                    remote_ref.strip_prefix(prefix).and_then(|s| {
                        if info.refs_style.contains(RefsStyle::HEADS) {
                            s.splitn_exact::<2>(b'/').map(|[b, _]| (c, b))
                        } else {
                            Some((c, s))
                        }
                    })
                })
            }) {
                for (_, info) in dag.traverse_parents(&[c], |_, info| {
                    matches!(*info.borrow(), Some(BranchInfo::Inferred(_)) | None)
                }) {
                    if matches!(*info.borrow(), Some(BranchInfo::Inferred(_)) | None) {
                        info.replace(Some(BranchInfo::Set(
                            (branch != b"default").then(|| branch.as_bstr().to_boxed()),
                        )));
                    }
                }
            }
            for (c, _, b) in &mut push_commits {
                if let Some((_, info)) = dag.get(*c) {
                    *b = info
                        .borrow()
                        .clone()
                        .expect("Branch name should have been set")
                        .unwrap();
                }
            }
        }

        if !push_commits.is_empty() {
            let has_root = push_commits.iter().any(|(_, p, _)| p.is_empty());
            if has_root && !no_topological_heads {
                if !force {
                    return Err("Cannot push a new root".to_string());
                }
                warn!(target: "root", "Pushing a new root");
            }
        }

        let mut result = None;
        if !push_commits.is_empty() && (!dry_run || data == RecordMetadata::Force) {
            conn.require_capability(b"unbundle");

            let b2caps = conn
                .get_capability(b"bundle2")
                .and_then(|caps| {
                    decodecaps(
                        percent_decode(caps)
                            .decode_utf8()
                            .ok()?
                            .as_bytes()
                            .as_bstr(),
                    )
                    .collect::<Option<HashMap<_, _>>>()
                })
                .unwrap_or_default();
            let (bundlespec, version) = if b2caps.is_empty() {
                (BundleSpec::ChangegroupV1, 1)
            } else {
                let version = b2caps
                    .get("changegroup")
                    .and_then(|cg| cg.iter().flat_map(|cg| cg.iter()).find(|cg| &***cg == "02"))
                    .and(Some(2))
                    .unwrap_or(1);
                (BundleSpec::V2None, version)
            };
            // TODO: Ideally, for dry-run, we wouldn't even create a temporary file.
            let tempfile = tempfile::Builder::new()
                .prefix("hg-bundle-")
                .suffix(".hg")
                .rand_bytes(6)
                .tempfile()
                .unwrap();
            let (file, path) = tempfile.into_parts();
            pushed = do_create_bundle(
                store,
                push_commits.iter().cloned(),
                bundlespec,
                version,
                &file,
                version == 2,
            )?;
            drop(file);
            if !dry_run {
                let file = File::open(path).unwrap();
                let empty_heads = [HgChangesetId::NULL];
                let heads = if force {
                    None
                } else if no_topological_heads {
                    Some(&empty_heads[..])
                } else {
                    Some(&info.topological_heads[..])
                };
                let response = conn.unbundle(heads, file);
                match response {
                    UnbundleResponse::Bundlev2(data) => {
                        let mut bundle = BundleReader::new(data).map_err(|e| e.to_string())?;
                        while let Some(part) = bundle.next_part().map_err(|e| e.to_string())? {
                            match part.part_type.as_bytes() {
                                b"reply:changegroup" => {
                                    // TODO: should check in-reply-to param.
                                    let response = part.get_param("return").unwrap();
                                    result = u32::from_str(response).ok();
                                }
                                b"error:abort" => {
                                    let mut message =
                                        part.get_param("message").unwrap().to_string();
                                    if let Some(hint) = part.get_param("hint") {
                                        message.push_str("\n\n");
                                        message.push_str(hint);
                                    }
                                    return Err(message);
                                }
                                _ => {}
                            }
                        }
                    }
                    UnbundleResponse::Raw(response) => {
                        result = u32::from_bytes(&response).ok();
                    }
                }
            }
        }

        if (result.unwrap_or(0) > 0 || dry_run) && push_commits.is_empty() {
            Ok(1)
        } else {
            Ok(0)
        }
    })();

    // Collect all the responses before sending anything back through
    // the remote-helper protocol, so that if something fails, we don't
    // send partial information to the remote-helper (although at this point,
    // the push has happened).
    let status = (result == Ok(0))
        .then(|| &push_refs[..])
        .into_iter()
        .flatten()
        .map(|(source_cid, dest, _)| {
            let status = if dest.starts_with(b"refs/tags/") {
                Err(if source_cid.is_some() {
                    "Pushing tags is unsupported"
                } else {
                    "Deleting remote tags is unsupported"
                })
            } else if let Some(name) =
                bookmark_prefix.and_then(|prefix| dest.strip_prefix(&**prefix))
            {
                let name = percent_decode(name).decode_utf8().unwrap();
                let csid = source_cid
                    .as_ref()
                    .map(|cid| GitChangesetId::from_unchecked(*cid).to_hg(store).unwrap());
                conn.require_capability(b"pushkey");
                let response = conn.pushkey(
                    "bookmarks",
                    &name,
                    &info
                        .bookmarks
                        .get(name.as_bytes().as_bstr())
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    &csid.as_ref().map(ToString::to_string).unwrap_or_default(),
                );
                Ok(u32::from_bytes(response.trim_end_with(|c| c == '\n'))
                    .map(|n| n > 0)
                    .unwrap_or_default())
            } else if source_cid.is_some() {
                Ok(!pushed.is_empty() || dry_run)
            } else {
                Err("Deleting remote branches is unsupported")
            };
            (*dest, status)
        })
        .collect::<HashMap<_, _>>();

    conn.sync();

    for (_, dest, _) in push_refs {
        let mut buf = Vec::new();
        match status
            .get(dest)
            .copied()
            .unwrap_or_else(|| result.as_ref().map(|_| false).map_err(|e| &**e))
        {
            Ok(true) => {
                buf.extend_from_slice(b"ok ");
                buf.extend_from_slice(dest);
            }
            Ok(false) => {
                buf.extend_from_slice(b"error ");
                buf.extend_from_slice(dest);
                buf.extend_from_slice(b" nothing changed on remote");
            }
            Err(e) => {
                buf.extend_from_slice(b"error ");
                buf.extend_from_slice(dest);
                buf.push(b' ');
                buf.extend_from_slice(e.as_bytes());
            }
        }
        buf.push(b'\n');
        stdout.write_all(&buf).unwrap();
    }
    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();

    let rollback =
        if status.is_empty() || pushed.is_empty() || (dry_run && data != RecordMetadata::Force) {
            true
        } else {
            match data {
                RecordMetadata::Force | RecordMetadata::Always => false,
                RecordMetadata::Never => true,
                RecordMetadata::Phase => {
                    let phases = conn.phases();
                    let phases = ByteSlice::lines(&*phases)
                        .filter_map(|l| {
                            l.splitn_exact(b'\t')
                                .map(|[k, v]| (k.as_bstr(), v.as_bstr()))
                        })
                        .collect::<HashMap<_, _>>();
                    let drafts = (!phases.contains_key(b"publishing".as_bstr()))
                        .then(|| {
                            phases
                                .into_iter()
                                .filter_map(|(phase, is_draft)| {
                                    u32::from_bytes(is_draft).ok().and_then(|is_draft| {
                                        (is_draft > 0).then(|| HgChangesetId::from_bytes(phase))
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()
                        .unwrap()
                        .unwrap_or_default();
                    if drafts.is_empty() {
                        false
                    } else {
                        // Theoretically, we could have commits with no
                        // metadata that the remote declares are public, while
                        // the rest of our push is in a draft state. That is
                        // however so unlikely that it's not worth the effort
                        // to support partial metadata storage.
                        !reachable_subset(
                            pushed
                                .heads()
                                .copied()
                                .filter_map(|h| h.to_git(store))
                                .map(Into::into),
                            drafts
                                .iter()
                                .copied()
                                .filter_map(|h| h.to_git(store))
                                .map(Into::into),
                        )
                        .is_empty()
                    }
                }
            }
        };
    if rollback {
        unsafe {
            do_cleanup(1);
        }
    } else {
        do_done_and_check(store, &[])
            .then_some(())
            .ok_or_else(|| "Fatal error".to_string())?;
    }
    Ok(())
}

fn git_remote_hg(remote: OsString, mut url: OsString) -> Result<c_int, String> {
    if !url.as_bytes().starts_with(b"hg:") {
        let mut new_url = OsString::from("hg::");
        new_url.push(url);
        url = new_url;
    }
    let remote = Some(remote.to_str().unwrap().to_owned())
        .and_then(|r| (!r.starts_with("hg://") && !r.starts_with("hg::")).then_some(r));
    let url = hg_url(&url).unwrap();
    let mut conn = (url.scheme() != "tags").then(|| get_connection(&url).unwrap());

    let stdin = stdin();
    let mut stdin = LoggingReader::new("remote-helper", log::Level::Info, stdin.lock());
    let stdout = stdout();
    let mut stdout = LoggingWriter::new("remote-helper", log::Level::Info, stdout.lock());
    let mut buf = Vec::new();
    let mut dry_run = false;
    let mut info = None;
    let mut store: Lazy<Result<_, _>> = Lazy::new(the_store);
    loop {
        buf.truncate(0);
        stdin.read_until(b'\n', &mut buf).unwrap();
        if buf.ends_with(b"\n") {
            buf.pop();
        }
        if buf.is_empty() {
            break;
        }
        let mut args = buf.split(|&b| b == b' ');
        let cmd = args.next().unwrap();
        match cmd {
            b"option" => {
                match &args.collect_vec()[..] {
                    [b"progress", value @ (b"true" | b"false")] => {
                        set_progress(bool::from_bytes(value).unwrap());
                        writeln!(stdout, "ok").unwrap();
                    }
                    [b"dry-run", value @ (b"true" | b"false")] => {
                        dry_run = bool::from_bytes(value).unwrap();
                        writeln!(stdout, "ok").unwrap();
                    }
                    _ => {
                        writeln!(stdout, "unsupported").unwrap();
                    }
                }
                stdout.flush().unwrap();
                continue;
            }
            b"capabilities" => {
                stdout.write_all("option\nimport\n".as_bytes()).unwrap();
                if url.scheme() != "tags" {
                    stdout
                        .write_all(
                            "push\n\
                             refspec refs/heads/*:refs/cinnabar/refs/heads/*\n\
                             refspec hg/*:refs/cinnabar/hg/*\n\
                             "
                            .as_bytes(),
                        )
                        .unwrap();
                }
                stdout
                    .write_all("refspec HEAD:refs/cinnabar/HEAD\n\n".as_bytes())
                    .unwrap();

                stdout.flush().unwrap();
                continue;
            }
            b"list" => {
                let for_push = match &args.collect_vec()[..] {
                    [b"for-push"] => true,
                    [] => false,
                    _ => panic!("unknown argument(s) to list command"),
                };
                if url.scheme() == "tags" {
                    assert!(!for_push);
                    remote_helper_tags_list(
                        store.as_ref().unwrap_or_else(|e| panic!("{}", e)),
                        &mut stdout,
                    );
                } else {
                    info = Some(remote_helper_repo_list(
                        store.as_ref().ok(),
                        conn.as_deref_mut().unwrap(),
                        remote.as_deref(),
                        &mut stdout,
                        for_push,
                    ));
                }
                continue;
            }
            _ => {}
        }
        let args = match cmd {
            b"import" | b"push" => args
                .map(|a| a.as_bstr().to_boxed())
                .chain(
                    (&mut stdin)
                        .byte_lines()
                        .take_while(|l| l.as_ref().map(|l| !l.is_empty()).unwrap_or(true))
                        .map(|line| {
                            line.unwrap()
                                .strip_prefix(cmd)
                                .and_then(|l| l.strip_prefix(b" "))
                                .unwrap()
                                .as_bstr()
                                .to_boxed()
                        }),
                )
                .collect_vec(),
            _ => panic!("unknown command: {}", cmd.as_bstr()),
        };
        match cmd {
            b"import" => {
                assert_ne!(url.scheme(), "tags");
                match remote_helper_import(
                    store.as_mut().unwrap_or_else(|e| panic!("{}", e)),
                    conn.as_deref_mut().unwrap(),
                    remote.as_deref(),
                    &args.iter().map(|r| &**r).collect_vec(),
                    info.take().unwrap(),
                    &mut stdout,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        // die will eventually get us to return an error code, but git
                        // actually ignores it. So we send it a command it doesn't know
                        // over the helper/fast-import protocol, so that it emits an
                        // error.
                        // Alternatively, we could send `feature done` before doing
                        // anything, and on the `done` command not being sent when
                        // we die, git would catch it, but that requires git >= 1.7.7
                        // and may trigger a more confusing error.
                        writeln!(stdout, "error").unwrap();
                        stdout.flush().unwrap();
                        die!("{}", e);
                    }
                }
            }
            b"push" => {
                assert_ne!(url.scheme(), "tags");
                remote_helper_push(
                    store.as_mut().unwrap_or_else(|e| panic!("{}", e)),
                    conn.as_deref_mut().unwrap(),
                    remote.as_deref(),
                    &args.iter().map(|r| &**r).collect_vec(),
                    info.take().unwrap(),
                    &mut stdout,
                    dry_run,
                )?;
            }
            _ => panic!("unknown command: {}", cmd.as_bstr()),
        }
    }
    // See comment in remote_helper_tags_list.
    dump_ref_updates();
    Ok(0)
}

static mut HAS_GIT_REPO: bool = false;

#[no_mangle]
unsafe extern "C" fn cinnabar_main(_argc: c_int, argv: *const *const c_char) -> c_int {
    let now = Instant::now();

    // We look at argv[0] to choose what behavior to take, but it's not
    // guaranteed to have a full path, while init_cinnabar (really, git-core)
    // needs one, so for that we use current_exe().
    let argv0 = CStr::from_ptr(*argv.as_ref().unwrap());
    let argv0_path = Path::new(argv0.to_osstr());

    // If for some reason current_exe() failed, fallback to argv[0].
    let exe = std::env::current_exe().map(|e| e.as_os_str().to_cstring());
    std::panic::set_hook(Box::new(|info| {
        if let Some(s) = info.payload().downcast_ref::<&str>() {
            eprintln!("fatal: {s}");
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            eprintln!("fatal: {s}");
        } else {
            eprintln!("fatal error");
        }
        if check_enabled(Checks::TRACEBACK) {
            eprintln!("{:#?}", backtrace::Backtrace::new());
        } else {
            eprintln!(
                "Run the command again with \
                `git -c cinnabar.check=traceback <command>` to see the \
                full traceback."
            );
        }
    }));
    HAS_GIT_REPO = init_cinnabar(exe.as_deref().unwrap_or(argv0).as_ptr()) != 0;
    logging::init(now);
    experiment(Experiments::MERGE);

    let ret = match argv0_path.file_stem().and_then(OsStr::to_str) {
        Some("git-cinnabar") => git_cinnabar(None),
        Some("git-remote-hg") => git_cinnabar(Some(
            &[OsStr::new("git-cinnabar"), OsStr::new("remote-hg")]
                .into_iter()
                .chain(
                    std::env::args_os()
                        .skip(1)
                        .collect_vec()
                        .iter()
                        .map(|a| &**a),
                )
                .collect_vec(),
        )),
        Some(_) | None => Ok(1),
    };
    if hg_connect_http::CURL_GLOBAL_INIT.get().is_some() {
        unsafe {
            curl_sys::curl_global_cleanup();
        }
    }
    match ret {
        Ok(code) => code,
        Err(msg) => {
            error!(target: "root", "{msg}");
            1
        }
    }
}

pub fn get_config(name: &str) -> Option<OsString> {
    get_config_remote(name, None)
}

pub trait ConfigType: ToOwned {
    fn from_os_string(value: OsString) -> Option<Self::Owned>;
}

impl ConfigType for str {
    fn from_os_string(value: OsString) -> Option<Self::Owned> {
        value.into_string().ok()
    }
}

impl ConfigType for bool {
    fn from_os_string(value: OsString) -> Option<Self::Owned> {
        match value.as_bytes() {
            b"1" | b"true" => Some(true),
            b"" | b"0" | b"false" => Some(false),
            _ => None,
        }
    }
}

pub fn get_typed_config<T: ConfigType + ?Sized>(name: &str) -> Option<T::Owned> {
    get_config(name).and_then(T::from_os_string)
}

pub fn get_config_remote(name: &str, remote: Option<&str>) -> Option<OsString> {
    const PREFIX: &str = "GIT_CINNABAR_";
    let mut env_key = String::with_capacity(name.len() + PREFIX.len());
    env_key.push_str(PREFIX);
    env_key.extend(name.chars().map(|c| match c.to_ascii_uppercase() {
        '-' => '_',
        c => c,
    }));
    std::env::var_os(env_key)
        .or_else(|| {
            remote.and_then(|remote| {
                const PREFIX: &str = "remote.";
                const KEY_PREFIX: &str = ".cinnabar-";
                let mut config_key = String::with_capacity(
                    name.len() + PREFIX.len() + KEY_PREFIX.len() + remote.len(),
                );
                config_key.push_str(PREFIX);
                config_key.push_str(remote);
                config_key.push_str(KEY_PREFIX);
                config_key.push_str(name);
                config_get_value(&config_key)
            })
        })
        .or_else(|| {
            const PREFIX: &str = "cinnabar.";
            let mut config_key = String::with_capacity(name.len() + PREFIX.len());
            config_key.push_str(PREFIX);
            config_key.push_str(name);
            config_get_value(&config_key)
        })
}

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq)]
    pub struct Checks: i32 {
        const HELPER = 0x1;
        const MANIFESTS = 0x2;
        const VERSION = 0x4;
        const NODEID = 0x8;
        const FILES = 0x20;
        const TIME = 0x100;
        const TRACEBACK = 0x200;
        const NO_BUNDLE2 = 0x400;
        const CINNABARCLONE = 0x800;
        const CLONEBUNDLES = 0x1000;
        const UNBUNDLER = 0x2000;

        const ALL_BASE_CHECKS = Checks::NODEID.bits() | Checks::MANIFESTS.bits() | Checks::HELPER.bits();
    }
}

static CHECKS: Lazy<Checks> = Lazy::new(|| checks_from_config(get_config("check")));

fn checks_from_config(config: Option<OsString>) -> Checks {
    let mut checks = Checks::VERSION;
    #[cfg(debug_assertions)]
    checks.set(Checks::TRACEBACK, true);
    if let Some(config) = config {
        for c in config.as_bytes().split(|&b| b == b',') {
            if matches!(c, b"true" | b"all") {
                checks = Checks::ALL_BASE_CHECKS;
            } else {
                let (value, name) = c
                    .strip_prefix(b"no-")
                    .map_or((true, c), |name| (false, name));
                let bits = match name {
                    b"helper" => Checks::HELPER,
                    b"manifests" => Checks::MANIFESTS,
                    b"version-check" => Checks::VERSION,
                    b"nodeid" => Checks::NODEID,
                    b"files" => Checks::FILES,
                    b"time" => Checks::TIME,
                    b"traceback" => Checks::TRACEBACK,
                    b"no-bundle2" => Checks::NO_BUNDLE2,
                    b"cinnabarclone" => Checks::CINNABARCLONE,
                    b"clonebundles" => Checks::CLONEBUNDLES,
                    b"unbundler" => Checks::UNBUNDLER,
                    _ => Checks::empty(),
                };
                checks.set(bits, value);
            }
        }
    }
    checks
}

#[test]
fn test_checks_from_config() {
    let mut default = Checks::VERSION;
    #[cfg(debug_assertions)]
    default.set(Checks::TRACEBACK, true);
    assert_eq!(checks_from_config(None), default);
    assert_eq!(checks_from_config(Some("".into())), default);
    assert_eq!(checks_from_config(Some(",".into())), default);
    assert_eq!(checks_from_config(Some("foo".into())), default);
    assert_eq!(
        checks_from_config(Some("helper".into())),
        default | Checks::HELPER
    );
    assert_eq!(
        checks_from_config(Some("helper,".into())),
        default | Checks::HELPER
    );
    assert_eq!(
        checks_from_config(Some("helper,nodeid".into())),
        default | Checks::HELPER | Checks::NODEID
    );
    assert_eq!(
        checks_from_config(Some("no-version-check".into())),
        default & !Checks::VERSION
    );
    assert_eq!(
        checks_from_config(Some("no-traceback".into())),
        Checks::VERSION
    );
    assert_eq!(checks_from_config(Some("helper,no-helper".into())), default);
    assert_eq!(
        checks_from_config(Some("no-helper,helper".into())),
        default | Checks::HELPER
    );
}

#[no_mangle]
unsafe extern "C" fn cinnabar_check(flag: c_int) -> c_int {
    CHECKS.contains(Checks::from_bits(flag).unwrap()) as c_int
}

pub fn check_enabled(checks: Checks) -> bool {
    CHECKS.contains(checks)
}

bitflags! {
    #[derive(Debug)]
    pub struct Compat: i32 {
        const CHANGESET_CONFLICT_NUL = 0x1;

        const CINNABAR_0_6 = Compat::CHANGESET_CONFLICT_NUL.bits();
    }
}

static COMPAT: Lazy<Compat> =
    Lazy::new(
        || match get_config("compat").as_ref().map(|x| x.as_bytes()) {
            Some(b"0.6") => Compat::CINNABAR_0_6,
            Some(x) => {
                warn!(target: "root", "Ignoring invalid value for compat: {}", x.as_bstr());
                Compat::empty()
            }
            None => Compat::empty(),
        },
    );

pub fn has_compat(c: Compat) -> bool {
    COMPAT.contains(c)
}

bitflags! {
    pub struct Experiments: i32 {
        const MERGE = 0x1;
        // Add git commit as extra metadata in mercurial changesets.
        const GIT_COMMIT = 0x2;
        const TAG = 0x4;
        const BRANCH = 0x8;
        const STRIP = 0x10;
        const TEST = 0x100;
    }
}
pub struct AllExperiments {
    flags: Experiments,
    similarity: CString,
}

static EXPERIMENTS: Lazy<AllExperiments> = Lazy::new(|| {
    let mut flags = Experiments::empty();
    let mut similarity = None;
    if let Some(config) = get_config("experiments") {
        for c in config.as_bytes().split(|&b| b == b',') {
            match c {
                b"true" | b"all" => {
                    warn!(target: "root", "`cinnabar.experiments` value `{}` is not supported anymore. Please enable experiments individually.", c.as_bstr());
                }
                b"merge" => {
                    flags |= Experiments::MERGE;
                }
                b"git_commit" => {
                    flags |= Experiments::GIT_COMMIT;
                }
                b"tag" => {
                    flags |= Experiments::TAG;
                }
                b"branch" => {
                    flags |= Experiments::BRANCH;
                }
                b"strip" => {
                    flags |= Experiments::STRIP;
                }
                b"test" => {
                    flags |= Experiments::TEST;
                }
                s if s.starts_with(b"similarity") => {
                    if let Some(value) = s[b"similarity".len()..].strip_prefix(b"=") {
                        match u8::from_bytes(value) {
                            Ok(value) if value <= 100 => {
                                similarity = Some(CString::new(format!("-C{value}%")).unwrap());
                            }
                            _ => {
                                warn!(target: "root", "Invalid value for similarity experiment: {}", value.as_bstr());
                            }
                        }
                    } else {
                        warn!(target: "root", "Missing value for similarity experiment.");
                    }
                }
                _ => {}
            }
        }
    }
    AllExperiments {
        flags,
        similarity: similarity.unwrap_or_else(|| cstr!("-C100%").into()),
    }
});

pub fn experiment(experiments: Experiments) -> bool {
    EXPERIMENTS.flags.contains(experiments)
}

pub fn experiment_similarity() -> &'static CStr {
    &EXPERIMENTS.similarity
}

#[no_mangle]
unsafe extern "C" fn do_panic(err: *const u8, len: usize) {
    panic!("{}", std::slice::from_raw_parts(err, len).as_bstr());
}
