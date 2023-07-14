/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(renamed_and_removed_lints)]
#![allow(clippy::borrowed_box)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::new_without_default)]
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
extern crate derivative;
#[macro_use]
extern crate all_asserts;
#[macro_use]
extern crate log;

use bstr::io::BufReadExt;
use byteorder::{BigEndian, WriteBytesExt};
use clap::{crate_version, ArgGroup, Parser};
use hg_bundle::{create_bundle, create_chunk_data, BundleSpec, RevChunkIter};
use indexmap::IndexSet;
use itertools::{EitherOrBoth, Itertools};
use logging::{LoggingReader, LoggingWriter};
use percent_encoding::{percent_decode, percent_encode, AsciiSet, CONTROLS};
use sha1::{Digest, Sha1};

#[macro_use]
mod util;
#[macro_use]
mod oid;
#[macro_use]
pub mod libgit;
mod graft;
mod libc;
mod libcinnabar;
mod logging;
mod progress;
pub mod store;
mod xdiff;

pub(crate) mod hg_bundle;
#[macro_use]
pub mod hg_connect;
pub(crate) mod hg_connect_http;
pub(crate) mod hg_connect_stdio;
pub(crate) mod hg_data;

use std::borrow::{Borrow, Cow};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::File;
use std::hash::Hash;
use std::io::{stdin, stdout, BufRead, BufWriter, Write};
use std::iter::repeat;
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, from_utf8, FromStr};
use std::sync::Mutex;
use std::{cmp, fmt};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;
use std::time::Instant;

use bitflags::bitflags;
use bstr::{BStr, ByteSlice};
use git_version::git_version;
use once_cell::sync::Lazy;
use url::Url;

use crate::hg_bundle::BundleReader;
use crate::hg_connect::{decodecaps, find_common, UnbundleResponse};
use crate::progress::set_progress;
use crate::store::{do_set_replace, reset_manifest_heads, set_changeset_heads, Dag, Traversal};
use crate::util::{FromBytes, ToBoxed};
use graft::{graft_finish, grafted, init_graft};
use hg_connect::{get_bundle, get_clonebundle_url, get_connection, get_store_bundle, HgRepo};
use libcinnabar::{files_meta, git2hg, hg2git, hg_object_id};
use libgit::{
    config_get_value, diff_tree, for_each_ref_in, for_each_remote, get_oid_committish,
    lookup_replace_commit, ls_tree, metadata_oid, object_id, reachable_subset, remote, resolve_ref,
    rev_list, rev_list_with_boundaries, strbuf, BlobId, CommitId, DiffTreeItem, FileMode,
    MaybeBoundary, RawBlob, RawCommit, RefTransaction,
};
use oid::{Abbrev, GitObjectId, HgObjectId, ObjectId};
use progress::Progress;
use store::{
    create_changeset, do_check_files, do_set, ensure_store_init, get_tags, has_metadata,
    raw_commit_for_changeset, store_git_blob, store_manifest, ChangesetHeads,
    GeneratedGitChangesetMetadata, GitChangesetId, GitFileId, GitFileMetadataId, GitManifestId,
    HgChangesetId, HgFileId, HgManifestId, RawGitChangesetMetadata, RawHgChangeset, RawHgFile,
    RawHgManifest, BROKEN_REF, CHANGESET_HEADS, CHECKED_REF, METADATA_REF, NOTES_REF, REFS_PREFIX,
    REPLACE_REFS_PREFIX,
};
use util::{CStrExt, IteratorExt, OsStrExt, SliceExt};

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
use version_check::{VersionInfo, VersionRequest};

pub const CARGO_PKG_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
pub const FULL_VERSION: &str = git_version!(
    args = [
        "--always",
        "--match=nothing/",
        "--abbrev=40",
        "--dirty=-modified"
    ],
    prefix = concat!(crate_version!(), "-"),
    cargo_prefix = "",
    fallback = crate_version!(),
);

#[allow(improper_ctypes)]
extern "C" {
    pub fn do_reload();
    fn do_cleanup(rollback: c_int);

    fn do_store_metadata(result: *mut object_id);

    #[cfg(windows)]
    fn wmain(argc: c_int, argv: *const *const u16) -> c_int;

    fn init_cinnabar(argv0: *const c_char);
    fn init_cinnabar_2() -> c_int;
    fn done_cinnabar();
}

static REF_UPDATES: Lazy<Mutex<HashMap<Box<BStr>, CommitId>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[no_mangle]
unsafe extern "C" fn dump_ref_updates() {
    let mut transaction = RefTransaction::new().unwrap();
    for (refname, oid) in REF_UPDATES.lock().unwrap().drain() {
        let refname = OsStr::from_bytes(&refname);
        if oid.is_null() {
            transaction.delete(refname, None, "update").unwrap();
        } else {
            transaction.update(refname, oid, None, "update").unwrap();
        }
    }
    transaction.commit().unwrap();
}

static MAYBE_INIT_CINNABAR_2: Lazy<Option<()>> = Lazy::new(|| unsafe {
    (init_cinnabar_2() != 0).then(|| {
        if let Some(refs) = [
            // Delete old tag-cache, which may contain incomplete data.
            "refs/cinnabar/tag-cache",
            // Delete new-type tag_cache, we don't use it anymore.
            "refs/cinnabar/tag_cache",
        ]
        .iter()
        .map(|r| resolve_ref(r).map(|cid| (*r, cid)))
        .collect::<Option<Vec<_>>>()
        {
            let mut transaction = RefTransaction::new().unwrap();
            for (refname, cid) in refs {
                transaction.delete(refname, Some(cid), "cleanup").unwrap();
            }
            transaction.commit().unwrap();
        }
        if let Some(objectformat) = config_get_value("extensions.objectformat") {
            if objectformat != OsStr::new("sha1") {
                // Ideally, we'd return error code 65 (Data format error).
                die!(
                    "Git repository uses unsupported {} object format",
                    objectformat.to_string_lossy()
                );
            }
        }
    })
});

static INIT_CINNABAR_2: Lazy<()> =
    Lazy::new(|| MAYBE_INIT_CINNABAR_2.unwrap_or_else(|| panic!("not a git repository")));

static HELPER_LOCK: Lazy<Mutex<()>> = Lazy::new(|| {
    Lazy::force(&MAYBE_INIT_CINNABAR_2);
    Mutex::new(())
});

#[no_mangle]
unsafe extern "C" fn locked_rollback() {
    let _lock = HELPER_LOCK.lock().unwrap();
    do_cleanup(1);
}

fn do_done_and_check(args: &[&[u8]]) -> bool {
    unsafe {
        if graft_finish() == Some(false) {
            // Rollback
            do_cleanup(1);
            error!(target: "root", "Nothing to graft");
            return false;
        }
        let mut new_metadata = object_id::default();
        do_store_metadata(&mut new_metadata);
        do_cleanup(0);
        let new_metadata = CommitId::from_unchecked(new_metadata.into());
        set_metadata_to(
            Some(new_metadata),
            MetadataFlags::FORCE | MetadataFlags::KEEP_REFS,
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
        do_reload();
    }
    do_check_files()
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

fn do_one_hg2git(sha1: Abbrev<HgChangesetId>) -> String {
    format!("{}", unsafe {
        hg2git
            .get_note_abbrev(sha1)
            .unwrap_or_else(GitObjectId::null)
    })
}

fn do_one_git2hg(committish: OsString) -> String {
    let note = get_oid_committish(committish.as_bytes())
        .map(lookup_replace_commit)
        .and_then(|oid| GitChangesetId::from_unchecked(oid).to_hg());
    format!("{}", note.unwrap_or_else(HgChangesetId::null))
}

fn do_conversion<T, I: Iterator<Item = T>, F: Fn(T) -> Result<String, String>, W: Write>(
    abbrev: Option<usize>,
    input: I,
    f: F,
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
    abbrev: Option<usize>,
    input: I,
    batch: bool,
    f: F,
) -> Result<(), String>
where
    T: FromStr,
    <T as FromStr>::Err: fmt::Display,
    I: Iterator<Item = T>,
    F: Fn(T) -> String,
{
    let f = &f;
    let out = stdout();
    let mut out = BufWriter::new(out.lock());
    do_conversion(abbrev, input, |t| Ok(f(t)), &mut out)?;
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
                    Ok(f(t))
                },
                &mut out,
            )?;
            out.flush().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn do_data_changeset(rev: Abbrev<HgChangesetId>) -> Result<(), String> {
    unsafe {
        let commit_id = hg2git
            .get_note_abbrev(rev)
            .ok_or_else(|| format!("Unknown changeset id: {}", rev))?;
        let changeset = RawHgChangeset::read(GitChangesetId::from_unchecked(
            CommitId::from_unchecked(commit_id),
        ))
        .unwrap();
        stdout().write_all(&changeset).map_err(|e| e.to_string())
    }
}

fn do_data_manifest(rev: Abbrev<HgManifestId>) -> Result<(), String> {
    unsafe {
        let commit_id = hg2git
            .get_note_abbrev(rev)
            .ok_or_else(|| format!("Unknown manifest id: {}", rev))?;
        let manifest = RawHgManifest::read(GitManifestId::from_unchecked(
            CommitId::from_unchecked(commit_id),
        ))
        .unwrap();
        stdout().write_all(&manifest).map_err(|e| e.to_string())
    }
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

fn do_fetch(remote: &OsStr, revs: &[OsString]) -> Result<(), String> {
    let url = remote::get(remote).get_url();
    let url =
        hg_url(url).ok_or_else(|| format!("Invalid mercurial url: {}", url.to_string_lossy()))?;
    let mut conn =
        hg_connect::get_connection(&url).ok_or_else(|| format!("Failed to connect to {}", url))?;
    if conn.get_capability(b"lookup").is_none() {
        return Err(
            "Remote repository does not support the \"lookup\" command. \
                 Cannot fetch."
                .to_owned(),
        );
    }
    let mut full_revs = vec![];
    let revs = revs
        .iter()
        .map(|rev| match rev.to_string_lossy() {
            Cow::Borrowed(s) => Ok(s),
            Cow::Owned(s) => Err(format!("Invalid character in revision: {}", s)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    for rev in revs {
        let result = conn.lookup(rev);
        let [success, data] = result
            .trim_end_with(|b| b.is_ascii_whitespace())
            .splitn_exact(b' ')
            .expect("lookup command result is malformed");
        if success == b"0" {
            return Err(data.to_str_lossy().into_owned());
        }
        full_revs.push(
            data.to_str()
                .ok()
                .and_then(|d| HgObjectId::from_str(d).ok())
                .expect("lookup command result is malformed")
                .to_string(),
        );
    }
    let cmd = Command::new("git")
        .arg("-c")
        .arg(format!("cinnabar.fetch={}", full_revs.join(" ")))
        .arg("fetch")
        .arg(remote)
        .args(full_revs.iter().map(|s| format!("hg/revs/{}", s)))
        .status()
        .map_err(|e| e.to_string())?;
    if cmd.success() {
        Ok(())
    } else {
        Err("fetch failed".to_owned())
    }
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
    pub struct MetadataFlags: i32 {
        const FORCE = 0x1;
        const KEEP_REFS = 0x2;
    }
}

fn set_metadata_to(
    new_metadata: Option<CommitId>,
    flags: MetadataFlags,
    msg: &str,
) -> Result<Option<CommitId>, String> {
    let mut refs = HashMap::new();
    for_each_ref_in(REFS_PREFIX, |r, oid| {
        if flags.contains(MetadataFlags::KEEP_REFS)
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
            .contains(MetadataFlags::FORCE)
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
                format!(
                    "Cannot rollback to {}, it is not in the ancestry of current metadata.",
                    new
                )
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
            return Err(format!("Invalid cinnabar metadata: {}", new));
        }
        transaction.update(METADATA_REF, new, metadata, msg)?;
        transaction.update(NOTES_REF, commit.parents()[3], notes, msg)?;
        for item in
            ls_tree(commit.tree()).map_err(|_| format!("Failed to read metadata: {}", new))?
        {
            // TODO: Check mode.
            // TODO: Check oid is valid.
            let mut replace_ref = REPLACE_REFS_PREFIX.to_owned();
            replace_ref.push_str(from_utf8(&item.path).unwrap());
            let replace_ref = OsString::from(replace_ref);
            transaction.update(
                &replace_ref,
                CommitId::from_unchecked(item.oid),
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

fn do_reclone() -> Result<(), String> {
    // TODO: Avoid resetting at all, possibly leaving the repo with no metadata
    // if this is interrupted somehow.
    let mut previous_metadata = set_metadata_to(None, MetadataFlags::empty(), "reclone")?;

    for_each_remote(|remote| {
        if remote.skip_default_update() || hg_url(remote.get_url()).is_none() {
            return Ok(());
        }
        let mut cmd = Command::new("git");
        if let Some(previous_metadata) = previous_metadata.take() {
            cmd.arg("-c")
                .arg(format!("cinnabar.previous-metadata={}", previous_metadata));
        }
        let cmd = cmd
            .args(["remote", "update", "--prune"])
            .arg(remote.name().unwrap())
            .status()
            .map_err(|e| e.to_string())?;
        if cmd.success() {
            Ok(())
        } else {
            Err("fetch failed".to_string())
        }
    })
    .map(|_| {
        println!("Please note that reclone left your local branches untouched.");
        println!("They may be based on entirely different commits.");
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
            print!("{}", m);
            let matched_labels = labels
                .iter()
                .filter_map(|(name, cid)| (*cid == m).then(|| *name))
                .collect_vec()
                .join(", ");
            if !matched_labels.is_empty() {
                print!(" ({})", matched_labels);
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
        if *committish == *CommitId::null().to_string() {
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
        MetadataFlags::FORCE
    } else {
        MetadataFlags::empty()
    };
    set_metadata_to(wanted_metadata, flags, "rollback").map(|_| ())
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

#[cfg(feature = "self-update")]
fn do_self_update(branch: Option<String>, exact: Option<CommitId>) -> Result<(), String> {
    assert!(!(branch.is_some() && exact.is_some()));
    cfg_if::cfg_if! {
        if #[cfg(windows)] {
            const BINARY: &str = "git-cinnabar.exe";
        } else {
            const BINARY: &str = "git-cinnabar";
        }
    };
    #[cfg(windows)]
    const FINISH_SELF_UPDATE: &str = "GIT_CINNABAR_FINISH_SELF_UPDATE";
    #[cfg(windows)]
    const FINISH_SELF_UPDATE_PARENT: &str = "GIT_CINNABAR_FINISH_SELF_UPDATE_PARENT";

    #[cfg(windows)]
    if let Some(old_path) = std::env::var_os(FINISH_SELF_UPDATE) {
        use std::os::windows::io::RawHandle;
        let handle = usize::from_str(&std::env::var(FINISH_SELF_UPDATE_PARENT).unwrap()).unwrap()
            as RawHandle;
        unsafe {
            winapi::um::synchapi::WaitForSingleObject(handle, winapi::um::winbase::INFINITE);
        }
        std::fs::remove_file(old_path).ok();
        return Ok(());
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_dir = exe.parent().unwrap();
    if let Some(version) = exact.map(VersionInfo::Commit).or_else(|| {
        version_check::check_new_version(
            branch
                .as_ref()
                .map_or_else(VersionRequest::default, |b| VersionRequest::from(&**b)),
        )
    }) {
        let mut tmpbuilder = tempfile::Builder::new();
        tmpbuilder.prefix(BINARY);
        let mut tmpfile = tmpbuilder.tempfile_in(exe_dir).map_err(|e| e.to_string())?;
        download_build(version, &mut tmpfile, BINARY)?;
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
            use std::os::windows::io::RawHandle;
            let mut handle: RawHandle = std::ptr::null_mut();
            let curproc = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
            if unsafe {
                winapi::um::handleapi::DuplicateHandle(
                    curproc,
                    curproc,
                    curproc,
                    &mut handle,
                    /* dwDesiredAccess */ 0,
                    /* bInheritHandle */ 1,
                    winapi::um::winnt::DUPLICATE_SAME_ACCESS,
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
fn download_build(
    version: VersionInfo,
    tmpfile: &mut impl Write,
    binary: &str,
) -> Result<(), String> {
    use crate::hg_connect_http::HttpRequest;

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

    let request = |url: &str| {
        eprintln!("Installing update from {url}");
        let mut req = HttpRequest::new(Url::parse(url).map_err(|e| e.to_string())?);
        req.follow_redirects(true);
        req.execute()
    };

    match version {
        VersionInfo::Commit(cid) => {
            const URL_BASE: &str =
            "https://community-tc.services.mozilla.com/api/index/v1/task/project.git-cinnabar.build";
            let url = format!("{URL_BASE}.{cid}.{SYSTEM_MACHINE}/artifacts/public/{binary}");
            let mut response = request(&url)?;
            std::io::copy(&mut response, tmpfile)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        VersionInfo::Tagged(tag, _) => {
            let tag = tag.to_string().replace('-', "");
            let url = format!("{CARGO_PKG_REPOSITORY}/releases/download/{tag}/git-cinnabar.{SYSTEM_MACHINE}.{ARCHIVE_EXT}");
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
                            .map_or(false, |p| p.file_name().unwrap() == binary)
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
                            == binary
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
                Err(format!(
                    "Could not find the {binary} executable in the downloaded archive."
                ))
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
                use winapi::shared::winerror::ERROR_PRIVILEGE_NOT_HELD;
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

fn do_data_file(rev: Abbrev<HgFileId>) -> Result<(), String> {
    unsafe {
        let mut stdout = stdout();
        let blob_id = hg2git
            .get_note_abbrev(rev)
            .ok_or_else(|| format!("Unknown file id: {}", rev))?;
        let file_id = GitFileId::from_unchecked(BlobId::from_unchecked(blob_id));
        let metadata_id = files_meta
            .get_note_abbrev(rev)
            .map(|oid| GitFileMetadataId::from_unchecked(BlobId::from_unchecked(oid)));
        let file = RawHgFile::read(file_id, metadata_id).unwrap();
        stdout.write_all(&file).map_err(|e| e.to_string())
    }
}

pub fn graft_config_enabled(remote: Option<&str>) -> Result<Option<bool>, String> {
    get_config_remote("graft", remote)
        .map(|v| {
            v.into_string()
                .and_then(|v| bool::from_str(&v).map_err(|_| v.into()))
        })
        .transpose()
        // TODO: This should report the environment variable is that's what was used.
        .map_err(|e| format!("Invalid value for cinnabar.graft: {}", e.to_string_lossy()))
}

fn do_unbundle(clonebundle: bool, mut url: OsString) -> Result<(), String> {
    if !url.as_bytes().starts_with(b"hg:") {
        let mut new_url = OsString::from("hg::");
        new_url.push(url);
        url = new_url;
    }
    let mut url = hg_url(&url).unwrap();
    if !["http", "https", "file"].contains(&url.scheme()) {
        return Err(format!("{} urls are not supported.", url.scheme()));
    }
    if graft_config_enabled(None)?.unwrap_or(false) {
        init_graft();
    }
    if clonebundle {
        let mut conn = get_connection(&url).unwrap();
        if conn.get_capability(b"clonebundles").is_none() {
            return Err("Repository does not support clonebundles")?;
        }
        url = get_clonebundle_url(&mut *conn).ok_or("Repository didn't provide a clonebundle")?;
        eprintln!("Getting clone bundle from {}", url);
    }
    let mut conn = get_connection(&url).unwrap();

    get_store_bundle(&mut *conn, &[], &[]).map_err(|e| String::from_utf8_lossy(&e).into_owned())?;

    do_done_and_check(&[])
        .then(|| ())
        .ok_or_else(|| "Fatal error".to_string())
}

fn do_bundle(
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
        (c, commit.parents().to_boxed())
    });
    let file = File::create(path).unwrap();
    let result = do_create_bundle(commits, bundlespec, version, &file, false).map(|_| 0);
    unsafe {
        do_cleanup(1);
    }
    result
}

fn hg_attr(mode: FileMode) -> &'static [u8] {
    match mode.0 {
        0o100644 => b"",
        0o100755 => b"x",
        0o120000 => b"l",
        _ => die!("Unexpected file mode"),
    }
}

fn git_mode(attr: &[u8]) -> FileMode {
    match attr {
        b"" => FileMode(0o100644),
        b"x" => FileMode(0o100755),
        b"l" => FileMode(0o120000),
        _ => die!("Unexpected attribute"),
    }
}

fn create_file(blobid: BlobId, parents: &[HgFileId]) -> HgFileId {
    let blob = RawBlob::read(blobid).unwrap();
    let mut hash = HgFileId::create();
    if parents.len() < 2 {
        hash.update(HgFileId::null().as_raw_bytes());
        hash.update(parents.get(0).unwrap_or(&HgFileId::null()).as_raw_bytes());
    } else {
        assert_eq!(parents.len(), 2);
        for parent in parents.iter().sorted() {
            hash.update(parent.as_raw_bytes());
        }
    }
    hash.update(blob.as_bytes());
    let fid = hash.finalize();
    unsafe {
        do_set(
            cstr::cstr!("file").as_ptr(),
            &hg_object_id::from(fid),
            &object_id::from(blobid),
        );
    }
    fid
}

fn create_copy(blobid: BlobId, source_path: &BStr, source_fid: HgFileId) -> HgFileId {
    let blob = RawBlob::read(blobid).unwrap();
    let mut metadata = strbuf::new();
    metadata.extend_from_slice(b"copy: ");
    metadata.extend_from_slice(source_path);
    metadata.extend_from_slice(b"\ncopyrev: ");
    write!(metadata, "{}", source_fid).unwrap();
    metadata.extend_from_slice(b"\n");

    let mut hash = HgFileId::create();
    hash.update(HgFileId::null().as_raw_bytes());
    hash.update(HgFileId::null().as_raw_bytes());
    hash.update(b"\x01\n");
    hash.update(metadata.as_bytes());
    hash.update(b"\x01\n");
    hash.update(blob.as_bytes());
    let fid = hash.finalize();

    let mut oid = object_id::default();
    unsafe {
        store_git_blob(&metadata, &mut oid);
        do_set(
            cstr::cstr!("file-meta").as_ptr(),
            &hg_object_id::from(fid),
            &oid,
        );
        do_set(
            cstr::cstr!("file").as_ptr(),
            &hg_object_id::from(fid),
            &object_id::from(blobid),
        );
    }
    fid
}

fn create_manifest(content: &[u8], parents: &[HgManifestId]) -> HgManifestId {
    let parent_manifest = parents
        .get(0)
        .map(|p| RawHgManifest::read(p.to_git().unwrap()).unwrap());
    let parent1 = parents.get(0).copied().unwrap_or_else(HgManifestId::null);
    let mut hash = HgManifestId::create();
    if parents.len() < 2 {
        hash.update(HgManifestId::null().as_raw_bytes());
        hash.update(parent1.as_raw_bytes());
    } else {
        assert_eq!(parents.len(), 2);
        for parent in parents.iter().sorted() {
            hash.update(parent.as_raw_bytes());
        }
    }
    hash.update(content);
    let mid = hash.finalize();
    let data = create_chunk_data(
        parent_manifest
            .as_ref()
            .map(|m| m.as_bstr())
            .unwrap_or_default(),
        content,
    );
    let mut manifest_chunk = Vec::new();
    manifest_chunk.extend_from_slice(b"\0\0\0\0");
    manifest_chunk.extend_from_slice(mid.as_raw_bytes());
    manifest_chunk.extend_from_slice(parent1.as_raw_bytes());
    manifest_chunk.extend_from_slice(
        parents
            .get(1)
            .unwrap_or(&HgManifestId::null())
            .as_raw_bytes(),
    );
    manifest_chunk.extend_from_slice(parent1.as_raw_bytes());
    manifest_chunk.extend_from_slice(HgManifestId::null().as_raw_bytes());
    manifest_chunk.extend_from_slice(&data);
    let len = manifest_chunk.len();
    (&mut manifest_chunk[..4])
        .write_u32::<BigEndian>(len as u32)
        .unwrap();
    manifest_chunk.extend_from_slice(b"\0\0\0\0");
    for chunk in RevChunkIter::new(2, manifest_chunk.as_bytes()) {
        unsafe {
            store_manifest(&chunk);
        }
    }
    mid
}

fn create_root_changeset(cid: CommitId) -> HgChangesetId {
    // TODO: this is all very suboptimal in what it does, how it does it,
    // and what the code looks like.
    unsafe {
        ensure_store_init();
    }
    let commit = RawCommit::read(cid).unwrap();
    let commit = commit.parse().unwrap();
    let mut manifest = Vec::new();
    let mut paths = Vec::new();
    for item in ls_tree(commit.tree()).unwrap() {
        let fid = create_file(BlobId::from_unchecked(item.oid), &[]);
        ManifestLine::from((&*item.path, fid, item.mode)).write_into(&mut manifest);
        paths.extend_from_slice(&item.path);
        paths.push(b'\0');
    }
    paths.pop();
    let mid = create_manifest(&manifest, &[]);
    let (csid, _) = create_changeset(cid, mid, Some(paths.to_boxed()));
    csid
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManifestLine<'a> {
    Line {
        line: &'a BStr,
        path_len: usize,
    },
    Content {
        path: &'a BStr,
        fid: HgFileId,
        mode: FileMode,
    },
}

impl<'a> From<&'a [u8]> for ManifestLine<'a> {
    fn from(line: &'a [u8]) -> Self {
        ManifestLine::Line {
            line: line.as_bstr(),
            path_len: line.find_byte(b'\0').unwrap(),
        }
    }
}

impl<'a> From<(&'a [u8], HgFileId, FileMode)> for ManifestLine<'a> {
    fn from((path, fid, mode): (&'a [u8], HgFileId, FileMode)) -> Self {
        ManifestLine::Content {
            path: path.as_bstr(),
            fid,
            mode,
        }
    }
}
impl<'a> ManifestLine<'a> {
    fn path(&self) -> &BStr {
        match self {
            ManifestLine::Line { line, path_len } => line[..*path_len].as_bstr(),
            ManifestLine::Content { path, .. } => path,
        }
    }

    fn fid(&self) -> HgFileId {
        match self {
            ManifestLine::Line { line, path_len } => {
                HgFileId::from_bytes(&line[path_len + 1..][..40]).unwrap()
            }
            ManifestLine::Content { fid, .. } => *fid,
        }
    }

    fn mode(&self) -> FileMode {
        match self {
            ManifestLine::Line { line, path_len } => git_mode(&line[path_len + 41..]),
            ManifestLine::Content { mode, .. } => *mode,
        }
    }

    fn write_into(&self, buf: &mut Vec<u8>) {
        match self {
            ManifestLine::Line { line, .. } => buf.extend_from_slice(line),
            ManifestLine::Content { path, fid, mode } => {
                buf.extend_from_slice(path);
                buf.push(b'\0');
                write!(buf, "{}", fid).unwrap();
                buf.extend_from_slice(hg_attr(*mode));
            }
        }
        buf.push(b'\n');
    }
}

impl<'a> Hash for ManifestLine<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path().hash(state);
    }
}

impl<'a> Borrow<[u8]> for ManifestLine<'a> {
    fn borrow(&self) -> &[u8] {
        self.path()
    }
}

fn create_simple_manifest(cid: CommitId, parent: CommitId) -> (HgManifestId, Option<Box<[u8]>>) {
    // TODO: this is all very suboptimal in what it does, how it does it,
    // and what the code looks like. And code should be shared with
    // `create_root_changeset`.
    let parent = GitChangesetId::from_unchecked(parent);
    let parent_metadata = RawGitChangesetMetadata::read(parent).unwrap();
    let parent_mid = parent_metadata.parse().unwrap().manifest_id();
    let parent_manifest = RawHgManifest::read(parent_mid.to_git().unwrap()).unwrap();
    let mut extra_diff = Vec::new();
    let mut diff = diff_tree(parent.into(), cid, true)
        .inspect(|item| {
            if let DiffTreeItem::Renamed {
                from_path,
                from_mode,
                from_oid,
                ..
            } = item
            {
                extra_diff.push(DiffTreeItem::Deleted {
                    path: from_path.clone(),
                    mode: *from_mode,
                    oid: *from_oid,
                });
            }
        })
        .map(|item| match item {
            DiffTreeItem::Renamed {
                to_path,
                to_oid,
                to_mode,
                ..
            }
            | DiffTreeItem::Copied {
                to_path,
                to_oid,
                to_mode,
                ..
            } if to_oid == RawBlob::EMPTY_OID => DiffTreeItem::Added {
                path: to_path,
                mode: to_mode,
                oid: to_oid,
            },
            item => item,
        })
        .collect_vec();
    if diff.is_empty() {
        return (parent_mid, None);
    }
    diff.append(&mut extra_diff);
    diff.sort_by(|a, b| a.path().cmp(b.path()));
    let parent_lines = ByteSlice::lines(&*parent_manifest)
        .map(ManifestLine::from)
        .collect::<IndexSet<_>>();
    let mut manifest = Vec::new();
    let mut paths = Vec::new();
    for either_or_both in parent_lines
        .iter()
        .merge_join_by(diff, |parent_line, diff_item| {
            (parent_line.path()).cmp(diff_item.path())
        })
    {
        let (path, fid, mode) = match either_or_both {
            EitherOrBoth::Left(manifest_line) => {
                manifest_line.write_into(&mut manifest);
                continue;
            }
            EitherOrBoth::Both(_, DiffTreeItem::Deleted { path, .. }) => {
                paths.extend_from_slice(&path);
                paths.push(b'\0');
                continue;
            }
            EitherOrBoth::Both(
                manifest_line,
                DiffTreeItem::Modified {
                    path,
                    from_oid,
                    to_mode,
                    to_oid,
                    ..
                },
            ) => {
                let mut fid = manifest_line.fid();
                if from_oid != to_oid {
                    fid = create_file(to_oid, &[fid]);
                }
                (path, fid, to_mode)
            }
            EitherOrBoth::Both(
                _,
                DiffTreeItem::Renamed {
                    to_path,
                    to_mode,
                    to_oid,
                    from_path,
                    ..
                }
                | DiffTreeItem::Copied {
                    to_path,
                    to_mode,
                    to_oid,
                    from_path,
                    ..
                },
            )
            | EitherOrBoth::Right(
                DiffTreeItem::Renamed {
                    to_path,
                    to_mode,
                    to_oid,
                    from_path,
                    ..
                }
                | DiffTreeItem::Copied {
                    to_path,
                    to_mode,
                    to_oid,
                    from_path,
                    ..
                },
            ) => (
                to_path,
                create_copy(
                    to_oid,
                    from_path.as_bstr(),
                    parent_lines.get(&*from_path).unwrap().fid(),
                ),
                to_mode,
            ),
            EitherOrBoth::Right(DiffTreeItem::Added { path, mode, oid }) => {
                (path, create_file(oid, &[]), mode)
            }

            thing => die!("Something went wrong {:?}", thing),
        };
        ManifestLine::from((&*path, fid, mode)).write_into(&mut manifest);
        paths.extend_from_slice(&path);
        paths.push(b'\0');
    }
    paths.pop();
    let mid = create_manifest(&manifest, &[parent_mid]);
    (mid, Some(paths.into_boxed_slice()))
}

fn create_simple_changeset(cid: CommitId, parent: CommitId) -> [HgChangesetId; 2] {
    unsafe {
        ensure_store_init();
    }
    let parent_csid = GitChangesetId::from_unchecked(parent).to_hg().unwrap();
    let (mid, paths) = create_simple_manifest(cid, parent);
    let (csid, _) = create_changeset(cid, mid, paths);
    [csid, parent_csid]
}

fn create_merge_changeset(
    cid: CommitId,
    parent1: CommitId,
    parent2: CommitId,
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
        let metadata = RawGitChangesetMetadata::read(csid).unwrap();
        let metadata = metadata.parse().unwrap();
        (metadata.changeset_id(), metadata.manifest_id())
    };
    let (parent1_csid, parent1_mid) = cs_mn(parent1);
    let (parent2_csid, parent2_mid) = cs_mn(parent2);
    if parent1_mid == parent2_mid {
        let (mid, paths) = create_simple_manifest(cid, parent1);
        let (csid, _) = create_changeset(cid, mid, paths);
        [csid, parent1_csid, parent2_csid]
    } else {
        let parent1_mn_cid = parent1_mid.to_git().unwrap();
        let parent2_mn_cid = parent2_mid.to_git().unwrap();
        let range = format!("{}...{}", &parent1_mn_cid, &parent2_mn_cid);
        let mut file_dags = HashMap::new();
        for cid in rev_list(["--topo-order", "--full-history", "--reverse", &range]) {
            let commit = RawCommit::read(cid).unwrap();
            let commit = commit.parse().unwrap();
            for (path, oid, parents) in get_changes(cid, commit.parents(), false) {
                let oid = HgFileId::from_str(&oid.to_string()).unwrap();
                let path = manifest_path(&path);
                let parents = parents
                    .iter()
                    .filter(|p| !p.is_null())
                    .map(|p| HgFileId::from_str(&p.to_string()).unwrap())
                    .collect_vec();
                let dag = file_dags.entry(path).or_insert_with(Dag::new);
                for &parent in &parents {
                    if dag.get(parent).is_none() {
                        dag.add(parent, &[], (), |_, _| ());
                    }
                }
                if dag.get(oid).is_none() {
                    dag.add(oid, &parents, (), |_, _| ());
                }
            }
        }

        let commit = RawCommit::read(cid).unwrap();
        let commit = commit.parse().unwrap();
        let files = ls_tree(commit.tree()).unwrap();
        let raw_parent1_manifest = RawHgManifest::read(parent1_mn_cid).unwrap();
        let parent1_manifest = ByteSlice::lines(&*raw_parent1_manifest).map(ManifestLine::from);
        let parent2_manifest = RawHgManifest::read(parent2_mn_cid).unwrap();
        let parent2_manifest = ByteSlice::lines(&*parent2_manifest).map(ManifestLine::from);
        let manifests =
            parent1_manifest.merge_join_by(parent2_manifest, |a, b| a.path().cmp(b.path()));

        let mut manifest = Vec::new();
        let mut paths = Vec::new();
        for item in files.merge_join_by(manifests, |a, b| {
            (*a.path).cmp(match b {
                EitherOrBoth::Both(b, _) | EitherOrBoth::Left(b) | EitherOrBoth::Right(b) => {
                    b.path()
                }
            })
        }) {
            let (l, parents, p1_mode) = match item {
                EitherOrBoth::Right(EitherOrBoth::Both(p1, _) | EitherOrBoth::Left(p1)) => {
                    // File was removed and was on the first parent, it's marked
                    // as affecting the changeset.
                    paths.extend_from_slice(p1.path());
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
                    (l, vec![p1.clone()].into_boxed_slice(), Some(p1.mode()))
                }
                EitherOrBoth::Both(l, EitherOrBoth::Right(p2)) => {
                    (l, vec![p2].into_boxed_slice(), None)
                }
                EitherOrBoth::Both(l, EitherOrBoth::Both(p1, p2)) => {
                    if p1.fid() == p2.fid() {
                        (l, vec![p1.clone()].into_boxed_slice(), Some(p1.mode()))
                    } else {
                        static WARN: std::sync::Once = std::sync::Once::new();
                        WARN.call_once(|| warn!(target: "root", "This may take a while..."));
                        let parents = file_dags
                            .remove(l.path.as_bstr())
                            .and_then(|mut dag| {
                                let mut is_ancestor = |a: HgFileId, b| {
                                    let mut result = false;
                                    dag.traverse_mut(b, Traversal::Parents, |p, _| {
                                        if p == a {
                                            result = true;
                                        }
                                        !result
                                    });
                                    result
                                };
                                let p1_fid = p1.fid();
                                let p2_fid = p2.fid();
                                if is_ancestor(p1_fid, p2_fid) {
                                    Some(vec![p2.clone()])
                                } else if is_ancestor(p2_fid, p1_fid) {
                                    Some(vec![p1.clone()])
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| vec![p1.clone(), p2]);
                        (l, parents.into_boxed_slice(), Some(p1.mode()))
                    }
                }
            };
            // empty file needs to be checked separately because hg2git metadata
            // doesn't store empty files because of the conflict with empty manifests.
            let unchanged = parents.len() == 1
                && ((parents[0].fid() == RawHgFile::EMPTY_OID && l.oid == RawBlob::EMPTY_OID)
                    || parents[0].fid().to_git().unwrap() == l.oid);
            let fid = if unchanged {
                parents[0].fid()
            } else {
                let parents = parents.iter().map(ManifestLine::fid).collect_vec();
                create_file(BlobId::from_unchecked(l.oid), &parents)
            };

            let line = ManifestLine::from((&*l.path, fid, l.mode));
            line.write_into(&mut manifest);
            if !unchanged || p1_mode.map(|mode| mode != l.mode).unwrap_or_default() {
                paths.extend_from_slice(&l.path);
                paths.push(b'\0');
            }
        }
        paths.pop();
        let (mid, paths) = if *manifest == *raw_parent1_manifest {
            (parent1_mid, None)
        } else {
            (
                create_manifest(&manifest, &[parent1_mid, parent2_mid]),
                Some(paths.into_boxed_slice()),
            )
        };
        let (csid, _) = create_changeset(cid, mid, paths);
        [csid, parent1_csid, parent2_csid]
    }
}

pub fn do_create_bundle(
    commits: impl Iterator<Item = (CommitId, Box<[CommitId]>)>,
    bundlespec: BundleSpec,
    version: u8,
    output: &File,
    replycaps: bool,
) -> Result<ChangesetHeads, String> {
    let changesets = commits.map(|(cid, parents)| {
        if let Some(csid) = GitChangesetId::from_unchecked(cid).to_hg() {
            let mut parents = parents.iter().copied();
            let parent1 = parents.next().map_or_else(HgChangesetId::null, |p| {
                GitChangesetId::from_unchecked(p).to_hg().unwrap()
            });
            let parent2 = parents.next().map_or_else(HgChangesetId::null, |p| {
                GitChangesetId::from_unchecked(p).to_hg().unwrap()
            });
            assert!(parents.next().is_none());
            [csid, parent1, parent2]
        } else if parents.is_empty() {
            [
                create_root_changeset(cid),
                HgChangesetId::null(),
                HgChangesetId::null(),
            ]
        } else if parents.len() == 1 {
            let [csid, parent1] = create_simple_changeset(cid, parents[0]);
            [csid, parent1, HgChangesetId::null()]
        } else if parents.len() == 2 {
            create_merge_changeset(cid, *parents.get(0).unwrap(), *parents.get(1).unwrap())
        } else {
            die!("Pushing octopus merges to mercurial is not supported");
        }
    });
    Ok(create_bundle(
        changesets, bundlespec, version, output, replycaps,
    ))
}

extern "C" {
    fn check_manifest(oid: *const object_id, hg_oid: *mut hg_object_id) -> c_int;
    fn check_file(
        oid: *const hg_object_id,
        parent1: *const hg_object_id,
        parent2: *const hg_object_id,
    ) -> c_int;
}

fn do_fsck(force: bool, full: bool, commits: Vec<OsString>) -> Result<i32, String> {
    if !has_metadata() {
        eprintln!(
            "There does not seem to be any git-cinnabar metadata.\n\
             Is this a git-cinnabar clone?"
        );
        return Ok(1);
    }
    let metadata_cid = unsafe { CommitId::from_unchecked(GitObjectId::from(metadata_oid.clone())) };
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
        return do_fsck_full(commits, metadata_cid, changesets_cid, manifests_cid);
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
        eprintln!("\r{}", s);
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
        let git_cid = changeset_node.to_git();
        let git_cid = if let Some(git_cid) = git_cid {
            git_cid
        } else {
            report(format!(
                "Missing hg2git metadata for changeset {}",
                changeset_node
            ));
            continue;
        };
        if git_cid != c {
            let parents = parents.get_or_insert_with(|| BTreeSet::from_iter(commit.parents()));
            if !parents.contains(&CommitId::from(git_cid)) {
                report(format!(
                    "Inconsistent metadata:\n\
                     \x20 Head metadata says changeset {} maps to {}\n
                     \x20 but hg2git metadata says it maps to {}",
                    changeset_node, c, git_cid
                ));
                continue;
            }
        }
        let commit = RawCommit::read(c).unwrap();
        let commit = commit.parse().unwrap();
        let metadata = if let Some(metadata) = RawGitChangesetMetadata::read(git_cid) {
            metadata
        } else {
            report(format!("Missing git2hg metadata for git commit {}", c));
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
        let raw_changeset = RawHgChangeset::from_metadata(&commit, &metadata).unwrap();
        let mut sha1 = Sha1::new();
        commit
            .parents()
            .iter()
            .copied()
            .map(|p| {
                GitChangesetId::from_unchecked(lookup_replace_commit(p))
                    .to_hg()
                    .unwrap()
            })
            .chain(repeat(HgChangesetId::null()))
            .take(2)
            .sorted()
            .for_each(|p| sha1.update(p.as_raw_bytes()));
        sha1.update(&*raw_changeset);
        let sha1 = sha1.finalize();
        if changeset_node.as_raw_bytes() != sha1.as_slice() {
            report(format!("Sha1 mismatch for changeset {}", changeset_node,));
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
                 \x20 Head metadata says changeset {} is in branch {}\n\
                 \x20 but git2hg metadata says it is in branch {}",
                changeset_node, branch, changeset_branch
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
    let manifests_arg = format!("{}^@", manifests_cid);
    let checked_manifests_arg = checked_manifests_cid.map(|c| format!("^{}^@", c));
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
            report(format!("Invalid manifest metadata in git commit {}", mid));
            continue;
        };
        let git_mid = if let Some(id) = hg_manifest_id.to_git() {
            id
        } else {
            report(format!(
                "Missing hg2git metadata for manifest {}",
                hg_manifest_id
            ));
            continue;
        };
        if mid != git_mid {
            report(format!(
                "Inconsistent metadata:\n\
                 \x20 Manifest DAG contains {} for manifest {}\n
                 \x20 but hg2git metadata says the manifest maps to {}",
                mid, hg_manifest_id, git_mid
            ));
        }
        if unsafe { check_manifest(&object_id::from(git_mid), std::ptr::null_mut()) } != 1 {
            report(format!("Sha1 mismatch for manifest {}", git_mid));
        }
        let files = if let Some(previous) = previous {
            diff_tree(previous, mid, false)
                .filter_map(|item| match item {
                    DiffTreeItem::Added { path, oid, .. } => Some((path, oid.into())),
                    DiffTreeItem::Modified {
                        path,
                        from_oid,
                        to_oid,
                        ..
                    } if from_oid != to_oid => Some((path, to_oid.into())),
                    _ => None,
                })
                .filter(|pair| !all_interesting.contains(pair))
                .collect_vec()
        } else {
            ls_tree(commit.tree())
                .unwrap()
                .map(|item| (item.path, item.oid))
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
            diff_tree(previous, r, false)
                .filter_map(|item| match item {
                    DiffTreeItem::Added { path, oid, .. } => Some((path, oid.into())),
                    DiffTreeItem::Modified {
                        path,
                        from_oid,
                        to_oid,
                        ..
                    } if from_oid != to_oid => Some((path, to_oid.into())),
                    _ => None,
                })
                .for_each(|item| {
                    all_interesting.remove(&item);
                });
        } else {
            // Yes, this is ridiculous.
            let commit = RawCommit::read(r).unwrap();
            let commit = commit.parse().unwrap();
            for item in ls_tree(commit.tree()).unwrap() {
                all_interesting.remove(&(item.path, item.oid));
            }
        }
        previous = Some(r);
    }

    let mut progress = repeat(()).progress(|n| format!("Checking {n} files"));
    while !all_interesting.is_empty() && !manifest_queue.is_empty() {
        let (mid, parents) = manifest_queue.pop().unwrap();
        for (path, hg_file, hg_fileparents) in get_changes(mid, &parents, true) {
            if hg_fileparents.iter().any(|p| *p == hg_file) {
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
                if unsafe {
                    check_file(
                        &HgObjectId::from_raw_bytes(hg_file.as_raw_bytes())
                            .unwrap()
                            .into(),
                        &hg_fileparents
                            .get(0)
                            .map_or_else(HgObjectId::null, |p| {
                                HgObjectId::from_raw_bytes(p.as_raw_bytes()).unwrap()
                            })
                            .into(),
                        &hg_fileparents
                            .get(1)
                            .map_or_else(HgObjectId::null, |p| {
                                HgObjectId::from_raw_bytes(p.as_raw_bytes()).unwrap()
                            })
                            .into(),
                    )
                } != 1
                {
                    report(format!(
                        "Sha1 mismatch for file {}\n\
                         \x20 revision {}",
                        manifest_path(&path),
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
            eprintln!(" . {} {}", oid, manifest_path(path));
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

    if do_done_and_check(&[CHECKED_REF.as_bytes()]) {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn do_fsck_full(
    commits: Vec<OsString>,
    metadata_cid: CommitId,
    changesets_cid: CommitId,
    manifests_cid: CommitId,
) -> Result<i32, String> {
    let full_fsck = commits.is_empty();
    let commit_queue = if full_fsck {
        let changesets_arg = format!("{}^@", changesets_cid);

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
                    if git_cs.to_hg().is_some() {
                        return Ok(git_cs.into());
                    }
                    let cs = HgChangesetId::from_bytes(c.as_bytes()).map_err(|_| {
                        format!("Invalid commit or changeset: {}", c.to_string_lossy())
                    })?;

                    if let Some(git_cs) = cs.to_git() {
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
        eprintln!("\r{}", s);
        broken.set(true);
    };
    let fixed = Cell::new(false);
    let fix = |s| {
        eprintln!("\r{}", s);
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
        let metadata = if let Some(metadata) = RawGitChangesetMetadata::read(cid) {
            metadata
        } else {
            report(format!("Missing note for git commit: {}", cid));
            continue;
        };
        seen_git2hg.insert(cid);

        let commit = RawCommit::read(cid.into()).unwrap();
        let commit = commit.parse().unwrap();
        let metadata = if let Some(metadata) = metadata.parse() {
            metadata
        } else {
            report(format!("Cannot parse note for git commit: {}", cid));
            continue;
        };
        let changeset_id = metadata.changeset_id();
        match changeset_id.to_git() {
            Some(oid) if oid == cid => {}
            Some(oid) => {
                report(format!(
                    "Commit mismatch for changeset {}\n\
                     \x20 hg2git: {}\n\
                     \x20 commit: {}",
                    changeset_id, oid, cid
                ));
            }
            None => {
                report(format!(
                    "Missing changeset in hg2git branch: {}",
                    changeset_id
                ));
                continue;
            }
        }
        seen_changesets.insert(changeset_id);
        let raw_changeset =
            if let Some(raw_changeset) = RawHgChangeset::from_metadata(&commit, &metadata) {
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
                    .to_hg()
                    .unwrap()
            })
            .collect_vec();
        hg_parents
            .iter()
            .copied()
            .chain(repeat(HgChangesetId::null()))
            .take(2)
            .sorted()
            .for_each(|p| sha1.update(p.as_raw_bytes()));
        sha1.update(&*raw_changeset);
        let sha1 = sha1.finalize();
        if changeset_id.as_raw_bytes() != sha1.as_slice() {
            report(format!("Sha1 mismatch for changeset {}", changeset_id));
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
                    "\nCommit mismatch for changeset {}\n\
                     \x20 it is commit {} here\n\
                     \x20 but would be {} on a fresh clone",
                    changeset_id, cid, fresh_cid
                );
            }
        }

        let branch = metadata
            .extra()
            .and_then(|e| e.get(b"branch"))
            .unwrap_or(b"default");
        changeset_heads.add(changeset_id, &hg_parents, branch.as_bstr());

        let fresh_metadata =
            GeneratedGitChangesetMetadata::generate(&commit, changeset_id, &raw_changeset).unwrap();
        if fresh_metadata != metadata {
            fix(format!("Adjusted changeset metadata for {}", changeset_id));
            unsafe {
                do_set(
                    cstr::cstr!("changeset").as_ptr(),
                    &hg_object_id::from(changeset_id),
                    &object_id::from(CommitId::null()),
                );
                do_set(
                    cstr::cstr!("changeset").as_ptr(),
                    &hg_object_id::from(changeset_id),
                    &object_id::from(cid),
                );
                let mut metadata_id = object_id::default();
                let mut buf = strbuf::new();
                buf.extend_from_slice(&fresh_metadata.serialize());
                store_git_blob(&buf, &mut metadata_id);
                do_set(
                    cstr::cstr!("changeset-metadata").as_ptr(),
                    &hg_object_id::from(changeset_id),
                    &object_id::from(CommitId::null()),
                );
                do_set(
                    cstr::cstr!("changeset-metadata").as_ptr(),
                    &hg_object_id::from(changeset_id),
                    &metadata_id,
                );
            }
        }

        let manifest_id = changeset.manifest();
        if !seen_manifests.insert(manifest_id) {
            // We've already seen the manifest.
            continue;
        }
        let manifest_cid = if let Some(manifest_cid) = manifest_id.to_git() {
            manifest_cid
        } else {
            report(format!(
                "Missing manifest in hg2git branch: {}",
                manifest_id
            ));
            continue;
        };

        let checked = unsafe {
            let manifest_cid = object_id::from(manifest_cid);
            check_manifest(&manifest_cid, std::ptr::null_mut()) == 1
        };
        if !checked {
            report(format!("Sha1 mismatch for manifest {}", manifest_id));
        }

        let hg_manifest_parents = hg_parents
            .iter()
            .map(|p| {
                let metadata = RawGitChangesetMetadata::read(p.to_git().unwrap()).unwrap();
                let metadata = metadata.parse().unwrap();
                metadata.manifest_id()
            })
            .collect_vec();
        let git_manifest_parents = hg_manifest_parents
            .into_iter()
            .filter_map(|p| p.to_git().map(Into::into))
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
        for (path, hg_file, hg_fileparents) in
            get_changes(manifest_cid.into(), &git_manifest_parents, false)
        {
            let hg_file = HgFileId::from_raw_bytes(hg_file.as_raw_bytes()).unwrap();
            if hg_file.is_null() || hg_file == RawHgFile::EMPTY_OID || !seen_files.insert(hg_file) {
                continue;
            }
            if unsafe {
                // TODO: add FileFindParents logging.
                check_file(
                    &hg_file.into(),
                    &hg_fileparents
                        .get(0)
                        .map_or_else(HgObjectId::null, |p| {
                            HgObjectId::from_raw_bytes(p.as_raw_bytes()).unwrap()
                        })
                        .into(),
                    &hg_fileparents
                        .get(1)
                        .map_or_else(HgObjectId::null, |p| {
                            HgObjectId::from_raw_bytes(p.as_raw_bytes()).unwrap()
                        })
                        .into(),
                )
            } != 1
            {
                report(format!(
                    "Sha1 mismatch for file {}\n\
                     \x20 revision {}",
                    manifest_path(&path),
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
                    .map(|x| format!("{}", x))
                    .chain(b.iter().map(|x| format!("^{}", x)))
            }
            let all_args = args
                .into_iter()
                .map(str::to_string)
                .chain(iter_manifests(&manifest_heads, &store_manifest_heads));
            for m in rev_list(all_args) {
                fix(format!("Missing manifest commit in manifest branch: {}", m));
            }

            let all_args = args
                .into_iter()
                .map(str::to_string)
                .chain(iter_manifests(&store_manifest_heads, &manifest_heads));
            for m in rev_list(all_args) {
                fix(format!(
                    "Removing manifest commit {} with no corresponding changeset",
                    m
                ));
            }

            for &h in store_manifest_heads.difference(&manifest_heads) {
                // TODO: This is gross.
                let m = RawCommit::read(h).unwrap();
                let m = m.parse().unwrap();
                let m = HgManifestId::from_bytes(m.body()).unwrap();
                if seen_manifests.contains(&m) {
                    fix(format!(
                        "Remove non-head reference to {} in manifests metadata",
                        h
                    ));
                }
            }

            unsafe {
                reset_manifest_heads();
                for h in manifest_heads {
                    // TODO: This is gross.
                    let m = RawCommit::read(h).unwrap();
                    let m = m.parse().unwrap();
                    let m = HgManifestId::from_bytes(m.body()).unwrap();
                    do_set(
                        cstr::cstr!("manifest").as_ptr(),
                        &hg_object_id::from(m),
                        &object_id::from(h),
                    );
                }
            }
        }
    }

    if full_fsck && !broken.get() {
        unsafe { &mut hg2git }.for_each(|h, _| {
            if seen_changesets.contains(&HgChangesetId::from_unchecked(h))
                || seen_manifests.contains(&HgManifestId::from_unchecked(h))
                || seen_files.contains(&HgFileId::from_unchecked(h))
            {
                return;
            }
            fix(format!("Removing dangling metadata for {}", h));
            // Theoretically, we should figure out if they are files, manifests
            // or changesets and set the right variable accordingly, but in
            // practice, it makes no difference. Reevaluate when refactoring,
            // though.
            unsafe {
                do_set(
                    cstr::cstr!("file").as_ptr(),
                    &hg_object_id::from(h),
                    &object_id::default(),
                );
                do_set(
                    cstr::cstr!("file-meta").as_ptr(),
                    &hg_object_id::from(h),
                    &object_id::default(),
                );
            }
        });
        unsafe { &mut git2hg }.for_each(|g, _| {
            // TODO: this is gross.
            let cid = GitChangesetId::from_unchecked(CommitId::from_unchecked(g));
            if seen_git2hg.contains(&cid) {
                return;
            }
            fix(format!("Removing dangling note for commit {}", g));
            let metadata = RawGitChangesetMetadata::read(cid).unwrap();
            let metadata = metadata.parse().unwrap();
            unsafe {
                do_set(
                    cstr::cstr!("changeset-metadata").as_ptr(),
                    &hg_object_id::from(metadata.changeset_id()),
                    &object_id::default(),
                );
            }
        });
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
            fix(format!("Adding missing head {} in branch {}", cid, branch));
        }
        for (cid, branch) in original_heads
            .difference(&computed_heads)
            .sorted_by_key(|(_, branch)| branch)
        {
            fix(format!(
                "Removing non-head reference to {} in branch {}",
                cid, branch
            ));
        }
        if original_heads != computed_heads {
            set_changeset_heads(changeset_heads);
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

    if do_done_and_check(&[CHECKED_REF.as_bytes()]) {
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
    let commit = RawCommit::read(metadata_cid).unwrap();
    let commit = commit.parse().unwrap();
    for r in ls_tree(commit.tree())
        .unwrap()
        .filter_map(|item| {
            let r = GitObjectId::from_bytes(&item.path).unwrap();
            (item.oid == r).then(|| r)
        })
        .progress(|n| format!("Removing {n} self-referencing grafts"))
    {
        unsafe {
            do_set_replace(&object_id::from(r), &object_id::default());
        }
    }
}

pub fn manifest_path(p: &[u8]) -> Box<BStr> {
    p.strip_prefix(b"_")
        .unwrap()
        .replace("/_", "/")
        .as_bstr()
        .to_boxed()
}

fn get_changes(
    cid: CommitId,
    parents: &[CommitId],
    all: bool,
) -> impl Iterator<Item = (Box<[u8]>, GitObjectId, Box<[GitObjectId]>)> {
    if parents.is_empty() {
        // Yes, this is ridiculous.
        let commit = RawCommit::read(cid).unwrap();
        let commit = commit.parse().unwrap();
        ls_tree(commit.tree())
            .unwrap()
            .map(|item| (item.path, item.oid, [].to_boxed()))
            .collect_vec()
            .into_iter()
    } else if parents.len() == 1 {
        manifest_diff(parents[0], cid)
            .map(|(path, node, parent)| (path, node, [parent].to_boxed()))
            .collect_vec()
            .into_iter()
    } else {
        manifest_diff2(parents[0], parents[1], cid, all)
            .map(|(path, node, parents)| (path, node, parents.to_boxed()))
            .collect_vec()
            .into_iter()
    }
}

fn manifest_diff(
    a: CommitId,
    b: CommitId,
) -> impl Iterator<Item = (Box<[u8]>, GitObjectId, GitObjectId)> {
    diff_tree(a, b, false).filter_map(|item| match item {
        DiffTreeItem::Added { path, oid, .. } => Some((path, oid.into(), GitObjectId::null())),
        DiffTreeItem::Modified {
            path,
            from_oid,
            to_oid,
            ..
        } if from_oid != to_oid => Some((path, to_oid.into(), from_oid.into())),
        DiffTreeItem::Deleted { path, oid, .. } => Some((path, GitObjectId::null(), oid.into())),
        _ => None,
    })
}

fn manifest_diff2(
    a: CommitId,
    b: CommitId,
    c: CommitId,
    all: bool,
) -> impl Iterator<Item = (Box<[u8]>, GitObjectId, [GitObjectId; 2])> {
    let mut iter1 = manifest_diff(a, c);
    let mut iter2 = manifest_diff(b, c);
    let mut item1 = iter1.next();
    let mut item2 = iter2.next();
    let mut result = Vec::new();
    loop {
        while let Some((path, oid, parent_oid)) = item1.as_ref() {
            if let Some((path2, ..)) = &item2 {
                if path >= path2 {
                    break;
                }
            }
            if all {
                result.push((path.clone(), *oid, [*parent_oid, *oid]));
            }
            item1 = iter1.next();
        }
        while let Some((path, oid, parent_oid)) = item2.as_ref() {
            if let Some((path1, ..)) = &item1 {
                if path >= path1 {
                    break;
                }
            }
            if all {
                result.push((path.clone(), *oid, [*oid, *parent_oid]));
            }
            item2 = iter2.next();
        }
        if item1.is_none() && item2.is_none() {
            break;
        }
        if item1.is_some()
            && item2.is_some()
            && item1.as_ref().unwrap().0 == item2.as_ref().unwrap().0
        {
            let (_, oid1, parent_oid1) = item1.as_ref().unwrap();
            let (path, oid2, parent_oid2) = item2.as_ref().unwrap();
            assert_eq!(oid1, oid2);
            result.push((path.clone(), *oid1, [*parent_oid1, *parent_oid2]));

            item1 = iter1.next();
            item2 = iter2.next();
        }
    }
    result.into_iter()
}

#[derive(Clone, Debug)]
struct AbbrevSize(usize);

impl FromStr for AbbrevSize {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = usize::from_str(s).map_err(|e| format!("{}", e))?;
        match value {
            3..=40 => Ok(AbbrevSize(value)),
            41..=std::usize::MAX => Err(format!("value too large: {}", value)),
            _ => Err(format!("value too small: {}", value)),
        }
    }
}

#[derive(Parser)]
#[clap(name = "git-cinnabar")]
#[clap(version=crate_version!())]
#[clap(long_version=FULL_VERSION)]
#[clap(arg_required_else_help = true)]
#[clap(dont_collapse_args_in_usage = true)]
#[clap(subcommand_required = true)]
enum CinnabarCommand {
    #[clap(name = "remote-hg")]
    #[clap(hide = true)]
    RemoteHg { remote: OsString, url: OsString },
    #[clap(name = "data")]
    #[clap(group = ArgGroup::new("input").multiple(false).required(true))]
    #[clap(about = "Dump the contents of a mercurial revision")]
    Data {
        #[clap(short = 'c')]
        #[clap(group = "input")]
        #[clap(help = "Open changelog")]
        changeset: Option<Abbrev<HgChangesetId>>,
        #[clap(short = 'm')]
        #[clap(group = "input")]
        #[clap(help = "Open manifest")]
        manifest: Option<Abbrev<HgManifestId>>,
        #[clap(group = "input")]
        #[clap(help = "Open file")]
        file: Option<Abbrev<HgFileId>>,
    },
    #[clap(name = "hg2git")]
    #[clap(group = ArgGroup::new("input").multiple(true).required(true))]
    #[clap(about = "Convert mercurial sha1 to corresponding git sha1")]
    Hg2Git {
        #[clap(long)]
        #[clap(require_equals = true)]
        #[clap(num_args = ..=1)]
        #[clap(help = "Show a partial prefix")]
        abbrev: Option<Vec<AbbrevSize>>,
        #[clap(group = "input")]
        #[clap(help = "Mercurial sha1")]
        sha1: Vec<Abbrev<HgChangesetId>>,
        #[clap(long)]
        #[clap(group = "input")]
        #[clap(help = "Read sha1s on stdin")]
        batch: bool,
    },
    #[clap(name = "git2hg")]
    #[clap(group = ArgGroup::new("input").multiple(true).required(true))]
    #[clap(about = "Convert git sha1 to corresponding mercurial sha1")]
    Git2Hg {
        #[clap(long)]
        #[clap(require_equals = true)]
        #[clap(num_args = ..=1)]
        #[clap(help = "Show a partial prefix")]
        abbrev: Option<Vec<AbbrevSize>>,
        #[clap(group = "input")]
        #[clap(help = "Git sha1/committish")]
        #[clap(value_parser)]
        committish: Vec<OsString>,
        #[clap(long)]
        #[clap(group = "input")]
        #[clap(help = "Read sha1/committish on stdin")]
        batch: bool,
    },
    #[clap(name = "fetch")]
    #[clap(about = "Fetch a changeset from a mercurial remote")]
    Fetch {
        #[clap(required_unless_present = "tags")]
        #[clap(help = "Mercurial remote name or url")]
        #[clap(value_parser)]
        remote: Option<OsString>,
        #[clap(required_unless_present = "tags")]
        #[clap(help = "Mercurial changeset to fetch")]
        #[clap(value_parser)]
        revs: Vec<OsString>,
        #[clap(long)]
        #[clap(exclusive = true)]
        #[clap(help = "Fetch tags")]
        tags: bool,
    },
    #[clap(name = "reclone")]
    #[clap(about = "Reclone all mercurial remotes")]
    Reclone,
    #[clap(name = "rollback")]
    #[clap(about = "Rollback cinnabar metadata state")]
    Rollback {
        #[clap(long)]
        #[clap(conflicts_with = "committish")]
        #[clap(help = "Show a list of candidates for rollback")]
        candidates: bool,
        #[clap(long)]
        #[clap(conflicts_with = "committish")]
        #[clap(conflicts_with = "candidates")]
        #[clap(help = "Rollback to the last successful fsck state")]
        fsck: bool,
        #[clap(long)]
        #[clap(conflicts_with = "candidates")]
        #[clap(
            help = "Force to use the given committish even if it is not in the current metadata's ancestry"
        )]
        force: bool,
        #[clap(help = "Git sha1/committish of the state to rollback to")]
        #[clap(value_parser)]
        committish: Option<OsString>,
    },
    #[clap(name = "fsck")]
    #[clap(about = "Check cinnabar metadata consistency")]
    Fsck {
        #[clap(long)]
        #[clap(
            help = "Force check, even when metadata was already checked. Also disables incremental fsck"
        )]
        force: bool,
        #[clap(long)]
        #[clap(help = "Check more thoroughly")]
        #[clap(conflicts_with = "commit")]
        full: bool,
        #[clap(help = "Specific commit or changeset to check")]
        #[clap(value_parser)]
        commit: Vec<OsString>,
    },
    #[clap(name = "bundle")]
    #[clap(about = "Create a mercurial bundle")]
    Bundle {
        #[clap(long)]
        #[clap(default_value = "2")]
        #[clap(value_parser = clap::value_parser!(u8).range(1..=2))]
        #[clap(help = "Bundle version")]
        version: u8,
        #[clap(long)]
        #[clap(short)]
        #[clap(help = "Type of bundle (bundlespec)")]
        #[clap(conflicts_with = "version")]
        r#type: Option<BundleSpec>,
        #[clap(help = "Path of the bundle")]
        #[clap(value_parser)]
        path: PathBuf,
        #[clap(help = "Git revision range (see the Specifying Ranges section of gitrevisions(7))")]
        #[clap(value_parser)]
        revs: Vec<OsString>,
    },
    #[clap(name = "unbundle")]
    #[clap(about = "Apply a mercurial bundle to the repository")]
    Unbundle {
        #[clap(long)]
        #[clap(help = "Get clone bundle from given repository")]
        clonebundle: bool,
        #[clap(help = "Url/Location of the bundle")]
        url: OsString,
    },
    #[clap(name = "upgrade")]
    #[clap(about = "Upgrade cinnabar metadata")]
    Upgrade,
    #[cfg(feature = "self-update")]
    #[clap(name = "self-update")]
    #[clap(about = "Update git-cinnabar")]
    SelfUpdate {
        #[clap(long)]
        #[clap(help = "Branch to get updates from")]
        branch: Option<String>,
        #[clap(long)]
        #[clap(help = "Exact commit to get a version from")]
        #[clap(value_parser)]
        #[clap(conflicts_with = "branch")]
        exact: Option<CommitId>,
    },
    #[clap(name = "setup")]
    #[clap(about = "Setup git-cinnabar")]
    #[clap(hide = true)]
    Setup,
}

use CinnabarCommand::*;

fn git_cinnabar(args: Option<&[&OsStr]>) -> Result<c_int, String> {
    let command = if let Some(args) = args {
        CinnabarCommand::try_parse_from(args)
    } else {
        CinnabarCommand::try_parse()
    };
    let command = match command {
        Ok(c) => c,
        Err(e) => {
            e.print().unwrap();
            return if e.use_stderr() { Ok(1) } else { Ok(0) };
        }
    };
    #[cfg(feature = "self-update")]
    if let SelfUpdate { branch, exact } = command {
        return do_self_update(branch, exact).map(|()| 0);
    }
    if let Setup = command {
        return do_setup().map(|()| 0);
    }
    let _v = VersionChecker::new();
    if let RemoteHg { remote, url } = command {
        return git_remote_hg(remote, url);
    }
    Lazy::force(&INIT_CINNABAR_2);
    let ret = match command {
        #[cfg(feature = "self-update")]
        SelfUpdate { .. } => unreachable!(),
        RemoteHg { .. } => unreachable!(),
        Setup => unreachable!(),
        Data {
            changeset: Some(c), ..
        } => do_data_changeset(c),
        Data {
            manifest: Some(m), ..
        } => do_data_manifest(m),
        Data { file: Some(f), .. } => do_data_file(f),
        Data { .. } => unreachable!(),
        Hg2Git {
            abbrev,
            sha1,
            batch,
        } => do_conversion_cmd(
            abbrev.map(|v| v.get(0).map_or(12, |a| a.0)),
            sha1.into_iter(),
            batch,
            do_one_hg2git,
        ),
        Git2Hg {
            abbrev,
            committish,
            batch,
        } => do_conversion_cmd(
            abbrev.map(|v| v.get(0).map_or(12, |a| a.0)),
            committish.into_iter(),
            batch,
            do_one_git2hg,
        ),
        Fetch {
            remote: Some(remote),
            revs,
            tags: false,
        } => do_fetch(&remote, &revs),
        Fetch { tags: true, .. } => do_fetch_tags(),
        Fetch { remote: None, .. } => unreachable!(),
        Reclone => do_reclone(),
        Rollback {
            candidates,
            fsck,
            force,
            committish,
        } => do_rollback(candidates, fsck, force, committish),
        Upgrade => do_upgrade(),
        Unbundle { clonebundle, url } => do_unbundle(clonebundle, url),
        Fsck {
            force,
            full,
            commit,
        } => match do_fsck(force, full, commit) {
            Ok(code) => return Ok(code),
            Err(e) => Err(e),
        },
        Bundle {
            version,
            r#type,
            path,
            revs,
        } => match do_bundle(version, r#type, path, revs) {
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

fn remote_helper_tags_list(mut stdout: impl Write) {
    Lazy::force(&INIT_CINNABAR_2);
    let _lock = HELPER_LOCK.lock().unwrap();
    let tags = get_tags();
    let tags = tags
        .iter()
        .filter_map(|(t, h)| h.to_git().map(|g| (t, g)))
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
        ref_updates.insert(buf.as_bstr().to_boxed(), CommitId::null());
    }
    transaction.commit().unwrap();

    for &(tag, cid) in &tags {
        let mut buf = format!("{} refs/tags/", cid).into_bytes();
        buf.extend_from_slice(tag);
        buf.push(b'\n');
        stdout.write_all(&buf).unwrap();
    }
    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();
}

bitflags! {
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

struct RemoteInfo {
    refs: HashMap<Box<BStr>, (HgChangesetId, Option<GitChangesetId>)>,
    topological_heads: Vec<HgChangesetId>,
    branch_names: Vec<Box<BStr>>,
    bookmarks: HashMap<Box<BStr>, HgChangesetId>,
    refs_style: RefsStyle,
}

fn remote_helper_repo_list(
    conn: &mut dyn HgRepo,
    remote: Option<&str>,
    mut stdout: impl Write,
    for_push: bool,
) -> RemoteInfo {
    let _lock = HELPER_LOCK.lock().unwrap();
    let refs_style = (for_push)
        .then(|| RefsStyle::from_config("pushrefs", remote))
        .flatten()
        .or_else(|| RefsStyle::from_config("refs", remote))
        .unwrap_or(RefsStyle::all());

    let mut refs = HashMap::new();

    // Valid characters in mercurial branch names are not necessarily valid
    // in git ref names. This function replaces unsupported characters with a
    // url-like escape such that the name can be reversed straightforwardly.
    // TODO: Actually sanitize all the conflicting cases, see
    // git-check-ref-format(1).
    const BRANCH_QUOTE_SET: &AsciiSet = &CONTROLS.add(b'%').add(b' ');

    let apply_template = |template: &[&str], values: &[&BStr]| {
        let mut buf = Vec::new();
        let mut values = values.iter();
        for part in template {
            if part.is_empty() {
                buf.extend_from_slice(values.next().unwrap());
            } else {
                buf.extend_from_slice(
                    percent_encode(part.as_bytes(), BRANCH_QUOTE_SET)
                        .to_string()
                        .as_bytes(),
                );
            }
        }
        buf.as_bstr().to_boxed()
    };

    let mut add_ref = |template: Option<&[&str]>, values: &[&BStr], csid: HgChangesetId| {
        if let Some(template) = template {
            let cid = csid.to_git();
            refs.insert(apply_template(template, values), (csid, cid));
        }
    };

    let fetches;
    let branchmap;
    let bookmarks;
    if let Some(fetch) = get_config("fetch").and_then(|f| (!f.is_empty()).then(|| f)) {
        fetches = Some(
            fetch
                .to_str()
                .unwrap()
                .split(' ')
                .map(HgChangesetId::from_str)
                .collect::<Result<Box<[_]>, _>>()
                .unwrap(),
        );
        branchmap = HashMap::new();
        bookmarks = HashMap::new();
    } else {
        fetches = None;
        branchmap = ByteSlice::lines(&*conn.branchmap())
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
            .collect();
        bookmarks = ByteSlice::lines(&*conn.bookmarks())
            .map(|l| {
                let [b, h] = l.splitn_exact(b'\t').unwrap();
                (
                    b.as_bstr().to_boxed(),
                    HgChangesetId::from_bytes(h).unwrap(),
                )
            })
            .collect();
    }

    let mut head_template = None;
    let mut tip_template = None;
    let mut default_tip = None;
    if refs_style.intersects(RefsStyle::HEADS | RefsStyle::TIPS) {
        if refs_style.contains(RefsStyle::HEADS | RefsStyle::TIPS) {
            head_template = Some(&["refs/heads/branches/", "", "/", ""][..]);
            tip_template = Some(&["refs/heads/branches/", "", "/tip"][..]);
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
                if let Some(git_head) = head.to_git() {
                    let metadata = RawGitChangesetMetadata::read(git_head).unwrap();
                    let metadata = metadata.parse().unwrap();
                    if metadata.extra().and_then(|e| e.get(b"close")).is_some() {
                        continue;
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

    for f in fetches.iter().flat_map(|f| f.iter()) {
        add_ref(
            Some(&["hg/revs/", ""]),
            &[f.to_string().as_bytes().as_bstr()],
            *f,
        );
    }

    let head_ref = if let Some(bookmark_template) = bookmarks
        .contains_key(b"@".as_bstr())
        .then(|| ())
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
                format!("{}", default_tip).as_bytes().as_bstr(),
            ],
        ))
    } else {
        None
    };

    if let Some(head_ref) = head_ref {
        if let Some((csid, cid)) = refs.get(&head_ref) {
            let mut buf = b"@".to_vec();
            buf.extend_from_slice(&head_ref);
            buf.push(b' ');
            buf.extend_from_slice(b"HEAD\n");
            stdout.write_all(&buf).unwrap();
            refs.insert(b"HEAD".as_bstr().to_boxed(), (*csid, *cid));
        }
    }

    for (refname, (_, cid)) in refs
        .iter()
        .filter(|(r, _)| &***r != b"HEAD".as_bstr())
        .sorted()
    {
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
    RemoteInfo {
        refs,
        topological_heads: fetches
            .is_none()
            .then(|| {
                conn.heads()
                    .trim_end_with(|c| c == '\n')
                    .split(|&b| b == b' ')
                    .map(HgChangesetId::from_bytes)
                    .collect::<Result<_, _>>()
            })
            .transpose()
            .unwrap()
            .unwrap_or_default(),
        branch_names: branchmap.into_keys().collect(),
        bookmarks,
        refs_style,
    }
}

fn remote_helper_import(
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

    if get_config("graft-refs").is_some() {
        warn!(
            target: "root",
            "The cinnabar.graft-refs configuration is deprecated.\n\
             Please unset it."
        );
    }

    let wanted_refs = wanted_refs
        .iter()
        .map(|refname| {
            info.refs
                .get_key_value(*refname)
                .map(|(k, (h, g))| (k.as_bstr(), h, g.as_ref()))
                .ok_or_else(|| refname.to_boxed())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|refname| format!("couldn't find remote ref {}", refname.as_bstr()))?;

    let mut tags = None;
    let mut unknown_wanted_heads = wanted_refs
        .iter()
        .filter_map(|(_, csid, cid)| cid.is_none().then(|| *(*csid)))
        .unique()
        .collect_vec();
    if !unknown_wanted_heads.is_empty() {
        tags = Some(get_tags());
        if graft_config_enabled(remote)?.unwrap_or(false) {
            init_graft();
        }
        // TODO: Mercurial can be an order of magnitude slower when
        // creating a bundle when not giving topological heads, which
        // some of the branch heads might not be.
        // http://bz.selenic.com/show_bug.cgi?id=4595
        // The heads we've been asked for either come from the repo
        // branchmap, and are a superset of its topological heads,
        // or from `hg/revs/*` fetch refs, in which case we want specific
        // things anyways. In the former case, that means if the heads
        // we don't know in those we were asked for are a superset of the
        // topological heads we don't know, then we should use those
        // instead.
        // In the case of `hg/revs/*` fetch refs, we don't have any branch
        // names, as per the branchmap initialization in
        // remote_helper_repo_list.
        if !info.branch_names.is_empty() {
            let unknown_topological_heads = info
                .topological_heads
                .into_iter()
                .filter(|h| h.to_git().is_none())
                .collect::<Vec<_>>();
            if unknown_wanted_heads
                .iter()
                .collect::<HashSet<_>>()
                .is_superset(&unknown_topological_heads.iter().collect())
            {
                unknown_wanted_heads = unknown_topological_heads;
            }
        }
        let branch_names = info
            .branch_names
            .iter()
            .map(|b| &**b)
            .collect::<HashSet<_>>();
        get_bundle(conn, &unknown_wanted_heads, &branch_names, remote)?;
    }

    do_done_and_check(&[])
        .then(|| ())
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
                    .unwrap_or_else(|| csid.to_git().unwrap())
                    .into(),
                None,
                "import",
            )
            .unwrap();
    }
    transaction.commit().unwrap();

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
        if old_tags != get_tags() {
            eprintln!(
                "\nRun the following command to update tags:\n\
                 \x20 git cinnabar fetch --tags"
            );
        }
    }
    Ok(())
}

fn remote_helper_push(
    conn: &mut dyn HgRepo,
    remote: Option<&str>,
    push_refs: &[&BStr],
    info: RemoteInfo,
    mut stdout: impl Write,
    dry_run: bool,
) -> Result<i32, String> {
    let push_refs = push_refs
        .iter()
        .map(|p| {
            let [source, dest] = p.splitn_exact(b':').unwrap();
            let (source, force) = source
                .strip_prefix(b"+")
                .map_or((source, false), |s| (s, true));
            (
                source.as_bstr(),
                (!source.is_empty()).then(|| get_oid_committish(source).unwrap()),
                dest.as_bstr(),
                force,
            )
        })
        .collect_vec();

    let broken = resolve_ref(METADATA_REF).map(|m| resolve_ref(BROKEN_REF) == Some(m));
    if broken == Some(true) || conn.get_capability(b"unbundle").is_none() {
        for (_, _, dest, _) in &push_refs {
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
        return Ok(0);
    }
    if let Some(metadata) = resolve_ref(METADATA_REF) {
        if Some(metadata) == resolve_ref(BROKEN_REF) {
            return Err(
                "Cannot fetch with broken metadata. Please fix your clone first.".to_string(),
            );
        }
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

    let mut pushed = ChangesetHeads::new();
    let result = (|| {
        let branch_names = info.branch_names.into_iter().collect::<HashSet<_>>();
        let push_commits = push_refs.iter().filter_map(|(_, c, _, _)| *c).collect_vec();
        let local_bases = rev_list_with_boundaries(
            CHANGESET_HEADS
                .lock()
                .unwrap()
                .branch_heads()
                .filter_map(|(h, b)| {
                    branch_names
                        .contains(b)
                        .then(|| format!("^{}", h.to_git().unwrap()))
                })
                .chain(push_commits.iter().map(ToString::to_string))
                .chain(["--topo-order".to_string(), "--full-history".to_string()]),
        )
        .filter_map(|b| match b {
            MaybeBoundary::Boundary(c) => Some(Ok(c)),
            MaybeBoundary::Shallow => Some(Err(
                "Pushing git shallow clones is not supported.".to_string()
            )),
            MaybeBoundary::Commit(_) => None,
        })
        .chain(push_commits.into_iter().map(Ok))
        .map_ok(GitChangesetId::from_unchecked)
        .filter_map_ok(GitChangesetId::to_hg)
        .unique()
        .collect::<Result<Vec<_>, _>>()?;

        let pushing_anything = push_refs.iter().any(|(_, c, _, _)| c.is_some());
        let force = push_refs.iter().all(|(_, _, _, force)| *force);
        let no_topological_heads = info.topological_heads.iter().all(ObjectId::is_null);
        if pushing_anything && local_bases.is_empty() && !no_topological_heads {
            let mut fail = true;
            if has_metadata() && force {
                let cinnabar_roots = rev_list([
                    "--topo-order",
                    "--full-history",
                    "--max-parents=0",
                    "refs/cinnabar/metadata^",
                ])
                .filter_map(|c| GitChangesetId::from_unchecked(c).to_hg())
                .collect_vec();
                fail = !conn.known(&cinnabar_roots).iter().any(|k| *k);
            }
            if fail {
                return Err(
                    "Cannot push to this remote without pulling/updating first.".to_string()
                );
            }
        }

        let common = find_common(conn, local_bases);

        let push_commits = rev_list(
            ["--topo-order", "--full-history", "--reverse"]
                .iter()
                .map(ToString::to_string)
                .chain(
                    common
                        .into_iter()
                        .map(|c| format!("^{}", c.to_git().unwrap())),
                )
                .chain(
                    push_refs
                        .iter()
                        .filter_map(|(_, c, _, _)| c.as_ref().map(ToString::to_string)),
                ),
        )
        .map(|c| {
            let commit = RawCommit::read(c).unwrap();
            let commit = commit.parse().unwrap();
            (c, commit.parents().to_boxed())
        })
        .collect_vec();

        if !push_commits.is_empty() {
            let has_root = push_commits.iter().any(|(_, p)| p.is_empty());
            if has_root && !no_topological_heads {
                if !force {
                    return Err("Cannot push a new root".to_string());
                }
                warn!(target: "root", "Pushing a new root");
            }
        }

        let mut result = None;
        if !push_commits.is_empty() && !dry_run {
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
            let tempfile = tempfile::Builder::new()
                .prefix("hg-bundle-")
                .suffix(".hg")
                .rand_bytes(6)
                .tempfile()
                .unwrap();
            let (file, path) = tempfile.into_parts();
            pushed = do_create_bundle(
                push_commits.iter().cloned(),
                bundlespec,
                version,
                &file,
                version == 2,
            )?;
            drop(file);
            let file = File::open(path).unwrap();
            let empty_heads = [HgChangesetId::null()];
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
                    let mut bundle = BundleReader::new(data).unwrap();
                    while let Some(part) = bundle.next_part().unwrap() {
                        match part.part_type.as_bytes() {
                            b"reply:changegroup" => {
                                // TODO: should check in-reply-to param.
                                let response = part.get_param("return").unwrap();
                                result = u32::from_str(response).ok();
                            }
                            b"error:abort" => {
                                let mut message = part.get_param("message").unwrap().to_string();
                                if let Some(hint) = part.get_param("hint") {
                                    message.push_str("\n\n");
                                    message.push_str(hint);
                                }
                                error!(target: "root", "{}", message);
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
        .map(|(_, source_cid, dest, _)| {
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
                    .map(|cid| GitChangesetId::from_unchecked(*cid).to_hg().unwrap());
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
                Ok(!pushed.is_empty())
            } else {
                Err("Deleting remote branches is unsupported")
            };
            (*dest, status)
        })
        .collect::<HashMap<_, _>>();

    if !status.is_empty() {
        for (_, _, dest, _) in push_refs {
            let mut buf = Vec::new();
            match status[dest] {
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
    }

    let data = get_config_remote("data", remote);
    let data = data
        .as_deref()
        .and_then(|d| (!d.is_empty()).then(|| d))
        .unwrap_or_else(|| OsStr::new("phase"));
    let valid = [
        OsStr::new("never"),
        OsStr::new("phase"),
        OsStr::new("always"),
    ];
    if !valid.contains(&data) {
        die!(
            "`{}` is not one of `never`, `phase` or `always`",
            data.as_bytes().as_bstr()
        );
    }
    let rollback = if status.is_empty() || pushed.is_empty() || dry_run {
        true
    } else {
        match data.to_str().unwrap() {
            "always" => false,
            "never" => true,
            "phase" => {
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
                            .filter_map(HgChangesetId::to_git)
                            .map(Into::into),
                        drafts
                            .iter()
                            .copied()
                            .filter_map(HgChangesetId::to_git)
                            .map(Into::into),
                    )
                    .is_empty()
                }
            }
            _ => unreachable!(),
        }
    };
    if rollback {
        unsafe {
            do_cleanup(1);
        }
    } else {
        do_done_and_check(&[])
            .then(|| ())
            .ok_or_else(|| "Fatal error".to_string())?;
    }
    result
}

fn git_remote_hg(remote: OsString, mut url: OsString) -> Result<c_int, String> {
    if !url.as_bytes().starts_with(b"hg:") {
        let mut new_url = OsString::from("hg::");
        new_url.push(url);
        url = new_url;
    }
    let remote = Some(remote.to_str().unwrap().to_owned())
        .and_then(|r| (!r.starts_with("hg://") && !r.starts_with("hg::")).then(|| r));
    let url = hg_url(&url).unwrap();
    let mut conn = (url.scheme() != "tags").then(|| get_connection(&url).unwrap());

    let stdin = stdin();
    let mut stdin = LoggingReader::new("remote-helper", log::Level::Info, stdin.lock());
    let stdout = stdout();
    let mut stdout = LoggingWriter::new("remote-helper", log::Level::Info, stdout.lock());
    let mut buf = Vec::new();
    let mut dry_run = false;
    let mut info = None;
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
                    remote_helper_tags_list(&mut stdout);
                } else {
                    info = Some(remote_helper_repo_list(
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
                let code = remote_helper_push(
                    conn.as_deref_mut().unwrap(),
                    remote.as_deref(),
                    &args.iter().map(|r| &**r).collect_vec(),
                    info.take().unwrap(),
                    &mut stdout,
                    dry_run,
                )?;
                if code > 0 {
                    return Ok(code);
                }
            }
            _ => panic!("unknown command: {}", cmd.as_bstr()),
        }
    }
    Ok(0)
}

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
    init_cinnabar(exe.as_deref().unwrap_or(argv0).as_ptr());
    logging::init(now);

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
    done_cinnabar();
    match ret {
        Ok(code) => code,
        Err(msg) => {
            error!(target: "root", "{}", msg);
            1
        }
    }
}

#[no_mangle]
unsafe extern "C" fn config(name: *const c_char, result: *mut strbuf) -> c_int {
    if let Some(res) = get_config(CStr::from_ptr(name).to_str().unwrap()) {
        result.as_mut().unwrap().extend_from_slice(res.as_bytes());
        0
    } else {
        1
    }
}

pub fn get_config(name: &str) -> Option<OsString> {
    get_config_remote(name, None)
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

        const ALL_BASE_CHECKS = Checks::NODEID.bits | Checks::MANIFESTS.bits | Checks::HELPER.bits;
    }
}

static CHECKS: Lazy<Checks> = Lazy::new(|| {
    let mut checks = Checks::VERSION;
    if let Some(config) = get_config("check") {
        for c in config.as_bytes().split(|&b| b == b',') {
            match c {
                b"true" | b"all" => checks = Checks::ALL_BASE_CHECKS,
                b"helper" => checks.set(Checks::HELPER, true),
                b"manifests" => checks.set(Checks::MANIFESTS, true),
                b"no-version-check" => checks.set(Checks::VERSION, false),
                b"nodeid" => checks.set(Checks::NODEID, true),
                b"files" => checks.set(Checks::FILES, true),
                b"time" => checks.set(Checks::TIME, true),
                b"traceback" => checks.set(Checks::TRACEBACK, true),
                b"no-bundle2" => checks.set(Checks::NO_BUNDLE2, true),
                b"cinnabarclone" => checks.set(Checks::CINNABARCLONE, true),
                b"clonebundles" => checks.set(Checks::CLONEBUNDLES, true),
                b"unbundler" => checks.set(Checks::UNBUNDLER, true),
                _ => {}
            }
        }
    }
    checks
});

#[no_mangle]
unsafe extern "C" fn cinnabar_check(flag: c_int) -> c_int {
    CHECKS.contains(Checks::from_bits(flag).unwrap()) as c_int
}

pub fn check_enabled(checks: Checks) -> bool {
    CHECKS.contains(checks)
}

bitflags! {
    pub struct Experiments: i32 {
        const MERGE = 0x1;
    }
}

static EXPERIMENTS: Lazy<Experiments> = Lazy::new(|| {
    let mut experiments = Experiments::empty();
    if let Some(config) = get_config("experiments") {
        for c in config.as_bytes().split(|&b| b == b',') {
            match c {
                b"true" | b"all" => experiments = Experiments::all(),
                b"merge" => experiments.set(Experiments::MERGE, true),
                _ => {}
            }
        }
    }
    experiments
});

pub fn experiment(experiments: Experiments) -> bool {
    EXPERIMENTS.contains(experiments)
}

#[no_mangle]
unsafe extern "C" fn do_panic(err: *const u8, len: usize) {
    panic!("{}", std::slice::from_raw_parts(err, len).as_bstr());
}
