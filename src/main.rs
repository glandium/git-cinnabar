/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
#![allow(dead_code)]

#[macro_use]
extern crate derivative;
#[macro_use]
extern crate all_asserts;
#[macro_use]
extern crate log;

use clap::{crate_version, AppSettings, ArgGroup, Parser};
use itertools::Itertools;

#[macro_use]
mod util;
#[macro_use]
mod oid;
#[macro_use]
pub mod libgit;
mod libc;
mod libcinnabar;
mod logging;
pub mod store;
mod xdiff;

pub(crate) mod hg_bundle;
#[macro_use]
pub mod hg_connect;
pub(crate) mod hg_connect_http;
pub(crate) mod hg_connect_stdio;
pub(crate) mod hg_data;

use std::borrow::Cow;
use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::{CStr, OsStr, OsString};
use std::fmt;
use std::io::{stdin, stdout, BufRead, BufReader, BufWriter, Cursor, Write};
use std::os::raw::c_char;
use std::os::raw::c_int;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, from_utf8, FromStr};
use std::thread::spawn;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::time::Instant;

use bitflags::bitflags;
use bstr::ByteSlice;
use git_version::git_version;
use once_cell::sync::Lazy;
use os_pipe::pipe;
use url::Url;
use which::which;

use hg_connect::connect_main_with;
use libcinnabar::{files_meta, hg2git};
use libgit::{
    config_get_value, for_each_ref_in, for_each_remote, get_oid_committish, lookup_replace_commit,
    ls_tree, remote, resolve_ref, strbuf, BlobId, CommitId, RawCommit, RefTransaction,
};
use oid::{Abbrev, GitObjectId, HgObjectId, ObjectId};
use store::{
    GitChangesetId, GitFileId, GitFileMetadataId, GitManifestId, HgChangesetId, HgFileId,
    HgManifestId, RawHgChangeset, RawHgFile, RawHgManifest, BROKEN_REF, CHECKED_REF, METADATA_REF,
    NOTES_REF, REFS_PREFIX, REPLACE_REFS_PREFIX,
};
use util::{CStrExt, Duplicate, IteratorExt, OsStrExt, SliceExt};

#[cfg(feature = "version-check")]
mod version_check;

#[cfg(not(feature = "version-check"))]
mod version_check {
    pub struct VersionCheck;

    impl VersionCheck {
        pub fn new() -> Self {
            VersionCheck
        }
    }
}

use version_check::VersionCheck;

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

extern "C" {
    #[allow(improper_ctypes)]
    fn helper_main(in_: *mut libcinnabar::reader, out: c_int) -> c_int;

    #[cfg(windows)]
    fn wmain(argc: c_int, argv: *const *const u16) -> c_int;

    fn init_cinnabar(argv0: *const c_char);
    fn init_cinnabar_2();
    fn done_cinnabar();
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

fn do_one_hg2git(sha1: &Abbrev<HgChangesetId>) -> String {
    format!("{}", unsafe {
        hg2git
            .get_note_abbrev(sha1)
            .unwrap_or_else(GitObjectId::null)
    })
}

fn do_one_git2hg(committish: &OsString) -> String {
    let note = get_oid_committish(committish.as_bytes())
        .as_ref()
        .map(lookup_replace_commit)
        .and_then(|oid| unsafe { GitChangesetId::from_unchecked(oid.into_owned()).to_hg() });
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

fn do_conversion_cmd<'a, T, I, F>(
    abbrev: Option<usize>,
    input: I,
    batch: bool,
    f: F,
) -> Result<(), String>
where
    T: 'a + FromStr,
    <T as FromStr>::Err: fmt::Display,
    I: Iterator<Item = &'a T>,
    F: Fn(&T) -> String,
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
                    Ok(f(&t))
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
            .get_note_abbrev(&rev)
            .ok_or_else(|| format!("Unknown changeset id: {}", rev))?;
        let changeset = RawHgChangeset::read(&GitChangesetId::from_unchecked(
            CommitId::from_unchecked(commit_id),
        ))
        .unwrap();
        stdout().write_all(&changeset).map_err(|e| e.to_string())
    }
}

fn do_data_manifest(rev: Abbrev<HgManifestId>) -> Result<(), String> {
    unsafe {
        let commit_id = hg2git
            .get_note_abbrev(&rev)
            .ok_or_else(|| format!("Unknown manifest id: {}", rev))?;
        let manifest = RawHgManifest::read(&GitManifestId::from_unchecked(
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
    let mut conn = hg_connect::get_connection(&url, 0)
        .ok_or_else(|| format!("Failed to connect to {}", url))?;
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

fn get_previous_metadata(metadata: &CommitId) -> Option<CommitId> {
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
        Some(parents[num_parents - 1].clone())
    } else {
        None
    }
}

fn rollback_to(
    new_metadata: Option<&CommitId>,
    force: bool,
    msg: &str,
) -> Result<Option<CommitId>, String> {
    let mut refs = HashMap::new();
    for_each_ref_in(REFS_PREFIX, |r, oid| {
        let mut full_ref = OsString::from(REFS_PREFIX);
        full_ref.push(r);
        if refs.insert(full_ref, oid.clone()).is_some() {
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
                transaction.delete(r, Some(&oid), msg)?;
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

        let mut m = metadata.clone();
        let found = std::iter::from_fn(move || {
            m = m.as_ref().and_then(get_previous_metadata);
            m.clone()
        })
        .try_find_(|m| -> Result<_, String> {
            if Some(m) == broken.as_ref() {
                state = MetadataState::Broken;
            } else if Some(m) == checked.as_ref() {
                state = MetadataState::Checked;
            } else if state == MetadataState::Broken {
                // We don't know whether ancestors of broken metadata are broken.
                state = MetadataState::Unknown;
            }
            Ok(m == new)
        })?
        .or_else(|| {
            if force {
                state = MetadataState::Unknown;
                Some(new.clone())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            format!(
                "Cannot rollback to {}, it is not in the ancestry of current metadata.",
                new
            )
        })?;
        // And just in case, check we got what we were looking for. Any error
        // should already have been returned by the `?` above.
        assert_eq!(found, *new);

        match state {
            MetadataState::Checked => {
                transaction.update(CHECKED_REF, new, checked.as_ref(), msg)?;
            }
            MetadataState::Broken => transaction.update(BROKEN_REF, new, broken.as_ref(), msg)?,
            MetadataState::Unknown => {}
        }

        // TODO: fully parse the metadata commit. Also check earlier
        // (ideally before calling this function).
        let commit = RawCommit::read(new).unwrap();
        let commit = commit.parse().unwrap();
        if commit.author() != b" <cinnabar@git> 0 +0000" {
            return Err(format!("Invalid cinnabar metadata: {}", new));
        }
        transaction.update(METADATA_REF, new, metadata.as_ref(), msg)?;
        transaction.update(NOTES_REF, &commit.parents()[3], notes.as_ref(), msg)?;
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
                &unsafe { CommitId::from_unchecked(item.oid) },
                replace_refs.remove(&replace_ref).as_ref(),
                msg,
            )?;
        }
        // Remove any remaining replace ref.
        for (r, oid) in replace_refs.into_iter() {
            transaction.delete(r, Some(&oid), msg)?;
        }
    } else if let Some(notes) = notes {
        transaction.delete(NOTES_REF, Some(&notes), msg)?;
    }
    transaction.commit()?;
    Ok(metadata)
}

fn do_reclone() -> Result<(), String> {
    // TODO: Avoid resetting at all, possibly leaving the repo with no metadata
    // if this is interrupted somehow.
    let mut previous_metadata = rollback_to(None, false, "reclone")?;

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
            .args(&["remote", "update", "--prune"])
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
            ("current", metadata.clone()),
            ("checked", resolve_ref(CHECKED_REF)),
            ("broken", resolve_ref(BROKEN_REF)),
        ];
        let labels = labels
            .iter()
            .filter_map(|(name, cid)| Some((*name, cid.clone()?)))
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
            metadata = get_previous_metadata(&m);
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
    } else if let Some(ref oid) = metadata {
        get_previous_metadata(oid)
    } else {
        return Err("Nothing to rollback.".to_string());
    };
    rollback_to(wanted_metadata.as_ref(), force, "rollback").map(|_| ())
}

#[allow(clippy::unnecessary_wraps)]
fn do_upgrade() -> Result<(), String> {
    // If we got here, init_cinnabar_2/init_metadata went through,
    // which means we didn't die because of unusable metadata.
    // There are currently no conditions that will require an upgrade.
    warn!(target: "root", "No metadata to upgrade");
    Ok(())
}

fn do_data_file(rev: Abbrev<HgFileId>) -> Result<(), String> {
    unsafe {
        let mut stdout = stdout();
        let blob_id = hg2git
            .get_note_abbrev(&rev)
            .ok_or_else(|| format!("Unknown file id: {}", rev))?;
        let file_id = GitFileId::from_unchecked(BlobId::from_unchecked(blob_id));
        let metadata_id = files_meta
            .get_note_abbrev(&rev)
            .map(|oid| GitFileMetadataId::from_unchecked(BlobId::from_unchecked(oid)));
        let file = RawHgFile::read(&file_id, metadata_id.as_ref()).unwrap();
        stdout.write_all(&file).map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
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
#[clap(setting(AppSettings::DeriveDisplayOrder))]
#[clap(dont_collapse_args_in_usage = true)]
#[clap(subcommand_required = true)]
enum CinnabarCommand {
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
        #[clap(max_values = 1)]
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
        #[clap(max_values = 1)]
        #[clap(help = "Show a partial prefix")]
        abbrev: Option<Vec<AbbrevSize>>,
        #[clap(group = "input")]
        #[clap(help = "Git sha1/committish")]
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
        committish: Vec<OsString>,
        #[clap(long)]
        #[clap(group = "input")]
        #[clap(help = "Read sha1/committish on stdin")]
        batch: bool,
    },
    #[clap(name = "fetch")]
    #[clap(about = "Fetch a changeset from a mercurial remote")]
    Fetch {
        #[clap(help = "Mercurial remote name or url")]
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
        remote: OsString,
        #[clap(required = true)]
        #[clap(help = "Mercurial changeset to fetch")]
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
        revs: Vec<OsString>,
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
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
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
        full: bool,
        #[clap(help = "Specific commit or changeset to check")]
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
        commit: Vec<OsString>,
    },
    #[clap(name = "bundle")]
    #[clap(about = "Create a mercurial bundle")]
    Bundle {
        #[clap(long)]
        #[clap(default_value = "2")]
        #[clap(possible_values = &["1", "2"])]
        #[clap(help = "Bundle version")]
        version: u8,
        #[clap(help = "Path of the bundle")]
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
        path: PathBuf,
        #[clap(help = "Git revision range (see the Specifying Ranges section of gitrevisions(7))")]
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
        revs: Vec<OsString>,
    },
    #[clap(name = "unbundle")]
    #[clap(about = "Apply a mercurial bundle to the repository")]
    Unbundle {
        #[clap(long)]
        #[clap(help = "Get clone bundle from given repository")]
        clonebundle: bool,
        #[clap(help = "Url of the bundle")]
        #[clap(parse(from_os_str))]
        #[clap(allow_invalid_utf8 = true)]
        url: OsString,
    },
    #[clap(name = "upgrade")]
    #[clap(about = "Upgrade cinnabar metadata")]
    Upgrade,
}

use CinnabarCommand::*;

fn git_cinnabar() -> i32 {
    let command = match CinnabarCommand::try_parse() {
        Ok(c) => c,
        Err(e) => {
            e.print().unwrap();
            return if e.use_stderr() { 1 } else { 0 };
        }
    };
    let _v = VersionCheck::new();
    unsafe {
        init_cinnabar_2();
    }
    let ret = match command {
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
            sha1.iter(),
            batch,
            do_one_hg2git,
        ),
        Git2Hg {
            abbrev,
            committish,
            batch,
        } => do_conversion_cmd(
            abbrev.map(|v| v.get(0).map_or(12, |a| a.0)),
            committish.iter(),
            batch,
            do_one_git2hg,
        ),
        Fetch { remote, revs } => do_fetch(&remote, &revs),
        Reclone => do_reclone(),
        Rollback {
            candidates,
            fsck,
            force,
            committish,
        } => do_rollback(candidates, fsck, force, committish),
        Upgrade => do_upgrade(),
        Bundle { .. } | Unbundle { .. } | Fsck { .. } => {
            match run_python_command(PythonCommand::GitCinnabar) {
                Ok(code) => {
                    return code;
                }
                Err(e) => Err(e),
            }
        }
    };
    match ret {
        Ok(()) => 0,
        Err(msg) => {
            error!(target: "root", "{}", msg);
            1
        }
    }
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

#[derive(PartialEq)]
enum PythonCommand {
    GitRemoteHg,
    GitCinnabar,
}

fn run_python_command(cmd: PythonCommand) -> Result<c_int, String> {
    let mut python = if let Ok(p) = which("python3") {
        Command::new(p)
    } else if let Ok(p) = which("py") {
        let mut c = Command::new(p);
        c.arg("-3");
        c
    } else {
        return Err("Could not find python 3.x".into());
    };

    // We aggregate the various parts of a bootstrap code that reads a
    // tarball from stdin, and use the contents of that tarball as a
    // source of python modules, using a custom loader.
    // The tarball itself is included compressed in this binary, and
    // we decompress it before sending.
    let mut bootstrap = String::new();
    let internal_python =
        cfg!(profile = "release") || std::env::var_os("GIT_CINNABAR_NO_INTERNAL_PYTHON").is_none();
    if internal_python {
        bootstrap.push_str(include_str!("../bootstrap/loader.py"));
    } else {
        bootstrap.push_str("import sys\n");
    }
    if std::env::var("GIT_CINNABAR_COVERAGE").is_ok() {
        bootstrap.push_str(include_str!("../bootstrap/coverage.py"));
    }
    bootstrap.push_str(match cmd {
        PythonCommand::GitRemoteHg => include_str!("../bootstrap/git-remote-hg.py"),
        PythonCommand::GitCinnabar => include_str!("../bootstrap/git-cinnabar.py"),
    });

    let mut extra_env = Vec::new();
    let (reader, writer) = if internal_python {
        let (reader, writer) = pipe().map_err(|e| format!("Failed to create pipe: {}", e))?;
        let reader = reader.dup_inheritable();
        extra_env.push(("GIT_CINNABAR_BOOTSTRAP_FD", format!("{}", reader)));
        (Some(reader), Some(writer))
    } else {
        (None, None)
    };

    let (wire_fds, wire_thread) = if cmd == PythonCommand::GitRemoteHg {
        let (reader1, writer1) = pipe().map_err(|e| format!("Failed to create pipe: {}", e))?;
        let (reader2, writer2) = pipe().map_err(|e| format!("Failed to create pipe: {}", e))?;
        let reader1 = reader1.dup_inheritable();
        let writer2 = writer2.dup_inheritable();
        extra_env.push(("GIT_CINNABAR_WIRE_FDS", format!("{},{}", reader1, writer2)));
        let thread = spawn(move || {
            connect_main_with(
                &mut logging::LoggingBufReader::new(
                    "helper-wire",
                    log::Level::Debug,
                    BufReader::new(reader2),
                ),
                &mut logging::LoggingWriter::new("helper-wire", log::Level::Debug, writer1),
            )
            .unwrap();
        });
        (Some((reader1, writer2)), Some(thread))
    } else {
        (None, None)
    };

    let (import_fds, import_thread) = {
        let (reader1, writer1) = pipe().map_err(|e| format!("Failed to create pipe: {}", e))?;
        let (reader2, writer2) = pipe().map_err(|e| format!("Failed to create pipe: {}", e))?;
        let reader1 = reader1.dup_inheritable();
        let writer2 = writer2.dup_inheritable();
        extra_env.push((
            "GIT_CINNABAR_IMPORT_FDS",
            format!("{},{}", reader1, writer2),
        ));
        let thread = spawn(move || {
            #[cfg(windows)]
            let writer1 = unsafe {
                ::libc::open_osfhandle(writer1.as_raw_handle() as isize, ::libc::O_RDONLY)
            };
            #[cfg(unix)]
            let writer1 = writer1.as_raw_fd();
            unsafe {
                helper_main(
                    &mut libcinnabar::reader(&mut BufReader::new(reader2)),
                    writer1,
                )
            };
        });
        ((reader1, writer2), thread)
    };

    let (logging_fd, logging_thread) = {
        let (reader, writer) = pipe().map_err(|e| format!("Failed to create pipe: {}", e))?;
        let writer = writer.dup_inheritable();
        extra_env.push(("GIT_CINNABAR_LOG_FD", format!("{}", writer)));
        let thread = spawn(move || {
            let reader = BufReader::new(reader);
            for line in reader.lines() {
                if let Some([level, target, msg]) = line.unwrap().splitn_exact(' ') {
                    if target == "stderr" {
                        eprintln!("{}", msg);
                    } else {
                        let level = match level {
                            "CRITICAL" => log::Level::Error,
                            "ERROR" => log::Level::Error,
                            "WARNING" => log::Level::Warn,
                            "INFO" => log::Level::Info,
                            "DEBUG" => log::Level::Debug,
                            _ => log::Level::Trace,
                        };
                        log!(target: target, level, "{}", msg);
                    }
                }
            }
        });
        (writer, thread)
    };

    let mut child = python
        .arg("-c")
        .arg(bootstrap)
        .args(std::env::args_os())
        .env("GIT_CINNABAR_HELPER", std::env::current_exe().unwrap())
        .envs(extra_env)
        .stdin(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to start python: {}", e))?;
    drop(wire_fds);
    drop(import_fds);
    drop(logging_fd);
    drop(reader);

    let sent_data = if let Some(mut writer) = writer {
        zstd::stream::copy_decode(&mut Cursor::new(cinnabar_py::CINNABAR_PY), &mut writer)
    } else {
        Ok(())
    };
    let status = child.wait().expect("Python command wasn't running?!");
    match status.code() {
        Some(0) => {}
        Some(code) => return Ok(code),
        None => {
            #[cfg(unix)]
            if let Some(signal) = status.signal() {
                return Ok(-signal);
            }
            return Ok(1);
        }
    };
    drop(wire_thread);
    drop(import_thread);
    drop(logging_thread);
    sent_data
        .map(|_| 0)
        .map_err(|e| format!("Failed to communicate with python: {}", e))
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
    init_cinnabar(exe.as_deref().unwrap_or(argv0).as_ptr());
    logging::init(now);

    let ret = match argv0_path.file_stem().and_then(OsStr::to_str) {
        Some("git-cinnabar") => git_cinnabar(),
        Some("git-cinnabar-helper") => {
            helper_main(&mut libcinnabar::reader(&mut stdin().lock()), 1)
        }
        Some("git-remote-hg") => {
            let _v = VersionCheck::new();
            match run_python_command(PythonCommand::GitRemoteHg) {
                Ok(code) => code,
                Err(e) => {
                    error!(target: "root", "{}", e);
                    1
                }
            }
        }
        Some(_) | None => 1,
    };
    done_cinnabar();
    ret
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
    const PREFIX: &str = "GIT_CINNABAR_";
    let mut env_key = String::with_capacity(name.len() + PREFIX.len());
    env_key.push_str(PREFIX);
    env_key.extend(name.chars().map(|c| match c.to_ascii_uppercase() {
        '-' => '_',
        c => c,
    }));
    std::env::var_os(env_key).or_else(|| {
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
        const BUNDLE = 0x10;
        const FILES = 0x20;
        const MEMORY = 0x40;
        const CPU = 0x80;
        const TIME = 0x100;
        const TRACEBACK = 0x200;
        const NO_BUNDLE2 = 0x400;
        const CINNABARCLONE = 0x800;
        const CLONEBUNDLES = 0x1000;
        const UNBUNDLER = 0x2000;
    }
}

static CHECKS: Lazy<Checks> = Lazy::new(|| {
    let mut checks = Checks::VERSION;
    if let Some(config) = get_config("check") {
        for c in config.as_bytes().split(|&b| b == b',') {
            match c {
                b"true" | b"all" => checks = Checks::all(),
                b"helper" => checks.set(Checks::HELPER, true),
                b"manifests" => checks.set(Checks::MANIFESTS, true),
                b"no-version-check" => checks.set(Checks::VERSION, false),
                b"nodeid" => checks.set(Checks::NODEID, true),
                b"bundle" => checks.set(Checks::BUNDLE, true),
                b"files" => checks.set(Checks::FILES, true),
                b"memory" => checks.set(Checks::MEMORY, true),
                b"cpu" => checks.set(Checks::CPU, true),
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
