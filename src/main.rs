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

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::{CStr, OsStr, OsString};
use std::io::{stdin, stdout, BufRead, BufReader, BufWriter, Cursor, Write};
use std::iter::repeat;
use std::os::raw::c_int;
use std::os::raw::{c_char, c_void};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, from_utf8, FromStr};
use std::sync::Mutex;
use std::thread;
use std::{cmp, fmt};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::time::Instant;

use bitflags::bitflags;
use bstr::{BStr, ByteSlice};
use git_version::git_version;
use once_cell::sync::Lazy;
use os_pipe::pipe;
use url::Url;
use which::which;

use crate::libc::FdFile;
use crate::store::{do_set_replace, reset_manifest_heads, set_changeset_heads};
use crate::util::{FromBytes, ToBoxed};
use graft::{do_graft, graft_finish, init_graft};
use hg_connect::{connect_main_with, get_clonebundle_url, get_connection, get_store_bundle};
use libcinnabar::{cinnabar_notes_tree, files_meta, git2hg, hg2git, hg_object_id};
use libgit::{
    config_get_value, diff_tree, for_each_ref_in, for_each_remote, get_oid_committish,
    lookup_replace_commit, ls_tree, metadata_oid, object_id, remote, resolve_ref, rev_list, strbuf,
    string_list, BlobId, CommitId, DiffTreeItem, RawCommit, RefTransaction,
};
use oid::{Abbrev, GitObjectId, HgObjectId, ObjectId};
use progress::{do_progress, Progress};
use store::{
    do_check_files, do_create, do_heads, do_raw_changeset, do_set_, do_store_changeset,
    has_metadata, merge_metadata, store_git_blob, ChangesetHeads, GeneratedGitChangesetMetadata,
    GitChangesetId, GitFileId, GitFileMetadataId, GitManifestId, HgChangesetId, HgFileId,
    HgManifestId, RawGitChangesetMetadata, RawHgChangeset, RawHgFile, RawHgManifest, BROKEN_REF,
    CHECKED_REF, METADATA_REF, NOTES_REF, REFS_PREFIX, REPLACE_REFS_PREFIX,
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

#[allow(improper_ctypes)]
extern "C" {
    fn string_list_new() -> *mut string_list;
    fn string_list_init_nodup(l: *mut string_list);
    fn string_list_clear(l: *mut string_list, free_util: c_int);
    fn string_list_split_in_place(
        l: *mut string_list,
        s: *mut c_char,
        delim: c_int,
        maxsplit: c_int,
    );

    fn do_get_note(t: *mut cinnabar_notes_tree, l: *const string_list, out: c_int);
    fn do_hg2git(l: *const string_list, out: c_int);
    fn do_manifest(l: *const string_list, out: c_int);
    fn do_check_manifest(l: *const string_list, out: c_int);
    fn do_cat_file(l: *const string_list, out: c_int);
    fn do_ls_tree(l: *const string_list, out: c_int);
    fn do_rev_list(l: *const string_list, out: c_int);
    fn do_diff_tree(l: *const string_list, out: c_int);
    fn do_create_git_tree(l: *const string_list, out: c_int);
    fn do_reload(l: *const string_list, out: c_int);
    fn do_cleanup(rollback: c_int);
    fn do_set(l: *const string_list);
    fn do_store(in_: *mut libcinnabar::reader, out: c_int, l: *const string_list);

    fn do_store_metadata(result: *mut object_id);

    #[cfg(windows)]
    fn wmain(argc: c_int, argv: *const *const u16) -> c_int;

    fn init_cinnabar(argv0: *const c_char);
    fn init_cinnabar_2();
    fn done_cinnabar();
}

static REF_UPDATES: Lazy<Mutex<HashMap<Box<BStr>, CommitId>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[no_mangle]
unsafe extern "C" fn dump_ref_updates() {
    let mut transaction = RefTransaction::new().unwrap();
    for (refname, oid) in REF_UPDATES.lock().unwrap().drain() {
        let refname = OsStr::from_bytes(&*refname);
        if oid == CommitId::null() {
            transaction.delete(refname, None, "update").unwrap();
        } else {
            transaction.update(refname, &oid, None, "update").unwrap();
        }
    }
    transaction.commit().unwrap();
}

fn do_reset(args: &[&[u8]]) {
    assert_eq!(args.len(), 2);
    let refname = args[0];
    let oid = CommitId::from_bytes(args[1]).unwrap();
    REF_UPDATES
        .lock()
        .unwrap()
        .insert(refname.as_bstr().to_boxed(), oid);
}

static INIT_CINNABAR_2: Lazy<()> = Lazy::new(|| unsafe { init_cinnabar_2() });

static HELPER_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
            Some(&new_metadata),
            MetadataFlags::FORCE | MetadataFlags::KEEP_REFS,
            "update",
        )
        .unwrap();
        if args.contains(&&b"refs/cinnabar/checked"[..]) {
            let mut transaction = RefTransaction::new().unwrap();
            transaction
                .update("refs/cinnabar/checked", &new_metadata, None, "fsck")
                .unwrap();
            transaction.commit().unwrap();
        }
        let args = string_list_new();
        do_reload(args, -1);
        ::libc::free(args as *mut c_void);
    }
    do_check_files()
}

fn helper_main(input: &mut dyn BufRead, out: c_int) -> c_int {
    let args = unsafe { string_list_new() };
    let mut line = Vec::new();
    loop {
        line.truncate(0);
        input.read_until(b'\n', &mut line).unwrap();
        if line.ends_with(b"\n") {
            line.pop();
        }
        if line.is_empty() {
            break;
        }
        Lazy::force(&INIT_CINNABAR_2);
        line.push(b'\0');
        let mut i = line.splitn_mut(2, |&b| b == b' ' || b == b'\0');
        let command = i.next().unwrap();
        let mut nul = [b'\0'];
        let args_ = i.next().filter(|a| !a.is_empty()).unwrap_or(&mut nul);
        let _locked = HELPER_LOCK.lock().unwrap();
        if let b"graft" | b"progress" | b"store-changeset" | b"create" | b"raw-changeset"
        | b"reset" | b"done-and-check" | b"merge-metadata" | b"heads" | b"done"
        | b"rollback" = &*command
        {
            let args = match args_.split_last().unwrap().1 {
                b"" => Vec::new(),
                args => args.split(|&b| b == b' ').collect::<Vec<_>>(),
            };
            let mut out = unsafe { FdFile::from_raw_fd(out) };
            match &*command {
                b"progress" => do_progress(out, &args),
                b"graft" => do_graft(&args),
                b"store-changeset" => do_store_changeset(input, out, &args),
                b"raw-changeset" => do_raw_changeset(out, &args),
                b"create" => do_create(input, out, &args),
                b"reset" => do_reset(&args),
                b"heads" => do_heads(out, &args),
                b"done" => unsafe {
                    do_cleanup(0);
                    writeln!(out, "ok").unwrap();
                },
                b"rollback" => unsafe {
                    do_cleanup(1);
                    writeln!(out, "ok").unwrap();
                },
                b"done-and-check" => writeln!(
                    out,
                    "{}",
                    if do_done_and_check(&args) { "ok" } else { "ko" }
                )
                .unwrap(),
                b"merge-metadata" => {
                    assert!(args.len() >= 2 && args.len() <= 3);
                    if merge_metadata(
                        Url::parse(args[0].to_str().unwrap()).unwrap(),
                        Url::parse(args[1].to_str().unwrap()).unwrap(),
                        args.get(2).copied(),
                    ) {
                        unsafe {
                            let args = string_list_new();
                            do_reload(args, -1);
                            ::libc::free(args as *mut c_void);
                        }
                        writeln!(out, "ok").unwrap();
                    } else {
                        writeln!(out, "ko").unwrap();
                    }
                }
                _ => unreachable!(),
            }
            continue;
        }

        unsafe {
            string_list_init_nodup(args);
            if args_ != b"\0" {
                string_list_split_in_place(
                    args,
                    args_.as_bytes_mut().as_mut_ptr() as *mut _,
                    b' ' as i32,
                    -1,
                );
            }
            match &*command {
                b"git2hg" => do_get_note(&mut git2hg as *mut _ as *mut _, args, out),
                b"file-meta" => do_get_note(&mut files_meta as *mut _ as *mut _, args, out),
                b"hg2git" => do_hg2git(args, out),
                b"manifest" => do_manifest(args, out),
                b"check-manifest" => do_check_manifest(args, out),
                b"cat-file" => do_cat_file(args, out),
                b"ls-tree" => do_ls_tree(args, out),
                b"rev-list" => do_rev_list(args, out),
                b"diff-tree" => do_diff_tree(args, out),
                b"reload" => do_reload(args, out),
                b"set" => do_set(args),
                b"store" => do_store(&mut libcinnabar::reader(input), out, args),
                _ => die!("Unknown command: {}", command.as_bstr()),
            }
            string_list_clear(args, 0);
        }
    }
    unsafe {
        ::libc::free(args as *mut c_void);
    }
    0
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
        .and_then(|oid| GitChangesetId::from_unchecked(oid.into_owned()).to_hg());
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

bitflags! {
    pub struct MetadataFlags: i32 {
        const FORCE = 0x1;
        const KEEP_REFS = 0x2;
    }
}

fn set_metadata_to(
    new_metadata: Option<&CommitId>,
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
        let found = flags
            .contains(MetadataFlags::FORCE)
            .then(|| {
                state = MetadataState::Unknown;
                new.clone()
            })
            .or_else(|| {
                std::iter::from_fn(move || {
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
                &CommitId::from_unchecked(item.oid),
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
    let flags = if force {
        MetadataFlags::FORCE
    } else {
        MetadataFlags::empty()
    };
    set_metadata_to(wanted_metadata.as_ref(), flags, "rollback").map(|_| ())
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

fn do_unbundle(clonebundle: bool, mut url: Url) -> Result<(), String> {
    if !["http", "https", "file"].contains(&url.scheme()) {
        return Err(format!("{} urls are not supported.", url.scheme()));
    }
    let graft = get_config("graft")
        .map(|v| {
            v.into_string()
                .and_then(|v| bool::from_str(&v).map_err(|_| v.into()))
        })
        .transpose()
        // TODO: This should report the environment variable is that's what was used.
        .map_err(|e| format!("Invalid value for cinnabar.graft: {}", e.to_string_lossy()))?
        .unwrap_or(false);
    if graft {
        init_graft();
    }
    if clonebundle {
        let mut conn = get_connection(&url, 0).unwrap();
        if conn.get_capability(b"clonebundles").is_none() {
            return Err("Repository does not support clonebundles")?;
        }
        url = get_clonebundle_url(&mut *conn).ok_or("Repository didn't provide a clonebundle")?;
        eprintln!("Getting clone bundle from {}", url);
    }
    let mut conn = get_connection(&url, 0).unwrap();

    get_store_bundle(&mut *conn, &[], &[]).map_err(|e| String::from_utf8_lossy(&e).into_owned())?;

    do_done_and_check(&[])
        .then(|| ())
        .ok_or_else(|| "Fatal error".to_string())
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
                 presumable clean.\n\
                 Try `--force` if you want to check anyway."
            );
            return Ok(0);
        }
        checked_cid
    };
    let commit = RawCommit::read(&metadata_cid).unwrap();
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
    let [changesets_cid, manifests_cid] = <&[_; 2]>::try_from(&commit.parents()[..2]).unwrap();
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
        return do_fsck_full(commits, &metadata_cid, changesets_cid, manifests_cid);
    }

    let [checked_changesets_cid, checked_manifests_cid] =
        checked_cid.as_ref().map_or([None, None], |c| {
            let commit = RawCommit::read(c).unwrap();
            let commit = commit.parse().unwrap();
            let mut parents = commit.parents().iter();
            [parents.next().cloned(), parents.next().cloned()]
        });
    let raw_checked = array_init::from_iter::<_, _, 2>(
        [&checked_changesets_cid, &checked_manifests_cid]
            .iter()
            .map(|c| c.as_ref().and_then(RawCommit::read)),
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

    for (c, (changeset_node, branch)) in commit
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
        if &*git_cid != c {
            let parents = parents.get_or_insert_with(|| BTreeSet::from_iter(commit.parents()));
            if !parents.contains(&*git_cid) {
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
        let metadata = if let Some(metadata) = RawGitChangesetMetadata::read(&git_cid) {
            metadata
        } else {
            report(format!("Missing git2hg metadata for git commit {}", c));
            continue;
        };
        let metadata = metadata.parse().unwrap();
        if metadata.changeset_id() != changeset_node {
            let heads_map = heads_set
                .get_or_insert_with(|| heads.iter().map(|(a, _)| a).collect::<BTreeSet<_>>());
            if !heads_map.contains(metadata.changeset_id()) {
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
            .map(|p| {
                GitChangesetId::from_unchecked(lookup_replace_commit(p).into_owned())
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
        if *branch != changeset_branch {
            report(format!(
                "Inconsistent metadata:\n\
                 \x20 Head metadata says changeset {} is in branch {}\n\
                 \x20 but git2hg metadata says it is in branch {}",
                changeset_node, branch, changeset_branch
            ));
            continue;
        }
        manifest_nodes.push(changeset.manifest().clone());
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
        OsStr::from_bytes(b"--topo-order"),
        OsStr::from_bytes(b"--reverse"),
        OsStr::from_bytes(b"--full-history"),
        OsStr::from_bytes(manifests_arg.as_bytes()),
    ];
    if let Some(a) = &checked_manifests_arg {
        args.push(OsStr::from_bytes(a.as_bytes()));
    }
    for mid in rev_list(&args).progress(|n| format!("Loading {n} manifests")) {
        let commit = RawCommit::read(&mid).unwrap();
        let commit = commit.parse().unwrap();
        manifest_queue.push((mid.clone(), commit.parents().to_boxed()));
        for p in commit.parents() {
            if !depths.contains_key(p) {
                roots.insert(p.clone());
            }
            depths.insert(
                mid.clone(),
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
        .filter(|p| match &checked_manifests {
            Some(checked) => !checked.parents().contains(p),
            None => true,
        })
        .sorted_by_key(|p| depths.get(*p).copied().unwrap_or(0))
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
        if mid != &*git_mid {
            report(format!(
                "Inconsistent metadata:\n\
                 \x20 Manifest DAG contains {} for manifest {}\n
                 \x20 but hg2git metadata says the manifest maps to {}",
                mid, hg_manifest_id, git_mid
            ));
        }
        if unsafe { check_manifest(&object_id::from((*git_mid).clone()), std::ptr::null_mut()) }
            != 1
        {
            report(format!("Sha1 mismatch for manifest {}", git_mid));
        }
        let files = if let Some(previous) = previous {
            diff_tree(previous, mid)
                .filter_map(|item| match item {
                    DiffTreeItem::Added { path, oid, .. } => Some((path, (*oid).clone())),
                    DiffTreeItem::Modified {
                        path,
                        from_oid,
                        to_oid,
                        ..
                    } if from_oid != to_oid => Some((path, (*to_oid).clone())),
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
        if let Some(previous) = &previous {
            diff_tree(previous, &r)
                .filter_map(|item| match item {
                    DiffTreeItem::Added { path, oid, .. } => Some((path, (*oid).clone())),
                    DiffTreeItem::Modified {
                        path,
                        from_oid,
                        to_oid,
                        ..
                    } if from_oid != to_oid => Some((path, (*to_oid).clone())),
                    _ => None,
                })
                .for_each(|item| {
                    all_interesting.remove(&item);
                });
        } else {
            // Yes, this is ridiculous.
            let commit = RawCommit::read(&r).unwrap();
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
        for (path, hg_file, hg_fileparents) in get_changes(&mid, &parents, true) {
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
                all_interesting.remove(&(path.clone(), p.clone()));
            }
            if let Some((path, hg_file)) = all_interesting.take(&(path, hg_file)) {
                if unsafe {
                    check_file(
                        // TODO: This is gross.
                        &hg_object_id::from(
                            HgObjectId::from_bytes(format!("{}", hg_file).as_bytes()).unwrap(),
                        ),
                        &hg_fileparents.get(0).map_or_else(
                            || hg_object_id::from(HgObjectId::null()),
                            |p| {
                                hg_object_id::from(
                                    HgObjectId::from_bytes(format!("{}", p).as_bytes()).unwrap(),
                                )
                            },
                        ),
                        &hg_fileparents.get(1).map_or_else(
                            || hg_object_id::from(HgObjectId::null()),
                            |p| {
                                hg_object_id::from(
                                    HgObjectId::from_bytes(format!("{}", p).as_bytes()).unwrap(),
                                )
                            },
                        ),
                    )
                } != 1
                {
                    report(format!(
                        "Sha1 mismatch for file {}\n\
                         \x20 revision {}",
                        manifest_path(&path),
                        hg_file
                    ));
                    let print_parents = hg_fileparents
                        .iter()
                        .filter(|p| **p != GitObjectId::null())
                        .join(" ");
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
             https://github.com/glandium/git-cinnabar/issues"
        );
        return Ok(1);
    }

    check_replace(&metadata_cid);

    if broken.get() {
        eprintln!(
            "\rYour git-cinnabar repository appears to be corrupted.\n\
             Please open an issue, with the information above, on\n\
             https://github.com/glandium/git-cinnabar/issues"
        );
        let mut transaction = RefTransaction::new().unwrap();
        transaction
            .update("refs/cinnabar/broken", &metadata_cid, None, "fsck")
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

    if do_done_and_check(&[b"refs/cinnabar/checked"]) {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn do_fsck_full(
    commits: Vec<OsString>,
    metadata_cid: &CommitId,
    changesets_cid: &CommitId,
    manifests_cid: &CommitId,
) -> Result<i32, String> {
    let full_fsck = commits.is_empty();
    let commit_queue = if full_fsck {
        let changesets_arg = format!("{}^@", changesets_cid);

        Box::new(rev_list(&[
            OsStr::new("--topo-order"),
            OsStr::new("--full-history"),
            OsStr::new("--reverse"),
            OsStr::new(&changesets_arg),
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
                        return Ok((*git_cs).clone());
                    }
                    let cs = HgChangesetId::from_bytes(c.as_bytes()).map_err(|_| {
                        format!("Invalid commit or changeset: {}", c.to_string_lossy())
                    })?;

                    if let Some(git_cs) = cs.to_git() {
                        Ok((*git_cs).clone())
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
    let empty_file = HgFileId::from_str("b80de5d138758541c5f05265ad144ab9fa86d1db").unwrap();

    for cid in commit_queue.progress(|n| format!("Checking {n} changesets")) {
        let cid = lookup_replace_commit(&cid);
        let cid = GitChangesetId::from_unchecked(cid.into_owned());
        let metadata = if let Some(metadata) = RawGitChangesetMetadata::read(&cid) {
            metadata
        } else {
            report(format!("Missing note for git commit: {}", cid));
            continue;
        };
        seen_git2hg.insert(cid.clone());

        let commit = RawCommit::read(&cid).unwrap();
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
        seen_changesets.insert(changeset_id.clone());
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
            .map(|p| {
                GitChangesetId::from_unchecked(lookup_replace_commit(p).into_owned())
                    .to_hg()
                    .unwrap()
            })
            .collect_vec();
        hg_parents
            .iter()
            .cloned()
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

        let branch = metadata
            .extra()
            .and_then(|e| e.get(b"branch"))
            .unwrap_or(b"default");
        changeset_heads.add(
            changeset_id,
            &hg_parents.iter().collect_vec(),
            branch.as_bstr(),
        );

        let fresh_metadata =
            GeneratedGitChangesetMetadata::generate(&commit, changeset_id, &raw_changeset).unwrap();
        if fresh_metadata != metadata {
            fix(format!("Adjusted changeset metadata for {}", changeset_id));
            unsafe {
                do_set_(
                    cstr::cstr!("changeset").as_ptr(),
                    &hg_object_id::from(changeset_id.clone()),
                    &object_id::from(CommitId::null()),
                );
                do_set_(
                    cstr::cstr!("changeset").as_ptr(),
                    &hg_object_id::from(changeset_id.clone()),
                    &object_id::from((*cid).clone()),
                );
                let mut metadata_id = object_id::default();
                let mut buf = strbuf::new();
                buf.extend_from_slice(&fresh_metadata.serialize());
                store_git_blob(&buf, &mut metadata_id);
                do_set_(
                    cstr::cstr!("changeset-metadata").as_ptr(),
                    &hg_object_id::from(changeset_id.clone()),
                    &object_id::from(CommitId::null()),
                );
                do_set_(
                    cstr::cstr!("changeset-metadata").as_ptr(),
                    &hg_object_id::from(changeset_id.clone()),
                    &metadata_id,
                );
            }
        }

        let changeset = raw_changeset.parse().unwrap();
        let manifest_id = changeset.manifest();
        if !seen_manifests.insert(manifest_id.clone()) {
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
            let manifest_cid = object_id::from((*manifest_cid).clone());
            check_manifest(&manifest_cid, std::ptr::null_mut()) == 1
        };
        if !checked {
            report(format!("Sha1 mismatch for manifest {}", manifest_id));
        }

        let hg_manifest_parents = hg_parents
            .iter()
            .map(|p| {
                let metadata = RawGitChangesetMetadata::read(&p.to_git().unwrap()).unwrap();
                let metadata = metadata.parse().unwrap();
                metadata.manifest_id().clone()
            })
            .collect_vec();
        let git_manifest_parents = hg_manifest_parents
            .iter()
            .filter_map(|p| p.to_git().map(|p| (*p).clone()))
            .sorted()
            .collect_vec();

        let manifest_commit = RawCommit::read(&manifest_cid).unwrap();
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
            manifest_heads.insert((*manifest_cid).clone());
            for p in manifest_commit.parents() {
                manifest_heads.remove(p);
            }
        }

        // TODO: check that manifest content matches changeset content.
        for (path, hg_file, hg_fileparents) in
            get_changes(&manifest_cid, &git_manifest_parents, false)
        {
            // TODO: This is gross.
            let hg_file = HgFileId::from_bytes(format!("{}", hg_file).as_bytes()).unwrap();
            if hg_file == HgFileId::null()
                || hg_file == empty_file
                || !seen_files.insert(hg_file.clone())
            {
                continue;
            }
            if unsafe {
                // TODO: add FileFindParents logging.
                check_file(
                    &hg_object_id::from(hg_file.clone()),
                    &hg_fileparents.get(0).map_or_else(
                        || hg_object_id::from(HgObjectId::null()),
                        |p| {
                            hg_object_id::from(
                                HgObjectId::from_bytes(format!("{}", p).as_bytes()).unwrap(),
                            )
                        },
                    ),
                    &hg_fileparents.get(1).map_or_else(
                        || hg_object_id::from(HgObjectId::null()),
                        |p| {
                            hg_object_id::from(
                                HgObjectId::from_bytes(format!("{}", p).as_bytes()).unwrap(),
                            )
                        },
                    ),
                )
            } != 1
            {
                report(format!(
                    "Sha1 mismatch for file {}\n\
                     \x20 revision {}",
                    manifest_path(&path),
                    hg_file
                ));
                let print_parents = hg_fileparents
                    .iter()
                    .filter(|p| **p != GitObjectId::null())
                    .join(" ");
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
            .cloned()
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
                .chain(iter_manifests(&manifest_heads, &store_manifest_heads))
                .map(OsString::from)
                .collect_vec();
            for m in rev_list(&all_args.iter().map(|s| &**s).collect_vec()) {
                fix(format!("Missing manifest commit in manifest branch: {}", m));
            }

            let all_args = args
                .into_iter()
                .map(str::to_string)
                .chain(iter_manifests(&store_manifest_heads, &manifest_heads))
                .map(OsString::from)
                .collect_vec();
            for m in rev_list(&all_args.iter().map(|s| &**s).collect_vec()) {
                fix(format!(
                    "Removing manifest commit {} with no corresponding changeset",
                    m
                ));
            }

            for h in store_manifest_heads.difference(&manifest_heads) {
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
                    let m = RawCommit::read(&h).unwrap();
                    let m = m.parse().unwrap();
                    let m = HgManifestId::from_bytes(m.body()).unwrap();
                    do_set_(
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
            if seen_changesets.contains(&HgChangesetId::from_unchecked(h.clone()))
                || seen_manifests.contains(&HgManifestId::from_unchecked(h.clone()))
                || seen_files.contains(&HgFileId::from_unchecked(h.clone()))
            {
                return;
            }
            fix(format!("Removing dangling metadata for {}", h));
            // Theoretically, we should figure out if they are files, manifests
            // or changesets and set the right variable accordingly, but in
            // practice, it makes no difference. Reevaluate when refactoring,
            // though.
            unsafe {
                do_set_(
                    cstr::cstr!("file").as_ptr(),
                    &hg_object_id::from(h.clone()),
                    &object_id::default(),
                );
                do_set_(
                    cstr::cstr!("file-meta").as_ptr(),
                    &hg_object_id::from(h.clone()),
                    &object_id::default(),
                );
            }
        });
        unsafe { &mut git2hg }.for_each(|g, _| {
            // TODO: this is gross.
            let cid = GitChangesetId::from_unchecked(CommitId::from_unchecked(g.clone()));
            if seen_git2hg.contains(&cid) {
                return;
            }
            fix(format!("Removing dangling note for commit {}", g));
            let metadata = RawGitChangesetMetadata::read(&cid).unwrap();
            let metadata = metadata.parse().unwrap();
            unsafe {
                do_set_(
                    cstr::cstr!("changeset-metadata").as_ptr(),
                    &hg_object_id::from(metadata.changeset_id().clone()),
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
            .update("refs/cinnabar/broken", metadata_cid, None, "fsck")
            .unwrap();
        transaction.commit().unwrap();
        return Ok(1);
    }

    if do_done_and_check(&[b"refs/cinnabar/checked"]) {
        if fixed.get() {
            Ok(2)
        } else {
            Ok(0)
        }
    } else {
        Ok(1)
    }
}

fn check_replace(metadata_cid: &CommitId) {
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

fn manifest_path(p: &[u8]) -> Box<BStr> {
    p.strip_prefix(b"_")
        .unwrap()
        .replace("/_", "/")
        .as_bstr()
        .to_boxed()
}

fn get_changes(
    cid: &CommitId,
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
        manifest_diff(&parents[0], cid)
            .map(|(path, node, parent)| (path, node, [parent].to_boxed()))
            .collect_vec()
            .into_iter()
    } else {
        manifest_diff2(&parents[0], &parents[1], cid, all)
            .map(|(path, node, parents)| (path, node, parents.to_boxed()))
            .collect_vec()
            .into_iter()
    }
}

fn manifest_diff(
    a: &CommitId,
    b: &CommitId,
) -> impl Iterator<Item = (Box<[u8]>, GitObjectId, GitObjectId)> {
    diff_tree(a, b).filter_map(|item| match item {
        DiffTreeItem::Added { path, oid, .. } => Some((path, (*oid).clone(), GitObjectId::null())),
        DiffTreeItem::Modified {
            path,
            from_oid,
            to_oid,
            ..
        } if from_oid != to_oid => Some((path, (*to_oid).clone(), (*from_oid).clone())),
        DiffTreeItem::Deleted { path, oid, .. } => {
            Some((path, GitObjectId::null(), (*oid).clone()))
        }
        _ => None,
    })
}

fn manifest_diff2(
    a: &CommitId,
    b: &CommitId,
    c: &CommitId,
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
                result.push((path.clone(), oid.clone(), [parent_oid.clone(), oid.clone()]));
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
                result.push((path.clone(), oid.clone(), [oid.clone(), parent_oid.clone()]));
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
            result.push((
                path.clone(),
                oid1.clone(),
                [parent_oid1.clone(), parent_oid2.clone()],
            ));

            item1 = iter1.next();
            item2 = iter2.next();
        }
    }
    result.into_iter()
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
        #[clap(conflicts_with = "commit")]
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
        #[clap(allow_invalid_utf8 = true)]
        url: Url,
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
    Lazy::force(&INIT_CINNABAR_2);
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
        Unbundle { clonebundle, url } => do_unbundle(clonebundle, url),
        Fsck {
            force,
            full,
            commit,
        } => match do_fsck(force, full, commit) {
            Ok(code) => return code,
            Err(e) => Err(e),
        },
        Bundle { .. } => match run_python_command(PythonCommand::GitCinnabar) {
            Ok(code) => return code,
            Err(e) => Err(e),
        },
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
        let thread = thread::Builder::new()
            .name("helper-wire".into())
            .spawn(move || {
                connect_main_with(
                    &mut logging::LoggingBufReader::new(
                        "helper-wire",
                        log::Level::Debug,
                        BufReader::new(reader2),
                    ),
                    &mut logging::LoggingWriter::new("helper-wire", log::Level::Debug, writer1),
                )
                .unwrap();
            })
            .unwrap();
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
        let thread = thread::Builder::new()
            .name("helper-import".into())
            .spawn(move || {
                #[cfg(windows)]
                let writer1 = unsafe {
                    ::libc::open_osfhandle(writer1.as_raw_handle() as isize, ::libc::O_RDONLY)
                };
                #[cfg(unix)]
                let writer1 = writer1.as_raw_fd();
                helper_main(&mut BufReader::new(reader2), writer1);
            })
            .unwrap();
        ((reader1, writer2), thread)
    };

    let (logging_fd, logging_thread) = {
        let (reader, writer) = pipe().map_err(|e| format!("Failed to create pipe: {}", e))?;
        let writer = writer.dup_inheritable();
        extra_env.push(("GIT_CINNABAR_LOG_FD", format!("{}", writer)));
        let thread = thread::Builder::new()
            .name("py-logger".into())
            .spawn(move || {
                let reader = BufReader::new(reader);
                for line in reader.lines() {
                    if let Some([level, target, msg]) = line.unwrap().splitn_exact(' ') {
                        let msg = msg.replace('\0', "\n");
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
            })
            .unwrap();
        (writer, thread)
    };

    let mut child = python
        .arg("-c")
        .arg(bootstrap)
        .args(std::env::args_os())
        .env("GIT_CINNABAR", std::env::current_exe().unwrap())
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
        Some("git-cinnabar") => git_cinnabar(),
        Some("git-cinnabar-import") => helper_main(&mut stdin().lock(), 1),
        Some("git-cinnabar-wire") => {
            match connect_main_with(&mut stdin().lock(), &mut stdout().lock()) {
                Ok(()) => 0,
                Err(e) => {
                    error!(target: "root", "{}", e);
                    1
                }
            }
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
                b"bundle" => checks.set(Checks::BUNDLE, true),
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

#[no_mangle]
unsafe extern "C" fn do_panic(err: *const u8, len: usize) {
    panic!("{}", std::slice::from_raw_parts(err, len).as_bstr());
}
