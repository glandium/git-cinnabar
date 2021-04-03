/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![cfg_attr(feature_bool_to_option, feature(bool_to_option))]
#![cfg_attr(feature_min_const_generics, feature(min_const_generics))]
#![cfg_attr(feature_slice_strip, feature(slice_strip))]
#![allow(clippy::borrowed_box)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::new_without_default)]
#![allow(dead_code)]

#[macro_use]
extern crate derivative;
#[macro_use]
extern crate all_asserts;

use structopt::clap::{crate_version, AppSettings, ArgGroup};
use structopt::StructOpt;

#[macro_use]
mod util;
#[macro_use]
mod oid;
#[macro_use]
pub mod libgit;
mod libc;
mod libcinnabar;
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
use std::convert::TryInto;
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{stdin, stdout, BufRead, BufWriter, Write};
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::path::Path;
use std::process::Command;
use std::str::{self, FromStr};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;

use bstr::ByteSlice;
use url::Url;

use libcinnabar::{files_meta, hg2git};
use libgit::{
    for_each_ref_in, for_each_remote, get_oid_committish, lookup_replace_commit, remote,
    resolve_ref, strbuf, BlobId, CommitId, RawCommit, RefTransaction,
};
use oid::{Abbrev, GitObjectId, HgObjectId, ObjectId};
use store::{
    GitChangesetId, GitFileId, GitFileMetadataId, GitManifestId, HgChangesetId, HgFileId,
    HgManifestId, RawHgChangeset, RawHgFile, RawHgManifest, BROKEN_REF, CHECKED_REF, METADATA_REF,
    NOTES_REF, REFS_PREFIX,
};
use util::{IteratorExt, OsStrExt, SliceExt};

const HELPER_HASH: &str = env!("HELPER_HASH");

#[no_mangle]
unsafe extern "C" fn get_helper_hash(buf: *mut strbuf) {
    let buf = buf.as_mut().unwrap();
    buf.extend_from_slice(HELPER_HASH.as_bytes());
}

extern "C" {
    fn helper_main(argc: c_int, argv: *const *const c_char) -> c_int;

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
    let mut arg = arg.encode_wide().collect::<Vec<_>>();
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
        .map(|oid| lookup_replace_commit(oid))
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
        let (scheme, port, remainder) = remainder
            .strip_prefix(b":")
            .map(|remainder| {
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
                    if port.iter().all(|b| b.is_ascii_digit()) {
                        [port, b"https"]
                    } else {
                        [b"", port]
                    }
                });
                (scheme, port, remainder)
            })
            .unwrap_or_else(|| (b"https", b"", remainder));
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

        Url::parse(&url.to_str().ok()?).ok()
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
    let url = remote::get(&remote).get_url();
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
        let mut result = strbuf::new();
        conn.lookup(&mut result, rev);
        let [success, data] = result
            .as_bytes()
            .trim_end()
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

fn rollback_to(new_metadata: Option<&CommitId>, msg: &str) -> Result<Option<CommitId>, String> {
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
    for (r, oid) in refs.iter() {
        match (new_metadata, r) {
            (Some(_), _) if r == METADATA_REF => metadata = Some(oid.clone()),
            (Some(_), _) if r == CHECKED_REF => checked = Some(oid),
            (Some(_), _) if r == BROKEN_REF => broken = Some(oid),
            _ => {
                transaction.delete(r, Some(oid), msg)?;
            }
        }
    }

    let broken = broken;
    let checked = checked;
    let metadata = metadata;

    if let Some(new) = new_metadata {
        #[derive(Debug, PartialEq)]
        enum MetadataState {
            Unknown,
            Broken,
            Checked,
        }

        let mut state = match metadata {
            Some(ref m) if Some(m) == broken => MetadataState::Broken,
            Some(ref m) if Some(m) == checked => MetadataState::Checked,
            _ => MetadataState::Unknown,
        };

        let mut m = metadata.clone();
        let found = std::iter::from_fn(move || {
            m = m.as_ref().and_then(get_previous_metadata);
            m.clone()
        })
        .try_find_(|m| -> Result<_, String> {
            if Some(m) == broken {
                state = MetadataState::Broken;
            } else if Some(m) == checked {
                state = MetadataState::Checked;
            } else if state == MetadataState::Broken {
                // We don't know whether ancestors of broken metadata are broken.
                state = MetadataState::Unknown;
            }
            Ok(m == new)
        })?
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
            MetadataState::Checked => transaction.update(CHECKED_REF, new, checked, msg)?,

            MetadataState::Broken => transaction.update(BROKEN_REF, new, broken, msg)?,
            MetadataState::Unknown => {}
        }

        transaction.update(METADATA_REF, new, metadata.as_ref(), msg)?;
    }
    if let Some(notes) = resolve_ref(NOTES_REF) {
        transaction.delete(NOTES_REF, Some(&notes), msg)?;
    }
    transaction.commit()?;
    Ok(metadata)
}

fn do_reclone() -> Result<(), String> {
    // TODO: Avoid resetting at all, possibly leaving the repo with no metadata
    // if this is interrupted somehow.
    let mut previous_metadata = rollback_to(None, "reclone")?;

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

fn do_rollback(fsck: bool, committish: Option<OsString>) -> Result<(), String> {
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
    } else if let Some(ref oid) = resolve_ref(METADATA_REF) {
        get_previous_metadata(&oid)
    } else {
        return Err("Nothing to rollback.".to_string());
    };
    rollback_to(wanted_metadata.as_ref(), "rollback").map(|_| ())
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

#[derive(StructOpt)]
#[structopt(name = "git-cinnabar")]
#[structopt(version=crate_version!())]
#[structopt(long_version=concat!(crate_version!(), "\nhelper-hash: ", env!("HELPER_HASH")))]
#[structopt(setting(AppSettings::AllowInvalidUtf8))]
#[structopt(setting(AppSettings::ArgRequiredElseHelp))]
#[structopt(setting(AppSettings::DeriveDisplayOrder))]
#[structopt(setting(AppSettings::DontCollapseArgsInUsage))]
#[structopt(setting(AppSettings::SubcommandRequired))]
#[structopt(setting(AppSettings::VersionlessSubcommands))]
enum CinnabarCommand {
    #[structopt(name = "data")]
    #[structopt(group = ArgGroup::with_name("input").multiple(false).required(true))]
    #[structopt(about = "Dump the contents of a mercurial revision")]
    Data {
        #[structopt(short = "c")]
        #[structopt(group = "input")]
        #[structopt(help = "Open changelog")]
        changeset: Option<Abbrev<HgChangesetId>>,
        #[structopt(short = "m")]
        #[structopt(group = "input")]
        #[structopt(help = "Open manifest")]
        manifest: Option<Abbrev<HgManifestId>>,
        #[structopt(group = "input")]
        #[structopt(help = "Open file")]
        file: Option<Abbrev<HgFileId>>,
    },
    #[structopt(name = "hg2git")]
    #[structopt(group = ArgGroup::with_name("input").multiple(true).required(true))]
    #[structopt(about = "Convert mercurial sha1 to corresponding git sha1")]
    Hg2Git {
        #[structopt(long)]
        #[structopt(require_equals = true)]
        #[structopt(max_values = 1)]
        #[structopt(help = "Show a partial prefix")]
        abbrev: Option<Vec<AbbrevSize>>,
        #[structopt(group = "input")]
        #[structopt(help = "Mercurial sha1")]
        sha1: Vec<Abbrev<HgChangesetId>>,
        #[structopt(long)]
        #[structopt(group = "input")]
        #[structopt(help = "Read sha1s on stdin")]
        batch: bool,
    },
    #[structopt(name = "git2hg")]
    #[structopt(group = ArgGroup::with_name("input").multiple(true).required(true))]
    #[structopt(about = "Convert git sha1 to corresponding mercurial sha1")]
    Git2Hg {
        #[structopt(long)]
        #[structopt(require_equals = true)]
        #[structopt(max_values = 1)]
        #[structopt(help = "Show a partial prefix")]
        abbrev: Option<Vec<AbbrevSize>>,
        #[structopt(group = "input")]
        #[structopt(help = "Git sha1/committish")]
        #[structopt(parse(from_os_str))]
        committish: Vec<OsString>,
        #[structopt(long)]
        #[structopt(group = "input")]
        #[structopt(help = "Read sha1/committish on stdin")]
        batch: bool,
    },
    #[structopt(name = "fetch")]
    #[structopt(about = "Fetch a changeset from a mercurial remote")]
    Fetch {
        #[structopt(help = "Mercurial remote name or url")]
        #[structopt(parse(from_os_str))]
        remote: OsString,
        #[structopt(required = true)]
        #[structopt(help = "Mercurial changeset to fetch")]
        #[structopt(parse(from_os_str))]
        revs: Vec<OsString>,
    },
    #[structopt(name = "reclone")]
    #[structopt(about = "Reclone all mercurial remotes")]
    Reclone,
    #[structopt(name = "rollback")]
    #[structopt(about = "Rollback cinnabar metadata state")]
    Rollback {
        #[structopt(long)]
        #[structopt(conflicts_with = "committish")]
        #[structopt(help = "Rollback to the last successful fsck state")]
        fsck: bool,
        #[structopt(help = "Git sha1/committish of the state to rollback to")]
        #[structopt(parse(from_os_str))]
        committish: Option<OsString>,
    },
}

use CinnabarCommand::*;

fn git_cinnabar(argv0: *const c_char, args: &mut dyn Iterator<Item = OsString>) -> i32 {
    let command = match CinnabarCommand::from_iter_safe(args) {
        Ok(c) => c,
        Err(e) if e.use_stderr() => {
            eprintln!("{}", e.message);
            return if e.message.contains("SUBCOMMAND") {
                128
            } else {
                1
            };
        }
        Err(e) => {
            println!("{}", e.message);
            return 0;
        }
    };
    unsafe {
        init_cinnabar(argv0);
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
            abbrev.map(|v| v.get(0).map(|a| a.0).unwrap_or(12)),
            sha1.iter(),
            batch,
            do_one_hg2git,
        ),
        Git2Hg {
            abbrev,
            committish,
            batch,
        } => do_conversion_cmd(
            abbrev.map(|v| v.get(0).map(|a| a.0).unwrap_or(12)),
            committish.iter(),
            batch,
            do_one_git2hg,
        ),
        Fetch { remote, revs } => do_fetch(&remote, &revs),
        Reclone => do_reclone(),
        Rollback { fsck, committish } => do_rollback(fsck, committish),
    };
    unsafe {
        done_cinnabar();
    }
    match ret {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("{}", msg);
            1
        }
    }
}

pub fn main() {
    let args: Vec<_> = std::env::args_os().map(prepare_arg).collect();
    let argc = args.len();
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

#[no_mangle]
unsafe extern "C" fn cinnabar_main(argc: c_int, argv: *const *const c_char) -> c_int {
    if let Some("git-cinnabar") = (|| {
        std::env::current_exe()
            .ok()?
            .file_stem()?
            .to_os_string()
            .into_string()
            .ok()
    })()
    .as_deref()
    {
        git_cinnabar(*argv.as_ref().unwrap(), &mut std::env::args_os())
    } else if let Some("--command") = std::env::args().nth(1).as_deref() {
        let mut args = Some(OsString::from("git-cinnabar"))
            .into_iter()
            .chain(std::env::args_os().skip(2));
        git_cinnabar(*argv.as_ref().unwrap(), &mut args)
    } else {
        helper_main(argc, argv)
    }
}
