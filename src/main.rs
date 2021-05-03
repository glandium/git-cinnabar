/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
use std::ffi::{CStr, OsStr, OsString};
use std::fmt;
use std::io::{copy, stdin, stdout, BufRead, BufWriter, Cursor, Write};
use std::os::raw::c_char;
use std::os::raw::c_int;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, FromStr};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;

use bstr::ByteSlice;
use git_version::git_version;
use url::Url;
use which::which;

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
use util::{CStrExt, IteratorExt, OsStrExt, SliceExt};

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
    fn helper_main(wire: c_int) -> c_int;

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

    let notes = resolve_ref(NOTES_REF);

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
            MetadataState::Checked => transaction.update(CHECKED_REF, new, checked, msg)?,

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
        transaction.update(METADATA_REF, new, metadata.as_ref(), msg)?;
        transaction.update(NOTES_REF, &commit.parents()[3], notes.as_ref(), msg)?;
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
            .collect::<Vec<_>>();
        let mut metadata = metadata;
        while let Some(m) = metadata {
            print!("{}", m);
            let matched_labels = labels
                .iter()
                .filter_map(|(name, cid)| (*cid == m).then(|| *name))
                .collect::<Vec<_>>()
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
        get_previous_metadata(&oid)
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
    println!("No metadata to upgrade");
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

#[derive(StructOpt)]
#[structopt(name = "git-cinnabar")]
#[structopt(version=crate_version!())]
#[structopt(long_version=FULL_VERSION)]
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
        #[structopt(help = "Show a list of candidates for rollback")]
        candidates: bool,
        #[structopt(long)]
        #[structopt(conflicts_with = "committish")]
        #[structopt(conflicts_with = "candidates")]
        #[structopt(help = "Rollback to the last successful fsck state")]
        fsck: bool,
        #[structopt(long)]
        #[structopt(conflicts_with = "candidates")]
        #[structopt(
            help = "Force to use the given committish even if it is not in the current metadata's ancestry"
        )]
        force: bool,
        #[structopt(help = "Git sha1/committish of the state to rollback to")]
        #[structopt(parse(from_os_str))]
        committish: Option<OsString>,
    },
    #[structopt(name = "fsck")]
    #[structopt(about = "Check cinnabar metadata consistency")]
    Fsck {
        #[structopt(long)]
        #[structopt(
            help = "Force check, even when metadata was already checked. Also disables incremental fsck"
        )]
        force: bool,
        #[structopt(long)]
        #[structopt(help = "Check more thoroughly")]
        full: bool,
        #[structopt(help = "Specific commit or changeset to check")]
        #[structopt(parse(from_os_str))]
        commit: Vec<OsString>,
    },
    #[structopt(name = "bundle")]
    #[structopt(about = "Create a mercurial bundle")]
    Bundle {
        #[structopt(long)]
        #[structopt(default_value = "2")]
        #[structopt(possible_values = &["1", "2"])]
        #[structopt(help = "Bundle version")]
        version: u8,
        #[structopt(help = "Path of the bundle")]
        #[structopt(parse(from_os_str))]
        path: PathBuf,
        #[structopt(
            help = "Git revision range (see the Specifying Ranges section of gitrevisions(7))"
        )]
        #[structopt(parse(from_os_str))]
        revs: Vec<OsString>,
    },
    #[structopt(name = "unbundle")]
    #[structopt(about = "Apply a mercurial bundle to the repository")]
    Unbundle {
        #[structopt(long)]
        #[structopt(help = "Get clone bundle from given repository")]
        clonebundle: bool,
        #[structopt(help = "Url of the bundle")]
        #[structopt(parse(from_os_str))]
        url: OsString,
    },
    #[structopt(name = "upgrade")]
    #[structopt(about = "Upgrade cinnabar metadata")]
    Upgrade,
}

use CinnabarCommand::*;

fn git_cinnabar() -> i32 {
    let command = match CinnabarCommand::from_args_safe() {
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
        Rollback {
            candidates,
            fsck,
            force,
            committish,
        } => do_rollback(candidates, fsck, force, committish),
        Upgrade => do_upgrade(),
        Bundle { .. } | Unbundle { .. } | Fsck { .. } => {
            return run_python_command(PythonCommand::GitCinnabar);
        }
    };
    match ret {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("{}", msg);
            1
        }
    }
}

#[derive(StructOpt)]
#[structopt(name = "git-cinnabar-helper")]
#[structopt(version=crate_version!())]
#[structopt(long_version=FULL_VERSION)]
#[structopt(setting(AppSettings::AllowInvalidUtf8))]
#[structopt(setting(AppSettings::ArgRequiredElseHelp))]
#[structopt(setting(AppSettings::DeriveDisplayOrder))]
#[structopt(setting(AppSettings::DontCollapseArgsInUsage))]
#[structopt(group = ArgGroup::with_name("mode").multiple(false).required(true))]
struct HelperCommand {
    #[structopt(long)]
    #[structopt(group = "mode")]
    wire: bool,
    #[structopt(long)]
    #[structopt(group = "mode")]
    import: bool,
}

extern "C" {
    static python3: c_int;
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

#[derive(PartialEq)]
enum PythonCommand {
    GitRemoteHg,
    GitCinnabar,
}

fn run_python_command(cmd: PythonCommand) -> c_int {
    let want_python2 = unsafe { python3 == 0 };
    let (loader, python) = if want_python2 {
        (
            include_str!("../bootstrap/loader_py2.py"),
            which("python2.7").or_else(|_| which("python2")),
        )
    } else {
        (include_str!("../bootstrap/loader_py3.py"), which("python3"))
    };
    let python = match python {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "Could not find python {}",
                if want_python2 { "2.7" } else { "3.x" }
            );
            return 1;
        }
    };

    // We aggregate the various parts of a bootstrap code that reads a
    // tarball from stdin, and use the contents of that tarball as a
    // source of python modules, using a custom loader.
    // The tarball itself is included compressed in this binary, and
    // we decompress it before sending.
    let mut bootstrap = String::new();
    bootstrap.push_str(include_str!("../bootstrap/loader_common.py"));
    bootstrap.push_str(loader);
    if std::env::var("GIT_CINNABAR_COVERAGE").is_ok() {
        bootstrap.push_str(include_str!("../bootstrap/coverage.py"));
    }
    bootstrap.push_str(match cmd {
        PythonCommand::GitRemoteHg => include_str!("../bootstrap/git-remote-hg.py"),
        PythonCommand::GitCinnabar => include_str!("../bootstrap/git-cinnabar.py"),
    });
    let mut child = match Command::new(python)
        .arg("-c")
        .arg(bootstrap)
        .args(std::env::args_os())
        .env("GIT_CINNABAR_HELPER", std::env::current_exe().unwrap())
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start python: {}", e);
            return 1;
        }
    };

    let mut child_stdin = child.stdin.as_mut().unwrap();
    let sent_data = (|| -> Result<(), std::io::Error> {
        writeln!(child_stdin, "{}", env!("PYTHON_TAR_SIZE"))?;
        zstd::stream::copy_decode(
            &mut Cursor::new(include_bytes!(env!("PYTHON_TAR"))),
            &mut child_stdin,
        )?;
        if cmd == PythonCommand::GitRemoteHg {
            copy(&mut std::io::stdin().lock(), child_stdin)?;
        }
        Ok(())
    })();
    let status = child.wait().expect("Python command wasn't running?!");
    match status.code() {
        Some(0) => {}
        Some(code) => return code,
        None => {
            #[cfg(unix)]
            if let Some(signal) = status.signal() {
                return -signal;
            }
            return 1;
        }
    };
    match sent_data {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Failed to communicate with python: {}", e);
            1
        }
    }
}

#[no_mangle]
unsafe extern "C" fn cinnabar_main(_argc: c_int, argv: *const *const c_char) -> c_int {
    // We look at argv[0] to choose what behavior to take, but it's not
    // guaranteed to have a full path, while init_cinnabar (really, git-core)
    // needs one, so for that we use current_exe().
    let argv0 = CStr::from_ptr(*argv.as_ref().unwrap());
    let argv0_path = Path::new(argv0.to_osstr());

    // If for some reason current_exe() failed, fallback to argv[0].
    let exe = std::env::current_exe().map(|e| e.as_os_str().to_cstring());
    init_cinnabar(exe.as_deref().unwrap_or(argv0).as_ptr());

    let ret = match argv0_path.file_stem().and_then(|a| a.to_str()) {
        Some("git-cinnabar") => git_cinnabar(),
        Some("git-cinnabar-helper") => {
            let helper = HelperCommand::from_args();
            assert_ne!(helper.wire, helper.import);
            helper_main(if helper.wire { 1 } else { 0 })
        }
        Some("git-remote-hg") => {
            let _v = VersionCheck::new();
            run_python_command(PythonCommand::GitRemoteHg)
        }
        Some(_) | None => 1,
    };
    done_cinnabar();
    ret
}
