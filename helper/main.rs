/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate cstr;

use structopt::clap::{crate_version, AppSettings};
use structopt::StructOpt;

#[macro_use]
pub mod libgit;
mod libc;
mod libcinnabar;
pub mod store;
mod util;

pub(crate) mod hg_bundle;
#[macro_use]
pub mod hg_connect;
pub(crate) mod hg_connect_http;
pub(crate) mod hg_connect_stdio;
pub(crate) mod hg_data;

use std::convert::TryInto;
use std::ffi::CString;
use std::ffi::OsString;
use std::io::{stdout, Write};
use std::iter::repeat;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::str::{self, FromStr};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;

use hg_data::Authorship;
use libcinnabar::{
    ensure_notes, files_meta, generate_manifest, hg_object_id, resolve_hg, AbbrevHgObjectId,
};
use libgit::{
    object_id, repo_get_oid_committish, strbuf, the_repository, BlobId, CommitId, RawBlob,
    RawCommit,
};
use store::{ChangesetExtra, GitChangesetId, GitChangesetMetadata, HgChangesetId};
use util::OsStrExt;

const HELPER_HASH: &str = env!("HELPER_HASH");

#[no_mangle]
unsafe extern "C" fn get_helper_hash(buf: *mut strbuf) {
    let buf = buf.as_mut().unwrap();
    buf.extend_from_slice(HELPER_HASH.as_bytes());
}

extern "C" {
    pub fn helper_main(argc: c_int, argv: *const *const c_char) -> c_int;

    #[cfg(windows)]
    pub fn wmain(argc: c_int, argv: *const *const u16) -> c_int;

    pub fn init_cinnabar(argv0: *const c_char);
    pub fn init_cinnabar_2();
    pub fn done_cinnabar();
}

#[cfg(unix)]
pub fn prepare_arg(arg: OsString) -> CString {
    CString::new(arg.as_bytes()).unwrap()
}

#[cfg(windows)]
pub fn prepare_arg(arg: OsString) -> Vec<u16> {
    let mut arg = arg.encode_wide().collect::<Vec<_>>();
    arg.push(0);
    arg
}

fn do_hg2git(abbrev: Option<usize>, sha1s: Vec<AbbrevHgObjectId>) -> Result<(), String> {
    let abbrev = abbrev.unwrap_or(40);
    for sha1 in &sha1s {
        let hex = format!("{}", sha1.to_git().unwrap_or_else(object_id::null));
        println!("{}", &hex[..abbrev]);
    }
    Ok(())
}

fn do_git2hg(abbrev: Option<usize>, committish: Vec<OsString>) -> Result<(), String> {
    let abbrev = abbrev.unwrap_or(40);
    unsafe {
        for c in &committish {
            let mut oid = GitChangesetId::null();
            let c = CString::new(c.as_bytes()).unwrap();
            let note = if repo_get_oid_committish(the_repository, c.as_ptr(), &mut **oid) == 0 {
                oid.to_hg()
            } else {
                None
            };
            let hex = format!("{}", note.unwrap_or_else(HgChangesetId::null));
            println!("{}", &hex[..abbrev]);
        }
    }
    Ok(())
}

enum HgObjectType {
    Changeset,
    Manifest,
    File,
}

fn do_data(rev: AbbrevHgObjectId, typ: HgObjectType) -> Result<(), String> {
    let git_obj = rev
        .to_git()
        .ok_or_else(|| format!("Unknown revision: {}", rev))?;
    match typ {
        HgObjectType::Changeset => unsafe {
            let commit_id = CommitId::from(git_obj);
            let commit = RawCommit::read(&commit_id).unwrap();
            let commit = commit.parse().unwrap();
            let (mut hg_author, hg_timestamp, hg_utcoffset) =
                Authorship::from_git_bytes(commit.author()).to_hg_parts();
            let hg_committer = if commit.author() != commit.committer() {
                Some(Authorship::from_git_bytes(commit.committer()).to_hg_bytes())
            } else {
                None
            };
            let hg_committer = hg_committer.as_ref();

            let metadata = GitChangesetMetadata::read(&GitChangesetId::from(commit_id)).unwrap();
            let metadata = metadata.parse().unwrap();
            if let Some(author) = metadata.author() {
                hg_author = author.to_owned();
            }
            let mut extra = metadata.extra();
            if let Some(hg_committer) = hg_committer {
                extra
                    .get_or_insert_with(ChangesetExtra::new)
                    .set(b"committer", &hg_committer);
            };
            let mut changeset = Vec::new();
            writeln!(changeset, "{}", metadata.manifest_id()).unwrap();
            changeset.extend_from_slice(&hg_author);
            changeset.push(b'\n');
            changeset.extend_from_slice(&hg_timestamp);
            changeset.push(b' ');
            changeset.extend_from_slice(&hg_utcoffset);
            if let Some(extra) = extra {
                changeset.push(b' ');
                extra.dump_into(&mut changeset);
            }
            let mut files = metadata.files().collect::<Vec<_>>();
            //TODO: probably don't actually need sorting.
            files.sort();
            for f in &files {
                changeset.push(b'\n');
                changeset.extend_from_slice(f);
            }
            changeset.extend_from_slice(b"\n\n");
            changeset.extend_from_slice(commit.body());

            if let Some(patch) = metadata.patch() {
                let mut patched = patch.apply(&changeset).unwrap();
                mem::swap(&mut changeset, &mut patched);
            }

            // Adjust for `handle_changeset_conflict`.
            // TODO: when creating the git2hg metadata moves to Rust, we can
            // create a patch instead, which would be handled above instead of
            // manually here.
            let node = metadata.changeset_id();
            let mut changeset = &changeset[..];
            while let [adjusted @ .., b'\0'] = changeset {
                let mut hash = hg_object_id::create();
                let mut parents = commit
                    .parents()
                    .iter()
                    .map(|p| GitChangesetId::from(p.clone()).to_hg().unwrap())
                    .collect::<Vec<_>>();
                parents.sort();
                for p in parents.iter().chain(repeat(&HgChangesetId::null())).take(2) {
                    hash.input(p.as_bytes());
                }
                hash.input(&changeset);
                if hash.result() == **node {
                    break;
                }
                changeset = adjusted;
            }
            //TODO: adjustement, per end of ChangesetPatcher.apply
            stdout().write_all(&changeset).map_err(|e| e.to_string())?;
        },
        HgObjectType::Manifest => {
            let buf = unsafe { generate_manifest(&git_obj).as_ref().unwrap() };
            stdout()
                .write_all(buf.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        HgObjectType::File => {
            let mut stdout = stdout();
            unsafe {
                ensure_notes(&mut files_meta);
                resolve_hg(&mut files_meta, rev.as_hg_object_id(), rev.len())
                    .as_ref()
                    .map(|oid| BlobId::from(oid.clone()))
                    .and_then(|oid| RawBlob::read(&oid))
                    .map(|o| {
                        stdout.write_all(b"\x01\n")?;
                        stdout.write_all(o.as_bytes())?;
                        stdout.write_all(b"\x01\n")
                    })
                    .transpose()
                    .and_then(|_| {
                        stdout.write_all(
                            RawBlob::read(&BlobId::from(git_obj.clone()))
                                .unwrap()
                                .as_bytes(),
                        )
                    })
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
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
    #[structopt(about = "Dump the contents of a mercurial revision")]
    Data {
        #[structopt(short = "c")]
        #[structopt(help = "Open changelog")]
        changeset: bool,
        #[structopt(short = "m")]
        #[structopt(conflicts_with = "changeset")]
        #[structopt(help = "Open manifest")]
        manifest: bool,
        #[structopt(required = true)]
        #[structopt(help = "Revision")]
        rev: AbbrevHgObjectId,
    },
    #[structopt(name = "hg2git")]
    #[structopt(about = "Convert mercurial sha1 to corresponding git sha1")]
    Hg2Git {
        #[structopt(long)]
        #[structopt(require_equals = true)]
        #[structopt(max_values = 1)]
        #[structopt(help = "Show a partial prefix")]
        abbrev: Option<Vec<AbbrevSize>>,
        #[structopt(required = true)]
        #[structopt(help = "Mercurial sha1")]
        sha1: Vec<AbbrevHgObjectId>,
    },
    #[structopt(name = "git2hg")]
    #[structopt(about = "Convert git sha1 to corresponding mercurial sha1")]
    Git2Hg {
        #[structopt(long)]
        #[structopt(require_equals = true)]
        #[structopt(max_values = 1)]
        #[structopt(help = "Show a partial prefix")]
        abbrev: Option<Vec<AbbrevSize>>,
        #[structopt(required = true)]
        #[structopt(help = "Git sha1/committish")]
        #[structopt(parse(from_os_str))]
        committish: Vec<OsString>,
    },
}

use CinnabarCommand::*;

fn git_cinnabar(argv0: *const c_char) -> i32 {
    let command = match CinnabarCommand::from_iter_safe(
        Some(OsString::from("git-cinnabar"))
            .into_iter()
            .chain(std::env::args_os().skip(2)),
    ) {
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
            changeset,
            manifest,
            rev,
        } => do_data(
            rev,
            match (changeset, manifest) {
                (true, false) => HgObjectType::Changeset,
                (false, true) => HgObjectType::Manifest,
                (false, false) => HgObjectType::File,
                (true, true) => unreachable!(),
            },
        ),
        Hg2Git { abbrev, sha1 } => {
            do_hg2git(abbrev.map(|v| v.get(0).map(|a| a.0).unwrap_or(12)), sha1)
        }
        Git2Hg { abbrev, committish } => do_git2hg(
            abbrev.map(|v| v.get(0).map(|a| a.0).unwrap_or(12)),
            committish,
        ),
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
    if let Some("--command") = std::env::args().skip(1).next().as_ref().map(|s| &**s) {
        git_cinnabar(*argv.as_ref().unwrap())
    } else {
        helper_main(argc, argv)
    }
}
