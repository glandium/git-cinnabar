/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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

use std::convert::TryInto;
use std::ffi::CString;
use std::ffi::OsString;
use std::fmt;
use std::io::{stdin, stdout, BufRead, BufWriter, Write};
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::str::{self, FromStr};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as WinOsStrExt;

use libcinnabar::{files_meta, hg2git};
use libgit::{get_oid_committish, strbuf, BlobId, CommitId};
use oid::{Abbrev, GitObjectId, ObjectId};
use store::{
    GitChangesetId, GitFileId, GitFileMetadataId, GitManifestId, HgChangesetId, HgFileId,
    HgManifestId, RawHgChangeset, RawHgFile, RawHgManifest,
};
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

fn do_one_hg2git(sha1: &Abbrev<HgChangesetId>) -> Result<String, String> {
    Ok(format!("{}", unsafe {
        hg2git
            .get_note_abbrev(sha1)
            .unwrap_or_else(GitObjectId::null)
    }))
}

fn do_one_git2hg(committish: &OsString) -> Result<String, String> {
    let note = get_oid_committish(committish.as_bytes())
        .and_then(|oid| unsafe { GitChangesetId::from(oid).to_hg() });
    Ok(format!("{}", note.unwrap_or_else(HgChangesetId::null)))
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
    F: Fn(&T) -> Result<String, String>,
{
    let f = &f;
    let out = stdout();
    let mut out = BufWriter::new(out.lock());
    do_conversion(abbrev, input, f, &mut out)?;
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
                    f(&t)
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
        let changeset =
            RawHgChangeset::read(&GitChangesetId::from(CommitId::from(commit_id))).unwrap();
        stdout().write_all(&changeset).map_err(|e| e.to_string())
    }
}

fn do_data_manifest(rev: Abbrev<HgManifestId>) -> Result<(), String> {
    unsafe {
        let commit_id = hg2git
            .get_note_abbrev(&rev)
            .ok_or_else(|| format!("Unknown manifest id: {}", rev))?;
        let manifest =
            RawHgManifest::read(&GitManifestId::from(CommitId::from(commit_id))).unwrap();
        stdout().write_all(&manifest).map_err(|e| e.to_string())
    }
}

fn do_data_file(rev: Abbrev<HgFileId>) -> Result<(), String> {
    unsafe {
        let mut stdout = stdout();
        let blob_id = hg2git
            .get_note_abbrev(&rev)
            .ok_or_else(|| format!("Unknown file id: {}", rev))?;
        let file_id = GitFileId::from(BlobId::from(blob_id));
        let metadata_id = files_meta
            .get_note_abbrev(&rev)
            .map(|oid| GitFileMetadataId::from(BlobId::from(oid)));
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
