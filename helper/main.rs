/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate cstr;

use structopt::clap::{crate_version, AppSettings};
use structopt::StructOpt;

#[macro_use]
mod libgit;
mod libc;
mod libcinnabar;
mod util;

pub(crate) mod hg_bundle;
#[macro_use]
pub mod hg_connect;
pub(crate) mod hg_connect_http;
pub(crate) mod hg_connect_stdio;

use std::convert::TryInto;
use std::ffi::OsString;
use std::os::raw::c_int;
use std::str::FromStr;

#[cfg(unix)]
use std::ffi::CString;
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use libcinnabar::AbbrevHgObjectId;
use libgit::{object_id, strbuf};

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

fn do_hg2git(abbrev: Option<usize>, sha1s: Vec<AbbrevHgObjectId>) -> i32 {
    let abbrev = abbrev.unwrap_or(40);
    for sha1 in &sha1s {
        let hex = format!("{}", sha1.to_git().unwrap_or_else(object_id::null));
        println!("{}", &hex[..abbrev]);
    }
    0
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
            return 1;
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
        Hg2Git { abbrev, sha1 } => {
            do_hg2git(abbrev.map(|v| v.get(0).map(|a| a.0).unwrap_or(12)), sha1)
        }
    };
    unsafe {
        done_cinnabar();
    }
    ret
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
