/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::process::{Command, Stdio};
#[cfg(feature = "version-check")]
use std::str::FromStr;
#[cfg(feature = "version-check")]
use std::sync::Arc;
#[cfg(feature = "version-check")]
use std::thread;
#[cfg(feature = "version-check")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bstr::ByteSlice;
use clap::crate_version;
use semver::Version;
use shared_child::SharedChild;

use crate::git::CommitId;
#[cfg(feature = "version-check")]
use crate::libgit::config_get_value;
use crate::util::{FromBytes, ReadExt, SliceExt};
use crate::FULL_VERSION;
#[cfg(feature = "version-check")]
use crate::{check_enabled, Checks};

const ALL_TAG_REFS: &str = "refs/tags/*";
const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(version_check_branch)]
const VERSION_CHECK_REF: &str = env!("VERSION_CHECK_BRANCH");
#[cfg(not(version_check_branch))]
const VERSION_CHECK_REF: &str = ALL_TAG_REFS;
#[cfg(feature = "version-check")]
const VERSION_CHECK_CONFIG: &str = "cinnabar.version-check";

pub enum VersionRequest<'a> {
    Tagged,
    Branch(&'a str),
}

impl<'a> From<&'a str> for VersionRequest<'a> {
    fn from(s: &'a str) -> Self {
        match s {
            "release" => VersionRequest::Tagged,
            s => VersionRequest::Branch(s),
        }
    }
}

impl<'a> Default for VersionRequest<'a> {
    fn default() -> Self {
        if VERSION_CHECK_REF == ALL_TAG_REFS {
            VersionRequest::Tagged
        } else {
            VersionRequest::Branch(VERSION_CHECK_REF)
        }
    }
}

#[allow(unused)]
pub enum VersionInfo {
    Tagged(Version, CommitId),
    Commit(CommitId),
}

#[cfg(feature = "version-check")]
pub struct VersionChecker {
    child: Option<Arc<SharedChild>>,
    thread: Option<thread::JoinHandle<Result<Option<VersionInfo>, ()>>>,
    when: Option<SystemTime>,
}

#[cfg(feature = "version-check")]
impl VersionChecker {
    pub fn new() -> Option<Self> {
        if !check_enabled(Checks::VERSION) {
            return None;
        }
        let now = SystemTime::now();
        // Don't run the check if the last one was less than 24 hours ago.
        if config_get_value(VERSION_CHECK_CONFIG)
            .and_then(|x| x.into_string().ok())
            .and_then(|x| u64::from_str(&x).ok())
            .and_then(|x| x.checked_add(86400))
            .and_then(|x| UNIX_EPOCH.checked_add(Duration::from_secs(x)))
            .filter(|x| x >= &now)
            .is_some()
        {
            return None;
        }

        let child = create_child(VersionRequest::default()).map(Arc::new);
        let thread = child.clone().and_then(|child| {
            thread::Builder::new()
                .name("version-check".into())
                .spawn(move || get_version(&child))
                .ok()
        });
        Some(VersionChecker {
            child,
            thread,
            when: Some(now),
        })
    }

    fn take_result(&mut self) -> Option<VersionInfo> {
        self.child.take().map(|c| c.kill().ok());
        self.thread
            .take()
            .and_then(|t| t.join().ok())
            .and_then(|result| {
                result.unwrap_or_else(|()| {
                    self.when.take();
                    None
                })
            })
    }
}

#[cfg(feature = "version-check")]
impl Drop for VersionChecker {
    fn drop(&mut self) {
        match self.take_result() {
            Some(VersionInfo::Tagged(version, _)) if VERSION_CHECK_REF == ALL_TAG_REFS => {
                warn!(
                    target: "root",
                    "New git-cinnabar version available: {} (current version: {})",
                    version, CARGO_PKG_VERSION
                );
                if cfg!(feature = "self-update") {
                    warn!(
                        target: "root",
                        "You may run `git cinnabar self-update` to update."
                    );
                }
            }
            Some(VersionInfo::Commit(_)) if VERSION_CHECK_REF != ALL_TAG_REFS => {
                warn!(
                    target: "root",
                    "The {} branch of git-cinnabar was updated. {}",
                    VERSION_CHECK_REF,
                    if cfg!(feature = "self-update") {
                        "You may run `git cinnabar self-update` to update."
                    } else {
                        "Please update your copy."
                    }
                );
                if cfg!(feature = "self-update") {
                    warn!(target: "root", "You can use `git cinnabar self-update --branch release` if you want to reduce these update notifications.");
                } else {
                    warn!(target: "root", "You can switch to the `release` branch if you want to reduce these update notifications.");
                }
            }
            _ => {}
        }

        if let Some(timestamp) = self
            .when
            .take()
            .and_then(|when| when.duration_since(UNIX_EPOCH).ok())
        {
            Command::new("git")
                .args([
                    "config",
                    "--global",
                    VERSION_CHECK_CONFIG,
                    &format!("{}", timestamp.as_secs()),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .ok();
        }
    }
}

#[cfg(feature = "self-update")]
pub fn check_new_version(req: VersionRequest) -> Option<VersionInfo> {
    create_child(req)
        .as_ref()
        .and_then(|child| get_version(child).ok().flatten())
}

fn create_child(req: VersionRequest) -> Option<SharedChild> {
    let mut cmd = Command::new("git");
    cmd.args(["ls-remote", crate::CARGO_PKG_REPOSITORY]);
    match req {
        VersionRequest::Tagged => cmd.arg(ALL_TAG_REFS),
        VersionRequest::Branch(branch) => cmd.arg(&format!("refs/heads/{branch}")),
    };
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    SharedChild::spawn(&mut cmd).ok()
}

fn get_version(child: &SharedChild) -> Result<Option<VersionInfo>, ()> {
    let build_commit = FULL_VERSION
        .strip_suffix("-modified")
        .unwrap_or(FULL_VERSION)
        .strip_prefix(concat!(crate_version!(), "-"))
        .unwrap_or("");
    let output = child.take_stdout().unwrap().read_all().map_err(|_| ());
    child.wait().map_err(|_| ())?;
    let output = output?;
    if output.is_empty() {
        return Err(());
    }
    let current_version = Version::parse(CARGO_PKG_VERSION).unwrap();
    let mut newest_version = None;
    for [sha1, r] in output
        .lines()
        .filter_map(|line| line.splitn_exact(u8::is_ascii_whitespace))
    {
        let cid = if let Ok(cid) = CommitId::from_bytes(sha1) {
            cid
        } else {
            continue;
        };
        if let Some(version) = r
            .strip_prefix(b"refs/tags/")
            .and_then(|tag| std::str::from_utf8(tag).ok())
            .and_then(parse_version)
        {
            if version > current_version
                && newest_version
                    .as_ref()
                    .map_or(true, |(n_v, _)| &version > n_v)
            {
                newest_version = Some((version, cid));
            }
        } else if sha1 != build_commit.as_bytes() {
            return Ok(Some(VersionInfo::Commit(cid)));
        }
    }
    if let Some((v, cid)) = newest_version {
        Ok(Some(VersionInfo::Tagged(v, cid)))
    } else {
        Ok(None)
    }
}

fn parse_version(v: &str) -> Option<Version> {
    Version::parse(v).ok().or_else(|| {
        // If the version didn't parse, try again by separating
        // x.y.z from everything that follows, and try parsing
        // again with a dash in between.
        v.find(|c: char| !c.is_ascii_digit() && c != '.')
            .map(|pos| {
                let (digits, rest) = v.split_at(pos);
                format!("{}-{}", digits, rest)
            })
            .as_deref()
            .and_then(|v| Version::parse(v).ok())
    })
}
