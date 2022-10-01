/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bstr::ByteSlice;
use clap::crate_version;
use semver::Version;
use shared_child::SharedChild;

use crate::libgit::config_get_value;
use crate::util::{ReadExt, SliceExt};
use crate::{check_enabled, Checks, FULL_VERSION};

const ALL_TAG_REFS: &str = "refs/tags/*";
const CARGO_PKG_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(version_check_branch)]
const VERSION_CHECK_REF: &str = concat!("refs/heads/", env!("VERSION_CHECK_BRANCH"));
#[cfg(not(version_check_branch))]
const VERSION_CHECK_REF: &str = ALL_TAG_REFS;
const VERSION_CHECK_CONFIG: &str = "cinnabar.version-check";

pub struct VersionCheck {
    child: Option<Arc<SharedChild>>,
    thread: Option<thread::JoinHandle<Option<String>>>,
    when: SystemTime,
}

impl VersionCheck {
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

        Some(version_check_from_repo(now))
    }

    fn take_result(&mut self) -> Option<String> {
        self.child.take().map(|c| c.kill().ok());
        self.thread.take().and_then(|t| t.join().ok()).flatten()
    }
}

fn version_check_from_repo(when: SystemTime) -> VersionCheck {
    let mut cmd = Command::new("git");
    cmd.args(["ls-remote", CARGO_PKG_REPOSITORY, VERSION_CHECK_REF]);
    let build_commit = FULL_VERSION
        .strip_suffix("-modified")
        .unwrap_or(FULL_VERSION)
        .strip_prefix(concat!(crate_version!(), "-"))
        .unwrap_or("");

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let child = SharedChild::spawn(&mut cmd).ok().map(Arc::new);
    let thread = child.as_ref().map(move |child| {
        let child = child.clone();
        thread::Builder::new()
            .name("version-check".into())
            .spawn(move || {
                let output = child.take_stdout().unwrap().read_all().ok()?;
                child.wait().ok()?;
                let mut new_version = None;
                let current_version = Version::parse(CARGO_PKG_VERSION).unwrap();
                for [sha1, r] in output
                    .lines()
                    .filter_map(|line| line.splitn_exact(u8::is_ascii_whitespace))
                {
                    if VERSION_CHECK_REF == ALL_TAG_REFS {
                        if let Some(version) = r
                            .strip_prefix(b"refs/tags/")
                            .and_then(|tag| std::str::from_utf8(tag).ok())
                            .and_then(parse_version)
                            .filter(|v| v > new_version.as_ref().unwrap_or(&current_version))
                        {
                            new_version = Some(version);
                        }
                    } else if r == VERSION_CHECK_REF.as_bytes() && sha1 != build_commit.as_bytes() {
                        return std::str::from_utf8(sha1).map(String::from).ok();
                    }
                }
                new_version.as_ref().map(Version::to_string)
            })
            .unwrap()
    });
    VersionCheck {
        child,
        thread,
        when,
    }
}

impl Drop for VersionCheck {
    fn drop(&mut self) {
        if let Some(version) = self.take_result() {
            if VERSION_CHECK_REF == ALL_TAG_REFS {
                warn!(
                    target: "root",
                    "New git-cinnabar version available: {} (current version: {})",
                    version, CARGO_PKG_VERSION
                );
            } else {
                warn!(
                    target: "root",
                    "The {} branch of git-cinnabar was updated. Please update your copy.",
                    VERSION_CHECK_REF.strip_prefix("refs/heads/").unwrap()
                );
                warn!(target: "root", "You can switch to the `release` branch if you want to reduce these update notifications.");
            }
        }

        if let Ok(timestamp) = self.when.duration_since(UNIX_EPOCH) {
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
