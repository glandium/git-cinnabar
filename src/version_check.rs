/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ops::Deref;
use std::process::{Command, Stdio};
use std::str::FromStr;
#[cfg(feature = "version-check")]
use std::sync::Arc;
#[cfg(feature = "version-check")]
use std::thread;
#[cfg(feature = "version-check")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bstr::ByteSlice;
use itertools::Itertools;
use shared_child::SharedChild;

use crate::git::CommitId;
#[cfg(feature = "version-check")]
use crate::util::DurationExt;
use crate::util::{FromBytes, OsStrExt, ReadExt, SliceExt};
use crate::version::BuildBranch::*;
use crate::version::{Version, BUILD_BRANCH, BUILD_COMMIT, SHORT_VERSION};
#[cfg(feature = "version-check")]
use crate::{check_enabled, get_config, Checks};

const ALL_TAG_REFS: &str = "refs/tags/*";
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

impl Default for VersionRequest<'_> {
    fn default() -> Self {
        if *BUILD_BRANCH == Release {
            VersionRequest::Tagged
        } else {
            VersionRequest::Branch(BUILD_BRANCH.as_str())
        }
    }
}

struct VersionRequestChild<'a> {
    child: SharedChild,
    request: VersionRequest<'a>,
}

impl<'a> VersionRequestChild<'a> {
    fn new(request: VersionRequest<'a>) -> Option<VersionRequestChild<'a>> {
        let mut cmd = Command::new("git");
        cmd.args(["ls-remote", crate::CARGO_PKG_REPOSITORY]);
        match request {
            VersionRequest::Tagged => cmd.arg(ALL_TAG_REFS),
            VersionRequest::Branch(branch) => cmd.arg(format!("refs/heads/{branch}")),
        };
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        debug!(target: "version-check", "Running git {}", cmd.get_args().map(|arg| arg.as_bytes().as_bstr()).join(" "));

        SharedChild::spawn(&mut cmd)
            .ok()
            .map(|child| VersionRequestChild { child, request })
    }

    fn fold<B, F: FnMut(B, VersionInfo) -> B>(&self, init: B, f: F) -> Result<B, ()> {
        let output = self.child.take_stdout().unwrap().read_all().map_err(|_| ());
        self.child.wait().map_err(|_| ())?;
        let output = output?;
        if output.is_empty() {
            return Err(());
        }
        Ok(output
            .lines()
            .filter_map(|line| {
                let [sha1, r] = line.splitn_exact(u8::is_ascii_whitespace)?;
                let cid = CommitId::from_bytes(sha1).ok()?;
                debug!(target: "version-check", "Found {}@{}", r.as_bstr(), cid);
                if matches!(self.request, VersionRequest::Tagged) {
                    std::str::from_utf8(r)
                        .ok()
                        .and_then(|tag| tag.strip_prefix("refs/tags/"))
                        .and_then(|tag| Version::parse(tag).ok())
                        .map(|v| VersionInfo::Tagged(v, cid))
                } else {
                    Some(VersionInfo::Commit(cid))
                }
            })
            .fold(init, f))
    }
}

impl Deref for VersionRequestChild<'_> {
    type Target = SharedChild;
    fn deref(&self) -> &SharedChild {
        &self.child
    }
}

#[allow(unused)]
#[derive(Clone)]
pub enum VersionInfo {
    Tagged(Version, CommitId),
    Commit(CommitId),
}

#[cfg(feature = "version-check")]
pub struct VersionChecker {
    child: Option<Arc<VersionRequestChild<'static>>>,
    thread: Option<thread::JoinHandle<Result<Option<VersionInfo>, ()>>>,
    when: Option<SystemTime>,
    show_current: bool,
}

#[cfg(feature = "version-check")]
impl VersionChecker {
    fn new_inner(force_now: bool, show_current: bool) -> Option<Self> {
        if !check_enabled(Checks::VERSION) {
            debug!(target: "version-check", "Version check is disabled");
            return None;
        }
        let now = SystemTime::now();
        // Don't run the check if the last one was less than 24 hours ago.
        let last_check_too_recent = get_config("version-check")
            .and_then(|x| x.into_string().ok())
            .and_then(|x| u64::from_str(&x).ok())
            .and_then(|x| UNIX_EPOCH.checked_add(Duration::from_secs(x)))
            .and_then(|x| {
                debug!(
                    target: "version-check",
                    "Last version check was {}.",
                    now.duration_since(x).map_or_else(
                        |_| "... some time in the future".to_string(),
                        |x| format!("{} ago", x.fuzzy_display_more()),
                    ),
                );
                x.checked_add(Duration::from_secs(86400))
            })
            .filter(|x| x >= &now)
            .is_some();
        if last_check_too_recent && !force_now {
            return None;
        }

        let child = VersionRequestChild::new(VersionRequest::default()).map(Arc::new);
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
            show_current,
        })
    }

    pub fn new() -> Option<Self> {
        Self::new_inner(false, true)
    }

    pub fn for_dashdash_version() -> Option<Self> {
        Self::new_inner(true, false)
    }

    pub fn wait(&mut self, timeout: Duration) {
        if let Some(child) = self.child.take() {
            let now = Instant::now();
            // Poor man's polling.
            while now.elapsed() < timeout {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            debug!(target: "version-check", "wait timeout {}", timeout.fuzzy_display());
            self.child = Some(child);
        }
    }

    fn take_result(&mut self) -> Option<VersionInfo> {
        self.child.take().map(|c| c.kill().ok());
        self.thread
            .take()
            .and_then(|t| t.join().ok())
            .and_then(|result| {
                result.unwrap_or_else(|()| {
                    if let Some(elapsed) = self.when.take().and_then(|when| when.elapsed().ok()) {
                        debug!(target: "version-check", "No result in {}", elapsed.fuzzy_display());
                    }
                    None
                })
            })
    }
}

#[cfg(feature = "version-check")]
impl Drop for VersionChecker {
    fn drop(&mut self) {
        match self.take_result() {
            Some(VersionInfo::Tagged(version, _)) if *BUILD_BRANCH == Release => {
                if self.show_current {
                    warn!(
                        target: "root",
                        "New git-cinnabar version available: {} (current version: {})",
                        version, *SHORT_VERSION
                    );
                } else {
                    warn!(
                        target: "root",
                        "New git-cinnabar version available: {}",
                        version,
                    );
                }
                if cfg!(feature = "self-update") {
                    warn!(
                        target: "root",
                        "You may run `git cinnabar self-update` to update."
                    );
                }
            }
            Some(VersionInfo::Commit(_)) if *BUILD_BRANCH != Release => {
                warn!(
                    target: "root",
                    "The {} branch of git-cinnabar was updated. {}",
                    BUILD_BRANCH.as_str(),
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
    VersionRequestChild::new(req)
        .as_ref()
        .and_then(|child| get_version(child).ok().flatten())
}

#[cfg(feature = "self-update")]
pub fn find_version(what: VersionInfo) -> Option<VersionInfo> {
    VersionRequestChild::new(VersionRequest::Tagged)
        .as_ref()
        .and_then(|child| {
            child
                .fold(None, |result, info| match &info {
                    VersionInfo::Tagged(v, c) => match &what {
                        VersionInfo::Tagged(version, _) if v == version => Some(info),
                        VersionInfo::Commit(cid) if c == cid => Some(info),
                        _ => result,
                    },
                    _ => unreachable!(),
                })
                .ok()
        })
        .flatten()
}

fn get_version(child: &VersionRequestChild) -> Result<Option<VersionInfo>, ()> {
    let current_version = Version::parse(&SHORT_VERSION).unwrap();
    let build_commit = CommitId::from_str(&BUILD_COMMIT).ok();
    let result = child.fold(None, |result, info| match &info {
        VersionInfo::Commit(cid) => build_commit.is_some_and(|c| &c != cid).then_some(info),
        VersionInfo::Tagged(version, _) if version <= &current_version => result,
        VersionInfo::Tagged(version, _) => match result {
            Some(VersionInfo::Tagged(ref result_ver, _)) if result_ver < version => Some(info),
            None => Some(info),
            _ => result,
        },
    })?;
    match &result {
        Some(VersionInfo::Tagged(v, _)) => {
            debug!(target: "version-check", "Newest version found: {}", v);
        }
        Some(VersionInfo::Commit(_)) => {
            debug!(target: "version-check", "Current version ({}) is different", *BUILD_COMMIT);
        }
        None => {
            debug!(target: "version-check", "No version is newer than current ({})", current_version);
        }
    }
    Ok(result)
}
