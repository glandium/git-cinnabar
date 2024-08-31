/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use clap::crate_version;
use concat_const::concat;
use git_version::git_version;

pub const SHORT_VERSION: &str = crate_version!();
const GIT_VERSION: &str = git_version!(
    args = ["--always", "--match=nothing/", "--abbrev=40", "--dirty=m"],
    fallback = "",
);
const MODIFIED: bool = matches!(GIT_VERSION.as_bytes().last(), Some(b'm'));
pub const BUILD_COMMIT: &str = unsafe {
    // Subslicing is not supported in const yet.
    std::str::from_utf8_unchecked(std::slice::from_raw_parts(
        GIT_VERSION.as_ptr(),
        GIT_VERSION.len() - if MODIFIED { 1 } else { 0 },
    ))
};

#[allow(clippy::const_is_empty)]
pub const FULL_VERSION: &str = if BUILD_COMMIT.is_empty() {
    SHORT_VERSION
} else {
    concat!(
        SHORT_VERSION,
        "-",
        BUILD_COMMIT,
        if MODIFIED { "-modified" } else { "" }
    )
};

#[cfg(any(feature = "version-check", feature = "self-update"))]
#[derive(PartialEq, Eq, Debug)]
pub enum BuildBranch {
    Release,
    Master,
    Next,
}

#[cfg(any(feature = "version-check", feature = "self-update"))]
impl BuildBranch {
    pub const fn from_version(version: &str) -> BuildBranch {
        let version = version.as_bytes();
        // TODO: Use version.last_chunk when MSRV >= 1.80
        // or version.split_last_chunk when MSRV >= 1.77
        const fn last_chunk<const N: usize>(b: &[u8]) -> Option<&[u8]> {
            if b.len() >= N {
                Some(b.split_at(b.len() - N).1)
            } else {
                None
            }
        }
        if matches!(last_chunk::<4>(version), Some(b".0-a")) {
            BuildBranch::Next
        } else if matches!(last_chunk::<2>(version), Some(b"-a" | b"-b")) {
            BuildBranch::Master
        } else {
            BuildBranch::Release
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            BuildBranch::Release => "release",
            BuildBranch::Master => "master",
            BuildBranch::Next => "next",
        }
    }
}

#[cfg(any(feature = "version-check", feature = "self-update"))]
#[test]
fn test_build_branch() {
    use semver::Version;

    // The following tests outline the expected lifecycle.
    let from_version = |v| {
        assert!(Version::parse(v).is_ok());
        BuildBranch::from_version(v)
    };
    assert_eq!(from_version("0.2.0-a"), BuildBranch::Next);
    assert_eq!(from_version("0.2.0-b"), BuildBranch::Master);
    assert_eq!(from_version("0.2.0-b1"), BuildBranch::Release); // optionally
    assert_eq!(from_version("0.2.0-beta1"), BuildBranch::Release); // alternative form
    assert_eq!(from_version("0.2.0-beta1"), BuildBranch::Release); // alternative form
    assert_eq!(from_version("0.3.0-a"), BuildBranch::Next); // possibly later
    assert_eq!(from_version("0.2.0-rc1"), BuildBranch::Release); // optionally
    assert_eq!(from_version("0.2.0"), BuildBranch::Release); // optionally
    assert_eq!(from_version("0.2.1-a"), BuildBranch::Master);
    assert_eq!(from_version("0.2.1"), BuildBranch::Release);
}

#[cfg(any(feature = "version-check", feature = "self-update"))]
pub const BUILD_BRANCH: BuildBranch = BuildBranch::from_version(SHORT_VERSION);
