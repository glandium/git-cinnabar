/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::{Borrow, Cow};
use std::str::FromStr;

use once_cell::sync::Lazy;
use semver::Version;

use crate::git::CommitId;
use crate::{experiment, get_typed_config, ConfigType, Experiments};

macro_rules! join {
    ($s:expr) => {
        Cow::Borrowed($s)
    };
    ($($s:expr),+) => {
        Cow::Owned(itertools::join(&[$($s),+], ""))
    }
}

macro_rules! full_version {
    ($short_version:expr, $build_commit:expr, $modified:expr, $macro:ident) => {
        if $build_commit.is_empty() {
            $macro!($short_version)
        } else {
            $macro!(
                $short_version,
                "-",
                $build_commit,
                if $modified { "-modified" } else { "" }
            )
        }
    };
}

mod static_ {
    use clap::crate_version;
    // Work around https://github.com/rust-lang/rust-analyzer/issues/8828 with `as cat`.
    use concat_const::concat as cat;
    use git_version::git_version;

    #[cfg(any(feature = "version-check", feature = "self-update"))]
    use super::BuildBranch;

    pub const SHORT_VERSION: &str = crate_version!();
    const GIT_VERSION: &str = git_version!(
        args = ["--always", "--match=nothing/", "--abbrev=40", "--dirty=m"],
        fallback = "",
    );
    pub const MODIFIED: bool = matches!(GIT_VERSION.as_bytes().last(), Some(b'm'));
    pub const BUILD_COMMIT: &str = unsafe {
        // Subslicing is not supported in const yet.
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(
            GIT_VERSION.as_ptr(),
            GIT_VERSION.len() - if MODIFIED { 1 } else { 0 },
        ))
    };

    #[cfg(any(feature = "version-check", feature = "self-update"))]
    pub const BUILD_BRANCH: BuildBranch = BuildBranch::from_version(SHORT_VERSION);

    //    #[allow(clippy::const_is_empty)]
    pub const FULL_VERSION: &str = full_version!(SHORT_VERSION, BUILD_COMMIT, MODIFIED, cat);
}

fn value<'a, T: 'a + ConfigType + ?Sized, F: FnOnce(&T) -> bool>(
    config: &str,
    static_value: &'a T,
    filter: F,
) -> Cow<'a, T> {
    if let Some(value) = experiment(Experiments::TEST)
        .then(|| get_typed_config::<T>(config))
        .flatten()
        .filter(|x| filter(x.borrow()))
    {
        Cow::Owned(value)
    } else {
        Cow::Borrowed(static_value)
    }
}

macro_rules! value {
    ($config:expr, $static_value:expr) => {
        value!($config, $static_value, |_| true)
    };
    ($config:expr, $static_value:expr, $filter:expr) => {
        Lazy::new(|| value($config, $static_value, $filter))
    };
}

type Value<T> = Lazy<Cow<'static, T>>;

fn is_overridden<T: ConfigType + ?Sized>(value: &Value<T>) -> bool {
    matches!(**value, Cow::Owned(_))
}

pub static SHORT_VERSION: Value<str> =
    value!("version", static_::SHORT_VERSION, |v| Version::parse(v)
        .is_ok());
pub static BUILD_COMMIT: Value<str> = value!("commit", static_::BUILD_COMMIT, |c| c.is_empty()
    || CommitId::from_str(c).is_ok());
static MODIFIED: Value<bool> = value!("modified", &static_::MODIFIED);
#[cfg(any(feature = "version-check", feature = "self-update"))]
pub static BUILD_BRANCH: Lazy<BuildBranch> = Lazy::new(|| {
    if is_overridden(&SHORT_VERSION) {
        BuildBranch::from_version(&SHORT_VERSION)
    } else {
        static_::BUILD_BRANCH
    }
});
pub static FULL_VERSION: Value<str> = Lazy::new(|| {
    if is_overridden(&SHORT_VERSION) || is_overridden(&BUILD_COMMIT) || is_overridden(&MODIFIED) {
        full_version!(
            SHORT_VERSION.as_ref(),
            BUILD_COMMIT.as_ref(),
            *MODIFIED.as_ref(),
            join
        )
    } else {
        Cow::Borrowed(static_::FULL_VERSION)
    }
});

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
