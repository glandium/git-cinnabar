/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::cmp::Ordering;
use std::str::FromStr;

use derive_more::Display;
use once_cell::sync::Lazy;

use crate::git::CommitId;
use crate::{experiment, get_typed_config, ConfigType, Experiments};

#[derive(Clone, Display, Debug)]
#[display(fmt = "{version}")]
pub struct Version {
    version: semver::Version,
    tag_has_v_prefix: bool,
}

impl PartialEq for Version {
    fn eq(&self, other: &Version) -> bool {
        self.version == other.version
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<Ordering> {
        self.version.partial_cmp(&other.version)
    }
}

impl Version {
    pub fn parse(v: &str) -> Result<Self, semver::Error> {
        let (v, tag_has_v_prefix) = v.strip_prefix("v").map_or((v, false), |v| (v, true));
        let mut version = semver::Version::parse(v).or_else(|e| {
            // If the version didn't parse, try again by separating
            // x.y.z from everything that follows with a dash.
            v.find(|c: char| !c.is_ascii_digit() && c != '.')
                .map(|pos| {
                    let (digits, rest) = v.split_at(pos);
                    format!("{}-{}", digits, rest)
                })
                .as_deref()
                .and_then(|v| semver::Version::parse(v).ok())
                .ok_or(e)
        })?;
        if !version.pre.is_empty() {
            if let Some(i) = version.pre.find(|c: char| c.is_ascii_digit()) {
                if version.pre.chars().nth(i - 1) != Some('.') {
                    let (a, b) = version.pre.split_at(i);
                    version.pre = semver::Prerelease::new(&format!("{a}.{b}"))?;
                }
            }
        }
        Ok(Version {
            version,
            tag_has_v_prefix,
        })
    }

    #[cfg(any(feature = "self-update", test))]
    pub fn as_tag(&self) -> String {
        if self.tag_has_v_prefix {
            format!("v{}", self.version)
        } else {
            let v = &self.version;
            let mut tag = semver::Version::new(v.major, v.minor, v.patch).to_string();
            if !v.pre.is_empty() {
                let mut pre = v.pre.chars();
                tag.extend(pre.by_ref().take_while(|&c| c != '.'));
                tag.extend(pre);
            }

            tag
        }
    }
}

#[test]
fn test_version() {
    use crate::util::{assert_gt, assert_lt};
    // Because earlier versions of git-cinnabar removed the dash from x.y.z-beta*
    // versions, we have to continue not putting a dash in tags.
    // But because (arbitrarily) I don't like the beta.1 form without the
    // dash, we also remove the dot there.
    assert_eq!(
        Version::parse("0.7.0-beta.1").unwrap().as_tag(),
        "0.7.0beta1".to_owned()
    );
    // There most probably won't be versions like this, but just in case,
    // ensure we deal with them properly.
    assert_eq!(
        Version::parse("0.7.0-beta.1.1").unwrap().as_tag(),
        "0.7.0beta1.1".to_owned()
    );

    // semver doesn't handle beta.x and betax the same way, and the ordering
    // of the latter is unfortunate. So internally, we normalize the latter
    // to the former.
    assert_lt!(
        semver::Version::parse("0.7.0-beta11").unwrap(),
        semver::Version::parse("0.7.0-beta2").unwrap()
    );
    assert_ne!(
        semver::Version::parse("0.7.0-beta2").unwrap(),
        semver::Version::parse("0.7.0-beta.2").unwrap()
    );
    assert!(semver::Version::parse("0.7.0beta2").is_err());
    assert_gt!(
        Version::parse("0.7.0-beta11").unwrap(),
        Version::parse("0.7.0-beta2").unwrap()
    );
    assert_eq!(
        Version::parse("0.7.0-beta2").unwrap(),
        Version::parse("0.7.0-beta.2").unwrap()
    );
    assert_eq!(
        Version::parse("0.7.0beta2").unwrap(),
        Version::parse("0.7.0-beta.2").unwrap()
    );

    assert_eq!(
        Version::parse("0.7.0-beta.2").unwrap().as_tag(),
        "0.7.0beta2".to_owned()
    );
    assert_eq!(
        Version::parse("0.7.0beta2").unwrap().to_string(),
        "0.7.0-beta.2".to_owned()
    );

    assert_eq!(
        Version::parse("v0.7.0-beta.2").unwrap(),
        Version::parse("0.7.0beta2").unwrap(),
    );
    assert_eq!(
        Version::parse("v0.7.0-beta.2").unwrap().as_tag(),
        "v0.7.0-beta.2".to_owned()
    );
    assert_eq!(
        Version::parse("v0.7.0-beta.2").unwrap().to_string(),
        "0.7.0-beta.2".to_owned()
    );
}

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
    #[cfg(feature = "full-version")]
    use concat_const::concat as cat;
    #[cfg(feature = "full-version")]
    use git_version::git_version;

    #[cfg(any(feature = "version-check", feature = "self-update"))]
    use super::BuildBranch;

    pub const SHORT_VERSION: &str = crate_version!();
    #[cfg(feature = "full-version")]
    const GIT_VERSION: &str = git_version!(
        args = ["--always", "--match=nothing/", "--abbrev=40", "--dirty=m"],
        fallback = "",
    );
    #[cfg(feature = "full-version")]
    pub const MODIFIED: bool = matches!(GIT_VERSION.as_bytes().last(), Some(b'm'));
    #[cfg(not(feature = "full-version"))]
    pub const MODIFIED: bool = false;
    #[cfg(feature = "full-version")]
    pub const BUILD_COMMIT: &str = unsafe {
        // Subslicing is not supported in const yet.
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(
            GIT_VERSION.as_ptr(),
            GIT_VERSION.len() - if MODIFIED { 1 } else { 0 },
        ))
    };
    #[cfg(not(feature = "full-version"))]
    pub const BUILD_COMMIT: &str = "";

    #[cfg(any(feature = "version-check", feature = "self-update"))]
    pub const BUILD_BRANCH: BuildBranch = BuildBranch::from_version(SHORT_VERSION);

    #[cfg(feature = "full-version")]
    pub const FULL_VERSION: &str = full_version!(SHORT_VERSION, BUILD_COMMIT, MODIFIED, cat);
    #[cfg(not(feature = "full-version"))]
    pub const FULL_VERSION: &str = SHORT_VERSION;
}

fn value<'a, T: 'a + ConfigType + ?Sized, F: FnOnce(T::Owned) -> Option<T::Owned>>(
    config: &str,
    static_value: &'a T,
    filter: F,
) -> Cow<'a, T> {
    if let Some(value) = experiment(Experiments::TEST)
        .then(|| get_typed_config::<T>(config))
        .flatten()
        .and_then(filter)
    {
        Cow::Owned(value)
    } else {
        Cow::Borrowed(static_value)
    }
}

macro_rules! value {
    ($config:expr, $static_value:expr) => {
        value!($config, $static_value, |x| Some(x))
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
    value!("version", static_::SHORT_VERSION, |v| Version::parse(&v)
        .ok()
        .map(|v| v.to_string()));
pub static BUILD_COMMIT: Value<str> = value!("commit", static_::BUILD_COMMIT, |c| (c.is_empty()
    || CommitId::from_str(&c).is_ok())
.then_some(c));
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
