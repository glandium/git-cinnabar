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
