/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use clap::crate_version;
use git_version::git_version;

pub const SHORT_VERSION: &str = crate_version!();
pub const FULL_VERSION: &str = git_version!(
    args = [
        "--always",
        "--match=nothing/",
        "--abbrev=40",
        "--dirty=-modified"
    ],
    prefix = concat!(crate_version!(), "-"),
    cargo_prefix = "",
    fallback = crate_version!(),
);
