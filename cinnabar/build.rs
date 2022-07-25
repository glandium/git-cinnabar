/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::Path;

use itertools::Itertools;
use tar::{Builder, EntryType, Header};
use walkdir::WalkDir;

fn env_os(name: &str) -> OsString {
    std::env::var_os(name).unwrap_or_else(|| panic!("Failed to get {}", name))
}

fn main() {
    let dir = env_os("CARGO_MANIFEST_DIR");
    let dir = Path::new(&dir);

    let python_tar = Path::new(&env_os("OUT_DIR")).join("python.tar");
    let output = File::create(&python_tar).unwrap();
    let mut builder = Builder::new(output);
    let mut python_files = WalkDir::new(&dir)
        .into_iter()
        .filter_map(|e| {
            e.ok()
                .filter(|e| e.path().extension() == Some(OsStr::new("py")))
        })
        .collect_vec();
    python_files.sort_unstable_by(|a, b| a.path().cmp(b.path()));

    for entry in python_files {
        println!("cargo:rerun-if-changed={}", entry.path().display());
        let mut header = Header::new_gnu();
        header
            .set_path(entry.path().strip_prefix(&dir).unwrap())
            .unwrap();
        header.set_size(entry.metadata().unwrap().len());
        header.set_mode(0o644);
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        builder
            .append(&header, File::open(entry.path()).unwrap())
            .unwrap();
    }
    println!("cargo:rustc-env=PYTHON_TAR={}", python_tar.display());
}
