/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use itertools::Itertools;
use make_cmd::gnu_make;

fn env(name: &str) -> String {
    std::env::var(name).expect(&format!("Failed to get {}", name))
}

fn env_os(name: &str) -> OsString {
    std::env::var_os(name).expect(&format!("Failed to get {}", name))
}

fn prepare_make(make: &mut Command) -> &mut Command {
    let mut result = make.arg("-f").arg("../helper/helper.mk");

    for chunk in &std::env::var("CINNABAR_MAKE_FLAGS")
        .unwrap_or_else(|_| "".into())
        .split('\'')
        .chunks(2)
    {
        let chunk: Vec<_> = chunk.collect();
        if chunk.len() == 2 {
            let name = chunk[0].trim_start().trim_end_matches('=');
            let value = chunk[1];
            result = result.arg(&format!("{}={}", name, value));
        }
    }
    result.env_remove("PROFILE")
}

fn main() {
    let target_arch = env("CARGO_CFG_TARGET_ARCH");
    let target_os = env("CARGO_CFG_TARGET_OS");
    let target_env = env("CARGO_CFG_TARGET_ENV");
    let target_endian = env("CARGO_CFG_TARGET_ENDIAN");
    let target_pointer_width = env("CARGO_CFG_TARGET_POINTER_WIDTH");
    if target_os == "windows" && target_env != "gnu" {
        panic!(
            "Compilation for {}-{} is not supported",
            target_os, target_env
        );
    }
    if std::env::var("CINNABAR_CROSS_COMPILE_I_KNOW_WHAT_I_M_DOING").is_err() {
        if target_arch != target::arch()
            || target_os != target::os()
            || target_env != target::env()
            || target_endian != target::endian()
            || target_pointer_width != target::pointer_width()
        {
            panic!("Cross-compilation is not supported");
        }
    }

    let dir = env_os("CARGO_MANIFEST_DIR");
    let dir = Path::new(&dir);

    let git_core = dir.parent().unwrap().join("git-core");

    let mut make = gnu_make();
    assert!(prepare_make(&mut make)
        .arg("libcinnabar.a")
        .arg("V=1")
        .arg("HAVE_WPGMPTR=")
        .arg("USE_LIBPCRE1=")
        .arg("USE_LIBPCRE2=")
        .env("MAKEFLAGS", format!("-j {}", env("CARGO_MAKEFLAGS")))
        .current_dir(&git_core)
        .status()
        .expect("Failed to execute GNU make")
        .success());

    let mut make = gnu_make();
    let output = prepare_make(&mut make)
        .arg("--no-print-directory")
        .arg("linker-flags")
        .arg("USE_LIBPCRE1=")
        .arg("USE_LIBPCRE2=")
        .current_dir(&git_core)
        .output()
        .expect("Failed to execute GNU make");
    let output = String::from_utf8(output.stdout).unwrap();

    println!("cargo:rustc-link-lib=static=cinnabar");
    println!("cargo:rustc-link-search=native={}", git_core.display());

    for flag in output.split_whitespace() {
        if flag.starts_with("-l") {
            println!("cargo:rustc-link-lib={}", &flag[2..]);
        } else if flag.starts_with("-L") {
            println!("cargo:rustc-link-search=native={}", &flag[2..]);
        }
    }

    for src in fs::read_dir(&dir).unwrap() {
        let path = src.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if (name.ends_with(".h")
            || name.ends_with(".c")
            || name.ends_with(".c.patch")
            || name.ends_with(".rs")
            || name.ends_with(".mk"))
            && !name.ends_with("patched.c")
        {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    println!("cargo:rerun-if-env-changed=CINNABAR_MAKE_FLAGS");

    let git_cinnabar = dir.parent().unwrap().join("git-cinnabar");
    let helper_hash = Command::new("python")
        .arg(git_cinnabar)
        .arg("--version=helper")
        .stderr(Stdio::null())
        .output()
        .unwrap();
    let helper_hash = String::from_utf8(helper_hash.stdout).unwrap();
    let helper_hash = helper_hash.split('/').last().unwrap();
    println!("cargo:rustc-env=HELPER_HASH={}", helper_hash);
}
