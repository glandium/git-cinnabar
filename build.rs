/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use itertools::Itertools;
use make_cmd::gnu_make;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("Failed to get {}", name))
}

fn env_os(name: &str) -> OsString {
    std::env::var_os(name).unwrap_or_else(|| panic!("Failed to get {}", name))
}

fn prepare_make(make: &mut Command) -> &mut Command {
    let mut build_mk = PathBuf::from(env_os("CARGO_MANIFEST_DIR"));
    build_mk.push("src");
    build_mk.push("build.mk");
    let mut result = make.arg("-f").arg(&build_mk);

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
    let extra_args = if target_os == "linux" {
        &["uname_S=Linux"][..]
    } else if target_os == "macos" {
        &["uname_S=Darwin", "uname_R=15.0"][..]
    } else if std::env::var("CINNABAR_CROSS_COMPILE_I_KNOW_WHAT_I_M_DOING").is_err()
        && target_arch != target::arch()
        || target_os != target::os()
        || target_env != target::env()
        || target_endian != target::endian()
        || target_pointer_width != target::pointer_width()
    {
        panic!("Cross-compilation is not supported");
    } else {
        &[][..]
    };

    let dir = env_os("CARGO_MANIFEST_DIR");
    let dir = Path::new(&dir);

    let out_dir = PathBuf::from(env_os("OUT_DIR"));

    let mut make = gnu_make();
    let cmd = prepare_make(&mut make);
    cmd.arg("libcinnabar.a")
        .arg("V=1")
        .arg("HAVE_WPGMPTR=")
        .arg("USE_LIBPCRE1=")
        .arg("USE_LIBPCRE2=")
        .arg("USE_NED_ALLOCATOR=")
        .arg("FSMONITOR_DAEMON_BACKEND=")
        .args(extra_args);

    let compiler = cc::Build::new().get_compiler();

    let cflags = [
        compiler.cflags_env().into_string().ok(),
        // cc-rs ignores TARGET_CFLAGS when TARGET == HOST
        if env("TARGET") == env("HOST") {
            std::env::var("TARGET_CFLAGS").ok()
        } else {
            None
        },
        std::env::var("DEP_CURL_INCLUDE")
            .map(|i| format!("-I{}", i))
            .ok(),
        std::env::var("DEP_CURL_STATIC")
            .map(|_| "-DCURL_STATICLIB".to_string())
            .ok(),
        std::env::var("DEP_Z_INCLUDE")
            .map(|i| format!("-I{}", i))
            .ok(),
    ]
    .iter()
    .filter_map(|v| v.as_deref())
    .chain(
        match &*target_os {
            "windows" => &[
                "-Dpthread_create=win32_pthread_create",
                "-Dpthread_self=win32_pthread_self",
            ][..],
            _ => &[][..],
        }
        .iter()
        .cloned(),
    )
    .join(" ");
    cmd.arg(format!("CFLAGS={}", cflags));
    cmd.arg(format!("CC={}", compiler.path().display()));

    println!("cargo:rerun-if-env-changed=CFLAGS_{}", env("TARGET"));
    println!(
        "cargo:rerun-if-env-changed=CFLAGS_{}",
        env("TARGET").replace("-", "_")
    );
    println!("cargo:rerun-if-env-changed=CFLAGS");
    println!("cargo:rerun-if-env-changed=TARGET_CFLAGS");
    println!("cargo:rerun-if-env-changed=DEP_CURL_INCLUDE");
    println!("cargo:rerun-if-env-changed=DEP_CURL_STATIC");
    println!("cargo:rerun-if-env-changed=DEP_Z_INCLUDE");
    println!("cargo:rerun-if-env-changed=CC_{}", env("TARGET"));
    println!(
        "cargo:rerun-if-env-changed=CC_{}",
        env("TARGET").replace("-", "_")
    );
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CRATE_CC_NO_DEFAULTS");

    #[cfg(feature = "curl-compat")]
    {
        if target_os != "linux" {
            panic!("The curl-compat feature is only supported on linux");
        } else if std::env::var("DEP_CURL_STATIC").is_ok() {
            panic!("The curl-compat feature is not compatible with building curl statically");
        }
        let mut cmd = compiler.to_command();
        cmd.args(&[
            "-shared",
            "-Wl,-soname,libcurl.so.4",
            "src/curl-compat.c",
            "-o",
        ]);
        let curl_dir = PathBuf::from(env_os("OUT_DIR"));
        cmd.arg(curl_dir.join("libcurl.so"));
        if let Ok(include) = std::env::var("DEP_CURL_INCLUDE") {
            cmd.arg(format!("-I{}", include));
        }
        match cmd.status() {
            Ok(s) if s.success() => {}
            _ => panic!("Failed to build libcurl.so with command {:?}", cmd),
        }
        println!("cargo:rerun-if-changed=src/curl-compat.c");
        println!("cargo:rustc-link-search=native={}", curl_dir.display());
    }

    assert!(cmd
        .env("MAKEFLAGS", format!("-j {}", env("CARGO_MAKEFLAGS")))
        .current_dir(&out_dir)
        .status()
        .expect("Failed to execute GNU make")
        .success());

    let mut make = gnu_make();
    let output = prepare_make(&mut make)
        .arg("--no-print-directory")
        .arg("linker-flags")
        .arg("USE_LIBPCRE1=")
        .arg("USE_LIBPCRE2=")
        .arg("USE_NED_ALLOCATOR=")
        .args(extra_args)
        .current_dir(&out_dir)
        .output()
        .expect("Failed to execute GNU make");
    let output = String::from_utf8(output.stdout).unwrap();

    println!("cargo:rustc-link-lib=static=cinnabar");

    if target_os == "windows" && target_env == "gnu" {
        println!("cargo:rustc-link-lib=ssp_nonshared");
        println!("cargo:rustc-link-lib=ssp");
    }

    for flag in output.split_whitespace() {
        if let Some(lib) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={}", lib);
        } else if let Some(libdir) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={}", libdir);
        }
    }

    for src in fs::read_dir(&dir.join("src")).unwrap() {
        let path = src.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if (name.ends_with(".h")
            || name.ends_with(".c")
            || name.ends_with(".c.patch")
            || name.ends_with(".mk"))
            && !name.ends_with("patched.c")
        {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    println!("cargo:rerun-if-env-changed=CINNABAR_MAKE_FLAGS");

    #[cfg(feature = "version-check")]
    {
        if env("CARGO_PKG_VERSION_PRE") == "a" {
            println!("cargo:rustc-cfg=version_check_branch");
            println!(
                "cargo:rustc-env=VERSION_CHECK_BRANCH={}",
                if env("CARGO_PKG_VERSION_PATCH") == "0" {
                    "next"
                } else {
                    "master"
                }
            );
        }
        println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
    }
    if let Ok(profile) = std::env::var("PROFILE") {
        println!("cargo:rustc-cfg=profile={:?}", profile);
    }
}
