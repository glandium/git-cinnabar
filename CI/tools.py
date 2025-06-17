# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import hashlib
import os

import msys
from docker import DockerImage
from tasks import (
    Task,
    TaskEnvironment,
    Tool,
    parse_version,
)
from util import build_commit

MERCURIAL_VERSION = "6.9.1"
GIT_VERSION = "2.49.0"

ALL_MERCURIAL_VERSIONS = (
    "1.9.3",
    "2.0.2",
    "2.1.2",
    "2.2.3",
    "2.3.2",
    "2.4.2",
    "2.5.4",
    "2.6.3",
    "2.7.2",
    "2.8.2",
    "2.9.1",
    "3.0.1",
    "3.1.2",
    "3.2.4",
    "3.3.3",
    "3.4.2",
    "3.5.2",
    "3.6.3",
    "3.7.3",
    "3.8.4",
    "3.9.2",
    "4.0.2",
    "4.1.3",
    "4.2.2",
    "4.3.3",
    "4.4.2",
    "4.5.3",
    "4.6.2",
    "4.7.2",
    "4.8.2",
    "4.9.1",
    "5.0.2",
    "5.1.2",
    "5.2.2",
    "5.3.2",
    "5.4.2",
    "5.5.2",
    "5.6.1",
    "5.7.1",
    "5.8.1",
    "5.9.3",
    "6.0.3",
    "6.1.4",
    "6.2.3",
    "6.3.3",
    "6.4.2",
    "6.5.3",
    "6.6.3",
    "6.7.4",
    "6.8.2",
    "6.9.1",
)

SOME_MERCURIAL_VERSIONS = (
    "1.9.3",
    "2.5.4",
    "3.4.2",
)

assert MERCURIAL_VERSION in ALL_MERCURIAL_VERSIONS
assert all(v in ALL_MERCURIAL_VERSIONS for v in SOME_MERCURIAL_VERSIONS)


def nproc(env):
    if env.os == "macos":
        return "sysctl -n hw.physicalcpu"
    return "nproc --all"


class Git(Task, metaclass=Tool):
    PREFIX = "git"

    def __init__(self, os_and_version):
        (os, version) = os_and_version.split(".", 1)
        self.os = os
        if os.endswith("osx"):
            build_image = TaskEnvironment.by_name("{}.build".format(os))
        else:
            build_image = DockerImage.by_name("build-tools")
        if os == "linux" or os.endswith("osx"):
            h = hashlib.sha1(build_image.hexdigest.encode())
            h.update(b"v4" if version == GIT_VERSION else b"v3")
            if os == "linux":
                description = "git v{}".format(version)
            else:
                env = build_image
                description = "git v{} {} {}".format(version, env.os, env.cpu)
            Task.__init__(
                self,
                task_env=build_image,
                description=description,
                index="git.v{}.{}".format(version, h.hexdigest()),
                command=Task.checkout(
                    "git://git.kernel.org/pub/scm/git/git.git",
                    "v{}".format(version),
                    dest="git",
                )
                + Task.checkout()
                + (
                    [
                        "patch -d git -p1 < repo/CI/git-transport-disconnect.diff",
                    ]
                    if version == GIT_VERSION
                    else []
                )
                + [
                    "make -C git -j$({}) install prefix=/ NO_GETTEXT=1"
                    " NO_OPENSSL=1 NO_TCLTK=1 NO_UNCOMPRESS2=1 INSTALL_STRIP=-s"
                    " DESTDIR=$PWD/git".format(nproc(build_image)),
                    "tar -c git | zstd -c > $ARTIFACTS/git-{}.tar.zst".format(version),
                ],
                artifact="git-{}.tar.zst".format(version),
            )
        else:
            env = TaskEnvironment.by_name("{}.build".format(os))
            raw_version = version
            if "windows" not in version:
                version = {
                    version: version + ".windows.1",
                    "2.17.1": "2.17.1.windows.2",
                }.get(version)
            if version.endswith(".windows.1"):
                min_ver = version[: -len(".windows.1")]
            else:
                min_ver = version.replace("windows.", "")
            h = hashlib.sha1(env.hexdigest.encode())
            h.update(b"v1")
            Task.__init__(
                self,
                task_env=build_image,
                description="git v{} {} {}".format(version, env.os, env.cpu),
                index="git.v{}.{}".format(raw_version, h.hexdigest()),
                command=[
                    "curl -L https://github.com/git-for-windows/git/releases/"
                    "download/v{}/MinGit-{}-{}-bit.zip"
                    " -o git.zip".format(version, min_ver, msys.bits(env.cpu)),
                    "unzip -d git git.zip",
                    "curl -L https://github.com/git-for-windows/git/releases/"
                    "download/v{}/Git-{}-{}-bit.tar.bz2 | "
                    "tar -C git --no-same-owner -jx "
                    "{}/libexec/git-core/git-http-backend.exe".format(
                        version,
                        min_ver,
                        msys.bits(env.cpu),
                        msys.mingw(env.cpu).lower(),
                    ),
                    "tar -c git | zstd -c > $ARTIFACTS/git-{}.tar.zst".format(
                        raw_version
                    ),
                ],
                artifact="git-{}.tar.zst".format(raw_version),
            )

    def mount(self):
        return {"directory:git": self}

    def install(self):
        if self.os.endswith(("linux", "osx")):
            return [
                "export PATH=$PWD/git/bin:$PATH",
                "export GIT_EXEC_PATH=$PWD/git/libexec/git-core",
                "export GIT_TEMPLATE_DIR=$PWD/git/share/git-core/templates",
            ]
        else:
            return []


class Hg(Task, metaclass=Tool):
    PREFIX = "hg"

    def __init__(self, os_and_version):
        (os, version) = os_and_version.split(".", 1)
        (version, suffix, _) = version.partition(".py3")
        if (
            suffix
            or len(version) == 40
            or parse_version(version) >= parse_version("6.2")
        ):
            python = "python3"
        else:
            python = "python2.7"
        if os == "linux":
            env = TaskEnvironment.by_name("{}.build-tools".format(os))
        else:
            env = TaskEnvironment.by_name("{}.build".format(os))
        kwargs = {}

        if len(version) == 40:
            # Assume it's a sha1
            pretty_version = "r{}{}".format(version, suffix)
            artifact_version = "99.0"
        else:
            pretty_version = "v{}{}".format(version, suffix)
            artifact_version = version
        desc = "hg {}".format(pretty_version)
        if os == "linux":
            platform_tag = "linux_x86_64"
            if python == "python3":
                python_tag = "cp39"
                abi_tag = "cp39"
            else:
                python_tag = "cp27"
                abi_tag = "cp27mu"
        else:
            desc = "{} {} {}".format(desc, env.os, env.cpu)
            if os.endswith("osx"):
                py_host_plat = "macosx-{}-{}".format(env.os_version, env.cpu)
                platform_tag = py_host_plat.replace(".", "_").replace("-", "_")
                if python == "python3":
                    python_tag = "cp311" if os == "arm64-osx" else "cp39"
                    abi_tag = python_tag
                else:
                    python_tag = "cp27"
                    abi_tag = "cp27m"
                env_ = kwargs.setdefault("env", {})
                env_.setdefault("MACOSX_DEPLOYMENT_TARGET", env.os_version)
                env_.setdefault("ARCHFLAGS", "-arch {}".format(env.cpu))
                env_.setdefault("_PYTHON_HOST_PLATFORM", py_host_plat)
            else:
                if python == "python3":
                    platform_tag = "mingw_x86_64"
                    python_tag = "cp311"
                    abi_tag = "cp311"
                else:
                    platform_tag = "mingw"
                    python_tag = "cp27"
                    abi_tag = "cp27m"

        artifact = "mercurial-{{}}-{}-{}-{}.whl".format(
            python_tag,
            abi_tag,
            platform_tag,
        )

        pre_command = []
        if len(version) == 40:
            hg = self.by_name("{}.{}".format(os, MERCURIAL_VERSION))
            kwargs.setdefault("mounts", []).append(hg.mount())
            pre_command.extend(hg.install())
            pre_command.extend(
                [
                    "hg clone https://www.mercurial-scm.org/repo/hg"
                    " -r {} mercurial-{}".format(version, version),
                    "rm -rf mercurial-{}/.hg".format(version),
                    "echo tag: {} > mercurial-{}/.hg_archival.txt".format(
                        artifact_version, version
                    ),
                ]
            )
        # 2.6.2 is the first version available on pypi
        elif parse_version("2.6.2") <= parse_version(version) and parse_version(
            version
        ) < parse_version("6.2"):
            # pip download does more than download, and while it runs setup.py
            # for version 6.2, a DistutilsPlatformError exception is thrown on
            # Windows.
            pre_command.append(
                "{} -m pip download --no-binary mercurial --no-deps"
                " --progress-bar off mercurial=={}".format(python, version)
            )
        else:
            url = "https://mercurial-scm.org/release/mercurial-{}.tar.gz"
            pre_command.append("curl -sLO {}".format(url.format(version)))

        if len(version) != 40:
            pre_command.append("tar -zxf mercurial-{}.tar.gz".format(version))

        if os.startswith("mingw"):
            # Work around https://bz.mercurial-scm.org/show_bug.cgi?id=6654
            # and https://bz.mercurial-scm.org/show_bug.cgi?id=6757
            pre_command.append(
                'sed -i "s/, output_dir=self.build_temp/'
                ", output_dir=self.build_temp, extra_postargs=[$EXTRA_FLAGS]/;"
                "/self.addlongpathsmanifest/d;"
                '" mercurial-{}/setup.py'.format(version)
            )
            if python == "python3":
                kwargs.setdefault("env", {}).setdefault("EXTRA_FLAGS", '"-municode"')
            pre_command.append(
                'sed -i "s/ifdef __GNUC__/if 0/"'
                " mercurial-{}/mercurial/exewrapper.c".format(version)
            )

        h = hashlib.sha1(env.hexdigest.encode())
        h.update(artifact.encode())
        if os.endswith("osx"):
            h.update(b"v4")
        elif os.startswith("mingw"):
            h.update(b"v6")
        else:
            h.update(b"v3")

        Task.__init__(
            self,
            task_env=env,
            description=desc,
            index="hg.{}.{}".format(pretty_version, h.hexdigest()),
            command=pre_command
            + [f"{python} -m pip wheel -v -w $ARTIFACTS ./mercurial-{version}"],
            artifact=artifact.format(artifact_version),
            **kwargs,
        )

    def mount(self):
        return {f"file:{os.path.basename(self.artifacts[0])}": self}

    def install(self):
        filename = os.path.basename(self.artifacts[0])
        if "cp3" in filename:
            python = "python3"
        else:
            python = "python2.7"
        return ["{} -m pip install --force-reinstall {}".format(python, filename)]


def install_rust(version="1.87.0", target="x86_64-unknown-linux-gnu"):
    rustup_opts = "-y --default-toolchain none"
    cargo_dir = "$HOME/.cargo/bin/"
    rustup = cargo_dir + "rustup"
    rust_install = [
        "curl -o rustup.sh https://sh.rustup.rs",
        "sh rustup.sh {rustup_opts}",
        "{rustup} install {version} --profile minimal",
        "{rustup} default {version}",
        "PATH={cargo_dir}:$PATH",
        "{rustup} target add {target}",
    ]
    loc = locals()
    return [r.format(**loc) for r in rust_install]


class Build(Task, metaclass=Tool):
    PREFIX = "build"

    def __init__(self, os_and_variant):
        os, variant = (os_and_variant.split(".", 1) + [""])[:2]
        env = TaskEnvironment.by_name(
            "{}.build".format(os.replace("arm64-linux", "linux"))
        )
        build_env = TaskEnvironment.by_name("linux.build")

        artifact = "git-cinnabar"
        if os.startswith("mingw"):
            artifact += ".exe"
        artifacts = [artifact]

        def prefix(p, s):
            return p + s if s else s

        hash = None
        head = None
        desc_variant = variant
        environ = {}
        cargo_flags = ["-vv", "--release"]
        cargo_features = ["self-update", "gitdev", "xz2/static", "bzip2/static"]
        rust_version = None
        if variant == "asan":
            if os.endswith("osx"):
                opt = "-O2"
            else:
                opt = "-Og"
            environ["TARGET_CFLAGS"] = " ".join(
                [
                    opt,
                    "-g",
                    "-fsanitize=address",
                    "-fno-omit-frame-pointer",
                    "-fPIC",
                ]
            )
            environ["RUSTFLAGS"] = " ".join(
                [
                    "-Zsanitizer=address",
                    "-Copt-level=1",
                    "-Cdebuginfo=full",
                    "-Cforce-frame-pointers=yes",
                ]
            )
        elif variant == "coverage":
            environ["TARGET_CFLAGS"] = " ".join(
                [
                    "-fprofile-instr-generate",
                    "-fcoverage-mapping",
                    "-fPIC",
                ]
            )
            environ["RUSTFLAGS"] = " ".join(
                [
                    "-Cinstrument-coverage",
                    "-Ccodegen-units=1",
                    "-Cinline-threshold=0",
                ]
            )
            # Build without --release
            cargo_flags.remove("--release")
            environ["CARGO_INCREMENTAL"] = "0"
        elif variant.startswith("old:"):
            head = variant[4:]
            hash = build_commit(head)
            variant = ""
        elif variant.startswith("rust-"):
            rust_version = variant[5:]
        elif variant:
            raise Exception("Unknown variant: {}".format(variant))

        environ["CC"] = "clang-19"

        if os.startswith("mingw"):
            cpu = msys.msys_cpu(env.cpu)
            rust_target = "{}-pc-windows-gnu".format(cpu)
        elif os.startswith("osx"):
            rust_target = "x86_64-apple-darwin"
        elif os.startswith("arm64-osx"):
            rust_target = "aarch64-apple-darwin"
        elif os == "linux":
            rust_target = "x86_64-unknown-linux-gnu"
        elif os == "arm64-linux":
            rust_target = "aarch64-unknown-linux-gnu"

        for target in dict.fromkeys(["x86_64-unknown-linux-gnu", rust_target]).keys():
            arch = {
                "x86_64": "amd64",
                "aarch64": "arm64",
            }[target.partition("-")[0]]
            multiarch = target.replace("unknown-", "")
            TARGET = target.replace("-", "_").upper()
            environ[f"CARGO_TARGET_{TARGET}_LINKER"] = environ["CC"]
            link_args = [
                f"--target={target}",
                "-fuse-ld=lld",
            ]
            if "linux" in os:
                link_args.append(f"--sysroot=/sysroot-{arch}")
            if os.startswith("mingw"):
                link_args.append(f"-L/usr/lib/gcc/{cpu}-w64-mingw32/10-win32")
                link_args.append("-Wl,-Xlink,-Brepro")
            environ[f"CARGO_TARGET_{TARGET}_RUSTFLAGS"] = " ".join(
                f"-C link-arg={arg}" for arg in link_args
            )
            environ["AR"] = "llvm-ar-19"
            rustflags = environ.pop("RUSTFLAGS", None)
            if rustflags:
                environ[f"CARGO_TARGET_{TARGET}_RUSTFLAGS"] += f" {rustflags}"
            if "linux" in os:
                environ[f"CFLAGS_{target.replace('-', '_')}"] = (
                    f"--sysroot=/sysroot-{arch}"
                )
        if "linux" in os:
            environ["PKG_CONFIG_PATH"] = ""
            environ["PKG_CONFIG_SYSROOT_DIR"] = f"/sysroot-{arch}"
            environ["PKG_CONFIG_LIBDIR"] = ":".join(
                (
                    f"/sysroot-{arch}/usr/lib/pkgconfig",
                    f"/sysroot-{arch}/usr/lib/{multiarch}/pkgconfig",
                    f"/sysroot-{arch}/usr/share/pkgconfig",
                )
            )
            cargo_features.append("curl-compat")
        if variant == "asan":
            environ["RUSTC_BOOTSTRAP"] = "1"
        if rust_version:
            rust_install = install_rust(rust_version, target=rust_target)
        else:
            rust_install = install_rust(target=rust_target)
        cargo_flags.extend(["--target", rust_target])
        if cargo_features:
            cargo_flags.extend(["--features", ",".join(cargo_features)])
        for key, value in list(environ.items()):
            # RUSTFLAGS values in the environment override builds.rustflags
            # from .cargo/config.toml.
            if "RUSTFLAGS" in key:
                environ[key] = value + " -Cforce-unwind-tables=yes"

        hash = hash or build_commit()

        if os.startswith("osx"):
            environ.setdefault("MACOSX_DEPLOYMENT_TARGET", "10.7")
        if os.startswith("arm64-osx"):
            environ.setdefault("MACOSX_DEPLOYMENT_TARGET", "11.0")
        sdk_install = []
        kwargs = {}
        if "osx" in os:
            sdk = Tool.by_name("macossdk.arm64-osx")
            sdk_install = sdk.install()
            kwargs.setdefault("mounts", []).append(sdk.mount())

        cpu = "arm64" if os == "arm64-linux" else env.cpu
        Task.__init__(
            self,
            task_env=build_env,
            description="build {} {}{}".format(env.os, cpu, prefix(" ", desc_variant)),
            index="build.{}.{}{}.{}".format(env.os, cpu, prefix(".", variant), hash),
            command=Task.checkout(commit=head)
            + sdk_install
            + rust_install
            + [
                "(cd repo ; CI/cargo.sh build {})".format(" ".join(cargo_flags)),
                "mv repo/target/{}/{}/{} $ARTIFACTS/".format(
                    rust_target,
                    "release" if "--release" in cargo_flags else "debug",
                    artifact,
                ),
            ],
            artifacts=artifacts,
            env=environ,
            **kwargs,
        )

    def mount(self):
        return {f"file:{os.path.basename(self.artifacts[0])}": self}

    def install(self):
        filename = os.path.basename(self.artifacts[0])
        return [
            f"cp {filename} repo/",
            "chmod +x repo/{}".format(filename),
            "$PWD/repo/{} setup".format(filename),
        ]
