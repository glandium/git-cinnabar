# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import concurrent.futures
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path
from urllib.request import urlopen


def main():
    ret = 0
    args = sys.argv[1:]
    if args and args[0] == "--download":
        download_py = Path(__file__).parent.parent / "download.py"
        args = (
            subprocess.check_output(
                [sys.executable, download_py, "--url", "--list"] + args[1:]
            )
            .decode()
            .splitlines()
        )
    else:
        for arg in args:
            if arg.startswith("-"):
                print(f"{arg} is not supported.")
                return 1
    if len(args) > 1:
        executor = concurrent.futures.ProcessPoolExecutor()
        map_ = executor.map
    else:
        map_ = map
    for path, pkg in zip(args, map_(package_from, args)):
        if pkg:
            print(f"Created {pkg} from {path}", file=sys.stderr)
        else:
            print(f"Can't determine platform type for {path}", file=sys.stderr)
            ret = 1
    return ret


def package_from(path):
    if path.startswith(("http:", "https:")):
        fh = urlopen(path)
        size = fh.length
    else:
        fh = open(path, "rb")
        size = os.stat(path).st_size
    with fh:
        fh = RewindOnce(fh)
        system, machine = detect_platform(fh)
        if not system or not machine:
            return

        fh.rewind()
        if size is None:
            fh = BytesIO(fh.read())
            size = len(fh.getbuffer())
        return package(fh, size, system, machine)


def package(fh, size, system, machine):
    stem = f"git-cinnabar.{system.lower()}.{machine.lower()}"
    if system == "Windows":
        pkg = f"{stem}.zip"
        zip = zipfile.ZipFile(
            pkg, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        )
        zip.mkdir("git-cinnabar")
        fh = RewindOnce(fh)
        with zip.open("git-cinnabar/git-cinnabar.exe", mode="w") as zipped:
            shutil.copyfileobj(fh, zipped)
        fh.rewind()
        with zip.open("git-cinnabar/git-remote-hg.exe", mode="w") as zipped:
            shutil.copyfileobj(fh, zipped)
    else:
        pkg = f"{stem}.tar.xz"
        tar = tarfile.open(pkg, mode="w:xz", preset=9)
        info = tarinfo("git-cinnabar/")
        info.mode = 0o755
        info.type = tarfile.DIRTYPE
        tar.addfile(info)

        info = tarinfo("git-cinnabar/git-cinnabar")
        info.mode = 0o700
        info.size = size
        info.type = tarfile.REGTYPE
        tar.addfile(info, fh)

        info = tarinfo("git-cinnabar/git-remote-hg")
        info.mode = 0o777
        info.type = tarfile.SYMTYPE
        info.linkname = "git-cinnabar"
        tar.addfile(info)
    return pkg


def tarinfo(name):
    info = tarfile.TarInfo(name)
    info.uid = 1000
    info.gid = 1000
    info.uname = "cinnabar"
    info.gname = "cinnabar"
    return info


class RewindOnce:
    def __init__(self, fh):
        self.buf = b""
        self.off = 0
        self.rewound = False
        self.fh = fh

    def read(self, length=None):
        if self.rewound:
            if length is None:
                return self.buf[self.off :] + self.fh.read()
            ret = self.buf[self.off :][:length]
            self.off += len(ret)
            missing = length - len(ret)
            if not missing:
                return ret
            return ret + self.fh.read(missing)

        ret = self.fh.read(length)
        self.buf += ret
        return ret

    def rewind(self):
        assert not self.rewound
        self.rewound = True


def detect_platform(executable):
    system, machine = None, None
    head = executable.read(4)
    if head[:2] == b"MZ":
        # Seek to 0x3c
        executable.read(0x3C - 4)
        (pe_offset,) = struct.unpack("<L", executable.read(4))
        # Seek to pe_offset
        executable.read(pe_offset - 0x40)
        pe_signature = executable.read(4)
        if pe_signature == b"PE\0\0":
            system = "Windows"
            (machine_type,) = struct.unpack("<H", executable.read(2))
            if machine_type == 0x8664:
                machine = "x86_64"
    elif head == b"\xcf\xfa\xed\xfe":
        system = "macOS"
        (machine_type,) = struct.unpack("<L", executable.read(4))
        if machine_type == 0x1000007:
            machine = "x86_64"
        elif machine_type == 0x100000C:
            machine = "arm64"
    elif head == b"\x7fELF":
        (ident,) = struct.unpack(">L", executable.read(4))
        # 64-bits little-endian Linux (in theory, System-V)
        if ident == 0x02010100:
            system = "Linux"
            # Seek to 0x12
            executable.read(10)
            (machine_type,) = struct.unpack("<H", executable.read(2))
            if machine_type == 0x3E:
                machine = "x86_64"
            elif machine_type == 0xB7:
                machine = "arm64"
    if system and machine:
        return system, machine
    return None, None


if __name__ == "__main__":
    sys.exit(main())
