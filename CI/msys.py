# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import hashlib

from docker import DockerImage
from tasks import (
    Task,
    TaskEnvironment,
    Tool,
    bash_command,
    join_command,
)

CPUS = ("x86_64",)
MSYS_VERSION = {
    "x86_64": "20240727",
}


def mingw(cpu):
    return {
        "x86_64": "MINGW64",
    }.get(cpu)


def msys(cpu):
    return {
        "x86_64": "msys64",
    }.get(cpu)


def msys_cpu(cpu):
    return cpu


def bits(cpu):
    return {
        "x86_64": "64",
    }.get(cpu)


class MsysCommon(object):
    os = "windows"

    def prepare_params(self, params):
        assert "workerType" not in params
        params["workerType"] = "windows"
        params.setdefault("mounts", []).append({"directory": self})
        params.setdefault("env", {})["MSYSTEM"] = mingw(self.cpu)

        command = []
        command.append("set HOME=%CD%")
        command.append("set ARTIFACTS=%CD%")
        for path in (mingw(self.cpu), "usr"):
            command.append(
                "set PATH=%CD%\\{}\\{}\\bin;%PATH%".format(msys(self.cpu), path)
            )
        command.append("set PATH=%CD%\\git\\{}\\bin;%PATH%".format(mingw(self.cpu)))
        if self.PREFIX != "msys":
            command.append(
                'bash -c -x "{}"'.format(
                    "; ".join(
                        (
                            "for postinst in /etc/post-install/*.post",
                            "do test -e $postinst && . $postinst",
                            "done",
                        )
                    )
                )
            )
        command.append(
            join_command(*bash_command(*params["command"]), for_windows=True)
        )
        params["command"] = command
        return params

    @property
    def index(self):
        return ".".join(("env", self.PREFIX, self.cpu, self.hexdigest))


class MsysBase(MsysCommon, Task, metaclass=Tool):
    PREFIX = "msys"

    def __init__(self, cpu):
        assert cpu in CPUS
        _create_command = (
            "curl -L http://repo.msys2.org/distrib/{cpu}"
            "/msys2-base-{cpu}-{version}.tar.xz | xz -cd | zstd -c"
            " > $ARTIFACTS/msys2.tar.zst".format(
                cpu=msys_cpu(cpu), version=MSYS_VERSION[cpu]
            )
        )
        h = hashlib.sha1(_create_command.encode())
        self.hexdigest = h.hexdigest()
        self.cpu = cpu

        Task.__init__(
            self,
            task_env=DockerImage.by_name("base"),
            description="msys2 image: base {}".format(cpu),
            index=self.index,
            expireIn="26 weeks",
            command=[_create_command],
            artifact="msys2.tar.zst",
        )


class MsysEnvironment(MsysCommon):
    def __init__(self, name):
        cpu = self.cpu
        create_commands = [
            "pacman-key --init",
            "pacman-key --populate msys2",
            "pacman-key --refresh",
            "pacman --noconfirm -Sy procps tar {}".format(
                " ".join(self.packages(name))
            ),
            "pkill gpg-agent",
            "pkill dirmngr",
            "rm -rf /var/cache/pacman/pkg",
            "python3 -m pip install pip==22.2.2 wheel==0.37.1 --upgrade",
            "mv {}/{}/bin/{{mingw32-,}}make.exe".format(msys(cpu), mingw(cpu)),
            "tar -c --hard-dereference {} | zstd -c > msys2.tar.zst".format(msys(cpu)),
        ]

        env = MsysBase.by_name(cpu)

        h = hashlib.sha1(env.hexdigest.encode())
        h.update(";".join(create_commands).encode())
        self.hexdigest = h.hexdigest()

        Task.__init__(
            self,
            task_env=env,
            description="msys2 image: {} {}".format(name, cpu),
            index=self.index,
            expireIn="26 weeks",
            command=create_commands,
            artifact="msys2.tar.zst",
        )

    def packages(self, name):
        def mingw_packages(pkgs):
            return ["mingw-w64-{}-{}".format(msys_cpu(self.cpu), pkg) for pkg in pkgs]

        packages = mingw_packages(
            [
                "curl",
                "make",
                "python3",
                "python3-pip",
            ]
        )

        if name == "build":
            return (
                packages
                + mingw_packages(
                    [
                        "gcc",
                    ]
                )
                + [
                    "patch",
                ]
            )
        elif name == "test":
            return packages + [
                "diffutils",
                "git",
            ]
        raise Exception("Unknown name: {}".format(name))


class Msys64Environment(MsysEnvironment, Task, metaclass=TaskEnvironment):
    PREFIX = "mingw64"
    cpu = "x86_64"
    __init__ = MsysEnvironment.__init__
