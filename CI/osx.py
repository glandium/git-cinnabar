# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import hashlib

from tasks import (
    Task,
    TaskEnvironment,
    Tool,
    bash_command,
)


class OsxCommon(object):
    os = "macos"
    cpu = "x86_64"
    SDK_VERSION = "15.2"
    XCODE_VERSION = "16.2"

    def __init__(self, name):
        self.hexdigest = hashlib.sha1(self.ITERATION.encode("utf-8")).hexdigest()
        self.name = name

    def prepare_params(self, params):
        assert "workerType" not in params
        params["workerType"] = self.WORKER_TYPE
        command = []
        command.append("export PWD=$(pwd)")
        command.append("export ARTIFACTS=$PWD")
        command.extend(params["command"])
        params["command"] = bash_command(*command)
        env = params.setdefault("env", {})
        dev = env.setdefault(
            "DEVELOPER_DIR",
            f"/Applications/Xcode_{self.XCODE_VERSION}.app/Contents/Developer",
        )
        env.setdefault(
            "SDKROOT",
            f"{dev}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX{self.SDK_VERSION}.sdk",
        )
        return params


class Osx(OsxCommon, metaclass=TaskEnvironment):
    ITERATION = "4"
    PREFIX = "osx"
    WORKER_TYPE = "osx"
    os_version = "10.15"


class OsxArm64(OsxCommon, metaclass=TaskEnvironment):
    cpu = "arm64"
    ITERATION = "2"
    PREFIX = "arm64-osx"
    WORKER_TYPE = "macos"
    os_version = "11.0"

    def prepare_params(self, params):
        env = params.setdefault("env", {})
        env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
        params["command"].insert(0, "export PATH=$PATH:/opt/homebrew/bin")
        return super(OsxArm64, self).prepare_params(params)


class MacosSDK(Task, metaclass=Tool):
    PREFIX = "macossdk"
    SDK_VERSION = OsxCommon.SDK_VERSION
    XCODE_VERSION = OsxCommon.XCODE_VERSION

    def __init__(self, name):
        dev = f"/Applications/Xcode_{self.XCODE_VERSION}.app/Contents/Developer"
        sdkroot = f"{dev}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX{self.SDK_VERSION}.sdk"
        Task.__init__(
            self,
            description=f"macossdk {self.SDK_VERSION}",
            task_env=TaskEnvironment.by_name("arm64-osx.build"),
            command=[
                f"cp -RH {sdkroot} MacOSX{self.SDK_VERSION}.sdk",
                f"gtar --zstd -cf MacOSX{self.SDK_VERSION}.sdk.tar.zst MacOSX{self.SDK_VERSION}.sdk",
            ],
            artifact=f"MacOSX{self.SDK_VERSION}.sdk.tar.zst",
            index=f"macossdk.{self.SDK_VERSION}",
        )

    def mount(self):
        return {f"directory:MacOSX{self.SDK_VERSION}.sdk": self}

    def install(self):
        return [f"export SDKROOT=$(realpath $PWD/MacOSX{self.SDK_VERSION}.sdk)"]
