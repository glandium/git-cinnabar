# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import hashlib

from tasks import (
    TaskEnvironment,
    bash_command,
)


class OsxCommon(object):
    os = "macos"
    cpu = "x86_64"

    def __init__(self, name):
        self.hexdigest = hashlib.sha1(self.ITERATION.encode("utf-8")).hexdigest()
        self.name = name

    def prepare_params(self, params):
        assert "workerType" not in params
        params["provisionerId"] = "proj-git-cinnabar"
        params["workerType"] = self.WORKER_TYPE
        command = []
        command.append("export PWD=$(pwd)")
        command.append("export ARTIFACTS=$PWD")
        command.extend(params["command"])
        params["command"] = bash_command(*command)
        env = params.setdefault("env", {})
        dev = env.setdefault(
            "DEVELOPER_DIR", "/Applications/Xcode_14.1.app/Contents/Developer"
        )
        env.setdefault(
            "SDKROOT",
            "{}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX13.0.sdk".format(dev),
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
        dev = env.setdefault(
            "DEVELOPER_DIR", "/Applications/Xcode_15.0.1.app/Contents/Developer"
        )
        env.setdefault(
            "SDKROOT",
            "{}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.0.sdk".format(dev),
        )
        env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
        params["command"].insert(0, "export PATH=$PATH:/opt/homebrew/bin")
        return super(OsxArm64, self).prepare_params(params)
