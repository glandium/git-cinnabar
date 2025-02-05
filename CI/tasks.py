# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import datetime
import hashlib
import numbers
import os
import random
import re
from collections import OrderedDict
from uuid import UUID

from pkg_resources import parse_version  # noqa: F401
from variables import *  # noqa: F403

rand = random.Random()
rand.seed(int(hashlib.sha256(TC_COMMIT.encode()).hexdigest(), 16))


def uuid4():
    return UUID(int=rand.getrandbits(128), version=4)


def slugid():
    rawBytes = bytearray(uuid4().bytes)
    # Ensure base64-encoded bytes start with [A-Za-f]
    if rawBytes[0] >= 0xD0:
        rawBytes[0] = rawBytes[0] & 0x7F
    result = base64.urlsafe_b64encode(rawBytes)[:-2]  # Drop '==' padding
    return result.decode()


timedelta = datetime.timedelta


class datetime(datetime.datetime):
    def format(self, no_usec=True):
        if no_usec:
            return self.replace(microsecond=0).isoformat() + "Z"
        if self.microsecond == 0:
            return self.isoformat() + ".000000Z"
        return self.isoformat() + "Z"

    def __add__(self, other):
        if isinstance(other, numbers.Number):
            other = timedelta(seconds=other)
        d = super(datetime, self).__add__(other)
        return self.combine(d.date(), d.timetz())


task_group_id = os.environ.get("TASK_GROUP_ID") or os.environ.get("TASK_ID") or slugid()
now = datetime.fromtimestamp(0)


class TaskNamespace(type):
    @classmethod
    def by_name(cls, fqdn):
        env = cls._namespace.get(fqdn)
        if not env:
            n = fqdn.split(".")
            prefix = n[:-1]
            name = n[-1:]
            while prefix:
                kls = cls._namespace.get(".".join(prefix))
                if isinstance(kls, type):
                    cls._namespace[fqdn] = env = kls(".".join(name))
                    break
                name.insert(0, prefix.pop())
        return env

    def __new__(cls, name, bases, dic):
        @classmethod
        def by_name(kls, name):
            return cls.by_name(".".join((kls.PREFIX, name)))

        dic["by_name"] = by_name

        kls = super(TaskNamespace, cls).__new__(cls, name, bases, dic)
        cls._namespace[dic["PREFIX"]] = kls
        return kls


class Tool(TaskNamespace):
    _namespace = OrderedDict()


class TaskEnvironment(TaskNamespace):
    _namespace = OrderedDict()


class Task(object):
    by_id = OrderedDict()

    @staticmethod
    def normalize_params(params):
        try:
            artifact = params.pop("artifact")
            assert "artifacts" not in params
            params["artifacts"] = [artifact]
        except KeyError:
            pass
        return params

        try:
            mount = params.pop("mount")
            assert "mounts" not in params
            params["mounts"] = [mount]
        except KeyError:
            pass

    @staticmethod
    def checkout(repo=None, commit=None, dest="repo"):
        repo = repo or TC_REPO_URL
        commit = commit or TC_COMMIT
        return [
            "git clone -n {} {}".format(repo, dest),
            "git -C {} fetch origin {}".format(dest, commit),
            "git -c core.autocrlf=input -c advice.detachedHead=false"
            " -C {} checkout {}".format(dest, commit),
        ]

    def __init__(self, **kwargs):
        task_env = kwargs.pop("task_env", None)
        kwargs = self.normalize_params(kwargs)
        if task_env:
            kwargs = task_env.prepare_params(kwargs)

        task = {
            "workerType": "linux",
            "metadata": {},
            "payload": {},
        }
        artifact_paths = []

        for k, v in kwargs.items():
            if k in ("workerType",):
                task[k] = v
            elif k == "description":
                task["metadata"][k] = task["metadata"]["name"] = v
            elif k == "index":
                task["routes"] = ["index.project.git-cinnabar.{}".format(v)]
            elif k == "command":
                task["payload"]["command"] = v
                if not kwargs.get("workerType", "").startswith("win"):
                    task["payload"]["command"] = [task["payload"]["command"]]

            elif k == "artifacts":
                artifacts = [
                    {
                        "name": "public/{}".format(os.path.basename(a)),
                        "path": a,
                        "type": "file",
                    }
                    for a in v
                ]
                artifact_paths.extend(a["name"] for a in artifacts)
                task["payload"]["artifacts"] = artifacts
            elif k == "env":
                task["payload"].setdefault("env", {}).update(v)
            elif k == "mounts":

                def file_format(url):
                    for ext in ("rar", "tar.zst", "tar.bz2", "tar.gz", "zip"):
                        if url.endswith(".{}".format(ext)):
                            return ext
                    raise Exception("Unsupported/unknown format for {}".format(url))

                mounts = task["payload"]["mounts"] = []
                for m in v:
                    assert isinstance(m, dict)
                    m = list(m.items())
                    assert len(m) == 1
                    kind, m = m[0]
                    if isinstance(m, Task):
                        content = {
                            "artifact": m.artifacts[0],
                            "taskId": m.id,
                        }
                    elif isinstance(m, dict):
                        content = m
                    else:
                        content = {
                            "url": m,
                        }
                    artifact = content.get("artifact") or content["url"]
                    if kind == "file" or kind.startswith("file:"):
                        mount = {
                            "content": content,
                            "file": kind[5:] or os.path.basename(artifact),
                        }
                        if kind[5:] == "dockerimage":
                            mount["format"] = os.path.splitext(content["artifact"])[
                                -1
                            ].replace(".", "")
                        mounts.append(mount)
                    elif kind == "directory" or kind.startswith("directory:"):
                        mounts.append(
                            {
                                "content": content,
                                "directory": os.path.dirname(kind[10:]) or ".",
                                "format": file_format(artifact),
                            }
                        )
            else:
                raise Exception("Don't know how to handle {}".format(k))
        self.id = slugid()
        if len(artifact_paths) > 1:
            self.artifacts = artifact_paths
        elif artifact_paths:
            self.artifact = artifact_paths[0]
            self.artifacts = [self.artifact]
        else:
            self.artifacts = []
        self.task = task
        Task.by_id.setdefault(self.id, self)

    @property
    def key(self):
        if routes := self.task.get("routes"):
            assert len(routes) == 1
            return routes[0]
        return self.id

    def __str__(self):
        return self.id


SHELL_QUOTE_RE = re.compile(r"[\\\t\r\n \'\"#<>&|`~(){}$;\*\?]")


def _quote(s, for_windows=False):
    if s and not SHELL_QUOTE_RE.search(s):
        return s
    if for_windows:
        for c in "^&\\<>|":
            s = s.replace(c, "^" + c)
    return "'{}'".format(s.replace("'", "'\\''"))


def join_command(*command, for_windows=False):
    return " ".join(_quote(a, for_windows) for a in command)


def bash_command(*commands):
    return ["bash", "-c", "-x", "-e", "; ".join(commands)]


class action(object):
    by_name = OrderedDict()

    def __init__(self, name, title=None, description=None):
        assert name not in self.by_name
        self.by_name[name] = self

    def __call__(self, func):
        self.func = func
        return func
