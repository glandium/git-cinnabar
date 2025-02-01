# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import hashlib
import json
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(__file__)
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, ".."))

from itertools import chain

import osx  # noqa: F401
from tasks import (
    Task,
    TaskEnvironment,
    Tool,
    action,
    parse_version,
)
from tools import (
    ALL_MERCURIAL_VERSIONS,
    GIT_VERSION,
    MERCURIAL_VERSION,
    SOME_MERCURIAL_VERSIONS,
    Build,
    Git,
    Hg,
    install_rust,
    nproc,
)
from variables import *  # noqa: F403


def git_rev_parse(committish):
    return subprocess.check_output(
        ["git", "rev-parse", committish], text=True, cwd=os.path.join(BASE_DIR, "..")
    ).strip()


def is_old_hg(version):
    # `version` is a sha1 for trunk, which means it's >= 3.6
    if len(version) == 40:
        return False
    try:
        version = [int(x) for x in version.split(".")]
    except ValueError:
        # Assume that an invalid version per the conversion above is
        # newer.
        return False
    return version < [3, 6]


UPGRADE_FROM = ()  # ('0.5.0',)


class TestTask(Task):
    coverage = []

    def __init__(self, **kwargs):
        git = kwargs.pop("git", GIT_VERSION)
        hg = kwargs.pop("hg", MERCURIAL_VERSION)
        hg_clone = kwargs.pop("hg_clone", None)
        commit = kwargs.pop("commit", None)
        task_env = kwargs.pop("task_env", "linux")
        variant = kwargs.pop("variant", None)
        build = kwargs.pop("build", None)
        clone = kwargs.pop("clone", TC_COMMIT)
        desc = kwargs.pop("description", None)
        short_desc = kwargs.pop("short_desc", "test")
        extra_desc = kwargs.pop("extra_desc", None)
        pre_command = kwargs.pop("pre_command", None)
        if build is None:
            build = "{}.{}".format(task_env, variant) if variant else task_env
            build = Build.by_name(build)
            kwargs.setdefault("mounts", []).append(build.mount())
            build = build.install()
        if variant:
            kwargs.setdefault("env", {})["VARIANT"] = variant
        env = TaskEnvironment.by_name("{}.test".format(task_env))
        command = []
        if pre_command:
            command.extend(pre_command)
        if hg:
            hg_task = Hg.by_name("{}.{}".format(task_env, hg))
            kwargs.setdefault("mounts", []).append(hg_task.mount())
            command.extend(hg_task.install())
            command.append("hg --version")
            if is_old_hg(hg):
                kwargs.setdefault("env", {})["NO_CLONEBUNDLES"] = "1"
        if git:
            git_task = Git.by_name("{}.{}".format(task_env, git))
            kwargs.setdefault("mounts", []).append(git_task.mount())
            command.extend(git_task.install())
            command.append("git --version")
        command.extend(Task.checkout(commit=commit))
        command.extend(build)
        if clone:
            kwargs.setdefault("mounts", []).append(
                {"file:bundle.git": Clone.by_name(clone)}
            )
            command.extend(
                [
                    "git init repo/hg.old.git",
                    "git -C repo/hg.old.git fetch ../../bundle.git refs/*:refs/*",
                    "git -C repo/hg.old.git remote add origin hg:${REPO#https:}",
                    "git -C repo/hg.old.git symbolic-ref HEAD"
                    " refs/heads/branches/default/tip",
                ]
            )
            kwargs.setdefault("env", {})["REPO"] = REPO
        command.extend(("repo/git-cinnabar --version",))
        if "command" not in kwargs or hg_clone:
            command += [
                "hg init repo/hg.pure.hg",
                "hg -R repo/hg.pure.hg unbundle bundle.hg",
            ]
            kwargs.setdefault("mounts", []).append(
                {"file:bundle.hg": HgClone.by_name(MERCURIAL_VERSION)}
            )
        if "command" in kwargs:
            kwargs["command"] = command + kwargs["command"]
        else:
            if commit:
                # Always use the current CI scripts
                command.append(
                    "git -C repo -c core.autocrlf=input checkout {} CI".format(
                        TC_COMMIT
                    )
                )
            output_sync = " --output-sync=target"
            if env.os == "macos":
                output_sync = ""
            kwargs["command"] = command + [
                "make -C repo -f CI/tests.mk -j$({}){}".format(nproc(env), output_sync),
            ]

        if variant == "coverage":
            kwargs["command"].extend(
                [
                    "shopt -s nullglob",
                    "cd repo",
                    'zip $ARTIFACTS/coverage.zip $(find . -name "*.profraw")',
                    "cd ..",
                    "shopt -u nullglob",
                ]
            )
            artifact = kwargs.pop("artifact", None)
            artifacts = kwargs.setdefault("artifacts", [])
            assert not (artifacts and artifact)
            if artifact:
                artifacts.push(artifact)
            artifacts.append("coverage.zip")
            self.coverage.append(self)
            kwargs.setdefault("env", {})["LLVM_PROFILE_FILE"] = "/repo/%m.profraw"
        elif variant == "asan" and task_env == "linux":
            kwargs["caps"] = ["SYS_PTRACE"]
        if not desc:
            desc = "{} w/ git-{} hg-{}".format(
                short_desc, git, "r" + hg if len(hg) == 40 else hg
            )
            if variant and variant != "coverage":
                desc = " ".join((desc, variant))
        if extra_desc:
            desc = " ".join((desc, extra_desc))
        if task_env != "linux":
            desc = " ".join((desc, env.os, env.cpu))
        kwargs["description"] = desc
        Task.__init__(self, task_env=env, **kwargs)


class Clone(TestTask, metaclass=Tool):
    PREFIX = "clone"

    def __init__(self, version):
        sha1 = git_rev_parse(version)
        expireIn = "26 weeks"
        kwargs = {}
        if version == TC_COMMIT or len(version) == 40:
            if version == TC_COMMIT:
                build = Build.by_name("linux")
            else:
                build = Build.by_name("linux.old:{}".format(version))
            kwargs.setdefault("mounts", []).append(build.mount())
            download = build.install()
            expireIn = "26 weeks"
        elif parse_version(version) < parse_version("0.6.0"):
            download = ["repo/git-cinnabar download"]
            if parse_version(version) < parse_version("0.5.7"):
                kwargs["git"] = "2.30.2"
        else:
            download = ["repo/download.py"]
        if REPO == DEFAULT_REPO:
            index = "bundle.{}".format(sha1)
        else:
            index = "bundle.{}.{}".format(hashlib.sha1(REPO).hexdigest(), sha1)
        TestTask.__init__(
            self,
            hg=MERCURIAL_VERSION,
            hg_clone=True,
            description="clone w/ {}".format(version),
            index=index,
            expireIn=expireIn,
            build=download,
            commit=sha1,
            clone=False,
            command=[
                "PATH=$PWD/repo:$PATH"
                " git -c fetch.prune=true clone -n hg::$PWD/repo/hg.pure.hg"
                " hg.old.git",
                "git -C hg.old.git bundle create $ARTIFACTS/bundle.git --all",
            ],
            artifact="bundle.git",
            priority="high",
            **kwargs,
        )


class HgClone(Task, metaclass=Tool):
    PREFIX = "hgclone"

    def __init__(self, version):
        if REPO == DEFAULT_REPO:
            index = "hgclone.{}".format(version)
        else:
            index = "hgclone.{}.{}".format(hashlib.sha1(REPO).hexdigest(), version)
        hg_task = Hg.by_name(f"linux.{version}")
        Task.__init__(
            self,
            task_env=TaskEnvironment.by_name("linux.test"),
            description=f"hg clone w/ {version}",
            index=index,
            expireIn="26 weeks",
            command=hg_task.install()
            + [
                "hg clone -U --stream $REPO repo",
                "hg -R repo bundle -t none-v1 -a $ARTIFACTS/bundle.hg",
            ],
            mounts=[hg_task.mount()],
            artifact="bundle.hg",
            env={
                "REPO": REPO,
            },
            priority="high",
        )


@action("decision")
def decision():
    for env in ("linux", "mingw64", "osx", "arm64-osx"):
        # Can't spawn osx workers from pull requests.
        if env.endswith("osx") and not TC_IS_PUSH and not IS_GH:
            continue

        TestTask(
            task_env=env,
            variant="coverage" if env == "linux" else None,
        )

        task_env = TaskEnvironment.by_name("{}.test".format(env))
        git = Git.by_name("{}.{}".format(env, GIT_VERSION))
        build = Build.by_name(env)
        bin = os.path.basename(build.artifacts[0])
        Task(
            task_env=task_env,
            description="download build {} {}".format(task_env.os, task_env.cpu),
            command=list(
                chain(
                    git.install(),
                    Task.checkout(),
                    build.install(),
                    [
                        f"python3 repo/CI/test_download.py repo/{bin}",
                    ],
                )
            ),
            mounts=[
                git.mount(),
                build.mount(),
            ],
        )

    # Because nothing is using the arm64 linux build, we need to manually
    # touch it.
    Build.by_name("arm64-linux")

    for upgrade in UPGRADE_FROM:
        TestTask(
            short_desc="upgrade tests",
            extra_desc="from-{}".format(upgrade),
            variant="coverage",
            clone=upgrade,
            env={
                "UPGRADE_FROM": upgrade,
            },
            hg="5.4.2",
        )

    for git in ("1.8.5", "2.7.4"):
        TestTask(git=git, env={"GIT_OLD_VERSION": "1"})

    for hg in SOME_MERCURIAL_VERSIONS:
        if hg != MERCURIAL_VERSION:
            do_hg_version(hg)

    TestTask(
        task_env="linux",
        variant="asan",
    )

    for env in ("linux", "mingw64", "osx", "arm64-osx"):
        # Can't spawn osx workers from pull requests.
        if env.endswith("osx") and not TC_IS_PUSH and not IS_GH:
            continue

        TestTask(
            task_env=env,
            variant="coverage" if env == "linux" else None,
            short_desc="graft tests",
            env={
                "GRAFT": "1",
            },
        )

    for env, variant in (
        ("linux", "coverage"),
        ("linux", "asan"),
        ("osx", None),
        ("arm64-osx", None),
    ):
        # Can't spawn osx workers from pull requests.
        if env.endswith("osx") and not TC_IS_PUSH and not IS_GH:
            continue

        pre_command = []
        if env != "linux":
            pre_command.append("pip install cram==0.7")

        TestTask(
            task_env=env,
            variant=variant,
            short_desc="cram",
            clone=False,
            command=pre_command
            + [
                "cram --verbose repo/tests",
            ],
            env={
                "GIT_CINNABAR_CHECK": "no-version-check",
            },
        )


def do_hg_version(hg):
    TestTask(hg=hg)
    # Don't run cram tests for version < 3.6, which would need
    # different tests because of server-side changes in behavior
    # wrt bookmarks.
    if not is_old_hg(hg):
        TestTask(
            short_desc="cram",
            clone=False,
            hg=hg,
            command=[
                "cram --verbose repo/tests",
            ],
            env={
                "GIT_CINNABAR_CHECK": "no-version-check",
            },
        )


@action(
    "more-hg-versions",
    title="More hg versions",
    description="Trigger tests against more mercurial versions",
)
def more_hg_versions():
    for hg in ALL_MERCURIAL_VERSIONS:
        if hg != MERCURIAL_VERSION and hg not in SOME_MERCURIAL_VERSIONS:
            do_hg_version(hg)


@action(
    "hg-trunk",
    title="Test w/ hg trunk",
    description="Trigger tests against current mercurial trunk",
)
def hg_trunk():
    import requests

    r = requests.get("https://www.mercurial-scm.org/repo/hg/?cmd=branchmap")
    trunk = None
    for l in r.text.splitlines():
        fields = l.split()
        if fields[0] == "default":
            trunk = fields[-1]
    if not trunk:
        raise Exception("Cannot find mercurial trunk changeset")
    do_hg_version(trunk)


def tasks():
    try:
        func = action.by_name[TC_ACTION or "decision"].func
    except AttributeError:
        raise Exception("Unsupported action: %s", TC_ACTION or "decision")

    func()

    merge_coverage = []

    if TestTask.coverage and TC_IS_PUSH and TC_BRANCH and IS_GH:
        coverage_mounts = [
            {f"file:cov-{task.id}.zip": task} for task in TestTask.coverage
        ]
        task = Build.by_name("linux.coverage")
        coverage_mounts.append(task.mount())

        merge_coverage.extend(install_rust())
        merge_coverage.append("rustup component add llvm-tools-preview")
        merge_coverage.append(
            "grcov -s repo -t lcov -o repo/coverage.lcov -b git-cinnabar "
            + " ".join(f"cov-{task.id}.zip" for task in TestTask.coverage)
        )

    if merge_coverage:
        Task(
            task_env=TaskEnvironment.by_name("linux.codecov"),
            description="upload coverage",
            mounts=coverage_mounts,
            command=list(
                chain(
                    Task.checkout(),
                    merge_coverage,
                    [
                        "cd repo",
                        'codecov -Z --name "taskcluster" -C {} -B {}'.format(
                            TC_COMMIT, TC_BRANCH
                        ),
                    ],
                )
            ),
            env={
                "CODECOV_TOKEN": "$CODECOV_TOKEN",
            },
        )


def print_output(name, value):
    if not isinstance(value, str):
        value = json.dumps(value, separators=(",", ":"))
    print(f"{name}={value}")


def main_gh():
    tasks()

    RUNNER = {
        "linux": "ubuntu-latest",
        "osx": "macos-13",
        "macos": "macos-14",
        "windows": "windows-latest",
    }
    matrix = {}
    artifacts = {}
    mounts = {}
    for t in Task.by_id.values():
        key = t.key
        task = t.task
        payload = task.get("payload", {})
        name = task.get("metadata", {})["name"]
        job_name = name.split()[0]
        if job_name == "hg" and name.startswith("hg clone"):
            job_name = "hg-clone"
        if job_name in ("docker", "msys2") and "base" in name:
            job_name = f"{job_name}-base"
        matrix.setdefault(job_name, []).append(
            {
                "task": name,
                "runner": RUNNER[task["workerType"]],
            }
        )
        for mount in payload.get("mounts", []):
            content = mount["content"]
            mounts.setdefault(name, []).append(
                {
                    "artifact": content["artifact"],
                    "key": Task.by_id[content["taskId"]].key,
                }
            )

        if payload.get("artifacts"):
            assert name not in artifacts
            artifacts[name] = {
                "paths": [
                    os.path.basename(artifact["name"])
                    for artifact in payload.get("artifacts", [])
                ],
                "key": key,
            }
    for m in matrix.values():
        m.sort(key=lambda x: x["task"])
    print_output("matrix", matrix)
    print_output("artifacts", artifacts)
    print_output("mounts", mounts)


def main_tc():
    tasks()

    run_tasks = {}

    def add_task(t):
        if t in run_tasks:
            return
        for d in t.task.get("dependencies"):
            dep = Task.by_id.get(d)
            if dep and dep not in run_tasks:
                add_task(dep)
        run_tasks[t] = None

    for t in Task.by_id.values():
        if TC_ACTION or t.task.get("metadata", {}).get("name", "").startswith("build"):
            add_task(t)

    for t in run_tasks:
        t.submit()

    if not TC_ACTION and "TC_GROUP_ID" in os.environ:
        actions = {
            "version": 1,
            "actions": [],
            "variables": {
                "e": dict(TC_DATA, decision_id=""),
                "tasks_for": "action",
            },
        }
        for name, a in action.by_name.items():
            if name != "decision":
                actions["actions"].append(
                    {
                        "kind": "task",
                        "name": a.name,
                        "title": a.title,
                        "description": a.description,
                        "context": [],
                        "task": a.task,
                    }
                )

        with open("actions.json", "w") as out:
            out.write(json.dumps(actions, indent=True))


if __name__ == "__main__":
    if IS_GH:
        main_gh()
    else:
        main_tc()
