# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import errno
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

import decision
from tasks import Task


def link_or_copy(src, dest):
    try:
        os.link(src, dest)
    except OSError as e:
        if e.errno == errno.EXDEV:
            shutil.copy2(src, dest)
        else:
            raise


def run_task(task, cwd, out=None, cache=None, recurse=True):
    id = task.id
    key = task.key
    task = task.task

    expected_system = {
        "windows": ("Windows", "AMD64"),
        "linux": ("Linux", "x86_64"),
        "osx": ("Darwin", "x86_64"),
        "macos": ("Darwin", "arm64"),
    }.get(task["workerType"], (None, None))
    if (platform.system(), platform.machine()) != expected_system:
        name = task.get("metadata", {}).get("name")
        raise RuntimeError(
            f"Cannot run '{name}' on {platform.system()} {platform.machine()}"
        )

    payload = task.get("payload", {})
    with tempfile.TemporaryDirectory(prefix="task", dir=cwd) as task_dir:
        for mount in payload.get("mounts", []):
            content = mount.get("content", {})
            task_id = content["taskId"]
            dep_task = Task.by_id[task_id]
            if cache:
                artifacts_base_dir = os.path.join(cache, dep_task.key)
            else:
                artifacts_base_dir = os.path.join(cwd, task_id)
            artifact = os.path.join(artifacts_base_dir, content["artifact"])
            if not os.path.exists(artifact):
                if recurse:
                    run_task(dep_task, cwd, cache=cache)
                else:
                    raise RuntimeError(f"Missing dependency {artifact}")

            if directory := mount.get("directory"):
                assert "file" not in mount
                directory = os.path.join(task_dir, directory)
                assert mount.get("format", "tar.zst")
                print(f"Extracting {os.path.basename(artifact)}", file=sys.stderr)
                start = time.monotonic()
                with subprocess.Popen(
                    ["zstd", "-cd", artifact], stdout=subprocess.PIPE
                ) as proc:
                    stdout = io.BufferedReader(proc.stdout, 1024 * 1024)
                    with tarfile.open(fileobj=stdout, mode="r|") as tar:
                        for tarinfo in tar:
                            # We want to preserve file mode, but not timestamps. Owner would only
                            # matter when running as Admin/root, but we're not expecting to be.
                            tar.extract(tarinfo, path=directory, set_attrs=False)
                            if tarinfo.type == tarfile.REGTYPE:
                                os.chmod(
                                    os.path.join(directory, tarinfo.name), tarinfo.mode
                                )
                end = time.monotonic()
                print(f"Took {end - start:.2f}s", file=sys.stderr)
            elif file := mount.get("file"):
                assert "directory" not in mount
                link_or_copy(artifact, os.path.join(task_dir, file))
            else:
                assert False

        env = os.environ.copy()
        env.update(payload.get("env", {}))
        if task["workerType"] == "windows":
            task_cmd = os.path.join(task_dir, "task.cmd")
            with open(task_cmd, "w") as fh:
                fh.write("\n".join(payload.get("command", [])))
            subprocess.check_call([os.path.abspath(task_cmd)], cwd=task_dir, env=env)
        else:
            for command in payload.get("command", []):
                subprocess.check_call(command, cwd=task_dir, env=env)
        if cache:
            artifacts_base_dir = os.path.join(cache, key)
        else:
            artifacts_base_dir = os.path.join(cwd, id)
        if out:
            os.makedirs(out, exist_ok=True)
        for artifact in payload.get("artifacts", []):
            assert artifact.get("type") == "file"
            dest = os.path.join(artifacts_base_dir, artifact["name"])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            assert not artifact["name"].startswith("/")
            link_or_copy(os.path.join(task_dir, artifact["path"]), dest)
            if out:
                link_or_copy(dest, os.path.join(out, os.path.basename(dest)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=str, metavar="PATH")
    parser.add_argument("--out", type=str, metavar="PATH")
    parser.add_argument("--no-recurse", action="store_true")
    parser.add_argument("task")
    args = parser.parse_args()
    decision.tasks()

    with tempfile.TemporaryDirectory(prefix="run_task") as tmpdir:
        for t in Task.by_id.values():
            if t.task.get("metadata", {}).get("name") == args.task:
                run_task(
                    t,
                    cwd=tmpdir,
                    out=args.out,
                    cache=args.cache,
                    recurse=not args.no_recurse,
                )
                break
        else:
            print(f"Unknown task: {args.task}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
