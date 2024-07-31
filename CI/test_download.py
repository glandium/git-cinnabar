# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import http.client
import http.server
import inspect
import itertools
import os
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

REPOSITORY = "https://github.com/glandium/git-cinnabar"


def do_test(cwd, worktree, git_cinnabar, download_py, package_py):
    # Avoid extra ls-remote traffic by forcing git to use a local mirror
    # created from the original clone.
    repo = cwd / "git-cinnabar"
    subprocess.check_call(
        [
            "git",
            "clone",
            "--bare",
            "--reference",
            worktree,
            REPOSITORY,
            repo,
        ]
    )
    env = os.environ.copy()
    env.update(
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0=f"url.{repo}.insteadOf",
        GIT_CONFIG_VALUE_0=REPOSITORY,
        GIT_CINNABAR_CHECK="no-version-check",
    )

    class CalledProcessError(subprocess.CalledProcessError):
        def __repr__(self):
            return (
                super().__repr__().removesuffix(")")
                + f", stdout={self.stdout!r}, stderr={self.stderr!r})"
            )

    def check_output(x, **kwargs):
        result = checked_call(
            subprocess.check_output, x, env=env, cwd=cwd, text=True, **kwargs
        )
        if isinstance(result, subprocess.CalledProcessError):
            result.__class__ = CalledProcessError
        if isinstance(result, Exception):
            return result
        return result.strip()

    def listdir(p):
        result = checked_call(os.listdir, p)
        if isinstance(result, Exception):
            return result
        return sorted(result)

    subprocess.run(
        [
            sys.executable,
            package_py,
            git_cinnabar,
        ],
        cwd=cwd,
        check=True,
    )
    pkg = cwd / os.listdir(cwd)[0]
    standalone_download_py = shutil.copy2(download_py, cwd)

    worktree_head = check_output(["git", "-C", worktree, "rev-parse", "HEAD"])
    head_version = check_output([git_cinnabar, "-V"])
    full_version = check_output([git_cinnabar, "--version"]).removesuffix("-modified")
    _, _, head = full_version.rpartition("-")
    head_branch = "release"
    if head_version.endswith(".0-a"):
        head_branch = "next"
    elif head_version.endswith(("-a", "-b")):
        head_branch = "master"
    # We may be testing a version that is not the current tip of the
    # head_branch. Update our mirror so that it is.
    subprocess.check_call(
        ["git", "-C", repo, "update-ref", f"refs/heads/{head_branch}", head]
    )
    tags = {
        v: check_output(["git", "-C", repo, "rev-parse", v])
        for v in ("0.6.3", "0.7.0beta1")
    }
    for last_tag in tags:
        pass

    BRANCHES = ("release", "master", "next")
    results = {
        script: {
            what: Result(check_output, [sys.executable, script, "--url"] + args)
            for what, args in itertools.chain(
                (
                    (None, []),
                    (head, ["--exact", head]),
                    (worktree_head, ["--exact", worktree_head]),
                ),
                ((v, ["--exact", sha1]) for v, sha1 in tags.items()),
                ((branch, ["--branch", branch]) for branch in BRANCHES),
            )
        }
        for script in (standalone_download_py, download_py)
    }
    urls = {
        what: result.value
        for what, result in results[download_py].items()
        if not isinstance(result.value, Exception)
    }

    status = Status()
    for k in results[download_py].keys():
        if k:
            status += assert_eq(
                results[standalone_download_py][k],
                results[download_py][k],
                "Same url should be used whether run standalone or not",
            )
    status += assert_eq(
        results[standalone_download_py][None],
        results[download_py]["release"],
        "Standalone download should download from release by default",
    )
    status += assert_eq(
        results[standalone_download_py][worktree_head],
        results[download_py][None],
        "Download from a worktree should download for the exact commit",
    )
    for branch in BRANCHES:
        if branch in urls and branch != "release":
            status += assert_startswith(
                urls[branch],
                "https://community-tc.services.mozilla.com/",
                f"Url from --branch {branch} should be on taskcluster",
            )
    if "release" in urls:
        status += assert_startswith(
            urls["release"],
            REPOSITORY,
            "Url from --branch release should be on github",
        )

    proxy = ProxyServer()
    try:
        if head_branch in urls:
            proxy.map(
                urls[head_branch], pkg if head_branch == "release" else git_cinnabar
            )
        if head in urls:
            url = urls[head]
            if url.startswith(REPOSITORY):
                proxy.map(url, pkg)
            else:
                proxy.map(url, git_cinnabar)

        env["HTTPS_PROXY"] = proxy.url
        env["GIT_SSL_NO_VERIFY"] = "1"

        versions = {}
        for v in itertools.chain(tags, [head]):
            git_cinnabar_v = cwd / v / git_cinnabar.name
            subprocess.run(
                [sys.executable, download_py, "-o", git_cinnabar_v, "--exact", v],
                cwd=cwd,
                env=env,
            )
            status += assert_eq(
                Result(listdir, cwd / v),
                sorted((git_cinnabar.name, f"git-remote-hg{git_cinnabar.suffix}")),
            )
            status += assert_eq(
                Result(check_output, [git_cinnabar_v, "-V"]),
                head_version
                if v == head
                else f"git-cinnabar {v.replace('beta', '-beta.')}",
            )
            versions[v] = check_output([git_cinnabar_v, "--version"])

        for v in versions:
            if last_tag in urls:
                update_dir = cwd / "update" / v
                shutil.copytree(cwd / v, update_dir, symlinks=True, dirs_exist_ok=True)
                git_cinnabar_v = update_dir / git_cinnabar.name
                status += assert_eq(
                    Result(
                        check_output,
                        [git_cinnabar_v, "self-update"],
                        stderr=subprocess.STDOUT,
                    ),
                    "WARNING Did not find an update to install."
                    if v in (head, head_version)
                    else f"Installing update from {urls[last_tag]}",
                )
                status += assert_eq(
                    Result(check_output, [git_cinnabar_v, "--version"]),
                    versions[head] if v == head else versions[last_tag],
                )
                shutil.rmtree(update_dir)

            if head_branch in urls:
                shutil.copytree(cwd / v, update_dir, symlinks=True, dirs_exist_ok=True)
                status += assert_eq(
                    Result(
                        check_output,
                        [git_cinnabar_v, "self-update", "--branch", head_branch],
                        stderr=subprocess.STDOUT,
                    ),
                    "WARNING Did not find an update to install."
                    if v in (head, head_version)
                    else f"Installing update from {urls[head_branch]}",
                )
                status += assert_eq(
                    Result(check_output, [git_cinnabar_v, "--version"]),
                    versions[head],
                )
                shutil.rmtree(update_dir)

    finally:
        proxy.shutdown()

    return status.as_return_code()


def main():
    assert len(sys.argv) <= 2
    if len(sys.argv) == 2:
        git_cinnabar = Path(sys.argv[1]).resolve()
        if not git_cinnabar.exists():
            print(f"{sys.argv[1]} not found")
            return 1
        if not git_cinnabar.is_file():
            print(f"{sys.argv[1]} not a file")
            return 1
    else:
        git_cinnabar = shutil.which("git-cinnabar")
        if not git_cinnabar:
            print("A git-cinnabar executable couldn't be found in $PATH")
            return 1
        git_cinnabar = Path(git_cinnabar)
    worktree = Path(__file__).parent.parent.absolute()
    git = worktree / ".git"
    download_py = worktree / "download.py"
    package_py = worktree / "CI" / "package.py"
    for f in (git, download_py, package_py):
        if not f.exists():
            print(f"{f} doesn't exist.")
            return 1
    with TemporaryDirectory() as d:
        return do_test(Path(d), worktree, git_cinnabar, download_py, package_py)


class Status:
    def __init__(self):
        self.success = True

    def __iadd__(self, other):
        self.success = bool(other) and self.success
        return self

    def as_return_code(self):
        return 0 if self.success else 1


class Func:
    def __init__(self, func):
        self.func = func

    def __repr__(self):
        func = self.func
        code = getattr(func, "__code__", None)
        if code:
            return f"{func.__name__}@{code.co_filename}:{code.co_firstlineno}"
        return func.__name__

    def __eq__(self, other):
        return other == self.func


class Args:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __repr__(self):
        args = (repr(a) for a in self.args)
        kwargs = (f"{k}={v!r}" for k, v in self.kwargs.items())
        return ", ".join(itertools.chain(args, kwargs))


class Result:
    def __init__(self, func, *args, **kwargs):
        self.func = Func(func)
        self.args = Args(*args, **kwargs)
        self.value = func(*args, **kwargs)

    def __repr__(self):
        return repr(self.value)

    def __eq__(self, other):
        return other == self.value

    def __getattr__(self, name):
        return getattr(self.value, name)


def assertion_message(assertion, msg):
    msg = f": {msg}" if msg else ""
    for frame in inspect.stack():
        info = inspect.getframeinfo(frame.frame)
        if not info.function.startswith("assert"):
            return (
                f"assertion `{assertion}` failed at {info.filename}:{info.lineno}{msg}"
            )
    # Just in case, but this shouldn't happen
    return f"assertion `{assertion}` failed{msg}"


def assert_op(op_msg, op, a, b, msg=None):
    if op(a, b):
        return True

    show = {}
    if isinstance(a, Result):
        show["f"] = a.func
        left = "f(a)"
        show["a"] = a.args
    else:
        left = "a"
    if isinstance(b, Result):
        f = show.get("f")
        if f:
            if b.func == f:
                right = "f(b)"
            else:
                show["g"] = b.func
                right = "g(b)"
            show["b"] = b.args
        else:
            show["f"] = b.func
            right = "f(b)"
    else:
        right = "b"
    show[left] = a
    show[right] = b
    print(
        assertion_message(op_msg.format(left=left, right=right), msg), file=sys.stderr
    )
    for k, v in show.items():
        if "f" in show:
            print(f"{k:>5}: {v!r}", file=sys.stderr)
        else:
            print(f" {k}: {v!r}", file=sys.stderr)
    return False


def assert_eq(a, b, msg=None):
    return assert_op("{left} == {right}", (lambda a, b: a == b), a, b, msg)


def assert_startswith(a, b, msg=None):
    def startswith(a, b):
        try:
            return a.startswith(b)
        except Exception:
            return False

    return assert_op("{left}.startswith({right})", startswith, a, b, msg)


def checked_call(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except Exception as e:
        return e


class ProxyServer(http.server.ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("localhost", 0), ProxyHTTPRequestHandler)
        self.mappings = {}
        self.url = f"http://localhost:{self.server_port}"
        self.thread = Thread(target=self.serve_forever)
        self.thread.start()

        this_script = Path(__file__)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Created with `openssl req -x509 -newkey rsa:2048 -keyout selfsigned.key
        # -out selfsigned.crt -days 36524 -nodes -subj "/CN=localhost"`
        self.context.load_cert_chain(
            this_script.with_name("selfsigned.crt"),
            this_script.with_name("selfsigned.key"),
        )

    def map(self, url, content):
        u = urllib.parse.urlparse(url)
        assert u.scheme == "https"
        path = u.path
        if u.query:
            path = f"{path}?{u.query}"
        self.mappings.setdefault((u.hostname, u.port or 443), {})[path] = content


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port)
        self.send_response_only(200)
        self.end_headers()

        mappings = self.server.mappings.get((host, port))
        if mappings:
            self.handle_locally(mappings, host, port)
        else:
            self.pass_through(host, port)

    def handle_locally(self, mappings, host, port):
        with self.server.context.wrap_socket(self.connection, server_side=True) as sock:
            HTTPRequestHandler(sock, self.client_address, (mappings, host, port))

    def pass_through(self, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))

            def relay(src, dest):
                try:
                    shutil.copyfileobj(
                        src.makefile("rb", buffering=False),
                        dest.makefile("wb", buffering=False),
                    )
                except ConnectionResetError:
                    pass

            t1 = Thread(target=relay, args=(self.connection, s))
            t1.start()
            t2 = Thread(target=relay, args=(s, self.connection))
            t2.start()
            t1.join()
            t2.join()


class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        mappings, host, port = self.server
        content = mappings.get(self.path)
        if content:
            self.send_content(content)
        else:
            self.pass_through(host, port)

    def log_request(self, code="-", size="-"):
        pass

    def send_content(self, content):
        self.send_response(200)
        if isinstance(content, str):
            content = content.encode()
        if isinstance(content, bytes):
            size = len(content)
        elif isinstance(content, Path):
            size = content.stat().st_size
        else:
            raise RuntimeError("mapped content is neither bytes, str nor Path")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        if isinstance(content, bytes):
            self.wfile.write(content)
        elif isinstance(content, Path):
            shutil.copyfileobj(content.open("rb"), self.wfile)

    def pass_through(self, host, port):
        conn = http.client.HTTPSConnection(host, port)
        conn.request("GET", self.path, headers=self.headers)
        response = conn.getresponse()
        self.send_response(response.status)
        for k, v in response.getheaders():
            self.send_header(k, v)
        self.end_headers()
        shutil.copyfileobj(response, self.wfile)


if __name__ == "__main__":
    sys.exit(main())
