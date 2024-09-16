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
import types
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

REPOSITORY = "https://github.com/glandium/git-cinnabar"

# The versions below are expected to be semantically ordered.
VERSIONS = {
    # Tag: Version in Cargo.toml
    "0.6.0rc2": "0.6.0-rc2",
    "0.6.0": "0.6.0",
    "0.6.3": "0.6.3",
    "0.7.0beta1": "0.7.0-beta.1",
    # Newer versions below. We're bound to what older versions were doing to find the
    # right download on self-update. I don't know what went through my head when I
    # made that code strip dashes from tag names...
    "0.7.0beta2": "0.7.0-beta.2",
    "0.7.0rc1": "0.7.0-rc.1",
    "0.7.0": "0.7.0",
    "0.7.1": "0.7.1",
    # Here's a trick to make things happy-ish in the future: older versions don't
    # handle tags prefixed with "v", but will still do a self-update to the first
    # one it finds.
    # Tag: Shortened version
    "v0.8.0-beta.1": "0.8.0beta1",
    "v0.8.0-rc.1": "0.8.0rc1",
    "v0.8.0": "0.8.0",
    "v0.8.1": "0.8.1",
    "v0.9.0-beta.1": "0.9.0beta1",
    "v0.9.0": "0.9.0",
    "v0.10.0-beta.1": "0.10.0beta1",
    "v0.10.0": "0.10.0",
}
VERSIONS_ORDER = {v: n for n, v in enumerate(VERSIONS)}


def version_for_tag(tag):
    if tag.startswith("v"):
        return tag[1:]
    return VERSIONS[tag]


def do_test(cwd, worktree, git_cinnabar, download_py, package_py, proxy):
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
    subprocess.check_call(
        ["git", "-C", repo, "fetch", worktree, "refs/tags/*:refs/tags/*"]
    )
    env = CommandEnvironment(cwd).derive_with(
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0=f"url.{repo}.insteadOf",
        GIT_CONFIG_VALUE_0=REPOSITORY,
        GIT_CINNABAR_CHECK="no-version-check",
        HTTPS_PROXY=proxy.url,
        GIT_SSL_NO_VERIFY="1",
    )

    def listdir(p):
        return sorted(os.listdir(p))

    executor = ThreadPoolExecutor(max_workers=1)

    def get_pkg():
        pkg_dir = cwd / "pkg"
        pkg_dir.mkdir()
        env.derive_with(cwd=pkg_dir).check_call(
            [
                sys.executable,
                package_py,
                git_cinnabar,
            ],
        )
        return pkg_dir / os.listdir(pkg_dir)[0]

    pkg = executor.submit(get_pkg)
    standalone_download_py = Path(shutil.copy2(download_py, cwd))

    worktree_head = env.check_output(["git", "-C", worktree, "rev-parse", "HEAD"])
    head_version = env.get_version([git_cinnabar, "-V"])
    head_full_version = env.get_version([git_cinnabar, "--version"])
    _, _, head = head_full_version.removesuffix("-modified").rpartition("-")
    head_branch = "release"
    if head_version.endswith(".0-a"):
        head_branch = "next"
    elif head_version.endswith(("-a", "-b")):
        head_branch = "master"
    # We may be testing a version that is not the current tip of the
    # head_branch. Update our mirror so that it is.
    env.check_call(["git", "-C", repo, "update-ref", f"refs/heads/{head_branch}", head])

    status = Status()
    last_known_tag = None
    previous_tag = None
    future_tags = {}
    tags = {}
    envs = {head: env}
    for t, v in VERSIONS.items():
        try:
            rev = env.check_output(
                ["git", "-C", repo, "rev-parse", t], stderr=subprocess.DEVNULL
            )
            last_known_tag = t
            envs[t] = env
        except Exception:
            assert previous_tag is not None
            previous_rev = tags[previous_tag]
            rev = env.derive_with(
                GIT_AUTHOR_NAME="foobar",
                GIT_AUTHOR_EMAIL="foo@bar",
                GIT_COMMITTER_NAME="foobar",
                GIT_COMMITTER_EMAIL="foo@bar",
            ).check_output(
                [
                    "git",
                    "-C",
                    repo,
                    "commit-tree",
                    f"{previous_rev}^{{tree}}",
                    "-p",
                    previous_rev,
                    "-m",
                    t,
                ]
            )
            repo_t = repo.parent / (repo.name + f"-{t}")
            envs[previous_tag].check_call(
                ["git", "clone", "--mirror", "--reference", repo, REPOSITORY, repo_t]
            )
            envs[t] = env.derive_with(GIT_CONFIG_KEY_0=f"url.{repo_t}.insteadOf")
            status += assert_eq(
                env.check_output(["git", "-C", repo_t, "tag", t, rev]), ""
            )
            future_tags[t] = None
        if v != t:
            assert v not in envs
            envs[v] = envs[t]
        tags[t] = rev
        previous_tag = t

    tag_by_sha1 = {sha1: t for t, sha1 in tags.items()}

    def get_url_with(script, args):
        use_env = None
        if args[:1] == ["--exact"]:
            use_env = envs.get(args[1])
            if not use_env:
                tag = tag_by_sha1.get(args[1])
                if tag:
                    use_env = envs.get(tag)
        if not use_env:
            use_env = env
        if script.suffix == ".py":
            cmd = [sys.executable, script]
        else:
            cmd = [script, "self-update"]
        return Result(
            use_env.check_output,
            cmd + ["--url"] + args,
            stderr=subprocess.PIPE,
        )

    BRANCHES = ("release", "master", "next")
    results = {
        script: {
            what: get_url_with(script, args)
            for what, args in itertools.chain(
                (
                    (None, []),
                    (head, ["--exact", head]),
                    (worktree_head, ["--exact", worktree_head]),
                ),
                ((t, ["--exact", t]) for t in tags),
                ((v, ["--exact", v]) for v in VERSIONS.values() if v not in tags),
                ((sha1, ["--exact", sha1]) for v, sha1 in tags.items()),
                ((branch, ["--branch", branch]) for branch in BRANCHES),
            )
        }
        for script in (standalone_download_py, download_py, git_cinnabar)
    }
    urls = {
        what: result.value
        for what, result in results[download_py].items()
        if not isinstance(result.value, Exception)
    }

    for t, v in VERSIONS.items():
        if t != v:
            status += assert_eq(
                results[download_py][t],
                results[download_py][v],
                "download.py should support different types of version strings",
            )

    for k in results[download_py].keys():
        if k:
            status += assert_eq(
                results[standalone_download_py][k],
                results[download_py][k],
                "Same url should be used whether run standalone or not",
            )
        if k and k != head_branch:
            status += assert_eq(
                results[download_py][k],
                results[git_cinnabar][k],
                "git cinnabar self-update should work the same as download.py",
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
        status += assert_eq(
            urls["release"],
            urls[last_known_tag],
            f"Url from --branch release should be the same as --exact {last_known_tag}",
        )
    for t, sha1 in tags.items():
        status += assert_eq(
            urls[t],
            urls[sha1],
            f"Url from --exact {t} should be the same as --exact {sha1}",
        )
        # Now that we've established that, we change the sha1 urls for vX.Y.Z tags
        # to point to TC. That's what versions prior to 0.7.0-beta.2 would use.
        if t.startswith("v"):
            urls[sha1] = get_url_with(download_py, ["--url", "--exact", sha1]).value

    full_versions = {t: f"{version_for_tag(t)}-{sha1}" for t, sha1 in tags.items()}
    mappings = {
        urls[h]: pkg if urls[h].startswith(REPOSITORY) else git_cinnabar
        for h in (head, None, "master", "next")
    }
    for h, url in urls.items():
        if h in (head, "master", "next"):
            full_versions[h] = head_full_version
        if url not in mappings:
            if h in future_tags:
                mappings[url] = pkg
            elif tag_by_sha1.get(h) in future_tags:
                mappings[url] = git_cinnabar
            else:
                mappings[url] = urllib.request.urlopen(url).read()
    for url, content in mappings.items():
        proxy.map(url, content)

    for t, v in itertools.chain([(head, head_version)], VERSIONS.items()):
        git_cinnabar_v = cwd / v / git_cinnabar.name
        envs[t].run(
            [sys.executable, download_py, "-o", git_cinnabar_v, "--exact", t],
        )
        status += assert_eq(
            Result(listdir, cwd / v),
            sorted((git_cinnabar.name, f"git-remote-hg{git_cinnabar.suffix}")),
        )
        status += assert_eq(
            Result(env.get_version, [git_cinnabar_v, "-V"]),
            head_version if t in future_tags else v,
        )

    for upgrade_to in itertools.chain([last_known_tag], future_tags):
        for t, v in itertools.chain(
            [(head, head_version)] if head_branch != "release" else [], VERSIONS.items()
        ):
            upgrade_env = envs[upgrade_to]
            if t in future_tags:
                upgrade_env = upgrade_env.derive_with(
                    GIT_CINNABAR_EXPERIMENTS="test",
                    GIT_CINNABAR_VERSION=v,
                    GIT_CINNABAR_MODIFIED="",
                    GIT_CINNABAR_COMMIT=tags[t],
                )
            git_cinnabar_v = cwd / v / git_cinnabar.name
            version = Result(
                upgrade_env.derive_with(GIT_CINNABAR_CHECK="").get_version,
                [git_cinnabar_v, "--version"],
                stderr=subprocess.STDOUT,
            )
            new_version_warning = ""
            # Starting with version 0.7.0beta1, a warning is shown when there is a
            # new version available. Unfortunately, 0.7.0beta1 has a bug that makes
            # it believe there's always an update even if it's the last version.
            # It also, like older versions doesn't support tags prefixed with "v",
            # and in that case, doesn't show the warning.
            if (
                "." in t
                and tuple(int(x) for x in t.replace("v", "").split(".")[:2]) >= (0, 7)
                and (
                    VERSIONS_ORDER[upgrade_to] > VERSIONS_ORDER[t] or t == "0.7.0beta1"
                )
                and (not upgrade_to.startswith("v") or t != "0.7.0beta1")
            ):
                new_version = version_for_tag(upgrade_to)
                current_version = ""
                if t == "0.7.0beta1":
                    new_version = upgrade_to.replace("b", "-b").replace("rc", "-rc")
                    current_version = f" (current version: {v})"
                new_version_warning = (
                    f"\n\nWARNING New git-cinnabar version available: {new_version}{current_version}"
                    "\n\nWARNING You may run `git cinnabar self-update` to update."
                )

            version_status = assert_eq(
                version,
                full_versions[t] + new_version_warning,
            )

            status += version_status
            version_status = True
            if not version_status or VERSIONS_ORDER[upgrade_to] <= VERSIONS_ORDER.get(
                t, -1
            ):
                continue

            for branch in (None,) + (BRANCHES if upgrade_to == last_known_tag else ()):
                update_dir = cwd / "update" / v
                if branch:
                    update_dir = update_dir / branch

                shutil.copytree(cwd / v, update_dir, symlinks=True, dirs_exist_ok=True)
                git_cinnabar_v = update_dir / git_cinnabar.name
                extra_args = []
                if branch:
                    extra_args += ["--branch", branch]
                if (
                    branch in (None, "release")
                    and VERSIONS_ORDER[upgrade_to] < VERSIONS_ORDER.get(t, -1)
                    or branch in (None, head_branch)
                    and t == head
                ):
                    update = None
                elif branch in (None, "release"):
                    if (
                        upgrade_to.startswith("v")
                        and VERSIONS_ORDER[t] <= VERSIONS_ORDER["0.7.0beta1"]
                    ):
                        # The mishandling of version parsing error in these versions
                        # makes it so that the first tag starting with "v" in alphanumeric
                        # order wins.
                        # Which, interestingly, means older versions will self-update to
                        # 0.8.0-beta.1, but no subsequent versions until 0.8.0.
                        # And jump to 0.10.0-beta.1 then 0.10.0. Of course, that only
                        # happens for versions that haven't been updated all that time.
                        mishandled_versions = [
                            v
                            for v in VERSIONS
                            if v.startswith("v")
                            and VERSIONS_ORDER[v] <= VERSIONS_ORDER[upgrade_to]
                        ]
                        update = tags[
                            min(mishandled_versions)
                            if mishandled_versions
                            else upgrade_to
                        ]
                    else:
                        update = upgrade_to
                else:
                    update = branch
                with proxy.capture_log() as log:
                    status += assert_eq(
                        Result(
                            upgrade_env.check_output,
                            [git_cinnabar_v, "self-update"] + extra_args,
                            stderr=subprocess.STDOUT,
                        ),
                        f"Installing update from {urls[update]}"
                        if update
                        else "WARNING Did not find an update to install.",
                    )
                if update:
                    status += assert_eq(log, [urls[update]])
                else:
                    status += assert_eq(log, [])
                status += assert_eq(
                    Result(env.get_version, [git_cinnabar_v, "--version"]),
                    full_versions[head if upgrade_to in future_tags else (update or t)],
                )
                shutil.rmtree(update_dir)

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
        proxy = ProxyServer()
        try:
            return do_test(
                Path(d), worktree, git_cinnabar, download_py, package_py, proxy
            )
        finally:
            proxy.shutdown()


class CommandEnvironment:
    def __init__(self, cwd, environ=os.environ):
        self.cwd = cwd
        self.env = environ.copy()

    class CalledProcessError(subprocess.CalledProcessError):
        def __repr__(self):
            return (
                super().__repr__().removesuffix(")")
                + f", stdout={self.stdout!r}, stderr={self.stderr!r})"
            )

    def check_call(self, x, **kwargs):
        return self.subprocess_func(subprocess.check_call, x, **kwargs)

    def check_output(self, x, **kwargs):
        return self.subprocess_func(subprocess.check_output, x, **kwargs)

    def run(self, x, **kwargs):
        return self.subprocess_func(subprocess.run, x, **kwargs)

    def subprocess_func(self, func, x, **kwargs):
        try:
            result = func(x, env=self.env, cwd=self.cwd, text=True, **kwargs)
        except Exception as e:
            if isinstance(e, subprocess.CalledProcessError):
                e.__class__ = self.CalledProcessError
            raise e
        if isinstance(result, str):
            return result.strip()
        return result

    def get_version(self, x, **kwargs):
        return self.check_output(x, **kwargs).removeprefix("git-cinnabar ")

    def derive_with(self, cwd=None, **kwargs):
        env = self.env.copy()
        for k, v in kwargs.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        return CommandEnvironment(self.cwd if cwd is None else cwd, env)

    def __repr__(self):
        return f"{self.__class__.__name__}(cwd={str(self.cwd)!r})"


class Status:
    def __init__(self):
        self.success = True

    def __iadd__(self, other):
        self.success = bool(other) and self.success
        return self

    def __bool__(self):
        return self.success

    def as_return_code(self):
        return 0 if self.success else 1


class Func:
    def __init__(self, func):
        self.func = func

    def __repr__(self):
        func = self.func
        name = func.__name__
        if code := getattr(func, "__code__", None):
            name = f"{name}@{code.co_filename}:{code.co_firstlineno}"
        if isinstance(func, types.MethodType):
            name = f"{func.__self__}.{name}"
        return name

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
        try:
            self.value = func(*args, **kwargs)
        except Exception as e:
            self.value = e

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


class ProxyServer(http.server.ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("localhost", 0), ProxyHTTPRequestHandler)
        self.log = None
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

    @contextmanager
    def capture_log(self):
        assert self.log is None
        self.log = []
        yield self.log
        self.log = None

    def log_url(self, url_elements):
        if self.log is not None:
            host, port, path = url_elements
            url = f"https://{host}"
            if port != 443:
                url += f":{port}"
            url += path
            self.log.append(url)

    @staticmethod
    def urlsplit(url):
        u = urllib.parse.urlsplit(url)
        assert u.scheme == "https"
        path = u.path
        if u.query:
            path = f"{path}?{u.query}"
        return (u.hostname, u.port or 443, path)

    def map(self, url, content):
        host, port, path = self.urlsplit(url)
        self.mappings.setdefault((host, port), {})[path] = content


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port)
        self.send_response_only(200)
        self.end_headers()

        mappings = self.server.mappings.get((host, port), {})
        if mappings or self.server.log is not None:
            self.handle_locally(mappings, host, port)
        else:
            self.pass_through(host, port)

    def handle_locally(self, mappings, host, port):
        with self.server.context.wrap_socket(self.connection, server_side=True) as sock:
            HTTPRequestHandler(
                sock, self.client_address, (self.server, mappings, host, port)
            )

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
        server, mappings, host, port = self.server
        content = mappings.get(self.path)
        server.log_url((host, port, self.path))
        if content:
            self.send_content(content)
        else:
            self.pass_through(host, port)

    def log_request(self, code="-", size="-"):
        pass

    def send_content(self, content):
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        if isinstance(content, Future):
            content = content.result()
        if isinstance(content, str):
            content = content.encode()
        if isinstance(content, bytes):
            content = BytesIO(content)
        elif isinstance(content, Path):
            content = content.open("rb")
        else:
            raise RuntimeError("mapped content is neither bytes, str nor Path")
        out = Chunker(self.wfile)
        shutil.copyfileobj(content, out)
        out.write(b"")

    def pass_through(self, host, port):
        conn = http.client.HTTPSConnection(host, port)
        conn.request("GET", self.path, headers=self.headers)
        response = conn.getresponse()
        self.send_response(response.status)
        for k, v in response.getheaders():
            self.send_header(k, v)
        self.end_headers()
        shutil.copyfileobj(response, self.wfile)


class Chunker:
    def __init__(self, out):
        self.out = out

    def write(self, data):
        self.out.write(f"{len(data):x}\r\n".encode())
        if data:
            self.out.write(data)
        self.out.write(b"\r\n")
        self.out.flush()


if __name__ == "__main__":
    sys.exit(main())
