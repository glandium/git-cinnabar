import atexit
import os
import subprocess
from git import (
    Git,
    GitProcess,
    sha1path,
)
from git.util import (
    one,
    next,
)
from contextlib import contextmanager
from collections import OrderedDict


class NoHelperException(Exception):
    pass


class GitHgHelper(object):
    _helper = False
    _last_manifest = None

    @classmethod
    def close(self):
        if self._helper:
            self._helper.wait()
        self._helper = None

    @classmethod
    @contextmanager
    def query(self, name, *args):
        if self._helper is False:
            if os.path.exists(os.path.join(os.environ.get('GIT_EXEC_PATH', ''),
                                           'git-cinnabar-helper')):
                self._helper = GitProcess('cinnabar-helper',
                                          stdin=subprocess.PIPE)
            else:
                self._helper = None

        if not self._helper:
            raise NoHelperException
        helper = self._helper
        helper.stdin.write('%s %s\n' % (name, ' '.join(args)))
        yield helper.stdout

    @classmethod
    def _read_file(self, expected_typ, stdout):
        hg_sha1 = stdout.read(41)
        if hg_sha1[-1] == '\n':
            from . import NULL_NODE_ID
            assert hg_sha1[:40] == NULL_NODE_ID
            return None
        typ, size = stdout.readline().split()
        size = int(size)
        assert expected_typ == 'auto' or typ == expected_typ
        ret = stdout.read(size)
        lf = stdout.read(1)
        assert lf == '\n'
        if expected_typ == 'auto':
            return typ, ret
        return ret

    @classmethod
    def cat_file(self, typ, sha1):
        try:
            with self.query('cat-file', sha1) as stdout:
                return self._read_file(typ, stdout)
        except NoHelperException:
            return Git.cat_file(typ, sha1)

    @classmethod
    def git2hg(self, sha1):
        try:
            with self.query('git2hg', sha1) as stdout:
                return self._read_file('blob', stdout)
        except NoHelperException:
            return Git.read_note('refs/notes/cinnabar', sha1)

    @classmethod
    def hg2git(self, hg_sha1):
        try:
            with self.query('hg2git', hg_sha1) as stdout:
                sha1 = stdout.read(41)
                assert sha1[-1] == '\n'
                return sha1[:40]
        except NoHelperException:
            ls = one(Git.ls_tree('refs/cinnabar/hg2git', sha1path(hg_sha1)))
            if not ls:
                from . import NULL_NODE_ID
                return NULL_NODE_ID
            mode, typ, gitsha1, path = ls
            return gitsha1

    @classmethod
    def _manifest(self, hg_sha1, git_sha1=None):
        try:
            with self.query('manifest', hg_sha1) as stdout:
                size = int(stdout.readline().strip())
                ret = stdout.read(size)
                lf = stdout.read(1)
                assert lf == '\n'
                from . import isplitmanifest
                for l in isplitmanifest(ret):
                    yield l
        except NoHelperException:
            from . import ManifestLine, GitHgStore
            attrs = {}
            if not git_sha1:
                git_sha1 = self.hg2git(hg_sha1)
            for mode, typ, filesha1, path in Git.ls_tree(git_sha1,
                                                         recursive=True):
                if path.startswith('git/'):
                    attr = GitHgStore.ATTR[mode]
                    if attr:
                        attrs[path[4:]] = attr
                else:
                    assert path.startswith('hg/')
                    path = path[3:]
                    line = ManifestLine(
                        name=path,
                        node=filesha1,
                        attr=attrs.get(path, ''),
                    )
                    yield line

    @classmethod
    def manifest(self, hg_sha1):
        git_sha1 = self.hg2git(hg_sha1)
        # TODO: Improve this horrible mess
        if self._last_manifest:
            from . import ManifestLine, GitHgStore
            gitreference, reference_lines = self._last_manifest
            lines = []
            attrs = {}
            removed = set()
            modified = {}
            created = OrderedDict()
            for line in Git.diff_tree(gitreference, git_sha1, recursive=True):
                mode_before, mode_after, sha1_before, sha1_after, status, \
                    path = line
                if path.startswith('git/'):
                    if status != 'D':
                        attr = GitHgStore.ATTR[mode_after]
                        attrs[path[4:]] = attr
                else:
                    assert path.startswith('hg/')
                    path = path[3:]
                    if status == 'D':
                        removed.add(path)
                    elif status == 'M':
                        modified[path] = (sha1_after, attrs.get(path))
                    else:
                        assert status == 'A'
                        created[path] = (sha1_after, attrs.get(path))
            for path, attr in attrs.iteritems():
                if not path in modified:
                    modified[path] = (None, attr)
            iter_created = created.iteritems()
            next_created = next(iter_created)
            for line in reference_lines:
                if line.name in removed:
                    continue
                mod = modified.get(line.name)
                if mod:
                    node, attr = mod
                    if attr is None:
                        attr = line.attr
                    if node is None:
                        node = line.node
                    line = ManifestLine(line.name, node, attr)
                while next_created and next_created[0] < line.name:
                    node, attr = next_created[1]
                    created_line = ManifestLine(next_created[0], node, attr)
                    lines.append(created_line)
                    next_created = next(iter_created)
                lines.append(line)
            while next_created:
                node, attr = next_created[1]
                created_line = ManifestLine(next_created[0], node, attr)
                lines.append(created_line)
                next_created = next(iter_created)

        else:
            lines = list(self._manifest(hg_sha1, git_sha1))

        self._last_manifest = (git_sha1, lines)
        return lines


atexit.register(GitHgHelper.close)
