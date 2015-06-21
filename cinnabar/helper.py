import atexit
import logging
import os
import re
import subprocess
from .git import (
    Git,
    GitProcess,
    Mark,
    NULL_NODE_ID,
    sha1path,
)
from .util import (
    one,
    next,
)
from contextlib import contextmanager
from collections import OrderedDict


SHA1_RE = re.compile('^[0-9a-fA-F]{40}$')


class NoHelperException(Exception):
    pass


class GitHgHelper(object):
    VERSION = 2
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
            git_exec_path = os.environ.get('GIT_EXEC_PATH')
            if (git_exec_path and not os.environ.get('GIT_CINNABAR_NO_HELPER')
                    and os.path.exists(os.path.join(git_exec_path,
                                                    'git-cinnabar-helper'))):
                self._helper = GitProcess('cinnabar-helper',
                                          stdin=subprocess.PIPE)
                if self._helper:
                    self._helper.stdin.write('version %d\n' % self.VERSION)
                    if not self._helper.stdout.readline():
                        self._helper.wait()
                        self._helper = None
                        logging.getLogger('helper').warn(
                            'Cinnabar helper executable is outdated. '
                            'Please rebuild it.')
                        raise NoHelperException
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
            if isinstance(sha1, Mark):
                raise NoHelperException
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
            if not SHA1_RE.match(sha1):
                sha1 = one(Git.iter('rev-parse', '--revs-only', sha1))
            return Git.read_note('refs/notes/cinnabar', sha1)

    @classmethod
    def hg2git(self, hg_sha1):
        try:
            with self.query('hg2git', hg_sha1) as stdout:
                sha1 = stdout.read(41)
                assert sha1[-1] == '\n'
                return sha1[:40]
        except NoHelperException:
            if len(hg_sha1) < 40:
                path = sha1path(hg_sha1)
                dir, partial = path.rsplit('/', 1)
                matches = []
                for ls in Git.ls_tree('refs/cinnabar/hg2git', dir + '/'):
                    mode, typ, gitsha1, path = ls
                    if path.startswith(partial):
                        matches.append(gitsha1)
                if len(matches) == 1:
                    return matches[0]
                ls = None
            else:
                ls = one(Git.ls_tree('refs/cinnabar/hg2git',
                                     sha1path(hg_sha1)))
            if not ls:
                return NULL_NODE_ID
            mode, typ, gitsha1, path = ls
            return gitsha1

    @classmethod
    def _manifest(self, hg_sha1, git_sha1):
        from githg import ManifestLine, GitHgStore
        # TODO: Improve this horrible mess
        attrs = {}
        if self._last_manifest:
            gitreference, reference_lines = self._last_manifest
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
                if path not in modified:
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
                    yield ManifestLine(next_created[0], node, attr)
                    next_created = next(iter_created)
                yield line
            while next_created:
                node, attr = next_created[1]
                yield ManifestLine(next_created[0], node, attr)
                next_created = next(iter_created)
        else:
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
        try:
            with self.query('manifest', hg_sha1) as stdout:
                size = int(stdout.readline().strip())
                ret = stdout.read(size)
                lf = stdout.read(1)
                assert lf == '\n'
                return ret
        except NoHelperException:
            git_sha1 = self.hg2git(hg_sha1)
            lines = list(self._manifest(hg_sha1, git_sha1))
            self._last_manifest = (git_sha1, lines)
            return lines


atexit.register(GitHgHelper.close)
