import atexit
import os
import subprocess
from git import (
    Git,
    GitProcess,
    sha1path,
)
from git.util import one
from contextlib import contextmanager


class NoHelperException(Exception):
    pass


class GitHgHelper(object):
    _helper = False

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
    def git2hg(self, sha1):
        try:
            with self.query('git2hg', sha1) as stdout:
                hg_sha1 = stdout.read(41)
                if hg_sha1[-1] == '\n':
                    from . import NULL_NODE_ID
                    assert hg_sha1[:40] == NULL_NODE_ID
                    return None
                typ, size = stdout.readline().split()
                size = int(size)
                assert typ == 'blob'
                ret = stdout.read(size)
                lf = stdout.read(1)
                assert lf == '\n'
                return ret
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


atexit.register(GitHgHelper.close)
