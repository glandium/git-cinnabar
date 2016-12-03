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
)
from .util import check_enabled
from contextlib import contextmanager


SHA1_RE = re.compile('^[0-9a-fA-F]{40}$')


class NoHelperException(Exception):
    pass


class HelperClosedException(Exception):
    pass


class BaseHelper(object):
    @classmethod
    def close(self):
        if self._helper and self._helper is not self:
            self._helper.wait()
        self._helper = self

    @classmethod
    @contextmanager
    def query(self, name, *args):
        if self._helper is False:
            helper_path = Git.config('cinnabar.helper')
            if helper_path == '':
                self._helper = None
        if self._helper is False:
            config = {'core.ignorecase': 'false'}
            if helper_path and os.path.exists(helper_path):
                config['alias.cinnabar-helper'] = '!' + helper_path
            stderr = None if check_enabled('helper') else open(os.devnull, 'w')
            self._helper = GitProcess('cinnabar-helper', stdin=subprocess.PIPE,
                                      stderr=stderr, config=config)
            self._helper.stdin.write('version %d\n' % self.VERSION)
            if not self._helper.stdout.readline():
                logger = logging.getLogger('helper')
                if self._helper.wait() == 128:
                    logger.error(
                        'Cinnabar helper executable is outdated. '
                        'Please try `git cinnabar download` or rebuild it.')
                else:
                    logger.error(
                        'Cannot find cinnabar helper executable. '
                        'Please try `git cinnabar download` or build it.')
                self._helper = None

        if not self._helper:
            raise NoHelperException
        if self._helper is self:
            raise HelperClosedException
        helper = self._helper
        if args:
            helper.stdin.write('%s %s\n' % (name, ' '.join(args)))
        else:
            helper.stdin.write('%s\n' % name)
        yield helper.stdout

    @classmethod
    def _read_file(self, expected_typ, stdout):
        hg_sha1 = stdout.read(41)
        if hg_sha1[-1] == '\n':
            assert hg_sha1[:40] == NULL_NODE_ID
            if expected_typ == 'auto':
                return 'missing', None
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
    def _read_data(self, stdout):
        size = int(stdout.readline().strip())
        ret = stdout.read(size)
        lf = stdout.read(1)
        assert lf == '\n'
        return ret


class GitHgHelper(BaseHelper):
    VERSION = 5
    _helper = False

    @classmethod
    def cat_file(self, typ, sha1):
        if isinstance(sha1, Mark):
            with self.query('get-mark', ':%d' % sha1) as stdout:
                sha1 = stdout.read(41)
                assert sha1[-1] == '\n'
                sha1 = sha1[:40]
        with self.query('cat-file', sha1) as stdout:
            return self._read_file(typ, stdout)

    @classmethod
    def git2hg(self, sha1):
        with self.query('git2hg', sha1) as stdout:
            return self._read_file('blob', stdout)

    @classmethod
    def hg2git(self, hg_sha1):
        with self.query('hg2git', hg_sha1) as stdout:
            sha1 = stdout.read(41)
            assert sha1[-1] == '\n'
            return sha1[:40]

    @classmethod
    def manifest(self, hg_sha1):
        with self.query('manifest', hg_sha1) as stdout:
            return self._read_data(stdout)

    @classmethod
    def check_manifest(self, hg_sha1):
        with self.query('check-manifest', hg_sha1) as stdout:
            return stdout.readline().strip() == 'ok'


atexit.register(GitHgHelper.close)


class HgRepoHelper(BaseHelper):
    VERSION = 4
    _helper = False

    @classmethod
    def connect(self, url):
        with self.query('connect', url) as stdout:
            resp = stdout.readline().rstrip()
            if resp != 'ok':
                raise Exception(resp)

    @classmethod
    def state(self):
        with self.query('state') as stdout:
            return {
                'branchmap': self._read_data(stdout),
                'heads': self._read_data(stdout),
                'bookmarks': self._read_data(stdout),
            }

    @classmethod
    def capable(self, name):
        with self.query('capable', name) as stdout:
            return self._read_data(stdout)

    @classmethod
    def known(self, nodes):
        with self.query('known', *nodes) as stdout:
            return self._read_data(stdout)

    @classmethod
    def listkeys(self, namespace):
        with self.query('listkeys', namespace) as stdout:
            return self._read_data(stdout)

    @classmethod
    def getbundle(self, heads, common, bundle2caps=False):
        with self.query('getbundle', ','.join(heads), ','.join(common),
                        bundle2caps) as stdout:
            return stdout

    @classmethod
    def unbundle(self, input_iterator, heads):
        with self.query('unbundle', *heads) as stdout:
            for data in input_iterator:
                self._helper.stdin.write(data)
            ret = self._read_data(stdout)
            try:
                return int(ret)
            except ValueError:
                return ret

    @classmethod
    def pushkey(self, namespace, key, old, new):
        with self.query("pushkey", namespace, key, old, new) as stdout:
            ret = self._read_data(stdout).rstrip()
            try:
                return bool(int(ret))
            except ValueError:
                return ret

    @classmethod
    def lookup(self, key):
        with self.query("lookup", key) as stdout:
            success, data = self._read_data(stdout).rstrip().split(' ', 1)
            return data if int(success) else None


atexit.register(HgRepoHelper.close)
