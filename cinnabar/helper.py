import atexit
import logging
import os
import subprocess
from StringIO import StringIO
from .git import (
    Git,
    NULL_NODE_ID,
    split_ls_tree,
)
from .hg.changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from .util import (
    IOLogger,
    Process,
)
from contextlib import contextmanager


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
            env = {
                'GIT_REPLACE_REF_BASE': 'refs/cinnabar/replace/',
            }
            if helper_path and os.path.exists(helper_path):
                command = (helper_path,)
            else:
                command = ('git', 'cinnabar-helper')
            try:
                self._helper = Process(*command, stdin=subprocess.PIPE,
                                       stderr=None, logger='cinnabar-helper',
                                       env=env)
                self._helper.stdin.write('version %d\n' % self.VERSION)
                response = self._helper.stdout.readline()
            except Exception:
                self._helper = None
                response = None
            if not response:
                logger = logging.getLogger('helper')
                if self._helper and self._helper.wait() == 128:
                    logger.error(
                        'Cinnabar helper executable is outdated. '
                        'Please try `git cinnabar download` or rebuild it.')
                else:
                    logger.error(
                        'Cannot find cinnabar helper executable. '
                        'Please try `git cinnabar download` or build it.')
                self._helper = None
            else:
                self._version = response.lstrip('ok\n') or 'unknown'
                atexit.register(self.close)

        if not self._helper:
            raise NoHelperException
        if self._helper is self:
            raise HelperClosedException

        if name == 'version':
            yield StringIO(self._version)
            return

        helper = self._helper
        logger = logging.getLogger(name)
        if logger.isEnabledFor(logging.INFO):
            wrapper = IOLogger(logger, helper.stdout, helper.stdin,
                               prefix='[%d]' % helper.pid)
        else:
            wrapper = helper.stdin

        if args:
            wrapper.write('%s %s\n' % (name, ' '.join(args)))
        else:
            wrapper.write('%s\n' % name)
        if logger.isEnabledFor(logging.DEBUG):
            yield wrapper
        else:
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
        if size < 0:
            ret = None
        else:
            ret = stdout.read(size)
        lf = stdout.read(1)
        assert lf == '\n'
        return ret


class GitHgHelper(BaseHelper):
    VERSION = 20
    _helper = False

    @classmethod
    def cat_file(self, typ, sha1):
        with self.query('cat-file', sha1) as stdout:
            return self._read_file(typ, stdout)

    @classmethod
    def git2hg(self, sha1):
        assert sha1 != 'changeset'
        with self.query('git2hg', sha1) as stdout:
            return self._read_file('blob', stdout)

    @classmethod
    def file_meta(self, sha1):
        with self.query('file-meta', sha1) as stdout:
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

    @classmethod
    def ls_tree(self, sha1, recursive=False):
        extra = () if not recursive else ('-r',)
        with self.query('ls-tree', sha1, *extra) as stdout:
            for line in self._read_data(stdout).split('\0'):
                if line:
                    yield split_ls_tree(line)

    @classmethod
    def rev_list(self, *args):
        with self.query('rev-list', *args) as stdout:
            for line in self._read_data(stdout).splitlines():
                parents = line.split()
                commit = parents.pop(0)
                tree = parents.pop(0)
                yield commit, tree, parents

    @classmethod
    def diff_tree(self, rev1, rev2, detect_copy=False):
        extra = () if not detect_copy else ('-C100%',)
        extra = extra + ('--ignore-submodules=dirty', '--')
        with self.query('diff-tree', rev1, rev2, *extra) as stdout:
            data = self._read_data(stdout)
            off = 0
            while off < len(data):
                tab = data.find('\t', off)
                assert tab != -1
                (mode_before, mode_after, sha1_before, sha1_after,
                 status) = data[off:tab].split(' ')
                if detect_copy and status[0] in 'RC':
                    orig = data.find('\0', tab + 1)
                    status = status[0] + data[tab + 1:orig]
                    tab = orig
                end = data.find('\0', tab + 1)
                path = data[tab + 1:end]
                off = end + 1
                yield (mode_before, mode_after, sha1_before, sha1_after,
                       status, path)

    @classmethod
    def set(self, *args):
        with self.query('set', *args):
            pass

    @classmethod
    def store(self, what, *args):
        if what == 'metadata':
            with self.query('store', what, *args) as stdout:
                sha1 = stdout.read(41)
                assert sha1[-1] == '\n'
                return sha1[:40]
        elif what == 'file':
            obj = args[0]
            if isinstance(obj, RawRevChunk01):
                delta_node = obj.delta_node
            elif isinstance(obj, RawRevChunk02):
                delta_node = 'cg2'
            else:
                assert False
            with self.query('store', what, delta_node, str(len(obj))):
                self._helper.stdin.write(obj)
        else:
            assert False

    @classmethod
    def heads(self, what):
        with self.query('heads', what) as stdout:
            data = self._read_data(stdout)
            return data.split()

    @classmethod
    def upgrade(self):
        with self.query('upgrade') as stdout:
            return stdout.readline().strip() == 'ok'


class HgRepoHelper(BaseHelper):
    VERSION = 17
    _helper = False

    @classmethod
    def connect(self, url):
        with self.query('connect', url) as stdout:
            resp = stdout.readline().rstrip()
            if resp == 'bundle':
                return stdout
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

    @classmethod
    def clonebundles(self):
        with self.query("clonebundles") as stdout:
            return self._read_data(stdout)
