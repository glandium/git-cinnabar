import logging
import os
import sys
from cinnabar.git import NULL_NODE_ID
from cinnabar.hg.changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from cinnabar.util import IOLogger
from contextlib import contextmanager


class ReadWriter(object):
    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer

    def read(self, size=None):
        if size is None:
            return self._reader.read()
        return self._reader.read(size)

    def readline(self):
        return self._reader.readline()

    def write(self, data=b''):
        self._writer.write(data)

    def flush(self):
        self._writer.flush()


class NoFdHelper(RuntimeError):
    """FdHelper not setup by parent process"""


class FdHelper(object):
    def __init__(self, mode):
        env_name = "GIT_CINNABAR_{}_FDS".format(mode.upper())
        if env_name not in os.environ:
            raise NoFdHelper
        (reader, writer) = (
            int(fd) for fd in os.environ[env_name].split(','))
        if sys.platform == 'win32':
            import msvcrt
            reader = msvcrt.open_osfhandle(reader, os.O_RDONLY)
            writer = msvcrt.open_osfhandle(writer, os.O_WRONLY)
        self.stdin = os.fdopen(writer, 'wb')
        self.stdout = os.fdopen(reader, 'rb')
        if mode == 'wire':
            return
        logger_name = "helper-{}".format(mode)
        logger = logging.getLogger(logger_name)
        if logger.isEnabledFor(logging.INFO):
            self.stdin = IOLogger(logger, self.stdout, self.stdin)
        if logger.isEnabledFor(logging.DEBUG):
            self.stdout = self.stdin


class BaseHelper(object):
    @classmethod
    def _ensure_helper(self):
        if self._helper is False:
            self._helper = FdHelper(self.MODE)

    @classmethod
    @contextmanager
    def query(self, name, *args):
        self._ensure_helper()
        helper = self._helper
        logger = logging.getLogger(name.decode('ascii'))
        if logger.isEnabledFor(logging.INFO):
            wrapper = IOLogger(logger, helper.stdout, helper.stdin)
        else:
            wrapper = helper.stdin

        if args:
            wrapper.write(b'%s %s\n' % (name, b' '.join(args)))
        else:
            wrapper.write(b'%s\n' % name)
        wrapper.flush()
        if logger.isEnabledFor(logging.DEBUG):
            yield wrapper
        else:
            yield ReadWriter(helper.stdout, helper.stdin)

    @classmethod
    def _read_file(self, expected_typ, stdout):
        hg_sha1 = stdout.read(41)
        if hg_sha1[-1:] == b'\n':
            assert hg_sha1[:40] == NULL_NODE_ID
            if expected_typ == b'auto':
                return b'missing', None
            return None
        typ, size = stdout.readline().split()
        size = int(size)
        assert expected_typ == b'auto' or typ == expected_typ
        ret = stdout.read(size)
        lf = stdout.read(1)
        assert lf == b'\n'
        if expected_typ == b'auto':
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
        assert lf == b'\n'
        return ret


class GitHgHelper(BaseHelper):
    MODE = 'import'
    _helper = False

    @classmethod
    def _cat_file(self, typ, sha1):
        with self.query(b'cat-file', sha1) as stdout:
            return self._read_file(typ, stdout)

    @classmethod
    def _cat_commit(self, sha1):
        return self._cat_file(b'commit', sha1)

    @classmethod
    def cat_file(self, typ, sha1):
        if typ == b'commit':
            return self._cat_commit(sha1)
        return self._cat_file(typ, sha1)

    @classmethod
    def git2hg(self, sha1):
        assert sha1 != b'changeset'
        with self.query(b'git2hg', sha1) as stdout:
            return self._read_file(b'blob', stdout)

    @classmethod
    def hg2git(self, hg_sha1):
        with self.query(b'hg2git', hg_sha1) as stdout:
            sha1 = stdout.read(41)
            assert sha1[-1:] == b'\n'
            return sha1[:40]

    @classmethod
    def manifest(self, hg_sha1):
        with self.query(b'manifest', hg_sha1) as stdout:
            return self._read_data(stdout)

    @classmethod
    def ls_tree(self, sha1, recursive=False):
        extra = () if not recursive else (b'-r',)
        with self.query(b'ls-tree', sha1, *extra) as stdout:
            for line in self._read_data(stdout).split(b'\0'):
                if line:
                    mode, typ, remainder = line.split(b' ', 2)
                    sha1, path = remainder.split(b'\t', 1)
                    yield mode, typ, sha1, path

    @classmethod
    def rev_list(self, *args):
        with self.query(b'rev-list', *args) as stdout:
            for line in self._read_data(stdout).splitlines():
                parents = line.split()
                commit = parents.pop(0)
                tree = parents.pop(0)
                yield commit, tree, parents

    @classmethod
    def diff_tree(self, rev1, rev2, detect_copy=False):
        extra = () if not detect_copy else (b'-C', b'-C')
        extra = extra + (b'--ignore-submodules=dirty', b'--')
        with self.query(b'diff-tree', rev1, rev2, *extra) as stdout:
            data = self._read_data(stdout)
            off = 0
            while off < len(data):
                tab = data.find(b'\t', off)
                assert tab != -1
                (mode_before, mode_after, sha1_before, sha1_after,
                 status) = data[off:tab].split(b' ')
                if detect_copy and status[:1] in b'RC':
                    orig = data.find(b'\0', tab + 1)
                    status = status[:1] + data[tab + 1:orig]
                    tab = orig
                end = data.find(b'\0', tab + 1)
                path = data[tab + 1:end]
                off = end + 1
                yield (mode_before, mode_after, sha1_before, sha1_after,
                       status, path)

    @classmethod
    def set(self, *args):
        with self.query(b'set', *args):
            pass

    @classmethod
    def store(self, what, *args):
        if what in (b'manifest',):
            obj = args[0]
            if isinstance(obj, RawRevChunk01):
                delta_node = obj.delta_node
            elif isinstance(obj, RawRevChunk02):
                delta_node = b'cg2'
            else:
                assert False
            with self.query(b'store', what, delta_node, b'%d' % len(obj)):
                self._helper.stdin.write(obj)
                self._helper.stdin.flush()
        else:
            assert False

    @classmethod
    def heads(self, what):
        with self.query(b'heads', what) as stdout:
            data = self._read_data(stdout)
            if what == b'manifests':
                return data.split()
            return (l.split() for l in data.splitlines())

    @classmethod
    def put_blob(self, data=b''):
        with self.query(b'store', b'blob', b'%d' % len(data)) as stdout:
            self._helper.stdin.write(data)
            self._helper.stdin.flush()
            sha1 = stdout.read(41)
            assert sha1[-1:] == b'\n'
            return sha1[:40]
