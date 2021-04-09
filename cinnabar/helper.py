from __future__ import absolute_import, unicode_literals
import atexit
import hashlib
import logging
import os
import subprocess
from types import GeneratorType
from cinnabar.exceptions import HelperClosedError
from cinnabar.git import (
    EMPTY_BLOB,
    Git,
    NULL_NODE_ID,
    split_ls_tree,
)
from cinnabar.hg.changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from cinnabar.util import (
    environ,
    fsdecode,
    iteritems,
    IOLogger,
    lrucache,
    one,
    Process,
)
from contextlib import contextmanager


def git_hash(type, data):
    h = hashlib.sha1(b'%s %d\0' % (type, len(data)))
    h.update(data)
    return h.hexdigest().encode('ascii')


def build_commit():
    try:
        workdir = os.path.join(os.path.dirname(__file__), '..')
    except NameError:
        return False
    env = environ().copy()
    for k in list(env.keys()):
        # Variables like GIT_DIR cause problems with the command below, so
        # unset them all.
        if k.startswith(b'GIT_'):
            del env[k]
    return one(Git.iter('-C', workdir, 'rev-parse', '--verify', 'HEAD',
                        stderr=open(os.devnull, 'wb'), env=env))


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


class BaseHelper(object):
    @classmethod
    def close(self):
        if self._helper and self._helper is not self:
            self._helper.wait()
        self._helper = self

    @classmethod
    def _helper_command(self):
        helper_path = Git.config('cinnabar.helper')
        env = {
            b'GIT_REPLACE_REF_BASE': b'refs/cinnabar/replace/',
        }
        for k, v in iteritems(environ()):
            if k.startswith(b'GIT_CINNABAR_'):
                env[k] = v
        if helper_path:
            helper_path = fsdecode(helper_path)
        if helper_path and os.path.exists(helper_path):
            command = [helper_path]
        else:
            command = ['git-cinnabar']
        return command, env

    @classmethod
    def _ensure_helper(self):
        if self._helper is False:
            command, env = self._helper_command()
            if len(command) == 1:
                executable = command[0]
                command[0] = 'git-cinnabar-helper'
            else:
                executable = None
            command.append('--{}'.format(self.MODE))

            self._helper = Process(
                *command, executable=executable,
                stdin=subprocess.PIPE, stderr=None, env=env,
                logger='helper-{}'.format(self.MODE))

            self._helper.stdin.write(b'helpercaps\n')
            self._helper.stdin.flush()
            response = self._read_data(self._helper.stdout)
            self._caps = {
                k: v.split(b',')
                for k, _, v in (l.partition(b'=')
                                for l in response.splitlines())
            }
            atexit.register(self.close)

        if self._helper is self:
            raise HelperClosedError

    @classmethod
    @contextmanager
    def query(self, name, *args):
        self._ensure_helper()
        helper = self._helper
        logger = logging.getLogger(name.decode('ascii'))
        if logger.isEnabledFor(logging.INFO):
            wrapper = IOLogger(logger, helper.stdout, helper.stdin,
                               prefix='[%d]' % helper.pid)
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

    @classmethod
    def supports(self, feature):
        self._ensure_helper()
        if isinstance(feature, int):
            return feature <= self._version
        assert isinstance(feature, tuple) and len(feature) == 2
        k, v = feature
        return v in self._caps.get(k, ())


class GitHgHelper(BaseHelper):
    MODE = 'import'
    _helper = False

    @classmethod
    def reload(self):
        with self.query(b'reload'):
            pass
        self.git2hg.invalidate()
        self.hg2git.invalidate()
        self._cat_commit.invalidate()

    @classmethod
    def _cat_file(self, typ, sha1):
        with self.query(b'cat-file', sha1) as stdout:
            return self._read_file(typ, stdout)

    @classmethod
    @lrucache(16)
    def _cat_commit(self, sha1):
        return self._cat_file(b'commit', sha1)

    @classmethod
    def cat_file(self, typ, sha1):
        if typ == b'commit':
            return self._cat_commit(sha1)
        return self._cat_file(typ, sha1)

    @classmethod
    @lrucache(16)
    def git2hg(self, sha1):
        assert sha1 != b'changeset'
        with self.query(b'git2hg', sha1) as stdout:
            return self._read_file(b'blob', stdout)

    @classmethod
    def file_meta(self, sha1):
        with self.query(b'file-meta', sha1) as stdout:
            return self._read_file(b'blob', stdout)

    @classmethod
    @lrucache(16)
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
    def check_manifest(self, hg_sha1):
        with self.query(b'check-manifest', hg_sha1) as stdout:
            return stdout.readline().strip() == b'ok'

    @classmethod
    def check_file(self, hg_sha1, *parents):
        with self.query(b'check-file', hg_sha1, *parents) as stdout:
            return stdout.readline().strip() == b'ok'

    @classmethod
    def ls_tree(self, sha1, recursive=False):
        extra = () if not recursive else (b'-r',)
        with self.query(b'ls-tree', sha1, *extra) as stdout:
            for line in self._read_data(stdout).split(b'\0'):
                if line:
                    yield split_ls_tree(line)

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
        if args[0] == b'changeset-metadata':
            self.git2hg.invalidate(self, self.hg2git(args[1]))
        elif args[0] != b'file-meta':
            self.hg2git.invalidate(self, args[1])
        with self.query(b'set', *args):
            pass

    @classmethod
    def store(self, what, *args):
        if what == b'metadata':
            with self.query(b'store', what, *args) as stdout:
                sha1 = stdout.read(41)
                assert sha1[-1:] == b'\n'
                return sha1[:40]
        elif what in (b'file', b'manifest'):
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
        elif what == b'manifest_changegroup':
            with self.query(b'store', what, *args):
                return self._helper.stdin
        else:
            assert False

    @classmethod
    @contextmanager
    def store_changegroup(self, version):
        with self.query(b'store', b'changegroup', b'%d' % version):
            yield self._helper.stdin

    @classmethod
    def heads(self, what):
        with self.query(b'heads', what) as stdout:
            data = self._read_data(stdout)
            return data.split()

    @classmethod
    def reset_heads(self, what):
        with self.query(b'reset-heads', what):
            pass

    @classmethod
    def upgrade(self):
        with self.query(b'upgrade') as stdout:
            return stdout.readline().strip() == b'ok'

    @classmethod
    def create_git_tree(self, manifest_sha1, ref_commit=None):
        extra_arg = (ref_commit,) if ref_commit else ()
        with self.query(b'create-git-tree', manifest_sha1,
                        *extra_arg) as stdout:
            sha1 = stdout.read(41)
            assert sha1[-1:] == b'\n'
            return sha1[:40]

    @classmethod
    def seen(self, typ, sha1):
        with self.query(b'seen', typ, sha1) as stdout:
            return stdout.readline().strip() == b'yes'

    @classmethod
    def dangling(self, typ):
        with self.query(b'dangling', typ) as stdout:
            data = self._read_data(stdout)
            return data.splitlines()

    @classmethod
    def update_ref(self, ref, newvalue):
        with self.query(b'reset', b'%s\nfrom %s\n' % (ref, newvalue)):
            self._helper.stdin.flush()

    @classmethod
    def cat_blob(self, ref):
        with self.query(b'cat-blob', ref) as stdout:
            sha1, blob, size = stdout.readline().split()
            assert blob == b'blob'
            size = int(size)
            content = stdout.read(size)
            lf = stdout.read(1)
            assert lf == b'\n'
            return content

    @classmethod
    def _get_last(self):
        with self.query(b'get-mark', b':1') as stdout:
            sha1 = stdout.read(41)
            assert sha1[-1:] == b'\n'
            return sha1[:40]

    @classmethod
    def put_blob(self, data=b'', want_sha1=True):
        with self.query(b'blob') as io:
            io.write(b'mark :1\n')
            io.write(b'data %d\n' % len(data))
            io.write(data)
            io.write(b'\n')
            io.flush()
            if want_sha1:
                return self._get_last()

    @classmethod
    @contextmanager
    def commit(self, ref, committer=b'<cinnabar@git> 0 +0000', author=None,
               message=b'', from_commit=None, parents=(), pseudo_mark=None):
        if isinstance(parents, GeneratorType):
            parents = tuple(parents)
        from_tree = None
        if parents and parents[0] == from_commit:
            _from = parents[0]
            merges = parents[1:]
        else:
            _from = NULL_NODE_ID
            merges = parents
            if from_commit:
                with self.query(b'ls', from_commit, b'') as stdout:
                    line = stdout.readline()
                    if line.startswith(b'missing '):
                        from_tree = None
                    else:
                        mode, typ, from_tree, path = split_ls_tree(line[:-1])

        helper = CommitHelper()
        helper.write(b'mark :1\n')
        # TODO: properly handle errors, like from the committer being badly
        # formatted.
        if author:
            helper.write(b'author %s\n' % author)
        helper.write(b'committer %s\n' % committer)
        helper.cmd_data(message)

        helper.write(b'from %s\n' % _from)
        for merge in merges:
            helper.write(b'merge %s\n' % merge)
        if from_tree:
            helper.write(b'M 040000 %s \n' % from_tree)

        yield helper
        helper.write(b'\n')

        with self.query(b'commit', ref) as stdout:
            stdout.write(helper.flush_buffer())
            stdout.flush()

        if not pseudo_mark:
            helper.sha1 = self._get_last()

    @classmethod
    def close(self, rollback=True):
        if not rollback and self._helper != self:
            with self.query(b'done'):
                pass
        super(GitHgHelper, self).close()


class CommitHelper(object):
    __slots__ = '_queue', 'sha1'

    def __init__(self):
        self._queue = []
        self.sha1 = None

    def write(self, data):
        self._queue.append(data)

    def cmd_data(self, data):
        self._queue.append(b'data %d\n' % len(data))
        self._queue.append(data)
        self._queue.append(b'\n')

    def flush_buffer(self):
        queue = self._queue
        self._queue = []
        return b''.join(queue)

    def filedelete(self, path):
        self.write(b'D %s\n' % path)

    MODE = {
        b'regular': b'644',
        b'exec': b'755',
        b'tree': b'040000',
        b'symlink': b'120000',
        b'commit': b'160000',
    }

    def filemodify(self, path, sha1=None, typ=b'regular', content=None):
        assert sha1 or (content and typ == b'regular')
        # We may receive the sha1 for an empty blob, even though there is no
        # empty blob stored in the repository. So for empty blobs, use an
        # inline filemodify.
        dataref = b'inline' if sha1 in (EMPTY_BLOB, None) else sha1
        self.write(b'M %s %s %s\n' % (
            self.MODE.get(typ, typ),
            dataref,
            path,
        ))
        if sha1 == EMPTY_BLOB:
            self.cmd_data(b'')
        elif sha1 is None:
            self.cmd_data(content)


class HgRepoHelper(BaseHelper):
    MODE = 'wire'
    _helper = False

    @classmethod
    def connect(self, url):
        with self.query(b'connect', url) as stdout:
            resp = stdout.readline().rstrip()
            if resp == b'bundle':
                return stdout
            if resp != b'ok':
                raise Exception(resp.decode('ascii'))

    @classmethod
    def state(self):
        with self.query(b'state') as stdout:
            return {
                'branchmap': self._read_data(stdout),
                'heads': self._read_data(stdout),
                'bookmarks': self._read_data(stdout),
            }

    @classmethod
    def capable(self, name):
        with self.query(b'capable', name) as stdout:
            return self._read_data(stdout)

    @classmethod
    def known(self, nodes):
        with self.query(b'known', *nodes) as stdout:
            return self._read_data(stdout)

    @classmethod
    def listkeys(self, namespace):
        with self.query(b'listkeys', namespace) as stdout:
            return self._read_data(stdout)

    @classmethod
    def getbundle(self, heads, common, bundle2caps=False):
        with self.query(b'getbundle', b','.join(heads), b','.join(common),
                        bundle2caps) as stdout:
            return stdout

    @classmethod
    def unbundle(self, input_iterator, heads):
        with self.query(b'unbundle', *heads) as stdout:
            for data in input_iterator:
                self._helper.stdin.write(data)
            self._helper.stdin.flush()
            ret = self._read_data(stdout)
            try:
                return int(ret)
            except ValueError:
                return ret

    @classmethod
    def pushkey(self, namespace, key, old, new):
        with self.query(b'pushkey', namespace, key, old, new) as stdout:
            ret = self._read_data(stdout).rstrip()
            try:
                return bool(int(ret))
            except ValueError:
                return ret

    @classmethod
    def lookup(self, key):
        with self.query(b'lookup', key) as stdout:
            success, data = self._read_data(stdout).rstrip().split(b' ', 1)
            return data if int(success) else None

    @classmethod
    def clonebundles(self):
        with self.query(b'clonebundles') as stdout:
            return self._read_data(stdout)

    @classmethod
    def cinnabarclone(self):
        with self.query(b'cinnabarclone') as stdout:
            return self._read_data(stdout)


class BundleHelper(HgRepoHelper):
    _helper = False
