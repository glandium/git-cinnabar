import atexit
import hashlib
import logging
import os
import subprocess
from binascii import unhexlify
from types import GeneratorType
from io import BytesIO
from .exceptions import NoHelperAbort, HelperClosedError
from .git import (
    EMPTY_BLOB,
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
    lrucache,
    Process,
)
from contextlib import contextmanager


def git_hash(type, data):
    h = hashlib.sha1('%s %d\0' % (type, len(data)))
    h.update(data)
    return h.hexdigest()


def tree_hash(files, full_base, base=''):
    if base:
        base = base + '/'
    tree = {}
    for f in files:
        p = f.split(os.sep, 1)
        if len(p) == 1:
            tree[p[0]] = None
        else:
            tree.setdefault(p[0], list()).append(p[1])
    content = ''
    for f, subtree in sorted(tree.iteritems()):
        path = os.path.join(full_base, f)
        if subtree:
            sha1 = tree_hash(subtree, path, '%s%s' % (base, f))
            attr = '40000'
        else:
            sha1 = git_hash('blob', open(path).read())
            attr = '100644'
            logging.debug('%s %s %s%s', attr, sha1, base, f)
        content += '%s %s\0%s' % (attr, f, unhexlify(sha1))
    sha1 = git_hash('tree', content)
    logging.debug('040000 %s %s', sha1, base.rstrip('/'))
    return sha1


def helper_hash():
    script_path = os.path.join(os.path.dirname(__file__), '..')
    d = os.path.join(script_path, 'helper')
    files = (os.listdir(d) if os.path.exists(d) else ())

    def match(f):
        return (f.endswith(('.h', '.c', '.c.patch')) and
                'patched' not in f) or f == 'GIT-VERSION.mk'
    files = list(f for f in files if match(f))

    if 'cinnabar-helper.c' not in files:
        return None

    return tree_hash(files, d)


class ReadWriter(object):
    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer

    def read(self, size=0):
        return self._reader.read(size)

    def readline(self):
        return self._reader.readline()

    def write(self, data=''):
        self._writer.write(data)

    def flush(self):
        self._writer.flush()


class BaseHelper(object):
    _helper_hash = None

    @classmethod
    def close(self):
        if self._helper and self._helper is not self:
            self._helper.wait()
        self._helper = self

    @classmethod
    def _ensure_helper(self):
        if self._helper is False:
            helper_path = Git.config('cinnabar.helper')
            env = {
                'GIT_REPLACE_REF_BASE': 'refs/cinnabar/replace/',
            }
            if helper_path and os.path.exists(helper_path):
                command = [helper_path]
            else:
                command = ['git', 'cinnabar-helper']
            command.append('--{}'.format(self.MODE))

            try:
                self._helper = Process(*command, stdin=subprocess.PIPE,
                                       stderr=None, logger='cinnabar-helper',
                                       env=env)
                self._helper.stdin.write('version %d\n' % self.VERSION)
                response = self._helper.stdout.readline()
            except Exception:
                self._helper = None
                response = None

            outdated = ('Cinnabar helper executable is outdated. '
                        'Please try `git cinnabar download` or '
                        'rebuild it.')

            if not response:
                if self._helper and self._helper.wait() == 128:
                    message = outdated
                else:
                    message = ('Cannot find cinnabar helper executable. '
                               'Please try `git cinnabar download` or '
                               'build it.')

                raise NoHelperAbort(message)
            else:
                version = response.lstrip('ok\n') or 'unknown'
                self._revision, _, version = version.partition(' ')
                if version:
                    self._version = int(version)
                else:
                    self._version = self.VERSION
                if self._version >= 3002:
                    self._helper.stdin.write('helpercaps\n')
                    response = self._read_data(self._helper.stdout)
                else:
                    response = ''
                self._caps = {
                    k: v.split(',')
                    for k, _, v in (l.partition('=')
                                    for l in response.splitlines())
                }

                if BaseHelper._helper_hash is None:
                    BaseHelper._helper_hash = helper_hash() or False
                    if BaseHelper._helper_hash != self._revision:
                        logging.warning(outdated)

                atexit.register(self.close)

        if self._helper is self:
            raise HelperClosedError

    @classmethod
    @contextmanager
    def query(self, name, *args):
        self._ensure_helper()
        if name == 'revision':
            yield BytesIO(self._revision)
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
            yield ReadWriter(helper.stdout, helper.stdin)

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

    @classmethod
    def supports(self, feature):
        self._ensure_helper()
        if self._version < 3002:
            feature = {
                ('compression', 'UN'): 3000,
            }.get(feature, feature)
        if isinstance(feature, int):
            return feature <= self._version
        assert isinstance(feature, tuple) and len(feature) == 2
        k, v = feature
        return v in self._caps.get(k, ())


class GitHgHelper(BaseHelper):
    VERSION = 3000
    MODE = 'import'
    STORE_CHANGEGROUP = 3001
    _helper = False

    @classmethod
    def reload(self):
        with self.query('reload'):
            pass
        self.git2hg.invalidate()
        self.hg2git.invalidate()
        self._cat_commit.invalidate()

    @classmethod
    def _cat_file(self, typ, sha1):
        with self.query('cat-file', sha1) as stdout:
            return self._read_file(typ, stdout)

    @classmethod
    @lrucache(16)
    def _cat_commit(self, sha1):
        return self._cat_file('commit', sha1)

    @classmethod
    def cat_file(self, typ, sha1):
        if typ == 'commit':
            return self._cat_commit(sha1)
        return self._cat_file(typ, sha1)

    @classmethod
    @lrucache(16)
    def git2hg(self, sha1):
        assert sha1 != 'changeset'
        with self.query('git2hg', sha1) as stdout:
            return self._read_file('blob', stdout)

    @classmethod
    def file_meta(self, sha1):
        with self.query('file-meta', sha1) as stdout:
            return self._read_file('blob', stdout)

    @classmethod
    @lrucache(16)
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
    def check_file(self, hg_sha1, *parents):
        with self.query('check-file', hg_sha1, *parents) as stdout:
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
        if args[0] == 'changeset-metadata':
            self.git2hg.invalidate(self, self.hg2git(args[1]))
        elif args[0] != 'file-meta':
            self.hg2git.invalidate(self, args[1])
        with self.query('set', *args):
            pass

    @classmethod
    def store(self, what, *args):
        if what == 'metadata':
            with self.query('store', what, *args) as stdout:
                sha1 = stdout.read(41)
                assert sha1[-1] == '\n'
                return sha1[:40]
        elif what in ('file', 'manifest'):
            obj = args[0]
            if isinstance(obj, RawRevChunk01):
                delta_node = obj.delta_node
            elif isinstance(obj, RawRevChunk02):
                delta_node = 'cg2'
            else:
                assert False
            with self.query('store', what, delta_node, str(len(obj))):
                self._helper.stdin.write(obj)
        elif what == 'manifest_changegroup':
            with self.query('store', what, *args):
                return self._helper.stdin
        else:
            assert False

    @classmethod
    @contextmanager
    def store_changegroup(self, version):
        with self.query('store', 'changegroup', str(version)):
            yield self._helper.stdin

    @classmethod
    def heads(self, what):
        with self.query('heads', what) as stdout:
            data = self._read_data(stdout)
            return data.split()

    @classmethod
    def reset_heads(self, what):
        with self.query('reset-heads', what):
            pass

    @classmethod
    def upgrade(self):
        with self.query('upgrade') as stdout:
            return stdout.readline().strip() == 'ok'

    @classmethod
    def create_git_tree(self, manifest_sha1, ref_commit=None):
        extra_arg = (ref_commit,) if ref_commit else ()
        with self.query('create-git-tree', manifest_sha1,
                        *extra_arg) as stdout:
            sha1 = stdout.read(41)
            assert sha1[-1] == '\n'
            return sha1[:40]

    @classmethod
    def seen(self, typ, sha1):
        with self.query('seen', typ, sha1) as stdout:
            return stdout.readline().strip() == 'yes'

    @classmethod
    def dangling(self, typ):
        with self.query('dangling', typ) as stdout:
            data = self._read_data(stdout)
            return data.splitlines()

    @classmethod
    def update_ref(self, ref, newvalue):
        with self.query('reset', '{}\nfrom {}\n'.format(ref, newvalue)):
            self._helper.stdin.flush()

    @classmethod
    def cat_blob(self, ref):
        with self.query('cat-blob', ref) as stdout:
            sha1, blob, size = stdout.readline().split()
            assert blob == 'blob'
            size = int(size)
            content = stdout.read(size)
            lf = stdout.read(1)
            assert lf == '\n'
            return content

    @classmethod
    def _get_last(self):
        with self.query('get-mark', ':1') as stdout:
            sha1 = stdout.read(41)
            assert sha1[-1] == '\n'
            return sha1[:40]

    @classmethod
    def put_blob(self, data='', want_sha1=True):
        with self.query('blob') as io:
            io.write('mark :1\n')
            io.write('data %d\n' % len(data))
            io.write(data)
            io.write('\n')
            if want_sha1:
                return self._get_last()

    @classmethod
    @contextmanager
    def commit(self, ref, committer='<cinnabar@git> 0 +0000', author=None,
               message='', from_commit=None, parents=(), pseudo_mark=None):
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
                with self.query('ls', from_commit, '') as stdout:
                    line = stdout.readline()
                    if line.startswith('missing '):
                        from_tree = None
                    else:
                        mode, typ, from_tree, path = split_ls_tree(line[:-1])

        helper = CommitHelper()
        helper.write('mark :1\n')
        # TODO: properly handle errors, like from the committer being badly
        # formatted.
        if author:
            helper.write('author %s\n' % author)
        helper.write('committer %s\n' % committer)
        helper.cmd_data(message)

        helper.write('from %s\n' % _from)
        for merge in merges:
            helper.write('merge %s\n' % merge)
        if from_tree:
            helper.write('M 040000 %s \n' % from_tree)

        yield helper
        helper.write('\n')

        with self.query('commit', ref) as stdout:
            stdout.write(helper.flush_buffer())

        if not pseudo_mark:
            helper.sha1 = self._get_last()

    @classmethod
    def close(self, rollback=True):
        if not rollback and self._helper != self:
            with self.query('done'):
                pass
        super(GitHgHelper, self).close()


class CommitHelper(object):
    __slots__ = "_queue", "sha1"

    def __init__(self):
        self._queue = []
        self.sha1 = None

    def write(self, data):
        self._queue.append(data)

    def cmd_data(self, data):
        self._queue.append('data %d\n' % len(data))
        self._queue.append(data)
        self._queue.append('\n')

    def flush_buffer(self):
        queue = self._queue
        self._queue = []
        return ''.join(queue)

    def filedelete(self, path):
        self.write('D %s\n' % path)

    MODE = {
        'regular': '644',
        'exec': '755',
        'tree': '040000',
        'symlink': '120000',
        'commit': '160000',
    }

    def filemodify(self, path, sha1=None, typ='regular', content=None):
        assert sha1 or (content and typ == 'regular')
        # We may receive the sha1 for an empty blob, even though there is no
        # empty blob stored in the repository. So for empty blobs, use an
        # inline filemodify.
        dataref = 'inline' if sha1 in (EMPTY_BLOB, None) else sha1
        self.write('M %s %s %s\n' % (
            self.MODE.get(typ, typ),
            dataref,
            path,
        ))
        if sha1 == EMPTY_BLOB:
            self.cmd_data('')
        elif sha1 is None:
            self.cmd_data(content)


class HgRepoHelper(BaseHelper):
    VERSION = 3000
    MODE = 'wire'
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

    @classmethod
    def cinnabarclone(self):
        with self.query("cinnabarclone") as stdout:
            return self._read_data(stdout)


class BundleHelper(HgRepoHelper):
    _helper = False
