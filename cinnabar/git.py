from __future__ import division
import atexit
import contextlib
import logging
import os
import subprocess
import time
from types import (
    GeneratorType,
    StringType,
)
from collections import Iterable
from .util import (
    check_enabled,
    IOLogger,
    LazyString,
    one,
    VersionedDict,
)
from binascii import hexlify
from itertools import chain
from distutils.version import LooseVersion

NULL_NODE_ID = '0' * 40


def normalize_path(path):
    if path[0] == '"' and path[-1] == '"':
        path = path[1:-1].decode('string_escape')
    return path


def sha1path(sha1, depth=2):
    def parts():
        i = -1
        for i in xrange(0, depth):
            yield sha1[i*2:i*2+2]
        yield sha1[i*2+2:]
    return '/'.join(parts())


def split_ls_tree(line):
    mode, typ, remainder = line.split(' ', 2)
    sha1, path = remainder.split('\t', 1)
    return mode, typ, sha1, path


git_dir = os.environ.get('GIT_DIR')
if not git_dir:
    git_dir = subprocess.check_output(
        ['git', 'rev-parse', '--git-dir']).rstrip('\n')

git_version = subprocess.check_output(['git', 'version'])
assert git_version.startswith('git version ')
git_version = LooseVersion(git_version[12:].strip())

HAS_REPLACE_REF_BASE = git_version > LooseVersion('2.6')


class GitProcess(object):
    KWARGS = set(['stdin', 'stdout', 'stderr', 'config', 'env'])
    _git_replace_path = None

    def __init__(self, *args, **kwargs):
        assert not kwargs or not set(kwargs.keys()) - self.KWARGS
        stdin = kwargs.get('stdin', None)
        stdout = kwargs.get('stdout', subprocess.PIPE)
        stderr = kwargs.get('stderr', None)
        config = kwargs.get('config', {})
        env = kwargs.get('env', {})
        if isinstance(stdin, (StringType, Iterable)):
            proc_stdin = subprocess.PIPE
        else:
            proc_stdin = stdin

        git = ['git'] + list(chain(*(['-c', '%s=%s' % (n, v)]
                                     for n, v in config.iteritems())))

        full_env = VersionedDict(os.environ)
        if env:
            full_env.update(env)

        if args[0] == 'config':
            # We don't need the replace ref setup for config.
            pass
        elif not check_enabled('replace') and HAS_REPLACE_REF_BASE:
            full_env['GIT_REPLACE_REF_BASE'] = 'refs/cinnabar/replace/'
        elif Git._replace:
            if not GitProcess._git_replace_path:
                from tempfile import mkdtemp
                # There are commands run before Git._replace is filled, but we
                # expect them all not to require the replace refs.
                path = mkdtemp(prefix='.cinnabar.', dir=git_dir)
                GitProcess._git_replace_path = path
                os.mkdir(os.path.join(path, 'refs'))
                with open(os.path.join(path, 'HEAD'), 'w') as fh:
                    subprocess.check_call(['git', 'rev-parse', 'HEAD'],
                                          stdout=fh)
                with open(os.path.join(path, 'packed-refs'), 'w') as fh:
                    subprocess.check_call(
                        ['git', 'for-each-ref',
                         '--format=%(objectname) %(refname)'], stdout=fh)
                    for sha1, target in Git._replace.iteritems():
                        fh.write('%s refs/replace/%s\n' % (target, sha1))

                logging.getLogger('replace').debug(LazyString(
                    lambda: 'Initializing in %s' % path))

            if 'GIT_OBJECT_DIRECTORY' not in full_env:
                full_env['GIT_OBJECT_DIRECTORY'] = os.path.join(
                    git_dir, 'objects')
            full_env['GIT_DIR'] = GitProcess._git_replace_path
            if 'GIT_CONFIG' not in full_env:
                full_env['GIT_CONFIG'] = os.path.join(git_dir, 'config')

        self._proc = self._popen(git + list(args), stdin=proc_stdin,
                                 stdout=stdout, stderr=stderr, env=full_env)

        logger = logging.getLogger(args[0])
        if logger.isEnabledFor(logging.INFO):
            self._stdin = IOLogger(logger, self._proc.stdout, self._proc.stdin,
                                   prefix='[%d]' % self._proc.pid)
        else:
            self._stdin = self._proc.stdin

        if logger.isEnabledFor(logging.DEBUG):
            self._stdout = self._stdin
        else:
            self._stdout = self._proc.stdout

        if proc_stdin == subprocess.PIPE:
            if isinstance(stdin, StringType):
                self._stdin.write(stdin)
            elif isinstance(stdin, Iterable):
                for line in stdin:
                    self._stdin.write('%s\n' % line)
            if proc_stdin != stdin:
                self._proc.stdin.close()

    def _popen(self, cmd, env, **kwargs):
        assert isinstance(env, VersionedDict)
        proc = subprocess.Popen(cmd, env=env, **kwargs)
        logging.getLogger('git').info(LazyString(lambda: '[%d] %s' % (
            proc.pid,
            ' '.join(chain(
                ('%s=%s' % (k, v)
                 for k, v in sorted((k, v) for s, k, v
                                    in env.iterchanges() if s != env.REMOVED)),
                cmd)),
        )))
        return proc

    def wait(self):
        for fh in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
            if fh:
                fh.close()
        return self._proc.wait()

    @property
    def pid(self):
        return self._proc.pid

    @property
    def stdin(self):
        return self._stdin

    @property
    def stdout(self):
        return self._stdout

    @property
    def stderr(self):
        return self._proc.stderr


class Git(object):
    _cat_file = None
    _update_ref = None
    _fast_import = None
    _diff_tree = {}
    _notes_depth = {}
    _refs = VersionedDict()
    _config = None
    _replace = {}

    @classmethod
    def register_fast_import(self, fast_import):
        self._fast_import = fast_import

    @classmethod
    def close(self, rollback=False):
        if self._cat_file:
            self._cat_file.wait()
            self._cat_file = None
        if self._update_ref:
            retcode = self._update_ref.wait()
            self._update_ref = None
            if retcode:
                raise Exception('git-update-ref failed')
        for diff_tree in self._diff_tree.itervalues():
            diff_tree.wait()
        self._diff_tree = {}
        try:
            if self._fast_import:
                self._fast_import.close(rollback)
                self._fast_import = None
        finally:
            if GitProcess._git_replace_path:
                # Copy the (updated) refs from _git_replace_path to the normal
                # git repository.
                # _refs may contain marks that we don't know anything about
                # anymore now that fast-import is closed (not that it would
                # tell us anyways, except with a checkpoint, but meh).
                # So we're going to ask for-each-ref with a list of all the
                # refs we have a mark for.
                # But we want for-each-ref to be launched in the
                # _git_replace_path, where the refs are fresh, now, and
                # update-ref in the normal git repo, so we need to accumulate
                # first.
                update = []
                unknown_refs = []
                for status, ref, sha1 in self._refs.iterchanges():
                    if isinstance(sha1, Mark):
                        unknown_refs.append(ref)
                    update.append((status, ref, sha1))
                # Resolve the marks, ensuring that for_each_ref doesn't use
                # anything cached.
                refs_bak = self._refs
                self._refs = VersionedDict()
                refs = {ref: sha1 for sha1, ref
                        in self.for_each_ref(*unknown_refs)}
                self._refs = refs_bak
                # Ensure update_ref runs in the normal git repo.
                replace = self._replace
                self._replace = {}
                for status, ref, sha1 in update:
                    if status == VersionedDict.REMOVED:
                        self.delete_ref(ref)
                    else:
                        if isinstance(sha1, Mark):
                            # We may still have unresolved marks, but in this
                            # case, they are from an aborted fast-import, in
                            # which case dropping them is the right thing to do
                            sha1 = refs.get(ref)
                        if sha1:
                            self.update_ref(ref, sha1)
                if self._update_ref:
                    retcode = self._update_ref.wait()
                    self._update_ref = None
                    if retcode:
                        raise Exception('git-update-ref failed')
                import shutil
                logging.getLogger('replace').debug(LazyString(
                    lambda: 'Cleaning up in %s' % GitProcess._git_replace_path)
                )
                shutil.rmtree(GitProcess._git_replace_path)
                GitProcess._git_replace_path = None
                self._replace = replace

    @classmethod
    def iter(self, *args, **kwargs):
        start = time.time()

        proc = GitProcess(*args, **kwargs)
        try:
            for line in proc.stdout or ():
                line = line.rstrip('\n')
                yield line

        finally:
            proc.wait()
            logging.getLogger(args[0]).info(
                LazyString(lambda: '[%d] wall time: %.3fs' % (
                    proc.pid,
                    time.time() - start,
                )))

    @classmethod
    def run(self, *args):
        return tuple(self.iter(*args, stdout=None))

    @classmethod
    def for_each_ref(self, *patterns):
        if not patterns:
            return
        # Ideally, this would not actually call for-each-ref if all refs
        # matching the given patterns are already known.
        for line in self.iter('for-each-ref', '--format',
                              '%(objectname) %(refname)', *patterns):
            sha1, ref = line.split(' ', 1)
            self._refs._previous[ref] = sha1
            # The ref might have been removed in self._refs
            if ref in self._refs:
                yield self._refs[ref], ref

    @classmethod
    def resolve_ref(self, ref):
        if ref not in self._refs:
            self._refs._previous[ref] = one(
                Git.iter('rev-parse', '--revs-only', ref))
        return self._refs[ref]

    @classmethod
    def cat_file(self, typ, sha1):
        if self._fast_import and typ == 'blob' and isinstance(sha1, Mark):
            return self._fast_import.cat_blob(sha1)

        if not self._cat_file:
            self._cat_file = GitProcess('cat-file', '--batch',
                                        stdin=subprocess.PIPE)

        self._cat_file.stdin.write(sha1 + '\n')
        header = self._cat_file.stdout.readline().split()
        if header[1] == 'missing':
            if typ == 'auto':
                return 'missing', None
            return None
        assert typ == 'auto' or header[1] == typ
        size = int(header[2])
        ret = self._cat_file.stdout.read(size)
        lf = self._cat_file.stdout.read(1)
        assert lf == '\n'
        if typ == 'auto':
            return header[1], ret
        return ret

    @classmethod
    def ls_tree(self, treeish, path='', recursive=False):
        if (not isinstance(treeish, Mark) and
                treeish.startswith('refs/')):
            treeish = self.resolve_ref(treeish)
        normalize = False
        if recursive:
            assert not isinstance(treeish, Mark)
            iterator = self.iter('ls-tree', '--full-tree', '-r', treeish,
                                 '--', path)
            normalize = True
        elif isinstance(treeish, Mark) and self._fast_import:
            assert not path.endswith('/')
            ls = self._fast_import.ls(treeish, path)
            if any(l is not None for l in ls):
                yield ls
            return
        elif not isinstance(treeish, Mark):
            if path == '' or path.endswith('/'):
                from githg import GitHgHelper
                treeish = treeish + ':' + path
                typ, data = GitHgHelper.cat_file('auto', treeish)
                assert typ in ('tree', 'missing')
                while data:
                    null = data.index('\0')
                    mode, path = data[:null].split(' ', 1)
                    if mode == '160000':
                        typ = 'commit'
                    elif mode == '40000':
                        typ = 'tree'
                        mode = '040000'
                    else:
                        typ = 'blob'
                    sha1 = hexlify(data[null + 1:null + 21])
                    yield mode, typ, sha1, path
                    data = data[null + 21:]
            else:
                base = path.rsplit('/', 1)
                if len(base) == 1:
                    base = ''
                else:
                    base, path = base
                    base += '/'
                for mode, typ, sha1, p in self.ls_tree(treeish, base):
                    if p == path:
                        yield mode, typ, sha1, path
            return
        else:
            iterator = self.iter('ls-tree', '--full-tree', treeish, '--', path)
            normalize = True

        for line in iterator:
            if normalize:
                mode, typ, sha1, path = split_ls_tree(line)
                yield mode, typ, sha1, normalize_path(path)
            else:
                yield split_ls_tree(line)

    @classmethod
    def diff_tree(self, treeish1, treeish2, path='', detect_copy=False,
                  recursive=False):
        key = (path, recursive, detect_copy)
        if key not in self._diff_tree:
            args = ['--stdin', '--', path]
            if recursive:
                args.insert(0, '-r')
            if detect_copy:
                args[:0] = ['-C100%']
            self._diff_tree[key] = GitProcess('diff-tree', *args,
                                              stdin=subprocess.PIPE)
        diff_tree = self._diff_tree[key]
        diff_tree.stdin.write('%s %s\n\n' % (treeish2, treeish1))
        line = diff_tree.stdout.readline(
            ).rstrip('\n')  # First line is a header

        while line:
            line = diff_tree.stdout.readline().rstrip('\n')
            if not line:
                break
            (mode_before, mode_after, sha1_before, sha1_after,
             remainder) = line.split(' ', 4)
            status, path = remainder.split('\t', 1)
            path = '\t'.join(normalize_path(p) for p in path.split('\t'))
            yield (mode_before[1:], mode_after, sha1_before, sha1_after,
                   status, path)

    @classmethod
    def read_note(self, notes_ref, sha1):
        sha1 = self._replace.get(sha1, sha1)
        if not notes_ref.startswith('refs/'):
            notes_ref = 'refs/notes/' + notes_ref
        if notes_ref in self._notes_depth:
            depths = (self._notes_depth[notes_ref],)
        else:
            depths = xrange(0, 20)
        for depth in depths:
            blob = self.cat_file('blob', '%s:%s' % (notes_ref,
                                                    sha1path(sha1, depth)))
            if blob:
                self._notes_depth[notes_ref] = depth
                return blob
        return None

    @classmethod
    def update_ref(self, ref, newvalue, oldvalue=None, store=True):
        if not isinstance(newvalue, Mark) and newvalue.startswith('refs/'):
            newvalue = self.resolve_ref(newvalue)
        if newvalue and newvalue != NULL_NODE_ID:
            self._refs[ref] = newvalue
        else:
            del self._refs[ref]
        if not store:
            return
        if self._fast_import:
            self._fast_import.write(
                'reset %s\n'
                'from %s\n'
                % (ref, newvalue)
            )
            self._fast_import.flush()
            return
        if not self._update_ref:
            self._update_ref = GitProcess('update-ref', '--stdin',
                                          stdin=subprocess.PIPE)

        if oldvalue is None:
            update = 'update %s %s\n' % (ref, newvalue)
        else:
            update = 'update %s %s %s\n' % (ref, newvalue, oldvalue)
        self._update_ref.stdin.write(update)

    @classmethod
    def delete_ref(self, ref, oldvalue=None):
        self.update_ref(ref, '0' * 40, oldvalue)

    @classmethod
    def config(self, name):
        if self._config is None:
            self._config = {
                k: v
                for k, v in (l.split('=', 1)
                             for l in self.iter('config', '-l'))
            }
        value = self._config.get(name)
        logging.getLogger('config').info(LazyString(
            lambda: '%s = %s' % (name, value or '')))
        return self._config.get(name)


atexit.register(Git.close, rollback=True)


class Mark(int):
    def __str__(self):
        return ':%d' % self


class EmptyMark(Mark):
    pass


class FastImport(IOLogger):
    def __init__(self):
        self._proc = GitProcess('fast-import', '--quiet',
                                stdin=subprocess.PIPE,
                                config={'core.ignorecase': 'false'})
        reader = self._proc.stdout
        writer = self._proc.stdin
        prefix = '[%d]' % self._proc.pid

        super(FastImport, self).__init__(logging.getLogger('fast-import'),
                                         reader, writer, prefix=prefix)
        self._last_mark = 0

        self.write(
            "feature force\n"
            "feature ls\n"
            "feature notes\n"
        )

        self._done = None

    def send_done(self):
        self.write('feature done\n')
        self._done = True

    def read(self, length=0, level=logging.INFO):
        self.flush()
        return super(FastImport, self).read(length, level)

    def readline(self, level=logging.INFO):
        self.flush()
        return super(FastImport, self).readline(level)

    def close(self, rollback=False):
        if not rollback or self._done is not False:
            self.write('done\n')
            self._done = None
        self.flush()
        retcode = self._proc.wait()
        if Git._fast_import == self:
            Git._fast_import = None
        if retcode:
            raise Exception('git-fast-import failed')

    def ls(self, dataref, path=''):
        assert not path.endswith('/')
        assert dataref and not isinstance(dataref, EmptyMark)
        self.write('ls %s %s\n' % (dataref, path))
        line = self.readline()
        if line.startswith('missing '):
            return None, None, None, None
        return split_ls_tree(line[:-1])

    def cat_blob(self, dataref):
        assert dataref and not isinstance(dataref, EmptyMark)
        self.write('cat-blob %s\n' % dataref)
        sha1, blob, size = self.readline().split()
        assert blob == 'blob'
        size = int(size)
        content = self.read(size, level=logging.DEBUG)
        lf = self.read(1)
        assert lf == '\n'
        return content

    def new_mark(self):
        self._last_mark += 1
        return EmptyMark(self._last_mark)

    def cmd_mark(self, mark):
        if mark:
            self.write('mark :%d\n' % mark)

    def cmd_data(self, data):
        self.write('data %d\n' % len(data))
        self.write(data, level=logging.DEBUG)
        self.write('\n')

    def put_blob(self, data='', mark=0):
        self.write('blob\n')
        self.cmd_mark(mark)
        self.cmd_data(data)
        self._done = False

    @staticmethod
    def _format_committer(author):
        author, epoch, utcoffset = author
        return '%s %d %s%02d%02d' % (
            author,
            epoch,
            '+' if utcoffset >= 0 else '-',
            abs(utcoffset) // 60,
            abs(utcoffset) % 60,
        )

    @contextlib.contextmanager
    def commit(self, ref, committer=('<cinnabar@git>', 0, 0), author=None,
               message='', from_commit=None, parents=(), mark=0):
        helper = FastImportCommitHelper(self)
        yield helper

        self.write('commit %s\n' % ref)
        if mark == 0:
            mark = self.new_mark()
        self.cmd_mark(mark)
        # TODO: properly handle errors, like from the committer being badly
        # formatted.
        if author:
            self.write('author %s\n' % self._format_committer(author))
        self.write('committer %s\n' % self._format_committer(committer))
        self.cmd_data(message)
        if isinstance(parents, GeneratorType):
            parents = tuple(parents)
        for count, parent in enumerate(parents):
            if count == 0 and parent == from_commit:
                from_commit = None
                resolved_ref = Git._refs.get(ref)
                if not isinstance(resolved_ref, Mark) or parent != resolved_ref:
                    self.write('from %s\n' % parent)
            else:
                if count == 0:
                    self.write('from %s\n' % NULL_NODE_ID)
                self.write('merge %s\n' % parent)
        if not parents:
            self.write('from %s\n' % NULL_NODE_ID)
        if from_commit:
            mode, typ, tree, path = self.ls(from_commit)
            self.write('M 040000 %s \n' % tree)
        helper.apply()
        self.write('\n')
        self._done = False
        if mark:
            Git._refs[ref] = Mark(mark)
            assert Git._refs.values().count(mark) == 1
        else:
            del Git._refs[ref]


class FastImportCommitHelper(object):
    def __init__(self, fast_import):
        self._fast_import = fast_import
        self._command_queue = []

    def write(self, data):
        self._command_queue.append((self._fast_import.write, data))

    def cmd_data(self, data):
        self._command_queue.append((self._fast_import.cmd_data, data))

    def filedelete(self, path):
        self.write('D %s\n' % path)

    MODE = {
        'regular': '644',
        'exec': '755',
        'tree': '040000',
        'symlink': '120000',
        'commit': '160000',
    }

    def filemodify(self, path, sha1, typ='regular'):
        assert sha1 and not isinstance(sha1, EmptyMark)
        self.write('M %s %s %s\n' % (
            self.MODE[typ],
            sha1,
            path,
        ))

    def notemodify(self, commitish, note):
        self.write('N inline %s\n' % commitish)
        self.cmd_data(note)

    def apply(self):
        for fn, arg in self._command_queue:
            fn(arg)
