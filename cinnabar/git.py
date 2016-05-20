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
    LazyCall,
    one,
    VersionedDict,
)
from binascii import hexlify
from itertools import chain
from distutils.version import LooseVersion

NULL_NODE_ID = '0' * 40
# An empty git tree has a fixed sha1 which is that of "tree 0\0"
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
# An empty git blob has a fixed sha1 which is that of "blob 0\0"
EMPTY_BLOB = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'


class InvalidConfig(Exception): pass


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


def get_git_dir():
    # --git-common-dir is not supported before v2.5, and up to version 2.8,
    # it would wrongfully return '.git' when running from a subdirectory of
    # a non worktree. Whether we are running from such a directory can be
    # determined with --show-cdup, which is supported since git v1.1.
    # Try to get all the necessary information from one subprocess.
    # Sadly, rev-parse doesn't have an option to output null-terminated
    # strings, so if the git dir or the git common dir contain '\n', we
    # can't really tell them apart when doing this in one pass. So we try
    # to be smart about it.
    output = subprocess.check_output(
        ['git', 'rev-parse', '--show-cdup', '--no-flags',
         '--git-dir', '--git-common-dir', '--git-dir']).splitlines()
    # The first line can be:
    # - empty when in the toplevel directory
    # - a series of '../'
    # - literally '--show-cdup' on git < v1.1
    # In the latter case, let's just say git is too old.
    cdup = output.pop(0)
    if cdup == '--show-cdup':
        raise Exception('git version is too old.')
    # Now, depending on whether --git-common-dir is supported, we either
    # have 2 or 3 set of lines.
    for cutoff in range(1, 1 + len(output) // 2):
        git_dir = '\n'.join(output[:cutoff])
        git_common_dir = '\n'.join(output[cutoff:-cutoff])
        if git_dir == '\n'.join(output[-cutoff:]):
            break
    # --git-common-dir is what we really want but can be empty or wrong.
    # That fortunately happens only when we are in the main work tree,
    # which means --git-dir is value to use. When in a non-main work tree,
    # --git-common-dir is always an absolute path. When in the main work
    # tree, if --git-common-dir is an absolute path, it's also correct.
    # Moreover, when in the main work tree, --git-dir and --git-common-dir
    # are supposed to point to the same location.
    # So fallback to --git-dir when --git-common-dir is not an absolute
    # path.
    if git_common_dir and os.path.isabs(git_common_dir):
        git_dir = git_common_dir

    return git_dir, cdup


git_dir, cdup = get_git_dir()


git_version = subprocess.check_output(['git', 'version'])
assert git_version.startswith('git version ')
git_version = LooseVersion(git_version[12:].strip())

HAS_REPLACE_REF_BASE = git_version > LooseVersion('2.6')

if git_version < LooseVersion('1.8.5'):
    raise Exception('git-cinnabar does not support git version prior to '
                    '1.8.5.')


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

        if args[0] == 'config' or not Git._replace:
            # We don't need the replace ref setup for config.
            pass
        elif not check_enabled('replace') and HAS_REPLACE_REF_BASE:
            full_env['GIT_REPLACE_REF_BASE'] = 'refs/cinnabar/replace/'
        else:
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

                logging.getLogger('replace').debug('Initializing in %s', path)

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

    def _env_strings(self, env):
        for k, v in sorted((k, v) for s, k, v in env.iterchanges()
                           if s != env.REMOVED):
            yield '%s=%s' % (k, v)

    def _popen(self, cmd, env, **kwargs):
        assert isinstance(env, VersionedDict)
        proc = subprocess.Popen(cmd, env=env, **kwargs)
        logging.getLogger('git').info('[%d] %s', proc.pid, LazyCall(
            ' '.join, chain(self._env_strings(env), cmd)))
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
    _initial_refs = _refs._previous
    _config = None
    _replace = {}

    @classmethod
    def register_fast_import(self, fast_import):
        self._fast_import = fast_import
        self._refs = VersionedDict(self._refs)

    @classmethod
    def _close_update_ref(self):
        if self._update_ref:
            retcode = self._update_ref.wait()
            self._update_ref = None
            if retcode:
                raise Exception('git-update-ref failed')

    @classmethod
    def close(self, rollback=False):
        if self._cat_file:
            self._cat_file.wait()
            self._cat_file = None
        self._close_update_ref()
        for diff_tree in self._diff_tree.itervalues():
            diff_tree.wait()
        self._diff_tree = {}
        try:
            if self._fast_import:
                self._fast_import.close(rollback)
                self._fast_import = None

                # Git before version 2.1 didn't remove refs when resetting
                # from NULL_NODE_ID. So remove again with update-ref.
                for status, ref, value in self._refs.iterchanges():
                    if status == self._refs.REMOVED:
                        self.delete_ref(ref)
                self._close_update_ref()
                self._refs = self._refs.flattened()
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
                self._close_update_ref()
                import shutil
                logging.getLogger('replace').debug(
                    'Cleaning up in %s', GitProcess._git_replace_path)
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
            logging.getLogger(args[0]).info('[%d] wall time: %.3fs',
                                            proc.pid, time.time() - start)

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
            self._initial_refs[ref] = sha1
            # The ref might have been removed in self._refs
            if ref in self._refs:
                yield self._refs[ref], ref

    @classmethod
    def resolve_ref(self, ref):
        if ref not in self._refs:
            self._initial_refs[ref] = one(
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
            args = ['--stdin', '--', cdup + path]
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
        notes_ref = self.resolve_ref(notes_ref)
        if not notes_ref:
            return None
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
        refs = self._refs if store else self._initial_refs
        if newvalue and newvalue != NULL_NODE_ID:
            refs[ref] = newvalue
        elif ref in refs:
            del refs[ref]
        if not store:
            return
        if self._fast_import:
            self._fast_import.write(
                'reset %s\n'
                'from %s\n'
                '\n'
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
    def config(self, name, remote=None, values={}):
        if self._config is None:
            proc = GitProcess('config', '-l', '-z')
            data = proc.stdout.read()
            proc.wait()
            self._config = {
                k: v
                for k, v in (l.split('\n', 1)
                             for l in data.split('\0') if l)
            }
        var = name
        value = None
        if name.startswith('cinnabar.'):
            var = 'GIT_%s' % name.replace('.', '_').upper()
            value = os.environ.get(var)
            if value is None and remote:
                var = 'remote.%s.%s' % (remote, name.replace('.', '-'))
                value = self._config.get(var)
        elif name == 'fetch.prune' and remote:
            var = 'remote.%s.prune' % remote
            value = self._config.get(var)
        if value is None:
            var = name
            value = self._config.get(name)
        logging.getLogger('config').info('%s = %r', var, value)
        if values:
            if value in values:
                if isinstance(values, dict):
                    value = values[value]
            else:
                values = ', '.join(repr(v) for v in sorted(values)
                                   if v is not None)
                if value is None:
                    raise InvalidConfig(
                        '%s must be set to one of %s' % (var, values))
                else:
                    raise InvalidConfig(
                        'Invalid value for %s: %s. Valid values: %s' % (
                            var, repr(value), values))
        return value


atexit.register(Git.close, rollback=True)


class Mark(int):
    def __str__(self):
        return ':%d' % self


class EmptyMark(Mark):
    pass


class FastImport(IOLogger):
    def __init__(self):
        if Git.config('cinnabar.experiments') == 'true':
            from githg import GitHgHelper
            # Ensure the helper is there.
            with GitHgHelper.query('feature', 'force'):
                pass
            self._proc = GitHgHelper._helper
        else:
            self._proc = GitProcess('fast-import', '--quiet',
                                    stdin=subprocess.PIPE,
                                    config={'core.ignorecase': 'false'})
        reader = self._proc.stdout
        writer = self._proc.stdin

        super(FastImport, self).__init__(logging.getLogger('fast-import'),
                                         reader, writer)
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
        from githg import GitHgHelper
        if self._proc is GitHgHelper._helper:
            retcode = self._proc.poll()
        else:
            retcode = self._proc.wait()
        if Git._fast_import == self:
            Git._fast_import = None
        if retcode and not rollback:
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

        yield helper

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

    def write(self, data):
        self._fast_import.write(data)

    def cmd_data(self, data):
        self._fast_import.cmd_data(data)

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
        # We may receive the sha1 for an empty blob, even though there is no
        # empty blob stored in the repository. So for empty blobs, use an
        # inline filemodify.
        dataref = 'inline' if sha1 == EMPTY_BLOB else sha1
        self.write('M %s %s %s\n' % (
            self.MODE[typ],
            dataref,
            path,
        ))
        if sha1 == EMPTY_BLOB:
            self.cmd_data('')

    def notemodify(self, commitish, note):
        self.write('N inline %s\n' % commitish)
        self.cmd_data(note)

    def ls(self, path=''):
        self.write('ls "%s"\n' % path)
        line = self._fast_import.readline()
        if line.startswith('missing '):
            return None, None, None, None
        return split_ls_tree(line[:-1])
