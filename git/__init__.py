from __future__ import division
import atexit
import contextlib
import logging
import os
import subprocess
import time
import types
from util import (
    IOLogger,
    LazyString,
    one,
)

git_logger = logging.getLogger('git')
# git_logger.setLevel(logging.INFO)


def sha1path(sha1, depth=2):
    i = -1
    return '/'.join(
        [sha1[i*2:i*2+2] for i in xrange(0, depth)] + [sha1[i*2+2:]])


def split_ls_tree(line):
    mode, typ, remainder = line.split(' ', 2)
    sha1, path = remainder.split('\t', 1)
    return mode, typ, sha1, path


class GitProcess(object):
    KWARGS = set(['stdin', 'stdout'])

    def __init__(self, *args, **kwargs):
        assert not kwargs or not set(kwargs.keys()) - self.KWARGS
        stdin = kwargs.get('stdin', None)
        stdout = kwargs.get('stdout', subprocess.PIPE)
        if isinstance(stdin, types.StringType) or callable(stdin):
            proc_stdin = subprocess.PIPE
        else:
            proc_stdin = stdin

        self._proc = subprocess.Popen(['git'] + list(args), stdin=proc_stdin,
                                      stdout=stdout)

        git_logger.info(LazyString(lambda: '[%d] git %s' % (
            self._proc.pid,
            ' '.join(args),
        )))

        if proc_stdin == subprocess.PIPE:
            if isinstance(stdin, types.StringType):
                self._proc.stdin.write(stdin_data)
            elif callable(stdin):
                for line in stdin():
                    self._proc.stdin.write(line)
            if proc_stdin != stdin:
                self._proc.stdin.close()

    def wait(self):
        if self.stdin:
            self.stdin.close()
        return self._proc.wait()

    @property
    def pid(self):
        return self._proc.pid

    @property
    def stdin(self):
        return self._proc.stdin

    @property
    def stdout(self):
        return self._proc.stdout


class Git(object):
    _cat_file = None
    _update_ref = None
    _fast_import = None
    _diff_tree = {}
    _notes_depth = {}
    _refs = {}

    @classmethod
    def register_fast_import(self, fast_import):
        self._fast_import = fast_import

    @classmethod
    def close(self):
        if self._cat_file:
            self._cat_file.wait()
            self._cat_file = None
        if self._update_ref:
            self._update_ref.wait()
            self._update_ref = None
        for diff_tree in self._diff_tree.itervalues():
            diff_tree.wait()
        self._diff_tree = {}
        if self._fast_import:
            self._fast_import.close()
            self._fast_import = None

    @classmethod
    def iter(self, *args, **kwargs):
        start = time.time()

        proc = GitProcess(*args, **kwargs)
        for line in proc.stdout or ():
            git_logger.debug(LazyString(lambda: '[%d] => %s' % (
                proc.pid,
                repr(line),
            )))
            line = line.rstrip('\n')
            yield line

        proc.wait()
        git_logger.info(LazyString(lambda: '[%d] wall time: %.3fs' % (
            proc.pid,
            time.time() - start,
        )))

    @classmethod
    def run(self, *args):
        return tuple(self.iter(*args, stdout=None))

    @classmethod
    def for_each_ref(self, pattern, format='%(objectname)'):
        if format:
            return self.iter('for-each-ref', '--format', format, pattern)
        return self.iter('for-each-ref', pattern)

    @classmethod
    def resolve_ref(self, ref):
        # TODO: self._refs should be updated by update_ref
        if ref not in self._refs:
            self._refs[ref] = one(self.for_each_ref(ref))
        return self._refs[ref]

    @classmethod
    def cat_file(self, typ, sha1):
        if not self._cat_file:
            self._cat_file = GitProcess('cat-file', '--batch',
                                        stdin=subprocess.PIPE)

        self._cat_file.stdin.write(sha1 + '\n')
        header = self._cat_file.stdout.readline().split()
        if header[1] == 'missing':
            return None
        assert header[1] == typ
        size = int(header[2])
        ret = self._cat_file.stdout.read(size)
        lf = self._cat_file.stdout.read(1)
        assert lf == '\n'
        return ret

    @classmethod
    def ls_tree(self, treeish, path='', recursive=False):
        if recursive:
            iterator = self.iter('ls-tree', '-r', treeish, '--', path)
        else:
            if not path.endswith('/') and self._fast_import:
                if treeish.startswith('refs/'):
                    treeish = self.resolve_ref(treeish)
                ls = self._fast_import.ls(treeish, path)
                if any(l is not None for l in ls):
                    yield ls
                return
            iterator = self.iter('ls-tree', treeish, '--', path)

        for line in iterator:
            yield split_ls_tree(line)

    @classmethod
    def diff_tree(self, treeish1, treeish2, path='', recursive=False):
        key = (path, recursive)
        if not key in self._diff_tree:
            args = ['--stdin', '--', path]
            if recursive:
                args.insert(0, '-r')
            self._diff_tree[key] = GitProcess('diff-tree', *args,
                                              stdin=subprocess.PIPE)
        diff_tree = self._diff_tree[key]
        diff_tree.stdin.write('%s %s\n\n' % (treeish2, treeish1))
        line = diff_tree.stdout.readline().rstrip('\n')  # First line is a header
        while line:
            line = diff_tree.stdout.readline().rstrip('\n')
            if not line:
                break
            mode_before, mode_after, sha1_before, sha1_after, remainder = line.split(' ', 4)
            status, path = remainder.split('\t', 1)
            yield (mode_before[1:], mode_after, sha1_before, sha1_after,
                status, path)

    @classmethod
    def read_note(self, notes_ref, sha1):
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
    def update_ref(self, ref, newvalue, oldvalue=None):
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
    def config(self, name, typ=None):
        if typ:
            args = ['--%s' % typ, name]
        else:
            args = [name]
        try:
            return one(self.iter('config', *args))
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:
                raise
            return None

atexit.register(Git.close)


class Mark(int):
    def __str__(self):
        return ':%d' % self


class EmptyMark(Mark):
    pass


class FastImport(IOLogger):
    def __init__(self, reader=None, writer=None):
        assert bool(reader) == bool(writer)

        if not reader and not writer:
            reader, writer = os.pipe()
            reader = os.fdopen(reader, 'r', 0)
            self._proc = GitProcess('fast-import', '--cat-blob-fd=%d' % writer,
                                    '--quiet', stdin=subprocess.PIPE)
            writer = self._proc.stdin
        else:
            self._proc = None

        super(FastImport, self).__init__(logging.getLogger('fast-import'),
                                         reader, writer)
        self._last_mark = 0

        self.write(
            "feature force\n"
            "feature ls\n"
            "feature notes\n"
        )

        self._done = False

    def send_done(self):
        self.write('feature done\n')
        self._done = True

    def progress_iter(self, what, iter, step=1000):
        count = 0
        for count, item in enumerate(iter, start=1):
            if count % step == 0:
                self.write('progress %d %s\n' % (count, what))
#                print hp.heap()
            yield item
        if count % step:
            self.write('progress %d %s\n' % (count, what))

    def read(self, length=0, level=logging.INFO):
        self.flush()
        return super(FastImport, self).read(length, level)

    def readline(self, level=logging.INFO):
        self.flush()
        return super(FastImport, self).readline(level)

    def close(self):
        if self._done:
            self.write('done\n')
        self.flush()
        if self._proc:
            self._proc.wait()
        if Git._fast_import == self:
            Git._fast_import = None

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
    def commit(self, ref, committer=('<remote-hg@git>', 0, 0), author=None,
               message='', parents=(), mark=0):
        helper = FastImportCommitHelper(self)
        yield helper

        self.write('commit %s\n' % ref)
        self.cmd_mark(mark)
        # TODO: properly handle errors, like from the committer being badly
        # formatted.
        if author:
            self.write('author %s\n' % self._format_committer(author))
        self.write('committer %s\n' % self._format_committer(committer))
        self.cmd_data(message)
        for count, parent in enumerate(parents):
            self.write('%s %s\n' % (
                'from' if count == 0 else 'merge',
                parent,
            ))
        helper.apply()
        self.write('\n')


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
