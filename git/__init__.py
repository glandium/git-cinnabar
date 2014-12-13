import atexit
import logging
import os
import subprocess
import time
import types
from util import LazyString

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
    def __init__(self, *args, **kwargs):
        assert not kwargs or kwargs.keys() == ['stdin']
        stdin = kwargs.get('stdin', None)
        if isinstance(stdin, types.StringType) or callable(stdin):
            proc_stdin = subprocess.PIPE
        else:
            proc_stdin = stdin

        self._proc = subprocess.Popen(['git'] + list(args), stdin=proc_stdin,
                                      stdout=subprocess.PIPE)

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
    _diff_tree = {}
    _notes_depth = {}

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

    @classmethod
    def iter(self, *args, **kwargs):
        start = time.time()

        proc = GitProcess(*args, **kwargs)
        for line in proc.stdout:
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
        return tuple(self.iter(*args))

    @classmethod
    def for_each_ref(self, pattern, format='%(objectname)'):
        if format:
            return self.iter('for-each-ref', '--format', format, pattern)
        return self.iter('for-each-ref', pattern)

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
        self._cat_file.stdout.read(1)  # LF
        return ret

    @classmethod
    def ls_tree(self, treeish, path='', recursive=False):
        if recursive:
            iterator = self.iter('ls-tree', '-r', treeish, '--', path)
        else:
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



atexit.register(Git.close)
