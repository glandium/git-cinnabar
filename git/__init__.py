import atexit
import logging
import os
import subprocess
import time
import types
from util import LazyString

git_logger = logging.getLogger('git')
# git_logger.setLevel(logging.INFO)


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

    @classmethod
    def close(self):
        if self._cat_file:
            self._cat_file.wait()
            self._cat_file = None

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
        if not pattern.startswith('refs/'):
            pattern = 'refs/remote-hg/%s' % pattern
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

atexit.register(Git.close)
