import logging
import os
import sys
import time
import unittest
from collections import OrderedDict
from difflib import (
    Match,
    SequenceMatcher,
)
from itertools import (
    chain,
    izip,
)


def init_logging():
    # Initialize logging from the GIT_CINNABAR_LOG environment variable
    # or the cinnabar.log configuration, the former taking precedence.
    # Still read the configuration to force the git config cache being
    # filled before logging is setup, so that the output of
    # `git config -l` is never logged.
    from .git import Git
    log_conf = Git.config('cinnabar.log')
    log_env = os.environ.get('GIT_CINNABAR_LOG')
    if not log_env and not log_conf:
        return
    if log_env is None:
        log_env = log_conf
    for assignment in log_env.split(','):
        try:
            name, value = assignment.split(':', 1)
            value = int(value)
            if name == '*':
                name = ''
            logging.getLogger(name).setLevel(
                max(logging.DEBUG, logging.FATAL - value * 10))
        except:
            pass


class CheckEnabledFunc(object):
    def __init__(self):
        self._check = None

    def __call__(self, name):
        if self._check is None:
            from .git import Git
            self._check = (Git.config('cinnabar.check') or '').split(',')
            for c in self._check:
                if c not in ('nodeid', 'manifests', 'helper'):
                    logging.getLogger('check').warn(
                        'Unknown value in cinnabar.check: %s' % c)
        return name in self._check

check_enabled = CheckEnabledFunc()


def next(iter):
    try:
        return iter.next()
    except StopIteration:
        return None


progress = True


def progress_iter(fmt, iter, filter_func=None):
    count = 0
    t0 = 0
    for item in iter:
        if progress:
            if not filter_func or filter_func(item):
                count += 1
            t1 = time.time()
            if t1 - t0 > 1:
                sys.stderr.write(('\r' + fmt) % count)
                t0 = t1
        yield item
    if progress and count:
        sys.stderr.write(('\r' + fmt + '\n') % count)


class IOLogger(object):
    def __init__(self, logger, reader, writer=None, prefix=''):
        self._reader = reader
        self._writer = writer or reader
        self._logger = logger
        self._prefix = (prefix + ' ') if prefix else ''

    def read(self, length=0, level=logging.INFO):
        ret = self._reader.read(length)
        if not isinstance(self._reader, IOLogger):
            self._logger.log(level, LazyString(lambda: '%s<= %s'
                                               % (self._prefix, repr(ret))))
        return ret

    def readline(self, level=logging.INFO):
        ret = self._reader.readline()
        if not isinstance(self._reader, IOLogger):
            self._logger.log(level, LazyString(lambda: '%s<= %s'
                                               % (self._prefix, repr(ret))))
        return ret

    def write(self, data, level=logging.INFO):
        if not isinstance(self._writer, IOLogger):
            self._logger.log(level, LazyString(lambda: '%s=> %s'
                                               % (self._prefix, repr(data))))
        return self._writer.write(data)

    def flush(self):
        self._writer.flush()

    def __iter__(self):
        while True:
            l = self.readline()
            if not l:
                break
            yield l


class LazyString(object):
    def __init__(self, obj):
        self._obj = obj

    def __str__(self):
        if callable(self._obj):
            self._obj = self._obj()
        return self._obj

    def __len__(self):
        return len(str(self))

    def __eq__(self, other):
        return str(self) == str(other)

    def __ne__(self, other):
        return str(self) != str(other)

    def __repr__(self):
        return '<LazyString %s>' % repr(str(self))

    def startswith(self, other):
        return str(self).startswith(other)


def one(l):
    l = list(l)
    if l:
        assert len(l) == 1
        return l[0]
    return None


class OrderedDefaultDict(OrderedDict):
    def __init__(self, default_factory, *args, **kwargs):
        OrderedDict.__init__(self, *args, **kwargs)
        self._default_factory = default_factory

    def __missing__(self, key):
        value = self[key] = self._default_factory()
        return value


def _iter_diff_blocks(a, b):
    m = SequenceMatcher(a=a, b=b, autojunk=False).get_matching_blocks()
    for start, end in izip(chain((Match(0, 0, 0),), m), m):
        if start.a + start.size != end.a or start.b + start.size != end.b:
            yield start.a + start.size, end.a, start.b + start.size, end.b


def byte_diff(a, b):
    '''Given two strings, returns the diff between them, at the byte level.

    Yields start offset in a, end offset in a and replacement string for
    each difference. Far from optimal results, but works well enough.'''
    a = tuple(a.splitlines(True))
    b = tuple(b.splitlines(True))
    offset = 0
    last = 0
    for start_a, end_a, start_b, end_b in _iter_diff_blocks(a, b):
        a2 = ''.join(a[start_a:end_a])
        b2 = ''.join(b[start_b:end_b])
        offset += sum(len(i) for i in a[last:start_a])
        last = start_a
        for start2_a, end2_a, start2_b, end2_b in _iter_diff_blocks(a2, b2):
            yield offset + start2_a, offset + end2_a, b2[start2_b:end2_b]


class TestByteDiff(unittest.TestCase):
    TEST_STRING = (
        'first line\n'
        'second line\n'
        'third line\n'
        'fourth line\n'
    )

    def assertDiffEqual(self, a, b, diff):
        result = tuple(byte_diff(a, b))
        self.assertEqual(result, diff)

    def test_equal(self):
        self.assertDiffEqual(self.TEST_STRING, self.TEST_STRING, ())

    def test_a(self):
        for extra in ('fifth line\n', 'line with no ending',
                      'more\nthan\none\nline'):
            self.assertDiffEqual(
                self.TEST_STRING,
                self.TEST_STRING + extra,
                ((len(self.TEST_STRING), len(self.TEST_STRING), extra),)
            )

            self.assertDiffEqual(
                self.TEST_STRING + extra,
                self.TEST_STRING,
                ((len(self.TEST_STRING), len(self.TEST_STRING + extra), ''),)
            )

    def test_b(self):
        for extra in ('zeroth line\n', 'more\nthan\none\nline\n'):
            self.assertDiffEqual(
                self.TEST_STRING,
                extra + self.TEST_STRING,
                ((0, 0, extra),)
            )

            self.assertDiffEqual(
                extra + self.TEST_STRING,
                self.TEST_STRING,
                ((0, len(extra), ''),)
            )

    def test_c(self):
        extra = 'extra\nstuff'
        extra2 = '\nother\nextra\n'
        self.assertDiffEqual(
            self.TEST_STRING,
            self.TEST_STRING[:15] + extra + self.TEST_STRING[15:18]
            + extra2 + self.TEST_STRING[18:],
            ((15, 15, extra),
             (18, 18, extra2))
        )

        self.assertDiffEqual(
            self.TEST_STRING[:15] + extra + self.TEST_STRING[15:18]
            + extra2 + self.TEST_STRING[18:],
            self.TEST_STRING,
            ((15, 15 + len(extra), ''),
             (18 + len(extra), 18 + len(extra + extra2), ''))
        )

        self.assertDiffEqual(
            self.TEST_STRING,
            self.TEST_STRING[:15] + extra + self.TEST_STRING[17:19]
            + extra2 + self.TEST_STRING[21:],
            ((15, 17, extra),
             (19, 21, extra2))
        )
