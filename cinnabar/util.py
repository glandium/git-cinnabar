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
    if not log_conf:
        return
    for assignment in log_conf.split(','):
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
            self._check = Git.config('cinnabar.check') or ''
            if self._check:
                self._check = self._check.split(',')
            for c in self._check:
                if c not in ('nodeid', 'manifests', 'helper', 'replace'):
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
        self._obj = obj._obj if isinstance(obj, LazyString) else obj

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

    def __hash__(self):
        return hash(str(self))

    def __add__(self, other):
        return str(self) + other


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


class VersionedDict(object):
    def __init__(self, content=None, **kwargs):
        if content:
            if kwargs:
                self._previous = VersionedDict(content)
                for k, v in kwargs.iteritems():
                    self._previous[k] = v
            elif isinstance(content, (VersionedDict, dict)):
                self._previous = content
            else:
                self._previous = dict(content)
        else:
            self._previous = dict(**kwargs)
        self._dict = {}
        self._deleted = set()

    def update(self, content=None, **kwargs):
        if content:
            if isinstance(content, (VersionedDict, dict)):
                content = content.iteritems()
            for k, v in content:
                self[k] = v
        for k, v in kwargs.iteritems():
            self[k] = v

    def __getitem__(self, key):
        if key in self._dict:
            return self._dict[key]
        return self._previous[key]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        if key in self._deleted:
            return False
        if key in self._dict:
            return True
        return key in self._previous

    def __delitem__(self, key):
        self._deleted.add(key)
        if key in self._dict:
            del self._dict[key]
        elif key not in self._previous:
            raise KeyError(key)

    def __setitem__(self, key, value):
        if key in self._deleted:
            self._deleted.remove(key)
        self._dict[key] = value

    def __len__(self):
        return len(self._dict) + sum(1 for k in self._previous
                                     if k not in self._deleted and
                                     k not in self._dict)

    def keys(self):
        if self._previous:
            return list(self)
        return self._dict.keys()

    def values(self):
        if self._previous:
            return list(chain(
                self._dict.values(),
                (v for k, v in self._previous.iteritems()
                 if k not in self._deleted and k not in self._dict)))
        return self._dict.values()

    def __iter__(self):
        if self._previous:
            return chain(self._dict,
                         (k for k in self._previous
                          if k not in self._deleted and k not in self._dict))
        return iter(self._dict)

    def iteritems(self):
        if self._previous:
            return chain(
                self._dict.iteritems(),
                ((k, v) for k, v in self._previous.iteritems()
                 if k not in self._deleted and k not in self._dict))
        return self._dict.iteritems()

    CREATED = 1
    MODIFIED = 2
    REMOVED = 3

    def iterchanges(self):
        for k, v in self._dict.iteritems():
            if k in self._previous:
                if self._previous[k] == v:
                    continue
                status = self.MODIFIED
            else:
                status = self.CREATED
            yield status, k, v
        for k in self._deleted:
            if k in self._previous:
                yield self.REMOVED, k, self._previous[k]


class TestVersionedDict(unittest.TestCase):
    def check_state(self, v, d):
        self.assertEquals(sorted(v.keys()), sorted(d.keys()))
        self.assertEquals(sorted(k for k in v), sorted(k for k in d))
        self.assertEquals(sorted(i for i in v.iteritems()),
                          sorted(i for i in d.iteritems()))
        self.assertEquals(sorted(v.values()), sorted(d.values()))
        self.assertEquals(bool(d), bool(v))
        self.assertEquals(len(d), len(v))
        for k, val in d.iteritems():
            self.assertTrue(k in v)
            self.assertEquals(v[k], val)

    def test_versioned_dict(self):
        for typ in (dict, VersionedDict):
            for init in ({}, {'hoge': 'hoge'},
                         {'hoge': 'hoge', 'fuga': 'fuga'}):
                d = {}
                d.update(init)
                v = typ(**init)
                self.check_state(v, d)
                v.update(foo='foo', bar='qux')
                d.update(foo='foo', bar='qux')
                self.check_state(v, d)
                self.assertEquals(v['foo'], 'foo')
                self.assertEquals(v['bar'], 'qux')
                with self.assertRaises(KeyError):
                    v['qux']
                with self.assertRaises(KeyError):
                    del v['qux']
                self.assertTrue('foo' in v)
                self.assertTrue('bar' in v)
                self.assertFalse('qux' in v)

                if 'fuga' in init:
                    self.check_state(v, d)
                    self.assertTrue('fuga' in v)
                    self.assertEquals(v['fuga'], 'fuga')
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                        ])

                    v['fuga'] = 'toto'
                    d['fuga'] = 'toto'
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.MODIFIED, 'fuga', 'toto'),
                        ])

                    del v['fuga']
                    del d['fuga']
                    self.assertFalse('fuga' in v)
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.REMOVED, 'fuga', 'fuga'),
                        ])
                elif 'hoge' in init:
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                        ])

                    del v['hoge']
                    del d['hoge']
                    self.assertFalse('hoge' in v)
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.REMOVED, 'hoge', 'hoge'),
                        ])

                    v['hoge'] = 'fuga'
                    d['hoge'] = 'fuga'
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.MODIFIED, 'hoge', 'fuga'),
                        ])

                    del v['hoge']
                    del d['hoge']
                    self.assertFalse('hoge' in v)
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.REMOVED, 'hoge', 'hoge'),
                        ])

                    v['hoge'] = 'hoge'
                    d['hoge'] = 'hoge'
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                        ])

                else:
                    self.check_state(v, d)

                    del v['foo']
                    del d['foo']
                    self.assertFalse('foo' in v)
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEquals(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                        ])

                for k in v.keys():
                    del v[k]
                    del d[k]
                    self.check_state(v, d)

    def test_init(self):
        d = {'foo': 'foo', 'bar': 'qux'}
        d1 = VersionedDict(d)
        self.assertIs(d1._previous, d)

        d1 = VersionedDict(**d)
        self.assertIsInstance(d1._previous, dict)
        self.assertIsNot(d1._previous, d)
        self.assertEquals(d1._previous, d)

        d1 = VersionedDict(d.iteritems())
        self.assertIsInstance(d1._previous, dict)
        self.assertIsNot(d1._previous, d)
        self.assertEquals(d1._previous, d)

        d1 = VersionedDict(d, bar='bar', hoge='hoge', fuga='toto')
        self.assertIsInstance(d1._previous, VersionedDict)
        self.assertEquals(sorted(d1._previous.iterchanges()), [
            (d1.CREATED, 'fuga', 'toto'),
            (d1.CREATED, 'hoge', 'hoge'),
            (d1.MODIFIED, 'bar', 'bar'),
        ])

        d2 = VersionedDict(d1)
        self.assertIs(d2._previous, d1)

        d2 = VersionedDict(d1, hoge=42, toto='titi')
        self.assertIsInstance(d2._previous, VersionedDict)
        self.assertIsNot(d2._previous, d1)
        self.assertEquals(sorted(d2._previous.iterchanges()), [
            (d1.CREATED, 'toto', 'titi'),
            (d1.MODIFIED, 'hoge', 42),
        ])

    def test_update(self):
        d1 = {'a': 1, 'b': 2}
        d2 = {'c': 3, 'd': 4}

        for content, kwargs in ((d1, {}), ((), d2), (d1, d2)):
            d = {}
            v = VersionedDict()
            args = content and [content]
            d.update(*args, **kwargs)
            v.update(*args, **kwargs)
            self.check_state(v, d)

    def test_change_previous(self):
        d = {'foo': 'foo', 'bar': 'qux'}
        d1 = VersionedDict(d)

        d1['hoge'] = 'hoge'
        del d1['hoge']
        self.assertTrue('hoge' not in d1)
        self.assertEquals(sorted(d1.iterchanges()), [])

        d['hoge'] = 'fuga'
        self.assertTrue('hoge' not in d1)
        self.assertEquals(sorted(d1.iterchanges()), [
            (d1.REMOVED, 'hoge', 'fuga'),
        ])

        d1['foo'] = 'foo'
        self.assertEquals(sorted(d1.iterchanges()), [
            (d1.REMOVED, 'hoge', 'fuga'),
        ])

        d['foo'] = 'bar'
        self.assertEqual(d1['foo'], 'foo')
        self.assertEquals(sorted(d1.iterchanges()), [
            (d1.MODIFIED, 'foo', 'foo'),
            (d1.REMOVED, 'hoge', 'fuga'),
        ])


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
