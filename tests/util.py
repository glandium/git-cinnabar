import unittest
from cinnabar.util import (
    byte_diff,
    lrucache,
    sorted_merge,
    VersionedDict,
)


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

    def test_nested(self):
        d = {'foo': 'foo', 'bar': 'qux'}
        d1 = VersionedDict(d)
        d1['hoge'] = 'hoge'
        d1['foo'] = 'foo2'
        del d1['bar']

        d2 = VersionedDict(d1)
        del d2['hoge']
        d2['fuga'] = 'fuga'

        self.assertTrue('hoge' in d1)
        self.assertTrue('hoge' not in d2)

        self.assertEquals(sorted(d2.iterchanges()), [
            (d2.CREATED, 'fuga', 'fuga'),
            (d2.REMOVED, 'hoge', 'hoge'),
        ])

        d3 = d2.flattened()

        self.assertTrue('hoge' not in d3)
        self.assertTrue('fuga' in d3)

        self.assertEquals(sorted(d3.iterchanges()), [
            (d2.CREATED, 'fuga', 'fuga'),
            (d2.MODIFIED, 'foo', 'foo2'),
            (d2.REMOVED, 'bar', 'qux'),
        ])


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
            self.TEST_STRING[:15] + extra + self.TEST_STRING[15:18] +
            extra2 + self.TEST_STRING[18:],
            ((15, 15, extra),
             (18, 18, extra2))
        )

        self.assertDiffEqual(
            self.TEST_STRING[:15] + extra + self.TEST_STRING[15:18] +
            extra2 + self.TEST_STRING[18:],
            self.TEST_STRING,
            ((15, 15 + len(extra), ''),
             (18 + len(extra), 18 + len(extra + extra2), ''))
        )

        self.assertDiffEqual(
            self.TEST_STRING,
            self.TEST_STRING[:15] + extra + self.TEST_STRING[17:19] +
            extra2 + self.TEST_STRING[21:],
            ((15, 17, extra),
             (19, 21, extra2))
        )


class TestSortedMerge(unittest.TestCase):
    def test_sorted_merge(self):
        a = [
            ('a', 1),
            ('b', 2),
            ('d', 4),
        ]
        b = [
            ('b', 'B'),
            ('c', 'C'),
        ]

        self.assertEquals(list(sorted_merge(a, b)), [
            ('a', (1,), ()),
            ('b', (2,), ('B',)),
            ('c', (), ('C',)),
            ('d', (4,), ()),
        ])

        self.assertEquals(list(sorted_merge(b, a)), [
            ('a', (), (1,)),
            ('b', ('B',), (2,)),
            ('c', ('C',), ()),
            ('d', (), (4,)),
        ])

        self.assertEquals(list(sorted_merge(a[:2], b[:1])), [
            ('a', (1,), ()),
            ('b', (2,), ('B',)),
        ])


class TestLRUCache(unittest.TestCase):
    def test_node(self):
        top = lrucache.node()
        top.next = top
        top.prev = top

        node = lrucache.node()
        node.insert(top)

        self.assertEquals(top.next, node)
        self.assertEquals(top.prev, node)
        self.assertEquals(node.next, top)
        self.assertEquals(node.prev, top)

        node2 = lrucache.node()
        node2.insert(top)
        self.assertEquals(node2.next, node)
        self.assertEquals(node2.prev, top)
        self.assertEquals(top.next, node2)
        self.assertEquals(top.prev, node)
        self.assertEquals(node.next, top)
        self.assertEquals(node.prev, node2)

        node.insert(top)
        self.assertEquals(node.next, node2)
        self.assertEquals(node.prev, top)
        self.assertEquals(top.next, node)
        self.assertEquals(top.prev, node2)
        self.assertEquals(node2.next, top)
        self.assertEquals(node2.prev, node)

        node2.detach()
        self.assertEquals(top.next, node)
        self.assertEquals(top.prev, node)
        self.assertEquals(node.next, top)
        self.assertEquals(node.prev, top)

    def test_lru_cache(self):
        cache = lrucache(2)

        self.calls = 0

        @cache
        def foo(value):
            self.calls += 1
            return value * 2

        self.assertEquals(foo(1), 2)
        self.assertEquals(self.calls, 1)
        self.assertEquals(foo(1), 2)
        self.assertEquals(self.calls, 1)
        self.assertEquals(len(cache), 1)

        self.assertEquals(foo(2), 4)
        self.assertEquals(self.calls, 2)
        self.assertEquals(foo(2), 4)
        self.assertEquals(self.calls, 2)
        self.assertEquals(len(cache), 2)

        self.assertEquals(foo(1), 2)
        self.assertEquals(self.calls, 2)

        self.assertEquals(foo(3), 6)
        self.assertEquals(self.calls, 3)
        self.assertEquals(len(cache), 2)

        self.assertEquals(foo(1), 2)
        self.assertEquals(self.calls, 3)

        self.assertEquals(foo(2), 4)
        self.assertEquals(self.calls, 4)
        self.assertEquals(len(cache), 2)

        foo.invalidate(1)
        self.assertEquals(foo(1), 2)
        self.assertEquals(self.calls, 5)

        self.assertEquals(foo(2), 4)
        self.assertEquals(self.calls, 5)
        self.assertEquals(len(cache), 2)

        foo.invalidate(3)
