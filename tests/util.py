try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import unittest
from cinnabar.util import (
    HTTPReader,
    byte_diff,
    lrucache,
    sorted_merge,
    VersionedDict,
)


class TestVersionedDict(unittest.TestCase):
    def check_state(self, v, d):
        self.assertEqual(sorted(v.keys()), sorted(d.keys()))
        self.assertEqual(sorted(k for k in v), sorted(k for k in d))
        self.assertEqual(sorted(i for i in v.items()),
                         sorted(i for i in d.items()))
        self.assertEqual(sorted(v.values()), sorted(d.values()))
        self.assertEqual(bool(d), bool(v))
        self.assertEqual(len(d), len(v))
        for k, val in d.items():
            self.assertTrue(k in v)
            self.assertEqual(v[k], val)

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
                self.assertEqual(v['foo'], 'foo')
                self.assertEqual(v['bar'], 'qux')
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
                    self.assertEqual(v['fuga'], 'fuga')
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                        ])

                    v['fuga'] = 'toto'
                    d['fuga'] = 'toto'
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.MODIFIED, 'fuga', 'toto'),
                        ])

                    del v['fuga']
                    del d['fuga']
                    self.assertFalse('fuga' in v)
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.REMOVED, 'fuga', 'fuga'),
                        ])
                elif 'hoge' in init:
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                        ])

                    del v['hoge']
                    del d['hoge']
                    self.assertFalse('hoge' in v)
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.REMOVED, 'hoge', 'hoge'),
                        ])

                    v['hoge'] = 'fuga'
                    d['hoge'] = 'fuga'
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.MODIFIED, 'hoge', 'fuga'),
                        ])

                    del v['hoge']
                    del d['hoge']
                    self.assertFalse('hoge' in v)
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                            (v.CREATED, 'foo', 'foo'),
                            (v.REMOVED, 'hoge', 'hoge'),
                        ])

                    v['hoge'] = 'hoge'
                    d['hoge'] = 'hoge'
                    self.check_state(v, d)
                    if typ == VersionedDict:
                        self.assertEqual(sorted(v.iterchanges()), [
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
                        self.assertEqual(sorted(v.iterchanges()), [
                            (v.CREATED, 'bar', 'qux'),
                        ])

                for k in list(v.keys()):
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
        self.assertEqual(d1._previous, d)

        d1 = VersionedDict(d.items())
        self.assertIsInstance(d1._previous, dict)
        self.assertIsNot(d1._previous, d)
        self.assertEqual(d1._previous, d)

        d1 = VersionedDict(d, bar='bar', hoge='hoge', fuga='toto')
        self.assertIsInstance(d1._previous, VersionedDict)
        self.assertEqual(sorted(d1._previous.iterchanges()), [
            (d1.CREATED, 'fuga', 'toto'),
            (d1.CREATED, 'hoge', 'hoge'),
            (d1.MODIFIED, 'bar', 'bar'),
        ])

        d2 = VersionedDict(d1)
        self.assertIs(d2._previous, d1)

        d2 = VersionedDict(d1, hoge=42, toto='titi')
        self.assertIsInstance(d2._previous, VersionedDict)
        self.assertIsNot(d2._previous, d1)
        self.assertEqual(sorted(d2._previous.iterchanges()), [
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
        self.assertEqual(sorted(d1.iterchanges()), [])

        d['hoge'] = 'fuga'
        self.assertTrue('hoge' not in d1)
        self.assertEqual(sorted(d1.iterchanges()), [
            (d1.REMOVED, 'hoge', 'fuga'),
        ])

        d1['foo'] = 'foo'
        self.assertEqual(sorted(d1.iterchanges()), [
            (d1.REMOVED, 'hoge', 'fuga'),
        ])

        d['foo'] = 'bar'
        self.assertEqual(d1['foo'], 'foo')
        self.assertEqual(sorted(d1.iterchanges()), [
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

        self.assertEqual(sorted(d2.iterchanges()), [
            (d2.CREATED, 'fuga', 'fuga'),
            (d2.REMOVED, 'hoge', 'hoge'),
        ])

        d3 = d2.flattened()

        self.assertTrue('hoge' not in d3)
        self.assertTrue('fuga' in d3)

        self.assertEqual(sorted(d3.iterchanges()), [
            (d2.CREATED, 'fuga', 'fuga'),
            (d2.MODIFIED, 'foo', 'foo2'),
            (d2.REMOVED, 'bar', 'qux'),
        ])


class TestByteDiff(unittest.TestCase):
    TEST_STRING = (
        b'first line\n'
        b'second line\n'
        b'third line\n'
        b'fourth line\n'
    )

    def assertDiffEqual(self, a, b, diff):
        result = tuple(byte_diff(a, b))
        self.assertEqual(result, diff)

    def test_equal(self):
        self.assertDiffEqual(self.TEST_STRING, self.TEST_STRING, ())

    def test_a(self):
        for extra in (b'fifth line\n', b'line with no ending',
                      b'more\nthan\none\nline'):
            self.assertDiffEqual(
                self.TEST_STRING,
                self.TEST_STRING + extra,
                ((len(self.TEST_STRING), len(self.TEST_STRING), extra),)
            )

            self.assertDiffEqual(
                self.TEST_STRING + extra,
                self.TEST_STRING,
                ((len(self.TEST_STRING), len(self.TEST_STRING + extra), b''),)
            )

    def test_b(self):
        for extra in (b'zeroth line\n', b'more\nthan\none\nline\n'):
            self.assertDiffEqual(
                self.TEST_STRING,
                extra + self.TEST_STRING,
                ((0, 0, extra),)
            )

            self.assertDiffEqual(
                extra + self.TEST_STRING,
                self.TEST_STRING,
                ((0, len(extra), b''),)
            )

    def test_c(self):
        extra = b'extra\nstuff'
        extra2 = b'\nother\nextra\n'
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
            ((15, 15 + len(extra), b''),
             (18 + len(extra), 18 + len(extra + extra2), b''))
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

        self.assertEqual(list(sorted_merge(a, b)), [
            ('a', (1,), ()),
            ('b', (2,), ('B',)),
            ('c', (), ('C',)),
            ('d', (4,), ()),
        ])

        self.assertEqual(list(sorted_merge(b, a)), [
            ('a', (), (1,)),
            ('b', ('B',), (2,)),
            ('c', ('C',), ()),
            ('d', (), (4,)),
        ])

        self.assertEqual(list(sorted_merge(a[:2], b[:1])), [
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

        self.assertEqual(top.next, node)
        self.assertEqual(top.prev, node)
        self.assertEqual(node.next, top)
        self.assertEqual(node.prev, top)

        node2 = lrucache.node()
        node2.insert(top)
        self.assertEqual(node2.next, node)
        self.assertEqual(node2.prev, top)
        self.assertEqual(top.next, node2)
        self.assertEqual(top.prev, node)
        self.assertEqual(node.next, top)
        self.assertEqual(node.prev, node2)

        node.insert(top)
        self.assertEqual(node.next, node2)
        self.assertEqual(node.prev, top)
        self.assertEqual(top.next, node)
        self.assertEqual(top.prev, node2)
        self.assertEqual(node2.next, top)
        self.assertEqual(node2.prev, node)

        node2.detach()
        self.assertEqual(top.next, node)
        self.assertEqual(top.prev, node)
        self.assertEqual(node.next, top)
        self.assertEqual(node.prev, top)

    def test_lru_cache(self):
        cache = lrucache(2)

        self.calls = 0

        @cache
        def foo(value):
            self.calls += 1
            return value * 2

        self.assertEqual(foo(1), 2)
        self.assertEqual(self.calls, 1)
        self.assertEqual(foo(1), 2)
        self.assertEqual(self.calls, 1)
        self.assertEqual(len(cache), 1)

        self.assertEqual(foo(2), 4)
        self.assertEqual(self.calls, 2)
        self.assertEqual(foo(2), 4)
        self.assertEqual(self.calls, 2)
        self.assertEqual(len(cache), 2)

        self.assertEqual(foo(1), 2)
        self.assertEqual(self.calls, 2)

        self.assertEqual(foo(3), 6)
        self.assertEqual(self.calls, 3)
        self.assertEqual(len(cache), 2)

        self.assertEqual(foo(1), 2)
        self.assertEqual(self.calls, 3)

        self.assertEqual(foo(2), 4)
        self.assertEqual(self.calls, 4)
        self.assertEqual(len(cache), 2)

        foo.invalidate(1)
        self.assertEqual(foo(1), 2)
        self.assertEqual(self.calls, 5)

        self.assertEqual(foo(2), 4)
        self.assertEqual(self.calls, 5)
        self.assertEqual(len(cache), 2)

        foo.invalidate(3)


class TestHTTPReader(unittest.TestCase):
    def test_recovery(self):
        sizes = {}
        length = 0
        for s in [162000, 64000, 57932]:
            sizes[length] = s
            length += s
        the_test = self

        # This HTTP server handler cuts responses before the full content is
        # returned, according to the partial sizes defined above.
        # It assumes the client will retry with a Range request starting from
        # where it left, up to the end of the file.
        class Handler(BaseHTTPRequestHandler):
            redirected_once = False
            errored_once = False

            def do_GET(self):
                if self.path == '/foo':
                    the_test.assertFalse(Handler.redirected_once)
                    Handler.redirected_once = True
                    self.send_response(301)
                    self.send_header('Location', '/bar')
                    self.end_headers()
                    return
                elif self.path != '/bar':
                    self.send_response(404)
                    self.end_headers()
                    return
                range_def = self.headers.get('Range')
                if range_def:
                    if not Handler.errored_once:
                        Handler.errored_once = True
                        self.send_response(500)
                        self.end_headers()
                        return
                    start, end = range_def.partition('bytes=')[2].split('-')
                    start = int(start) if start else 0
                    end = int(end) if end else length - 1
                    the_test.assertIn(start, sizes)
                    the_test.assertEqual(end, length - 1)
                    self.send_response(206)
                    self.send_header('Content-Range',
                                     'bytes %d-%d/%d' % (start, end, length))
                else:
                    start = 0
                    self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(length))
                self.send_header('Accept-Ranges', 'bytes')
                self.end_headers()

                buf = b'-' * 4096
                left = sizes[start]
                while left:
                    if left < len(buf):
                        buf = buf[:left]
                    self.wfile.write(buf)
                    left -= len(buf)

            def log_request(self, *args, **kwargs):
                pass

        server = HTTPServer(('', 0), Handler)
        port = server.socket.getsockname()[1]
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            reader = HTTPReader('http://localhost:%d/foo' % port)
            read = 0
            while True:
                buf = reader.read(1250)
                # If the read above is interrupted and the HTTPReader can
                # recover with a range request, we still expect the right
                # size.
                self.assertEqual(len(buf), min(1250, length - read))
                read += len(buf)
                if not buf:
                    break

            self.assertEqual(read, length)

        finally:
            server.shutdown()
            thread.join()
