from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import unittest
from cinnabar.util import (
    HTTPReader,
    byte_diff,
    sorted_merge,
)


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
