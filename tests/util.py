import unittest
from cinnabar.util import (
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
