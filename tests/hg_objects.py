import unittest
from binascii import unhexlify
from cinnabar.git import NULL_NODE_ID
from cinnabar.hg.changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from cinnabar.hg.objects import File


class TestFileCG01(unittest.TestCase):
    RevChunk = RawRevChunk01

    @staticmethod
    def delta_node(x):
        return ''

    def test_file(self):
        f = File()
        f.content = 'foo'
        self.assertEqual(f.sha1, '49d8cbb15ce257920447006b46978b7af980a979')

        chunk = f.to_chunk(self.RevChunk)

        self.assertEqual(
            chunk,
            unhexlify('49d8cbb15ce257920447006b46978b7af980a979') +
            '\0' * 20 +
            '\0' * 20 +
            self.delta_node('\0' * 20) +
            '\0' * 20 +
            '\0' * 4 + '\0' * 4 + ('\0' * 3 + '\3') + 'foo'
        )

        f = File.from_chunk(chunk)
        self.assertEqual(f.node, '49d8cbb15ce257920447006b46978b7af980a979')
        self.assertEqual(f.parent1, NULL_NODE_ID)
        self.assertEqual(f.parent2, NULL_NODE_ID)
        self.assertEqual(f.changeset, NULL_NODE_ID)
        self.assertEqual(f.metadata, {})
        self.assertEqual(f.content, 'foo')

        f2 = File()
        f2.parent1 = f.node
        f2.content = 'barbaz'
        self.assertEqual(f2.sha1, 'a474d1cb79c2f90dccc2bef320e293b89aae7079')

        chunk = f2.to_chunk(self.RevChunk)

        self.assertEqual(
            chunk,
            unhexlify('a474d1cb79c2f90dccc2bef320e293b89aae7079') +
            unhexlify('49d8cbb15ce257920447006b46978b7af980a979') +
            '\0' * 20 +
            self.delta_node('\0' * 20) +
            '\0' * 20 +
            '\0' * 4 + '\0' * 4 + ('\0' * 3 + '\6') + 'barbaz'
        )

        chunk = f2.to_chunk(self.RevChunk, f)

        self.assertEqual(
            chunk,
            unhexlify('a474d1cb79c2f90dccc2bef320e293b89aae7079') +
            unhexlify('49d8cbb15ce257920447006b46978b7af980a979') +
            '\0' * 20 +
            self.delta_node(unhexlify(
                '49d8cbb15ce257920447006b46978b7af980a979')) +
            '\0' * 20 +
            '\0' * 4 + ('\0' * 3 + '\3') + ('\0' * 3 + '\6') + 'barbaz'
        )

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk)

        f2 = File.from_chunk(chunk, f)
        self.assertEqual(f2.node, 'a474d1cb79c2f90dccc2bef320e293b89aae7079')
        self.assertEqual(f2.parent1,
                         '49d8cbb15ce257920447006b46978b7af980a979')
        self.assertEqual(f2.parent2, NULL_NODE_ID)
        self.assertEqual(f2.changeset, NULL_NODE_ID)
        self.assertEqual(f2.metadata, {})
        self.assertEqual(f2.content, 'barbaz')

        f3 = File()
        f3.content = f2.content
        f3.metadata = {
            'copy': 'foo',
            'copyrev': 'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        }
        self.assertEqual(f3.sha1, '5b783e760678fc60083be1b0844865c025dbe062')

        chunk = f3.to_chunk(self.RevChunk, f2)
        self.assertEqual(
            chunk,
            unhexlify('5b783e760678fc60083be1b0844865c025dbe062') +
            '\0' * 20 +
            '\0' * 20 +
            self.delta_node(unhexlify(
                'a474d1cb79c2f90dccc2bef320e293b89aae7079')) +
            '\0' * 20 +
            '\0' * 4 + '\0' * 4 + ('\0' * 3 + '\x40') + '\1\n' +
            'copy: foo\n' +
            'copyrev: a474d1cb79c2f90dccc2bef320e293b89aae7079\n' +
            '\1\n'
        )

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk)

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk, f)

        f3 = File.from_chunk(chunk, f2)
        self.assertEqual(f3.node, '5b783e760678fc60083be1b0844865c025dbe062')
        self.assertEqual(f3.parent1, NULL_NODE_ID)
        self.assertEqual(f3.parent2, NULL_NODE_ID)
        self.assertEqual(f3.changeset, NULL_NODE_ID)
        self.assertEqual(f3.metadata, {
            'copy': 'foo',
            'copyrev': 'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        })
        self.assertEqual(f3.content, 'barbaz')

        chunk = f3.to_chunk(self.RevChunk, f)
        self.assertEqual(
            chunk,
            unhexlify('5b783e760678fc60083be1b0844865c025dbe062') +
            '\0' * 20 +
            '\0' * 20 +
            self.delta_node(unhexlify(
                '49d8cbb15ce257920447006b46978b7af980a979')) +
            '\0' * 20 +
            '\0' * 4 + ('\0' * 3 + '\3') + ('\0' * 3 + '\x46') + '\1\n' +
            'copy: foo\n' +
            'copyrev: a474d1cb79c2f90dccc2bef320e293b89aae7079\n' +
            '\1\n' +
            'barbaz'
        )

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk)

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk, f2)

        f3 = File.from_chunk(chunk, f)
        self.assertEqual(f3.node, '5b783e760678fc60083be1b0844865c025dbe062')
        self.assertEqual(f3.parent1, NULL_NODE_ID)
        self.assertEqual(f3.parent2, NULL_NODE_ID)
        self.assertEqual(f3.changeset, NULL_NODE_ID)
        self.assertEqual(f3.metadata, {
            'copy': 'foo',
            'copyrev': 'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        })
        self.assertEqual(f3.content, 'barbaz')


class TestFileCG02(TestFileCG01):
    RevChunk = RawRevChunk02

    @staticmethod
    def delta_node(x):
        return x


class TestFile(unittest.TestCase):
    def test_file(self):
        f = File()
        f.parents = ('a474d1cb79c2f90dccc2bef320e293b89aae7079',
                     '49d8cbb15ce257920447006b46978b7af980a979')
        self.assertEqual(f.parent1,
                         'a474d1cb79c2f90dccc2bef320e293b89aae7079')
        self.assertEqual(f.parent2,
                         '49d8cbb15ce257920447006b46978b7af980a979')

        f.parents = ('a474d1cb79c2f90dccc2bef320e293b89aae7079',)
        self.assertEqual(f.parent1,
                         'a474d1cb79c2f90dccc2bef320e293b89aae7079')
        self.assertEqual(f.parent2, NULL_NODE_ID)

        f.parents = ()
        self.assertEqual(f.parent1, NULL_NODE_ID)
        self.assertEqual(f.parent2, NULL_NODE_ID)

        f.content = ''
        self.assertEqual(f.raw_data, '')

        f.metadata = {
            'copy': 'foo',
            'copyrev': 'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        }
        data = (
            '\1\n' +
            'copy: foo\n' +
            'copyrev: a474d1cb79c2f90dccc2bef320e293b89aae7079\n' +
            '\1\n')

        self.assertEqual(f.raw_data, data)

        f.content = 'foo'
        self.assertEqual(f.raw_data, data + 'foo')

        f.metadata = {}
        self.assertEqual(f.raw_data, 'foo')
