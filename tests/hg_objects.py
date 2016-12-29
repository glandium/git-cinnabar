import unittest
from binascii import unhexlify
from cinnabar.git import NULL_NODE_ID
from cinnabar.hg.changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from cinnabar.hg.objects import (
    Authorship,
    Changeset,
    File,
)


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


class TestAuthorship(unittest.TestCase):
    def test_from_hg(self):
        # Simple common cases
        a = Authorship.from_hg('Foo Bar', 0, 0)
        self.assertEqual(a.name, 'Foo Bar')
        self.assertEqual(a.email, '')

        a = Authorship.from_hg('foo@bar', 0, 0)
        self.assertEqual(a.name, '')
        self.assertEqual(a.email, 'foo@bar')

        a = Authorship.from_hg('<foo@bar>', 0, 0)
        self.assertEqual(a.name, '')
        self.assertEqual(a.email, 'foo@bar')

        a = Authorship.from_hg('Foo Bar <foo@bar>', 0, 0)
        self.assertEqual(a.name, 'Foo Bar')
        self.assertEqual(a.email, 'foo@bar')

        # Corner cases that exist in the wild, and that may or may not be
        # handled the nicest way they could, but changing that now would affect
        # the corresponding git commit sha1.
        a = Authorship.from_hg('Foo Bar<foo@bar>', 0, 0)
        self.assertEqual(a.name, 'Foo Bar')
        self.assertEqual(a.email, 'foo@bar')

        a = Authorship.from_hg('Foo Bar <foo@bar>, Bar Baz <bar@baz>', 0, 0)
        self.assertEqual(a.name, 'Foo Bar')
        self.assertEqual(a.email, 'foo@bar')

        a = Authorship.from_hg('Foo Bar (foo@bar)', 0, 0)
        self.assertEqual(a.name, '')
        self.assertEqual(a.email, 'Foo Bar (foo@bar)')

        a = Authorship.from_hg('<Foo Bar> foo@bar', 0, 0)
        self.assertEqual(a.name, '')
        self.assertEqual(a.email, 'Foo Bar')

        a = Authorship.from_hg('"Foo Bar <foo@bar>"', 0, 0)
        self.assertEqual(a.name, '"Foo Bar')
        self.assertEqual(a.email, 'foo@bar')

        a = Authorship.from_hg('"Foo Bar <foo@bar>"', '1482880019', '3600')
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, 3600)

        a = Authorship.from_hg('"Foo Bar <foo@bar>"', '1482880019', '-1100',
                               maybe_git_utcoffset=True)
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, 39600)

        a = Authorship.from_hg('"Foo Bar <foo@bar>"', '1482880019', '-3600',
                               maybe_git_utcoffset=True)
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, -3600)

    def test_from_git(self):
        a = Authorship.from_git('Foo Bar <foo@bar>', 0, 0)
        self.assertEqual(a.name, 'Foo Bar')
        self.assertEqual(a.email, 'foo@bar')

        a = Authorship.from_git('Foo Bar <foo@bar>', '1482880019', '-0100')
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, 3600)

        a = Authorship.from_git('Foo Bar <foo@bar>', '1482880019', '+0200')
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, -7200)

    def test_to_hg(self):
        a = Authorship.from_git('Foo Bar <foo@bar>', '1482880019', '+0200')
        who, timestamp, utcoffset = a.to_hg()
        self.assertEqual(who, 'Foo Bar <foo@bar>')
        self.assertEqual(timestamp, '1482880019')
        self.assertEqual(utcoffset, '-7200')

        for who in (
            'Foo Bar',
            '<foo@bar>',
            'Foo Bar <foo@bar>',
        ):
            a = Authorship.from_hg(who, 0, 0)
            self.assertEqual(who, a.to_hg()[0])

    def test_to_git(self):
        a = Authorship.from_hg('Foo Bar', 0, 0)
        self.assertEqual(a.to_git()[0], 'Foo Bar <>')

        a = Authorship.from_hg('foo@bar', 0, 0)
        self.assertEqual(a.to_git()[0], ' <foo@bar>')

        a = Authorship.from_hg('Foo Bar <foo@bar>', 0, 0)
        self.assertEqual(a.to_git()[0], 'Foo Bar <foo@bar>')

        a = Authorship.from_hg('Foo Bar <foo@bar>', '1482880019', '-7200')
        who, timestamp, utcoffset = a.to_git()
        self.assertEqual(timestamp, '1482880019')
        self.assertEqual(utcoffset, '+0200')


class TestChangeset(unittest.TestCase):
    def test_changeset(self):
        c = Changeset()
        c.author = 'Foo Bar <foo@bar>'
        c.timestamp = '1482880019'
        c.utcoffset = '-7200'
        c.body = 'Nothing'

        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + '\n' +
            'Foo Bar <foo@bar>\n' +
            '1482880019 -7200\n' +
            '\n' +
            'Nothing'
        )

        c = Changeset()
        c.author = 'Foo Bar <foo@bar>'
        c.timestamp = '1482880019'
        c.utcoffset = '-7200'
        c.files = [
            'foo',
            'bar',
        ]
        c.body = 'Add foo and bar'

        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + '\n' +
            'Foo Bar <foo@bar>\n' +
            '1482880019 -7200\n' +
            'bar\n' +
            'foo\n' +
            '\n' +
            'Add foo and bar'
        )

        chunk = c.to_chunk(RawRevChunk02)
        c2 = Changeset.from_chunk(chunk)
        self.assertEqual(c2.node, '746f659780ce1db9e78cea98095a93bd570062f2')
        self.assertEqual(c2.author, 'Foo Bar <foo@bar>')
        self.assertEqual(c2.timestamp, '1482880019')
        self.assertEqual(c2.utcoffset, '-7200')
        self.assertEqual(c2.files, ['bar', 'foo'])
        self.assertEqual(c2.extra, None)
        self.assertEqual(c2.body, 'Add foo and bar')

        c.extra = ''
        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + '\n' +
            'Foo Bar <foo@bar>\n' +
            '1482880019 -7200 \n' +
            'bar\n' +
            'foo\n' +
            '\n' +
            'Add foo and bar'
        )

        chunk = c.to_chunk(RawRevChunk02)
        c2 = Changeset.from_chunk(chunk)
        self.assertEqual(c2.extra, {})

        c.extra = extra = {
            'rebase_source': '746f659780ce1db9e78cea98095a93bd570062f2',
        }
        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + '\n' +
            'Foo Bar <foo@bar>\n' +
            '1482880019 -7200 ' +
            'rebase_source:746f659780ce1db9e78cea98095a93bd570062f2\n' +
            'bar\n' +
            'foo\n' +
            '\n' +
            'Add foo and bar'
        )

        chunk = c.to_chunk(RawRevChunk02)
        c2 = Changeset.from_chunk(chunk)
        self.assertEqual(c2.extra, extra)

    def test_extra_property(self):
        c = Changeset()
        self.assertEqual(c.branch, None)
        self.assertEqual(c.committer, None)
        self.assertEqual(c.extra, None)

        c.branch = 'foo'
        self.assertEqual(c.branch, 'foo')
        self.assertEqual(c.extra, {
            'branch': 'foo',
        })

        c.extra['committer'] = 'Foo Bar <foo@bar>'
        self.assertEqual(c.committer, 'Foo Bar <foo@bar>')
        self.assertEqual(c.extra, {
            'branch': 'foo',
            'committer': 'Foo Bar <foo@bar>',
        })

        c.branch = None
        self.assertEqual(c.extra, {
            'committer': 'Foo Bar <foo@bar>',
        })

        c.branch = None
        c.committer = None
        self.assertEqual(c.extra, None)
