from __future__ import absolute_import, unicode_literals
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
    Manifest,
)


class TestFileCG01(unittest.TestCase):
    RevChunk = RawRevChunk01

    @staticmethod
    def delta_node(x):
        return b''

    def test_file(self):
        f = File()
        f.content = b'foo'
        self.assertEqual(f.sha1, b'49d8cbb15ce257920447006b46978b7af980a979')

        chunk = f.to_chunk(self.RevChunk)

        self.assertEqual(
            chunk,
            unhexlify(b'49d8cbb15ce257920447006b46978b7af980a979') +
            b'\0' * 20 +
            b'\0' * 20 +
            self.delta_node(b'\0' * 20) +
            b'\0' * 20 +
            b'\0' * 4 + b'\0' * 4 + (b'\0' * 3 + b'\3') + b'foo'
        )

        f = File.from_chunk(chunk)
        self.assertEqual(f.node, b'49d8cbb15ce257920447006b46978b7af980a979')
        self.assertEqual(f.parent1, NULL_NODE_ID)
        self.assertEqual(f.parent2, NULL_NODE_ID)
        self.assertEqual(f.changeset, NULL_NODE_ID)
        self.assertEqual(f.metadata, {})
        self.assertEqual(f.content, b'foo')

        f2 = File()
        f2.parent1 = f.node
        f2.content = b'barbaz'
        self.assertEqual(f2.sha1, b'a474d1cb79c2f90dccc2bef320e293b89aae7079')

        chunk = f2.to_chunk(self.RevChunk)

        self.assertEqual(
            chunk,
            unhexlify(b'a474d1cb79c2f90dccc2bef320e293b89aae7079') +
            unhexlify(b'49d8cbb15ce257920447006b46978b7af980a979') +
            b'\0' * 20 +
            self.delta_node(b'\0' * 20) +
            b'\0' * 20 +
            b'\0' * 4 + b'\0' * 4 + (b'\0' * 3 + b'\6') + b'barbaz'
        )

        chunk = f2.to_chunk(self.RevChunk, f)

        self.assertEqual(
            chunk,
            unhexlify(b'a474d1cb79c2f90dccc2bef320e293b89aae7079') +
            unhexlify(b'49d8cbb15ce257920447006b46978b7af980a979') +
            b'\0' * 20 +
            self.delta_node(unhexlify(
                b'49d8cbb15ce257920447006b46978b7af980a979')) +
            b'\0' * 20 +
            b'\0' * 4 + (b'\0' * 3 + b'\3') + (b'\0' * 3 + b'\6') + b'barbaz'
        )

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk)

        f2 = File.from_chunk(chunk, f)
        self.assertEqual(f2.node, b'a474d1cb79c2f90dccc2bef320e293b89aae7079')
        self.assertEqual(f2.parent1,
                         b'49d8cbb15ce257920447006b46978b7af980a979')
        self.assertEqual(f2.parent2, NULL_NODE_ID)
        self.assertEqual(f2.changeset, NULL_NODE_ID)
        self.assertEqual(f2.metadata, {})
        self.assertEqual(f2.content, b'barbaz')

        f3 = File()
        f3.content = f2.content
        f3.metadata = {
            b'copy': b'foo',
            b'copyrev': b'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        }
        self.assertEqual(f3.sha1, b'5b783e760678fc60083be1b0844865c025dbe062')

        chunk = f3.to_chunk(self.RevChunk, f2)
        self.assertEqual(
            chunk,
            unhexlify(b'5b783e760678fc60083be1b0844865c025dbe062') +
            b'\0' * 20 +
            b'\0' * 20 +
            self.delta_node(unhexlify(
                b'a474d1cb79c2f90dccc2bef320e293b89aae7079')) +
            b'\0' * 20 +
            b'\0' * 4 + b'\0' * 4 + (b'\0' * 3 + b'\x40') + b'\1\n' +
            b'copy: foo\n' +
            b'copyrev: a474d1cb79c2f90dccc2bef320e293b89aae7079\n' +
            b'\1\n'
        )

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk)

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk, f)

        f3 = File.from_chunk(chunk, f2)
        self.assertEqual(f3.node, b'5b783e760678fc60083be1b0844865c025dbe062')
        self.assertEqual(f3.parent1, NULL_NODE_ID)
        self.assertEqual(f3.parent2, NULL_NODE_ID)
        self.assertEqual(f3.changeset, NULL_NODE_ID)
        self.assertEqual(f3.metadata, {
            b'copy': b'foo',
            b'copyrev': b'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        })
        self.assertEqual(f3.content, b'barbaz')

        chunk = f3.to_chunk(self.RevChunk, f)
        self.assertEqual(
            chunk,
            unhexlify(b'5b783e760678fc60083be1b0844865c025dbe062') +
            b'\0' * 20 +
            b'\0' * 20 +
            self.delta_node(unhexlify(
                b'49d8cbb15ce257920447006b46978b7af980a979')) +
            b'\0' * 20 +
            b'\0' * 4 + (b'\0' * 3 + b'\3') + (b'\0' * 3 + b'\x46') + b'\1\n' +
            b'copy: foo\n' +
            b'copyrev: a474d1cb79c2f90dccc2bef320e293b89aae7079\n' +
            b'\1\n' +
            b'barbaz'
        )

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk)

        with self.assertRaises(AssertionError):
            File.from_chunk(chunk, f2)

        f3 = File.from_chunk(chunk, f)
        self.assertEqual(f3.node, b'5b783e760678fc60083be1b0844865c025dbe062')
        self.assertEqual(f3.parent1, NULL_NODE_ID)
        self.assertEqual(f3.parent2, NULL_NODE_ID)
        self.assertEqual(f3.changeset, NULL_NODE_ID)
        self.assertEqual(f3.metadata, {
            b'copy': b'foo',
            b'copyrev': b'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        })
        self.assertEqual(f3.content, b'barbaz')


class TestFileCG02(TestFileCG01):
    RevChunk = RawRevChunk02

    @staticmethod
    def delta_node(x):
        return x


class TestFile(unittest.TestCase):
    def test_file(self):
        f = File()
        f.parents = (b'a474d1cb79c2f90dccc2bef320e293b89aae7079',
                     b'49d8cbb15ce257920447006b46978b7af980a979')
        self.assertEqual(f.parent1,
                         b'a474d1cb79c2f90dccc2bef320e293b89aae7079')
        self.assertEqual(f.parent2,
                         b'49d8cbb15ce257920447006b46978b7af980a979')

        f.parents = (b'a474d1cb79c2f90dccc2bef320e293b89aae7079',)
        self.assertEqual(f.parent1,
                         b'a474d1cb79c2f90dccc2bef320e293b89aae7079')
        self.assertEqual(f.parent2, NULL_NODE_ID)

        f.parents = ()
        self.assertEqual(f.parent1, NULL_NODE_ID)
        self.assertEqual(f.parent2, NULL_NODE_ID)

        f.content = b''
        self.assertEqual(f.raw_data, b'')

        f.metadata = {
            b'copy': b'foo',
            b'copyrev': b'a474d1cb79c2f90dccc2bef320e293b89aae7079',
        }
        data = (
            b'\1\n' +
            b'copy: foo\n' +
            b'copyrev: a474d1cb79c2f90dccc2bef320e293b89aae7079\n' +
            b'\1\n')

        self.assertEqual(f.raw_data, data)

        f.content = b'foo'
        self.assertEqual(f.raw_data, data + b'foo')

        f.metadata = {}
        self.assertEqual(f.raw_data, b'foo')


class TestAuthorship(unittest.TestCase):
    def test_from_hg(self):
        # Simple common cases
        a = Authorship.from_hg(b'Foo Bar', 0, 0)
        self.assertEqual(a.name, b'Foo Bar')
        self.assertEqual(a.email, b'')

        a = Authorship.from_hg(b'foo@bar', 0, 0)
        self.assertEqual(a.name, b'')
        self.assertEqual(a.email, b'foo@bar')

        a = Authorship.from_hg(b'<foo@bar>', 0, 0)
        self.assertEqual(a.name, b'')
        self.assertEqual(a.email, b'foo@bar')

        a = Authorship.from_hg(b'Foo Bar <foo@bar>', 0, 0)
        self.assertEqual(a.name, b'Foo Bar')
        self.assertEqual(a.email, b'foo@bar')

        # Corner cases that exist in the wild, and that may or may not be
        # handled the nicest way they could, but changing that now would affect
        # the corresponding git commit sha1.
        a = Authorship.from_hg(b'Foo Bar<foo@bar>', 0, 0)
        self.assertEqual(a.name, b'Foo Bar')
        self.assertEqual(a.email, b'foo@bar')

        a = Authorship.from_hg(b'Foo Bar <foo@bar>, Bar Baz <bar@baz>', 0, 0)
        self.assertEqual(a.name, b'Foo Bar')
        self.assertEqual(a.email, b'foo@bar')

        a = Authorship.from_hg(b'Foo Bar (foo@bar)', 0, 0)
        self.assertEqual(a.name, b'')
        self.assertEqual(a.email, b'Foo Bar (foo@bar)')

        a = Authorship.from_hg(b'<Foo Bar> foo@bar', 0, 0)
        self.assertEqual(a.name, b'')
        self.assertEqual(a.email, b'Foo Bar')

        a = Authorship.from_hg(b'"Foo Bar <foo@bar>"', 0, 0)
        self.assertEqual(a.name, b'"Foo Bar')
        self.assertEqual(a.email, b'foo@bar')

        a = Authorship.from_hg(b'"Foo Bar <foo@bar>"', b'1482880019', b'3600')
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, 3600)

        a = Authorship.from_hg(b'"Foo Bar <foo@bar>"', b'1482880019', b'-1100',
                               maybe_git_utcoffset=True)
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, 39600)

        a = Authorship.from_hg(b'"Foo Bar <foo@bar>"', b'1482880019', b'-3600',
                               maybe_git_utcoffset=True)
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, -3600)

    def test_from_git(self):
        a = Authorship.from_git(b'Foo Bar <foo@bar>', 0, 0)
        self.assertEqual(a.name, b'Foo Bar')
        self.assertEqual(a.email, b'foo@bar')

        a = Authorship.from_git(b'Foo Bar <foo@bar>', b'1482880019', b'-0100')
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, 3600)

        a = Authorship.from_git(b'Foo Bar <foo@bar>', b'1482880019', b'+0200')
        self.assertEqual(a.timestamp, 1482880019)
        self.assertEqual(a.utcoffset, -7200)

    def test_to_hg(self):
        a = Authorship.from_git(b'Foo Bar <foo@bar>', b'1482880019', b'+0200')
        who, timestamp, utcoffset = a.to_hg()
        self.assertEqual(who, b'Foo Bar <foo@bar>')
        self.assertEqual(timestamp, b'1482880019')
        self.assertEqual(utcoffset, b'-7200')

        for who in (
            b'Foo Bar',
            b'<foo@bar>',
            b'Foo Bar <foo@bar>',
        ):
            a = Authorship.from_hg(who, 0, 0)
            self.assertEqual(who, a.to_hg()[0])

    def test_to_git(self):
        a = Authorship.from_hg(b'Foo Bar', 0, 0)
        self.assertEqual(a.to_git()[0], b'Foo Bar <>')

        a = Authorship.from_hg(b'foo@bar', 0, 0)
        self.assertEqual(a.to_git()[0], b' <foo@bar>')

        a = Authorship.from_hg(b'Foo Bar <foo@bar>', 0, 0)
        self.assertEqual(a.to_git()[0], b'Foo Bar <foo@bar>')

        a = Authorship.from_hg(b'Foo Bar <foo@bar>', b'1482880019', b'-7200')
        who, timestamp, utcoffset = a.to_git()
        self.assertEqual(timestamp, b'1482880019')
        self.assertEqual(utcoffset, b'+0200')


class TestChangeset(unittest.TestCase):
    def test_changeset(self):
        c = Changeset()
        c.author = b'Foo Bar <foo@bar>'
        c.timestamp = b'1482880019'
        c.utcoffset = b'-7200'
        c.body = b'Nothing'

        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + b'\n' +
            b'Foo Bar <foo@bar>\n' +
            b'1482880019 -7200\n' +
            b'\n' +
            b'Nothing'
        )

        c = Changeset()
        c.author = b'Foo Bar <foo@bar>'
        c.timestamp = b'1482880019'
        c.utcoffset = b'-7200'
        c.files = [
            b'foo',
            b'bar',
        ]
        c.body = b'Add foo and bar'

        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + b'\n' +
            b'Foo Bar <foo@bar>\n' +
            b'1482880019 -7200\n' +
            b'bar\n' +
            b'foo\n' +
            b'\n' +
            b'Add foo and bar'
        )

        chunk = c.to_chunk(RawRevChunk02)
        c2 = Changeset.from_chunk(chunk)
        self.assertEqual(c2.node, b'746f659780ce1db9e78cea98095a93bd570062f2')
        self.assertEqual(c2.author, b'Foo Bar <foo@bar>')
        self.assertEqual(c2.timestamp, b'1482880019')
        self.assertEqual(c2.utcoffset, b'-7200')
        self.assertEqual(c2.files, [b'bar', b'foo'])
        self.assertEqual(c2.extra, None)
        self.assertEqual(c2.body, b'Add foo and bar')

        c.extra = b''
        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + b'\n' +
            b'Foo Bar <foo@bar>\n' +
            b'1482880019 -7200 \n' +
            b'bar\n' +
            b'foo\n' +
            b'\n' +
            b'Add foo and bar'
        )

        chunk = c.to_chunk(RawRevChunk02)
        c2 = Changeset.from_chunk(chunk)
        self.assertEqual(c2.extra, {})

        c.extra = extra = {
            b'rebase_source': b'746f659780ce1db9e78cea98095a93bd570062f2',
        }
        self.assertEqual(
            c.raw_data,
            NULL_NODE_ID + b'\n' +
            b'Foo Bar <foo@bar>\n' +
            b'1482880019 -7200 ' +
            b'rebase_source:746f659780ce1db9e78cea98095a93bd570062f2\n' +
            b'bar\n' +
            b'foo\n' +
            b'\n' +
            b'Add foo and bar'
        )

        chunk = c.to_chunk(RawRevChunk02)
        c2 = Changeset.from_chunk(chunk)
        self.assertEqual(c2.extra, extra)

    def test_extra_property(self):
        c = Changeset()
        self.assertEqual(c.branch, None)
        self.assertEqual(c.committer, None)
        self.assertEqual(c.extra, None)

        c.branch = b'foo'
        self.assertEqual(c.branch, b'foo')
        self.assertEqual(c.extra, {
            b'branch': b'foo',
        })

        c.extra[b'committer'] = b'Foo Bar <foo@bar>'
        self.assertEqual(c.committer, b'Foo Bar <foo@bar>')
        self.assertEqual(c.extra, {
            b'branch': b'foo',
            b'committer': b'Foo Bar <foo@bar>',
        })

        c.branch = None
        self.assertEqual(c.extra, {
            b'committer': b'Foo Bar <foo@bar>',
        })

        c.branch = None
        c.committer = None
        self.assertEqual(c.extra, None)


class TestManifest(unittest.TestCase):
    def test_manifest(self):
        m = Manifest()
        m.add(b'foo', b'49d8cbb15ce257920447006b46978b7af980a979')

        with self.assertRaises(AssertionError):
            m.add(b'bar', b'a324b8bf63f7d56de9d36f8747e3b68a72a4d968')

        m.add(b'hoge', b'618faf0766206b33a8e424f93966ff5d99fd8828', b'x')

        self.assertEqual(m.items, [
            b'foo\x0049d8cbb15ce257920447006b46978b7af980a979',
            b'hoge\x00618faf0766206b33a8e424f93966ff5d99fd8828x',
        ])

        self.assertEqual(
            m.raw_data,
            b'foo\x0049d8cbb15ce257920447006b46978b7af980a979\n'
            b'hoge\x00618faf0766206b33a8e424f93966ff5d99fd8828x\n'
        )

        m2 = Manifest()
        m2.add(b'foo', b'49d8cbb15ce257920447006b46978b7af980a979')
        m2.add(b'fuga', b'a7b3deabf88ddf313b21064bd29051cfbb284b7c')
        m2.add(b'hoge', b'618faf0766206b33a8e424f93966ff5d99fd8828', b'x')

        chunk = m2.to_chunk(RawRevChunk02, m)
        m3 = Manifest.from_chunk(chunk, m)
        self.assertEqual(m2.items, m3.items)

        chunk = m.to_chunk(RawRevChunk02, m2)
        m3 = Manifest.from_chunk(chunk, m2)
        self.assertEqual(m.items, m3.items)

        m2 = Manifest()
        m2.add(b'fuga', b'a7b3deabf88ddf313b21064bd29051cfbb284b7c')
        m2.add(b'hoge', b'618faf0766206b33a8e424f93966ff5d99fd8828', b'x')

        chunk = m2.to_chunk(RawRevChunk02, m)
        m3 = Manifest.from_chunk(chunk, m)
        self.assertEqual(m2.items, m3.items)

        m = Manifest()
        m.raw_data = (
            b'foo\x0049d8cbb15ce257920447006b46978b7af980a979\n'
            b'hoge\x00618faf0766206b33a8e424f93966ff5d99fd8828x\n'
        )

        self.assertEqual(m.items, [
            b'foo\x0049d8cbb15ce257920447006b46978b7af980a979',
            b'hoge\x00618faf0766206b33a8e424f93966ff5d99fd8828x',
        ])

        m2 = Manifest()
        for i in m:
            m2.add(i)
        self.assertEqual(m.raw_data, m2.raw_data)
        self.assertEqual(m.items, m2.items)
