from __future__ import absolute_import, unicode_literals
import unittest
from cinnabar.git import NULL_NODE_ID
from cinnabar.githg import (
    Changeset,
    ChangesetPatcher,
    GitCommit,
    GitHgStore,
)
from cinnabar.helper import GitHgHelper


class FakeGitCommit(GitCommit):
    def __init__(self):
        pass


class TestChangeset(unittest.TestCase):
    def test_changeset(self):
        commit = FakeGitCommit()
        commit.author = b'Foo Bar <foo@bar> 1482880019 +0200'
        commit.committer = commit.author
        commit.body = b'Some commit'

        changeset = Changeset.from_git_commit(commit)
        self.assertEqual(changeset.author, b'Foo Bar <foo@bar>')
        self.assertEqual(changeset.timestamp, b'1482880019')
        self.assertEqual(changeset.utcoffset, b'-7200')
        self.assertEqual(changeset.body, b'Some commit')
        self.assertEqual(changeset.extra, None)
        self.assertEqual(changeset.manifest, NULL_NODE_ID)
        self.assertEqual(changeset.files, [])

        commit.committer = b'Bar Baz <bar@baz> 1482988370 -0500'

        changeset = Changeset.from_git_commit(commit)
        self.assertEqual(changeset.author, b'Foo Bar <foo@bar>')
        self.assertEqual(changeset.timestamp, b'1482880019')
        self.assertEqual(changeset.utcoffset, b'-7200')
        self.assertEqual(changeset.body, b'Some commit')
        self.assertEqual(changeset.extra, {
            b'committer': b'Bar Baz <bar@baz> 1482988370 18000',
        })
        self.assertEqual(changeset.manifest, NULL_NODE_ID)
        self.assertEqual(changeset.files, [])


class TestChangesetPatcher(unittest.TestCase):
    def compare(self, changeset1, changeset2):
        for field in ('node', 'author', 'timestamp', 'utcoffset', 'body',
                      'extra', 'manifest', 'files'):
            self.assertEqual(getattr(changeset1, field),
                             getattr(changeset2, field))

    def test_changeset_patcher(self):
        changeset = Changeset()
        changeset.author = b'Foo Bar <foo@bar>'
        changeset.timestamp = b'1482880019'
        changeset.utcoffset = b'-7200'
        changeset.body = b'Some commit'
        self.assertEqual(changeset.extra, None)
        self.assertEqual(changeset.manifest, NULL_NODE_ID)
        self.assertEqual(changeset.files, [])

        changeset2 = ChangesetPatcher().apply(changeset)
        self.compare(changeset, changeset2)
        self.assertEqual(
            ChangesetPatcher.from_diff(changeset, changeset2), b'')

        changeset2.manifest = b'b80de5d138758541c5f05265ad144ab9fa86d1db'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 819432449785de2ce91b6afffec95a3cdee8c58b\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.author = b'Foo Bar <foo@bar> and Bar Baz <bar@baz>'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset bb75162aa9dd2401403fce07fab70ecb744c9c81\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'author Foo Bar <foo@bar> and Bar Baz <bar@baz>'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.extra = b''
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 1aa91b0daf86ebb0876c804bbb895e47d4de0923\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            b'extra '
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.extra = {
            b'committer': b'Bar Baz <bar@baz> 1482880019 -7200',
        }
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 12c357c434ed7d5770f8d2fa869c02510a450bd1\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            b'extra committer:Bar Baz <bar@baz> 1482880019 -7200'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.files = [
            b'bar',
            b'foo',
        ]
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 9c0d9cb8a2c18ac3e73a1cd861c5013ac731de77\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            b'extra committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            b'files bar\x00foo'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.utcoffset = b'-7201'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 4db77e6e5dc0b61dc42fc0ce0d17130f96457914\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            b'extra committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            b'files bar\x00foo\n'
            b'patch 96,97,1'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.body += b'\n'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 2a50ebd0f4b26428413d4309b950939616c5bfca\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            b'extra committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            b'files bar\x00foo\n'
            b'patch 96,97,1\x00163,163,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.extra[b'amend_source'] = \
            b'2a50ebd0f4b26428413d4309b950939616c5bfca'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 3ae3ee64c97d3f35fa057d1957c6ed3d5c053a3e\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            b'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            b'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            b'files bar\x00foo\n'
            b'patch 96,97,1\x00217,217,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.author = changeset.author
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 14d43b6cb9272f6dad335ebd7fb8b5e3d77d910f\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            b'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            b'files bar\x00foo\n'
            b'patch 74,75,1\x00195,195,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.files = []
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 9fa49f5cfbaae8b2f1b6e4d3a483a2b2c1a3fed1\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            b'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            b'patch 74,75,1\x00187,187,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset.extra = {
            b'committer': b'Bar Baz <bar@baz> 1482880019 -7200',
        }
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 9fa49f5cfbaae8b2f1b6e4d3a483a2b2c1a3fed1\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\n'
            b'patch 74,75,1\x00187,187,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset.extra = {
            b'committer': b'Bar Baz <bar@baz> 1482988370 18000',
        }
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            b'changeset 9fa49f5cfbaae8b2f1b6e4d3a483a2b2c1a3fed1\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            b'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            b'patch 74,75,1\x00187,187,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

    def test_changeset_conflict(self):
        changeset = Changeset()
        changeset.author = b'Foo Bar <foo@bar>'
        changeset.timestamp = b'1482880019'
        changeset.utcoffset = b'-7200'
        changeset.body = b'Some commit'

        patcher = ChangesetPatcher(
            b'changeset 819432449785de2ce91b6afffec95a3cdee8c58b\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
        )

        changeset2 = patcher.apply(changeset)

        self.assertEqual(changeset2.sha1, changeset2.node)

        patcher = ChangesetPatcher(
            b'changeset 44d7916212a640292755f2a135e3cf90f355a1ff\n'
            b'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            b'extra branch:foo\n'
        )

        changeset2 = patcher.apply(changeset)
        self.assertEqual(changeset2.sha1, changeset2.node)

        changeset.body += b'\0'
        changeset2 = patcher.apply(changeset)
        self.assertEqual(changeset2.sha1, changeset2.node)


class TestMergeBranches(unittest.TestCase):
    def tearDown(self):
        GitHgHelper.close(rollback=True)
        GitHgHelper._helper = False

    def test_merge_branches(self):
        self.assertEqual(GitHgStore._try_merge_branches(
            b'https://server/'), [
                b'server',
                b'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            b'https://server:443/'), [
                b'server',
                b'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            b'https://server:443/repo'), [
                b'repo',
                b'server/repo',
                b'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            b'https://server:443/dir_a/repo'), [
                b'repo',
                b'dir_a/repo',
                b'server/dir_a/repo',
                b'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            b'https://server:443/dir_a/dir_b/repo'), [
                b'repo',
                b'dir_b/repo',
                b'dir_a/dir_b/repo',
                b'server/dir_a/dir_b/repo',
                b'metadata',
        ])
