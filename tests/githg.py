import unittest
from cinnabar.git import NULL_NODE_ID
from cinnabar.githg import (
    Changeset,
    ChangesetPatcher,
    GitCommit,
    GitHgStore,
)


class FakeGitCommit(GitCommit):
    def __init__(self):
        pass


class TestChangeset(unittest.TestCase):
    def test_changeset(self):
        commit = FakeGitCommit()
        commit.author = 'Foo Bar <foo@bar> 1482880019 +0200'
        commit.committer = commit.author
        commit.body = 'Some commit'

        changeset = Changeset.from_git_commit(commit)
        self.assertEqual(changeset.author, 'Foo Bar <foo@bar>')
        self.assertEqual(changeset.timestamp, '1482880019')
        self.assertEqual(changeset.utcoffset, '-7200')
        self.assertEqual(changeset.body, 'Some commit')
        self.assertEqual(changeset.extra, None)
        self.assertEqual(changeset.manifest, NULL_NODE_ID)
        self.assertEqual(changeset.files, [])

        commit.committer = 'Bar Baz <bar@baz> 1482988370 -0500'

        changeset = Changeset.from_git_commit(commit)
        self.assertEqual(changeset.author, 'Foo Bar <foo@bar>')
        self.assertEqual(changeset.timestamp, '1482880019')
        self.assertEqual(changeset.utcoffset, '-7200')
        self.assertEqual(changeset.body, 'Some commit')
        self.assertEqual(changeset.extra, {
            'committer': 'Bar Baz <bar@baz> 1482988370 18000',
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
        changeset.author = 'Foo Bar <foo@bar>'
        changeset.timestamp = '1482880019'
        changeset.utcoffset = '-7200'
        changeset.body = 'Some commit'
        self.assertEqual(changeset.extra, None)
        self.assertEqual(changeset.manifest, NULL_NODE_ID)
        self.assertEqual(changeset.files, [])

        changeset2 = ChangesetPatcher().apply(changeset)
        self.compare(changeset, changeset2)
        self.assertEqual(ChangesetPatcher.from_diff(changeset, changeset2), '')

        changeset2.manifest = 'b80de5d138758541c5f05265ad144ab9fa86d1db'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 819432449785de2ce91b6afffec95a3cdee8c58b\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.author = 'Foo Bar <foo@bar> and Bar Baz <bar@baz>'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset bb75162aa9dd2401403fce07fab70ecb744c9c81\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'author Foo Bar <foo@bar> and Bar Baz <bar@baz>'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.extra = ''
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 1aa91b0daf86ebb0876c804bbb895e47d4de0923\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            'extra '
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.extra = {
            'committer': 'Bar Baz <bar@baz> 1482880019 -7200',
        }
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 12c357c434ed7d5770f8d2fa869c02510a450bd1\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            'extra committer:Bar Baz <bar@baz> 1482880019 -7200'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.files = [
            'bar',
            'foo',
        ]
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 9c0d9cb8a2c18ac3e73a1cd861c5013ac731de77\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            'extra committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            'files bar\x00foo'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.utcoffset = '-7201'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 4db77e6e5dc0b61dc42fc0ce0d17130f96457914\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            'extra committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            'files bar\x00foo\n'
            'patch 96,97,1'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.body += '\n'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 2a50ebd0f4b26428413d4309b950939616c5bfca\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            'extra committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            'files bar\x00foo\n'
            'patch 96,97,1\x00163,163,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.extra['amend_source'] = \
            '2a50ebd0f4b26428413d4309b950939616c5bfca'
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 3ae3ee64c97d3f35fa057d1957c6ed3d5c053a3e\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'author Foo Bar <foo@bar> and Bar Baz <bar@baz>\n'
            'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            'files bar\x00foo\n'
            'patch 96,97,1\x00217,217,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.author = changeset.author
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 14d43b6cb9272f6dad335ebd7fb8b5e3d77d910f\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            'files bar\x00foo\n'
            'patch 74,75,1\x00195,195,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset2.files = []
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 9fa49f5cfbaae8b2f1b6e4d3a483a2b2c1a3fed1\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            'patch 74,75,1\x00187,187,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset.extra = {
            'committer': 'Bar Baz <bar@baz> 1482880019 -7200',
        }
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 9fa49f5cfbaae8b2f1b6e4d3a483a2b2c1a3fed1\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\n'
            'patch 74,75,1\x00187,187,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

        changeset.extra = {
            'committer': 'Bar Baz <bar@baz> 1482988370 18000',
        }
        changeset2.node = changeset2.sha1
        patcher = ChangesetPatcher.from_diff(changeset, changeset2)
        self.assertEqual(
            patcher,
            'changeset 9fa49f5cfbaae8b2f1b6e4d3a483a2b2c1a3fed1\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'extra amend_source:2a50ebd0f4b26428413d4309b950939616c5bfca\x00'
            'committer:Bar Baz <bar@baz> 1482880019 -7200\n'
            'patch 74,75,1\x00187,187,%0A'
        )
        self.compare(patcher.apply(changeset), changeset2)

    def test_changeset_conflict(self):
        changeset = Changeset()
        changeset.author = 'Foo Bar <foo@bar>'
        changeset.timestamp = '1482880019'
        changeset.utcoffset = '-7200'
        changeset.body = 'Some commit'

        patcher = ChangesetPatcher(
            'changeset 819432449785de2ce91b6afffec95a3cdee8c58b\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
        )

        changeset2 = patcher.apply(changeset)

        self.assertEqual(changeset2.sha1, changeset2.node)

        patcher = ChangesetPatcher(
            'changeset 44d7916212a640292755f2a135e3cf90f355a1ff\n'
            'manifest b80de5d138758541c5f05265ad144ab9fa86d1db\n'
            'extra branch:foo\n'
        )

        changeset2 = patcher.apply(changeset)
        self.assertEqual(changeset2.sha1, changeset2.node)

        changeset.body += '\0'
        changeset2 = patcher.apply(changeset)
        self.assertEqual(changeset2.sha1, changeset2.node)


class TestMergeBranches(unittest.TestCase):
    def test_merge_branches(self):
        self.assertEqual(GitHgStore._try_merge_branches(
            'https://server/'), [
                'server',
                'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            'https://server:443/'), [
                'server',
                'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            'https://server:443/repo'), [
                'repo',
                'server/repo',
                'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            'https://server:443/dir_a/repo'), [
                'repo',
                'dir_a/repo',
                'server/dir_a/repo',
                'metadata',
        ])
        self.assertEqual(GitHgStore._try_merge_branches(
            'https://server:443/dir_a/dir_b/repo'), [
                'repo',
                'dir_b/repo',
                'dir_a/dir_b/repo',
                'server/dir_a/dir_b/repo',
                'metadata',
        ])
