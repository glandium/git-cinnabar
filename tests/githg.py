import unittest
from cinnabar.git import NULL_NODE_ID
from cinnabar.githg import (
    Changeset,
    GitCommit,
)


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
