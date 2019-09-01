import os
import shutil
import tempfile
import unittest
from cinnabar.git import (
    EMPTY_BLOB,
    Git,
    NULL_NODE_ID,
)
from cinnabar.helper import (
    GitHgHelper,
)


class TestNotes(unittest.TestCase):
    def setUp(self):
        self.git_dir = os.environ.get('GIT_DIR')
        tmpdir = tempfile.mkdtemp()
        Git.run('init', '--bare', tmpdir, stdout=open(os.devnull, 'w'))
        os.environ['GIT_DIR'] = tmpdir

    def tearDown(self):
        GitHgHelper.close(rollback=True)
        GitHgHelper._helper = False
        shutil.rmtree(os.environ['GIT_DIR'])
        if self.git_dir is None:
            del os.environ['GIT_DIR']
        else:
            os.environ['GIT_DIR'] = self.git_dir

    def test_notes(self):
        HEX = '0123456789abcdef'
        self.assertEqual(GitHgHelper.put_blob(''), EMPTY_BLOB)
        for prefix_len in range(20):
            prefix = '0' * prefix_len
            for n in HEX:
                GitHgHelper.set(
                    'file', (prefix + '0' + n + NULL_NODE_ID)[:40], EMPTY_BLOB)
                for o in HEX:
                    GitHgHelper.set(
                        'file', (prefix + '1' + n + o + NULL_NODE_ID)[:40],
                        EMPTY_BLOB)
            for n in HEX:
                self.assertEqual(
                    GitHgHelper.hg2git(prefix + '0' + n), EMPTY_BLOB)
            for l in range(prefix_len + 1):
                self.assertEqual(
                    GitHgHelper.hg2git((prefix + '0')[:l + 1]), NULL_NODE_ID)
                self.assertEqual(
                    GitHgHelper.hg2git((prefix + '1')[:l + 1]), NULL_NODE_ID)
            for n in HEX:
                for l in range(prefix_len + 2):
                    self.assertEqual(
                        GitHgHelper.hg2git((prefix + '1' + n)[:l + 1]),
                        NULL_NODE_ID)
                for o in HEX:
                    self.assertEqual(
                        GitHgHelper.hg2git(prefix + '1' + n + o), EMPTY_BLOB)
