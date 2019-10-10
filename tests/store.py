from __future__ import absolute_import, unicode_literals
import os
import shutil
import tempfile
import unittest
from binascii import unhexlify
from collections import OrderedDict
from itertools import chain
from cinnabar.git import Git
from cinnabar.githg import (
    GitCommit,
    GitHgStore,
)
from cinnabar.hg.changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from cinnabar.hg.objects import (
    Changeset,
    File,
    Manifest,
)
from cinnabar.helper import (
    GitHgHelper,
    git_hash,
)
from cinnabar.util import one


class TestStoreCG01(unittest.TestCase):
    RevChunk = RawRevChunk01
    NEW_STORE = False

    def setUp(self):
        self.git_dir = os.environ.get('GIT_DIR')
        tmpdir = tempfile.mkdtemp()
        Git.run('init', '--bare', tmpdir, stdout=open(os.devnull, 'w'))
        os.environ['GIT_DIR'] = tmpdir
        os.environ['GIT_CINNABAR_EXPERIMENTS'] = \
            'store' if self.NEW_STORE else ''
        self.assertEquals(
            GitHgHelper.supports((b'store', b'new')), self.NEW_STORE)

    def tearDown(self):
        GitHgHelper.close(rollback=True)
        GitHgHelper._helper = False
        shutil.rmtree(os.environ['GIT_DIR'])
        if self.git_dir is None:
            del os.environ['GIT_DIR']
        else:
            os.environ['GIT_DIR'] = self.git_dir

    def test_store_file(self):
        f = File()
        f.content = b'foo\n'
        f.node = f.sha1

        chunk = f.to_chunk(self.RevChunk)
        GitHgHelper.store(b'file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash(b'blob', f.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f2 = File()
        f2.parent1 = f.node
        f2.content = f.content + b'bar\n'
        f2.node = f2.sha1

        chunk = f2.to_chunk(self.RevChunk, f)
        GitHgHelper.store(b'file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash(b'blob', f2.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f3 = File()
        f3.parent1 = f.node
        f3.content = f.content + b'baz\n'
        f3.node = f3.sha1

        if self.RevChunk == RawRevChunk01:
            delta_node = f2
        else:
            delta_node = f
        chunk = f3.to_chunk(self.RevChunk, delta_node)
        GitHgHelper.store(b'file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash(b'blob', f3.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f4 = File()
        f4.parents = (f2.node, f3.node)
        f4.content = f2.content + b'baz\n'
        f4.node = f4.sha1

        if self.RevChunk == RawRevChunk01:
            delta_node = f3
        else:
            delta_node = f2
        chunk = f4.to_chunk(self.RevChunk, delta_node)
        GitHgHelper.store(b'file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash(b'blob', f4.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f5 = File()
        f5.content = f4.content
        f5.metadata = {
            b'copy': b'foo',
            b'copyrev': f4.node,
        }
        f5.node = f5.sha1

        chunk = f5.to_chunk(self.RevChunk)
        GitHgHelper.store(b'file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash(b'blob', f5.content))

        self.assertEqual(
            GitHgHelper.file_meta(chunk.node),
            b'copy: foo\ncopyrev: %s\n' % f4.node)

        f6 = File()
        f6.parent1 = f5.node
        f6.content = f5.content + b'qux\n'
        f6.node = f6.sha1

        chunk = f6.to_chunk(self.RevChunk, f5)
        GitHgHelper.store(b'file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash(b'blob', f6.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

    @staticmethod
    def manifest_tree(m):
        tree = OrderedDict()
        for item in m:
            t = tree
            path = item.path.split(b'/')
            for p in path[:-1]:
                t = t.setdefault(p, OrderedDict())
            t[path[-1]] = (GitHgStore.MODE[item.attr], item.sha1)

        def recurse(t):
            tree = b''
            for p, v in t.items():
                if isinstance(v, OrderedDict):
                    mode = b'40000'
                    sha1 = recurse(v)
                else:
                    mode, sha1 = v
                tree += b'%s _%s\0%s' % (mode, p, unhexlify(sha1))
            return git_hash(b'tree', tree)

        return recurse(tree)

    def test_store_manifest(self):
        m = Manifest()
        m.add(b'foo', b'1' * 40)
        m.add(b'hoge', b'2' * 40)
        m.node = m.sha1

        chunk = m.to_chunk(self.RevChunk)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m))

        m2 = Manifest()
        m2.parent1 = m.node
        m2.items.append(m.items[0])
        m2.add(b'fuga', b'3' * 40)
        m2.items.append(m.items[1])
        m2.node = m2.sha1

        chunk = m2.to_chunk(self.RevChunk, m)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m2))

        m3 = Manifest()
        m3.parent1 = m.node
        m3.items.append(m.items[0])
        m3.add(b'fuga/bar/foo', b'3' * 40)
        m3.add(b'fuga/bar/qux', b'4' * 40)
        m3.add(b'fuga/foo', b'5' * 40, b'x')
        m3.add(b'fuga/fuga/bar', b'6' * 40)
        m3.add(b'fuga/fuga/baz', b'7' * 40, b'l')
        m3.add(b'fuga/fuga/qux', b'8' * 40)
        m3.add(b'hoge', b'9' * 40)
        m3.node = m3.sha1

        if self.RevChunk == RawRevChunk01:
            delta_node = m2
        else:
            delta_node = m
        chunk = m3.to_chunk(self.RevChunk, delta_node)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m3))

        m4 = Manifest()
        m4.parents = (m2.node, m3.node)
        for item in m3.items:
            m4.items.append(item)
        m4.node = m4.sha1

        if self.RevChunk == RawRevChunk01:
            delta_node = m3
        else:
            delta_node = m2
        chunk = m4.to_chunk(self.RevChunk, delta_node)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m4))

        m5 = Manifest()
        m5.parent1 = m4.node
        for item in chain(m4.items[:2], m4.items[5:]):
            m5.items.append(item)
        m5.node = m5.sha1

        chunk = m5.to_chunk(self.RevChunk, m4)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m5))

        m6 = Manifest()
        m6.parent1 = m5.node
        for item in m4.items:
            m6.items.append(item)
        m6.node = m6.sha1
        self.assertEqual(m4.raw_data, m6.raw_data)

        chunk = m6.to_chunk(self.RevChunk, m5)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m6))

        m7 = Manifest()
        for item in m3.items:
            m7.items.append(item)
        m7.node = m7.sha1

        chunk = m7.to_chunk(self.RevChunk)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m7))

        m8 = Manifest()
        for item in chain(m3.items[:3], m3.items[7:]):
            m8.items.append(item)
        m8.node = m8.sha1

        chunk = m8.to_chunk(self.RevChunk, m7)
        GitHgHelper.store(b'manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m8))

    @staticmethod
    def commit_tree(m, files):
        tree = OrderedDict()
        attrs = {v: k for k, v in GitHgStore.ATTR.items()}
        for item in m:
            t = tree
            path = item.path.split(b'/')
            for p in path[:-1]:
                t = t.setdefault(p, OrderedDict())
            t[path[-1]] = (attrs[item.attr], files[item.sha1])

        def recurse(t):
            tree = b''
            for p, v in t.items():
                if isinstance(v, OrderedDict):
                    mode = b'40000'
                    sha1 = recurse(v)
                else:
                    mode, sha1 = v
                tree += b'%s %s\0%s' % (mode, p, unhexlify(sha1))
            return git_hash(b'tree', tree)

        return recurse(tree)

    def test_store_changeset(self):
        files = {}
        f = File()
        f.content = b'foo\n'
        f.node = f.sha1

        chunk = f.to_chunk(self.RevChunk)
        GitHgHelper.store(b'file', chunk)
        files[f.node] = GitHgHelper.hg2git(chunk.node)

        f2 = File()
        f2.content = b'bar\n'
        f2.node = f2.sha1

        chunk = f2.to_chunk(self.RevChunk)
        GitHgHelper.store(b'file', chunk)
        files[f2.node] = GitHgHelper.hg2git(chunk.node)

        m = Manifest()
        m.add(b'bar', f.node)
        m.add(b'foo/.bar', f.node)
        m.add(b'foo/.foo', f.node)
        m.add(b'foo/bar/baz', f.node)
        m.add(b'foo/bar/foo', f.node)
        m.add(b'foo/bar/qux', f.node)
        m.add(b'foo/foo', f.node)
        m.add(b'foo/hoge', f.node)
        m.add(b'foo/qux', f.node)
        m.add(b'qux', f.node)
        m.node = m.sha1

        chunk = m.to_chunk(self.RevChunk)
        GitHgHelper.store(b'manifest', chunk)

        store = GitHgStore()

        c = Changeset()
        c.manifest = m.node
        c.author = b'Cinnabar test <cinnabar@test>'
        c.timestamp = b'0'
        c.utcoffset = b'0000'
        c.files = [i.path for i in m]
        c.body = b'Test commit'
        c.node = c.sha1

        store.store_changeset(c)
        c_gen = store.changeset(c.node)
        self.assertEqual(c.raw_data, c_gen.raw_data)

        commit = GitCommit(GitHgHelper.hg2git(c.node))
        self.assertEqual(commit.body, c.body)
        ct = self.commit_tree(m, files)
        self.assertEqual(commit.tree, ct)

        # Weird case as seen in the GNU octave repo.
        # The bar subdirectory is supposed to be transposed to the same
        # content as the git tree for the manifest above.
        m2 = Manifest()
        m2.add(b'bar/bar', f.node)
        m2.add(b'bar/foo/.foo', f.node)
        m2.add(b'bar/foo//.bar', f.node)
        m2.add(b'bar/foo//.foo', f2.node)
        m2.add(b'bar/foo//bar/baz', f2.node)
        m2.add(b'bar/foo//bar/foo', f.node)
        m2.add(b'bar/foo//hoge', f.node)
        m2.add(b'bar/foo/bar/baz', f.node)
        m2.add(b'bar/foo/bar/qux', f.node)
        m2.add(b'bar/foo/foo', f.node)
        m2.add(b'bar/foo/qux', f.node)
        m2.add(b'bar/qux', f.node)
        m2.node = m2.sha1

        chunk = m2.to_chunk(self.RevChunk, m)
        GitHgHelper.store(b'manifest', chunk)

        c2 = Changeset()
        c2.parent1 = c.node
        c2.manifest = m2.node
        c2.author = b'Cinnabar test <cinnabar@test>'
        c2.timestamp = b'0'
        c2.utcoffset = b'0000'
        c2.files = [i.path for i in m2]
        c2.body = b'Test commit'
        c2.node = c2.sha1

        store.store_changeset(c2)
        c2_gen = store.changeset(c2.node)
        self.assertEqual(c2.raw_data, c2_gen.raw_data)

        commit = GitCommit(GitHgHelper.hg2git(c2.node))
        self.assertEqual(commit.body, c2.body)
        self.assertEqual(ct, one(Git.ls_tree(commit.tree, b'bar'))[2])


class TestStoreCG02(TestStoreCG01):
    RevChunk = RawRevChunk02


class TestNewStoreCG01(TestStoreCG01):
    NEW_STORE = True


class TestNewStoreCG02(TestStoreCG02):
    NEW_STORE = True
