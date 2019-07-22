import os
import unittest
from binascii import unhexlify
from collections import OrderedDict
from itertools import chain
from cinnabar.githg import (
    GitCommit,
    GitHgStore,
)
from cinnabar.hg.changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from cinnabar.hg.objects import (
    File,
    Manifest,
)
from cinnabar.helper import (
    GitHgHelper,
    git_hash,
)


class TestStoreCG01(unittest.TestCase):
    RevChunk = RawRevChunk01
    NEW_STORE = False

    def setUp(self):
        os.environ['GIT_CINNABAR_EXPERIMENTS'] = \
            'store' if self.NEW_STORE else ''
        self.assertEquals(
            GitHgHelper.supports(('store', 'new')), self.NEW_STORE)

    def tearDown(self):
        GitHgHelper.close(rollback=True)
        GitHgHelper._helper = False

    def test_store_file(self):
        f = File()
        f.content = 'foo\n'
        f.node = f.sha1

        chunk = f.to_chunk(self.RevChunk)
        GitHgHelper.store('file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash('blob', f.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f2 = File()
        f2.parent1 = f.node
        f2.content = f.content + 'bar\n'
        f2.node = f2.sha1

        chunk = f2.to_chunk(self.RevChunk, f)
        GitHgHelper.store('file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash('blob', f2.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f3 = File()
        f3.parent1 = f.node
        f3.content = f.content + 'baz\n'
        f3.node = f3.sha1

        if self.RevChunk == RawRevChunk01:
            delta_node = f2
        else:
            delta_node = f
        chunk = f3.to_chunk(self.RevChunk, delta_node)
        GitHgHelper.store('file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash('blob', f3.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f4 = File()
        f4.parents = (f2.node, f3.node)
        f4.content = f2.content + 'baz\n'
        f4.node = f4.sha1

        if self.RevChunk == RawRevChunk01:
            delta_node = f3
        else:
            delta_node = f2
        chunk = f4.to_chunk(self.RevChunk, delta_node)
        GitHgHelper.store('file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash('blob', f4.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

        f5 = File()
        f5.content = f4.content
        f5.metadata = {
            'copy': 'foo',
            'copyrev': f4.node,
        }
        f5.node = f5.sha1

        chunk = f5.to_chunk(self.RevChunk)
        GitHgHelper.store('file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash('blob', f5.content))

        self.assertEqual(
            GitHgHelper.file_meta(chunk.node),
            'copy: foo\ncopyrev: {}\n'.format(f4.node))

        f6 = File()
        f6.parent1 = f5.node
        f6.content = f5.content + 'qux\n'
        f6.node = f6.sha1

        chunk = f6.to_chunk(self.RevChunk, f5)
        GitHgHelper.store('file', chunk)

        self.assertEqual(
            GitHgHelper.hg2git(chunk.node),
            git_hash('blob', f6.content))
        self.assertEqual(GitHgHelper.file_meta(chunk.node), None)

    @staticmethod
    def manifest_tree(m):
        tree = OrderedDict()
        for item in m:
            t = tree
            path = item.path.split('/')
            for p in path[:-1]:
                t = t.setdefault(p, OrderedDict())
            t[path[-1]] = (GitHgStore.MODE[item.attr], item.sha1)

        def recurse(t):
            tree = ''
            for p, v in t.iteritems():
                if isinstance(v, OrderedDict):
                    mode = '40000'
                    sha1 = recurse(v)
                else:
                    mode, sha1 = v
                tree += '%s _%s\0%s' % (mode, p, unhexlify(sha1))
            return git_hash('tree', tree)

        return recurse(tree)

    def test_store_manifest(self):
        m = Manifest()
        m.add('foo', '1' * 40)
        m.add('hoge', '2' * 40)
        m.node = m.sha1

        chunk = m.to_chunk(self.RevChunk)
        GitHgHelper.store('manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m))

        m2 = Manifest()
        m2.parent1 = m.node
        m2.items.append(m.items[0])
        m2.add('fuga', '3' * 40)
        m2.items.append(m.items[1])
        m2.node = m2.sha1

        chunk = m2.to_chunk(self.RevChunk, m)
        GitHgHelper.store('manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m2))

        m3 = Manifest()
        m3.parent1 = m.node
        m3.items.append(m.items[0])
        m3.add('fuga/bar/foo', '3' * 40)
        m3.add('fuga/bar/qux', '4' * 40)
        m3.add('fuga/foo', '5' * 40, 'x')
        m3.add('fuga/fuga/bar', '6' * 40)
        m3.add('fuga/fuga/baz', '7' * 40, 'l')
        m3.add('fuga/fuga/qux', '8' * 40)
        m3.add('hoge', '9' * 40)
        m3.node = m3.sha1

        if self.RevChunk == RawRevChunk01:
            delta_node = m2
        else:
            delta_node = m
        chunk = m3.to_chunk(self.RevChunk, delta_node)
        GitHgHelper.store('manifest', chunk)

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
        GitHgHelper.store('manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m4))

        m5 = Manifest()
        m5.parent1 = m4.node
        for item in chain(m4.items[:2], m4.items[5:]):
            m5.items.append(item)
        m5.node = m5.sha1

        chunk = m5.to_chunk(self.RevChunk, m4)
        GitHgHelper.store('manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m5))

        m6 = Manifest()
        m6.parent1 = m5.node
        for item in m4.items:
            m6.items.append(item)
        m6.node = m6.sha1
        self.assertEqual(m4.raw_data, m6.raw_data)

        chunk = m6.to_chunk(self.RevChunk, m5)
        GitHgHelper.store('manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m6))

        m7 = Manifest()
        for item in m3.items:
            m7.items.append(item)
        m7.node = m7.sha1

        chunk = m7.to_chunk(self.RevChunk)
        GitHgHelper.store('manifest', chunk)

        git_m = GitHgHelper.hg2git(chunk.node)
        self.assertEqual(GitCommit(git_m).tree, self.manifest_tree(m7))


class TestStoreCG02(TestStoreCG01):
    RevChunk = RawRevChunk02


class TestNewStoreCG01(TestStoreCG01):
    NEW_STORE = True


class TestNewStoreCG02(TestStoreCG02):
    NEW_STORE = True
