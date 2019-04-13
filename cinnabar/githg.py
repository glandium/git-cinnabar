#!/usr/bin/env python2.7

from __future__ import division
from binascii import hexlify, unhexlify
from itertools import izip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import urllib
from collections import (
    OrderedDict,
    Sequence,
    defaultdict,
)
from urlparse import urlparse
from .exceptions import (
    AmbiguousGraftAbort,
    NothingToGraftException,
    OldUpgradeAbort,
    UpgradeAbort,
)
from .util import (
    HTTPReader,
    byte_diff,
    check_enabled,
    one,
    VersionedDict,
)
from .git import (
    EMPTY_BLOB,
    EMPTY_TREE,
    Git,
    GitProcess,
    NULL_NODE_ID,
)
from .hg.changegroup import (
    RawRevChunk,
    RevDiff,
)
from .hg.objects import (
    Authorship,
    Changeset,
    File,
    textdiff,
)
from .helper import GitHgHelper
from .util import progress_iter
from .dag import gitdag

import logging


# An empty mercurial file with no parent has a fixed sha1 which is that of
# "\0" * 40 (incidentally, this is the same as for an empty manifest with
# no parent.
HG_EMPTY_FILE = 'b80de5d138758541c5f05265ad144ab9fa86d1db'


revchunk_log = logging.getLogger('revchunks')


class RevChunk(object):
    __slots__ = ('node', 'parent1', 'parent2', 'changeset', 'data',
                 'delta_node', '_rev_data')

    def __init__(self, chunk):
        self.node, self.parent1, self.parent2, self.changeset = (
            chunk.node, chunk.parent1, chunk.parent2, chunk.changeset)
        self.delta_node = chunk.delta_node
        self._rev_data = chunk.data
        revchunk_log.debug('%s %s %s %s', self.node, self.parent1,
                           self.parent2, self.changeset)
        revchunk_log.debug('%r', self._rev_data)

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.node)

    def init(self, previous_chunk):
        assert self.delta_node == NULL_NODE_ID or previous_chunk
        self.data = self.patch_data(previous_chunk.data if previous_chunk
                                    else '', self._rev_data)

    def patch_data(self, data, rev_patch):
        return RevDiff(rev_patch).apply(data)

    @property
    def sha1(self):
        p1 = unhexlify(self.parent1)
        p2 = unhexlify(self.parent2)
        return hashlib.sha1(
            min(p1, p2) +
            max(p1, p2) +
            self.data
        ).hexdigest()

    def diff(self, other):
        return textdiff(other.data if other else '', self.data)

    def serialize(self, other, type):
        result = type()
        result.node = self.node
        result.parent1 = self.parent1
        result.parent2 = self.parent2
        if other:
            result.delta_node = other.node
        result.changeset = self.changeset
        result.data = self.diff(other)
        return result

    @property
    def parents(self):
        if self.parent1 != NULL_NODE_ID:
            if self.parent2 != NULL_NODE_ID:
                return (self.parent1, self.parent2)
            return (self.parent1,)
        if self.parent2 != NULL_NODE_ID:
            return (self.parent2,)
        return ()


class GeneratedRevChunk(RevChunk):
    def __init__(self, node, data):
        self.node = node
        self.data = data

    def init(self, previous_chunk):
        pass

    def set_parents(self, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        self.parent1 = parent1
        self.parent2 = parent2


class FileFindParents(object):
    logger = logging.getLogger('generated_file')

    @staticmethod
    def _invalid_if_new(file):
        if file.node == NULL_NODE_ID:
            raise Exception('Trying to create an invalid file. '
                            'Please open an issue with details.')

    @staticmethod
    def set_parents(file, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID,
                    git_manifest_parents=None, path=None):
        assert git_manifest_parents is not None and path is not None
        path = GitHgStore.manifest_metadata_path(path)

        # Remove null nodes
        parents = tuple(p for p in (parent1, parent2) if p != NULL_NODE_ID)
        orig_parents = parents

        # On merges, a file with copy metadata has either no parent, or only
        # one. In that latter case, the parent is always set as second parent.
        # On non-merges, a file with copy metadata doesn't have a parent.
        if file.metadata or file.content.startswith('\1\n'):
            if len(parents) == 2:
                FileFindParents._invalid_if_new(file)
            elif len(parents) == 1:
                if git_manifest_parents is not None:
                    if len(git_manifest_parents) != 2:
                        FileFindParents._invalid_if_new(file)
                parents = (NULL_NODE_ID, parents[0])
            elif git_manifest_parents is not None:
                if len(git_manifest_parents) == 0:
                    FileFindParents._invalid_if_new(file)
        elif len(parents) == 2:
            if git_manifest_parents is not None:
                if len(git_manifest_parents) != 2:
                    FileFindParents._invalid_if_new(file)
            if parents[0] == parents[1]:
                parents = parents[:1]
            elif (git_manifest_parents is not None and
                  (file.node == NULL_NODE_ID or check_enabled('files'))):
                # Checking if one parent is the ancestor of another is slow.
                # So, unless we're actually creating this file, skip over
                # this by default, the fallback will work just fine.
                file_dag = gitdag()
                mapping = {}
                for sha1, tree, fparents in GitHgHelper.rev_list(
                        '--parents', '--boundary', '--topo-order', '--reverse',
                        '%s...%s' % git_manifest_parents, '--', path):
                    if sha1.startswith('-'):
                        sha1 = sha1[1:]
                    node = [
                        s
                        for mode, typ, s, p in
                        Git.ls_tree(sha1, path)
                    ]
                    if not node:
                        continue
                    node = node[0]
                    mapping[sha1] = node
                    file_dag.add(node, tuple(mapping[p]
                                             for p in fparents
                                             if p in mapping))

                file_dag.tag_nodes_and_parents((parents[0],), 'a')
                if file_dag._tags.get(parents[1]) == 'a':
                    parents = parents[:1]
                else:
                    file_dag._tags.clear()
                    file_dag.tag_nodes_and_parents((parents[1],), 'b')
                    if file_dag._tags.get(parents[0]) == 'b':
                        parents = parents[1:]

        file.parents = parents
        if file.node != NULL_NODE_ID and file.node != file.sha1:
            if parents != orig_parents:
                if FileFindParents._try_parents(file, *orig_parents):
                    FileFindParents.logger.debug(
                        'Right parents given for %s, but they don\'t match '
                        'what modern mercurial normally would do', file.node)
                    return
            FileFindParents._set_parents_fallback(file, parent1, parent2)

    @staticmethod
    def _set_parents_fallback(file, parent1=NULL_NODE_ID,
                              parent2=NULL_NODE_ID):
        result = (  # In some cases, only one parent is stored in a merge,
                    # because the other parent is actually an ancestor of the
                    # first one, but checking that is likely more expensive
                    # than to check if the sha1 matches with either parent.
                    FileFindParents._try_parents(file, parent1) or
                    FileFindParents._try_parents(file, parent2) or
                    # Some mercurial versions stores the first parent twice in
                    # merges.
                    FileFindParents._try_parents(file, parent1, parent1) or
                    # As last resort, try without any parents.
                    FileFindParents._try_parents(file))

        FileFindParents.logger.debug('Wrong parents given for %s', file.node)
        FileFindParents.logger.debug('  Got: %s %s', parent1, parent2)
        if result:
            FileFindParents.logger.debug('  Expected: %s %s', file.parent1,
                                         file.parent2)

        # If none of the above worked, we failed big time
        if not result:
            raise Exception('Failed to create file. '
                            'Please open an issue with details.')

    @staticmethod
    def _try_parents(file, *parents):
        file.parents = parents
        return file.node == file.sha1


class ManifestLine(object):
    __slots__ = ('name', 'node', 'attr', '_str', '_len')

    def __init__(self, name, node, attr):
        self.name = name
        self.node = node
        self.attr = attr
        assert len(self.node) == 40
        self._str = '%s\0%s%s\n' % (self.name, self.node, self.attr)
        self._len = len(self.name) + len(self.attr) + 41

    def __str__(self):
        return self._str

    def __len__(self):
        return self._len


def isplitmanifest(data):
    for l in data.splitlines():
        null = l.find('\0')
        if null == -1:
            return
        yield ManifestLine(l[:null], l[null + 1:null + 41], l[null + 41:])


class ManifestInfo(RevChunk):
    __slots__ = ('removed', 'modified')

    def patch_data(self, raw_data, rev_patch):
        new = bytearray()
        data = memoryview(raw_data)
        end = 0
        before_list = {}
        after_list = {}
        for diff in RevDiff(rev_patch):
            new += data[end:diff.start]
            new += diff.text_data
            end = diff.end

            start = raw_data.rfind('\n', 0, diff.start) + 1
            if diff.end == 0 or data[diff.end - 1] == '\n':
                finish = diff.end
            else:
                finish = raw_data.find('\n', diff.end)
            if finish != -1:
                before = data[start:finish]
            else:
                before = data[start:]
            after = before[:diff.start - start].tobytes() + \
                diff.text_data.tobytes() + \
                before[diff.end - start:].tobytes()
            before_list.update({f.name: (f.node, f.attr)
                                for f in isplitmanifest(before.tobytes())})
            after_list.update({f.name: (f.node, f.attr)
                               for f in isplitmanifest(after)})
        new += data[end:]
        self.removed = set(before_list.keys()) - set(after_list.keys())
        self.modified = after_list
        return new


class ChangesetPatcher(str):
    class ChangesetPatch(RawRevChunk):
        __slots__ = ('patch', '_changeset')

        class Patch(RevDiff):
            class Part(object):
                __slots__ = ('start', 'end', 'text_data')

            def __init__(self, buf):
                self._buf = buf

            def __str__(self):
                return self._buf

            def __iter__(self):
                for line in self._buf.split('\0'):
                    if line:
                        part = self.Part()
                        start, end, text_data = line.split(',')
                        part.start = int(start)
                        part.end = int(end)
                        part.text_data = urllib.unquote(text_data)
                        yield part

            @classmethod
            def from_items(cls, items):
                return cls('\0'.join(
                    ','.join((str(start), str(end), urllib.quote(text_data)))
                    for start, end, text_data in items))

            @classmethod
            def from_obj(cls, obj):
                if isinstance(obj, (tuple, list)):
                    return cls.from_items(obj)
                return cls(obj)

        def __init__(self, changeset, patch_data):
            self._changeset = changeset
            self.patch = self.Patch(patch_data)

        def __getattr__(self, name):
            if name == 'delta_node':
                name = 'node'
            return getattr(self._changeset, name)

    def apply(self, changeset):
        # Sneaky way to create a copy of the changeset
        chunk = self.ChangesetPatch(changeset, '')
        changeset = Changeset.from_chunk(chunk, changeset)

        for k, v in (l.split(' ', 1) for l in self.splitlines()):
            if k == 'changeset':
                changeset.node = v
            elif k == 'manifest':
                changeset.manifest = v
            elif k == 'author':
                changeset.author = v
            elif k == 'extra':
                extra = changeset.extra
                changeset.extra = v
                if extra is not None:
                    changeset.extra.update(
                        (k, v) for k, v in extra.iteritems()
                        if k not in changeset.extra)
            elif k == 'files':
                changeset.files = v.split('\0')
            elif k == 'patch':
                chunk = self.ChangesetPatch(changeset, v)
                changeset = Changeset.from_chunk(chunk, changeset)

        # This should not occur in normal changeset bodies. If it occurs,
        # it likely comes from our handling of conflicting commits.
        # So in that case, adjust until we have the right sha1.
        while changeset.body.endswith('\0') and \
                changeset.sha1 != changeset.node:
            changeset.body = changeset.body[:-1]

        return changeset

    @classmethod
    def from_diff(cls, changeset1, changeset2):
        items = []
        if changeset1.node != changeset2.node:
            items.append('changeset %s' % changeset2.node)
        if changeset1.manifest != changeset2.manifest:
            items.append('manifest %s' % changeset2.manifest)
        if changeset1.author != changeset2.author:
            items.append('author %s' % changeset2.author)
        if changeset1.extra != changeset2.extra:
            if changeset2.extra is not None:
                items.append('extra %s' % Changeset.ExtraData({
                    k: v
                    for k, v in changeset2.extra.iteritems()
                    if not changeset1.extra or changeset1.extra.get(k) != v
                }))
        if changeset1.files != changeset2.files:
            items.append('files %s' % '\0'.join(changeset2.files))

        this = cls('\n'.join(items))
        new = this.apply(changeset1)
        if new.raw_data != changeset2.raw_data:
            items.append('patch %s' % cls.ChangesetPatch.Patch.from_items(
                byte_diff(new.raw_data, changeset2.raw_data)))
            this = cls('\n'.join(items))

        return this


class Changeset(Changeset):
    @classmethod
    def from_git_commit(cls, git_commit):
        if not isinstance(git_commit, GitCommit):
            git_commit = GitCommit(git_commit)

        changeset = cls()

        (changeset.author, changeset.timestamp, changeset.utcoffset) = \
            Authorship.from_git_str(git_commit.author).to_hg()

        if git_commit.committer != git_commit.author:
            changeset.committer = Authorship.from_git_str(
                git_commit.committer).to_hg_str()

        changeset.body = git_commit.body

        return changeset


class GeneratedManifestInfo(GeneratedRevChunk, ManifestInfo):
    __slots__ = ('__lines', '_data')

    def __init__(self, node):
        super(GeneratedManifestInfo, self).__init__(node, '')
        if node == NULL_NODE_ID:
            self.__lines = []
        else:
            self.__lines = None
        self._data = None
        self.removed = set()
        self.modified = {}

    def init(self, previous_chunk):
        pass

    @property
    def data(self):
        if self._data is None and self.__lines is None:
            self._data = GitHgHelper.manifest(self.node)

        if self._data is None:
            # Normally, it'd be better to use str(l), but it turns out to make
            # things significantly slower. Sigh python.
            self._data = ''.join(l._str for l in self._lines)
        return self._data

    @data.setter
    def data(self, value):
        self._data = value
        self.__lines = None

    @property
    def _lines(self):
        if self.__lines is None:
            self.__lines = list(isplitmanifest(self.data or ''))
        return iter(self.__lines)

    @_lines.setter
    def _lines(self, value):
        self.__lines = value
        self._data = None

    def append_line(self, line, modified=False):
        self.__lines.append(line)
        if modified:
            self.modified[line.name] = (line.node, line.attr)
        self._data = None


class TagSet(object):
    def __init__(self):
        self._tags = {}
        self._taghist = defaultdict(set)

    def __setitem__(self, key, value):
        old = self._tags.get(key)
        if old:
            self._taghist[key].add(old)
        self._tags[key] = value

    def __getitem__(self, key):
        return self._tags[key]

    def update(self, other):
        if not other:
            return
        assert isinstance(other, TagSet)
        for key, anode in other._tags.iteritems():
            # derived from mercurial's _updatetags
            ahist = other._taghist[key]
            if key not in self._tags:
                self._tags[key] = anode
                self._taghist[key] = set(ahist)
                continue
            bnode = self._tags[key]
            bhist = self._taghist[key]
            if (bnode != anode and anode in bhist and
                    (bnode not in ahist or len(bhist) > len(ahist))):
                anode = bnode
            self._tags[key] = anode
            self._taghist[key] = ahist | set(
                n for n in bhist if n not in ahist)

    def __iter__(self):
        return self._tags.iteritems()

    def hist(self, key):
        return set(self._taghist[key])


class GitCommit(object):
    __slots__ = ('sha1', 'body', 'parents', 'tree', 'author', 'committer')

    def __init__(self, sha1):
        self.sha1 = sha1
        commit = GitHgHelper.cat_file('commit', sha1)
        header, self.body = commit.split('\n\n', 1)
        parents = []
        for line in header.splitlines():
            if line == '\n':
                break
            typ, data = line.split(' ', 1)
            if typ == 'parent':
                parents.append(data.strip())
            elif typ in self.__slots__:
                assert not hasattr(self, typ)
                setattr(self, typ, data)
        self.parents = tuple(parents)


class PseudoGitCommit(GitCommit):
    def __init__(self, sha1):
        self.sha1 = sha1


def autohexlify(h):
    if len(h) == 40:
        return h
    elif len(h) == 20:
        return hexlify(h)
    assert False


class BranchMap(object):
    __slots__ = "_heads", "_all_heads", "_tips", "_git_sha1s", "_unknown_heads"

    def __init__(self, store, remote_branchmap, remote_heads):
        self._heads = {}
        self._all_heads = tuple(autohexlify(h) for h in remote_heads)
        self._tips = {}
        self._git_sha1s = {}
        self._unknown_heads = set()
        for branch, heads in remote_branchmap.iteritems():
            # We can't keep track of tips if the list of heads is not sequenced
            sequenced = isinstance(heads, Sequence) or len(heads) == 1
            branch_heads = []
            for head in heads:
                head = autohexlify(head)
                branch_heads.append(head)
                sha1 = store.changeset_ref(head)
                if not sha1:
                    self._unknown_heads.add(head)
                    continue
                assert head not in self._git_sha1s
                self._git_sha1s[head] = sha1
            # Use last non-closed head as tip. Caveat: we don't know a
            # head is closed until we've pulled it.
            if branch and heads and sequenced:
                for head in reversed(branch_heads):
                    if head in self._git_sha1s:
                        changeset = store.changeset(head)
                        if changeset.close:
                            continue
                    self._tips[branch] = head
                    break
            if branch:
                self._heads[branch] = tuple(branch_heads)

    def names(self):
        return self._heads.keys()

    def heads(self, branch=None):
        if branch:
            return self._heads.get(branch, ())
        return self._all_heads

    def unknown_heads(self):
        return self._unknown_heads

    def git_sha1(self, head):
        return self._git_sha1s.get(head, '?')

    def tip(self, branch):
        return self._tips.get(branch, None)


class Grafter(object):
    __slots__ = "_store", "_early_history", "_graft_trees", "_grafted"

    def __init__(self, store):
        self._store = store
        self._early_history = set()
        self._graft_trees = defaultdict(list)
        self._grafted = False
        refs = ['--exclude=refs/cinnabar/*', '--all']
        if store._has_metadata:
            refs += ['--not', 'refs/cinnabar/metadata^']
        for node, tree, parents in progress_iter(
                'Reading {} graft candidates',
                GitHgHelper.rev_list('--full-history', *refs)):
            self._graft_trees[tree].append(node)
        if not self._graft_trees:
            raise NothingToGraftException()

    def _is_cinnabar_commit(self, commit):
        data = self._store.read_changeset_data(commit)
        return '\npatch' not in data if data else False

    def _graft(self, changeset, parents):
        store = self._store
        tree = store.git_tree(changeset.manifest, *changeset.parents[:1])
        do_graft = tree and tree in self._graft_trees
        if not do_graft:
            return None

        commits = {}

        def graftable(c):
            commit = commits.get(c)
            if not commit:
                commit = commits[c] = GitCommit(c)
            if (Authorship.from_git_str(commit.author).timestamp !=
                    int(changeset.timestamp)):
                return False

            if all(store._replace.get(p1, p1) == store._replace.get(p2, p2)
                   for p1, p2 in zip(commit.parents, parents)):
                return True

            # Allow to graft if one of the parents is from early history
            return any(p in self._early_history for p in parents)

        nodes = tuple(c for c in self._graft_trees[tree] if graftable(c))

        if len(nodes) > 1:
            # Ideally, this should all be tried with fuzziness, and
            # independently of the number of nodes we got, but the
            # following is enough to graft github.com/mozilla/gecko-dev
            # to mozilla-central and related repositories.
            # Try with commits with the same subject line
            subject = changeset.body.split('\n', 1)[0]
            possible_nodes = tuple(
                n for n in nodes
                if commits[n].body.split('\n', 1)[0] == subject
            )
            if len(possible_nodes) > 1:
                # Try with commits with the same author ; this is attempted
                # separately from checking timestamps because author may
                # have been munged.
                possible_nodes = tuple(
                    n for n in possible_nodes
                    if (Authorship.from_git_str(commits[n].author)
                        .to_hg()[0] == changeset.author)
                )
            if len(possible_nodes) == 1:
                nodes = possible_nodes

        # If we still have multiple nodes, check if one of them is one that
        # cinnabar would have created. If it is, we prefer other commits on
        # the premise that it means we've been asked to reclone with a graft.
        # on a repo that was already handled by cinnabar.
        if len(nodes) > 1:
            possible_nodes = []
            for node in nodes:
                commit = commits[node]
                cs = Changeset.from_git_commit(commit)
                patcher = ChangesetPatcher.from_diff(cs, changeset)
                if '\npatch' in patcher:
                    possible_nodes.append(node)
            nodes = possible_nodes

        if len(nodes) > 1:
            raise AmbiguousGraftAbort(
                'Cannot graft changeset %s. Candidates: %s'
                % (changeset.node, ', '.join(nodes)))

        if nodes:
            node = nodes[0]
            self._graft_trees[tree].remove(node)
            return commits[node]
        return None

    def graft(self, changeset):
        # TODO: clarify this function because it's hard to follow.
        store = self._store
        parents = tuple(store.changeset_ref(p) for p in changeset.parents)
        if None in parents:
            result = None
        else:
            result = self._graft(changeset, parents)
        if parents:
            is_early_history = all(p in self._early_history for p in parents)
        else:
            is_early_history = not result
        if not (is_early_history or result):
            raise NothingToGraftException()
        if is_early_history or not result:
            commit = store.changeset_ref(changeset.node)
        else:
            commit = result
        store.store_changeset(changeset, commit or False)
        commit = store.changeset_ref(changeset.node)
        if is_early_history:
            if result:
                store._replace[result.sha1] = commit
            else:
                self._early_history.add(commit)
        elif not parents:
            if result:
                commit = result.sha1
            if self._is_cinnabar_commit(commit):
                self._early_history.add(commit)

        if result:
            self._grafted = True

    def close(self):
        if not self._grafted and self._early_history:
            raise NothingToGraftException()


class GitHgStore(object):
    FLAGS = [
        'files-meta',
        'unified-manifests-v2',
    ]

    METADATA_REFS = (
        'refs/cinnabar/changesets',
        'refs/cinnabar/manifests',
        'refs/cinnabar/hg2git',
        'refs/notes/cinnabar',
        'refs/cinnabar/files-meta',
    )

    def _metadata(self):
        if self._metadata_sha1:
            metadata = GitCommit(self._metadata_sha1)
            self._flags = set(metadata.body.split())
            refs = self.METADATA_REFS
            if 'files-meta' not in self._flags:
                refs = list(refs)
                refs.remove('refs/cinnabar/files-meta')
            return metadata, dict(zip(refs, metadata.parents))

    def metadata(self):
        metadata = self._metadata()
        if metadata:
            if len(self._flags) > len(self.FLAGS):
                raise UpgradeAbort(
                    'It looks like this repository was used with a newer '
                    'version of git-cinnabar. Cannot use this version.')
            if set(self._flags) != set(self.FLAGS):
                raise UpgradeAbort()
        return metadata

    def __init__(self):
        self._flags = set()
        self._closed = False
        self._graft = None

        self._hgheads = VersionedDict()
        self._branches = {}

        self._replace = Git._replace
        self._tagcache_ref = None
        self._metadata_sha1 = None
        # While doing a for_each_ref, ensure refs/notes/cinnabar is in the
        # cache.
        for sha1, ref in Git.for_each_ref('refs/cinnabar',
                                          'refs/notes/cinnabar'):
            if ref.startswith('refs/cinnabar/replace/'):
                self._replace[ref[22:]] = sha1
            elif ref.startswith('refs/cinnabar/branches/'):
                raise OldUpgradeAbort()
            elif ref == 'refs/cinnabar/metadata':
                self._metadata_sha1 = sha1
            elif ref == 'refs/cinnabar/tag_cache':
                self._tagcache_ref = sha1
        self._replace = VersionedDict(self._replace)

        self._tagcache = {}
        self._tagfiles = {}
        self._tags = {NULL_NODE_ID: {}}
        self._cached_changeset_ref = {}
        self._tagcache_items = set()
        if self._tagcache_ref:
            for line in Git.ls_tree(self._tagcache_ref):
                mode, typ, sha1, path = line
                if typ == 'blob':
                    if self.ATTR[mode] == 'x':
                        self._tagfiles[path] = sha1
                    else:
                        self._tagcache[path] = sha1
                elif typ == 'commit':
                    assert sha1 == NULL_NODE_ID
                    self._tagcache[path] = sha1
                self._tagcache_items.add(path)

        self.tag_changes = False

        metadata = self.metadata()
        if metadata:
            metadata, refs = metadata
        self._has_metadata = bool(metadata)
        self._metadata_refs = refs if metadata else {}
        self._manifest_heads_orig = set()
        if metadata:
            changesets_ref = self._metadata_refs.get(
                'refs/cinnabar/changesets')
            if changesets_ref:
                commit = GitCommit(changesets_ref)
                for sha1, head in izip(commit.parents,
                                       commit.body.splitlines()):
                    hghead, branch = head.split(' ', 1)
                    self._hgheads._previous[hghead] = branch

            self._manifest_heads_orig = set(GitHgHelper.heads('manifests'))

            replace = {}
            for line in Git.ls_tree(metadata.tree):
                mode, typ, sha1, path = line
                replace[path] = sha1

            if self._replace and not replace:
                raise OldUpgradeAbort()

            # Delete old tag-cache, which may contain incomplete data.
            Git.delete_ref('refs/cinnabar/tag-cache')

    def prepare_graft(self):
        self._graft = Grafter(self)

    @staticmethod
    def _try_merge_branches(repo_url):
        parsed_url = urlparse(repo_url)
        branches = []
        path = parsed_url.path.lstrip('/').rstrip('/')
        if path:
            parts = list(reversed(path.split('/')))
        else:
            parts = []
        host = parsed_url.netloc.split(':', 1)[0]
        if host:
            parts.append(host)
        last_path = ''
        for part in parts:
            if last_path:
                last_path = '%s/%s' % (part, last_path)
            else:
                last_path = part
            branches.append(last_path)
        branches.append('metadata')
        return branches

    @staticmethod
    def _find_branch(branches, remote_refs):
        for branch in branches:
            if branch in remote_refs:
                return branch
            if 'refs/cinnabar/%s' % branch in remote_refs:
                return 'refs/cinnabar/%s' % branch
            if 'refs/heads/%s' % branch in remote_refs:
                return 'refs/heads/%s' % branch

    def merge(self, git_repo_url, hg_repo_url, branch=None):
        # Eventually we'll want to handle a full merge, but for now, we only
        # handle the case where we don't have metadata to begin with.
        # The caller should avoid calling this function otherwise.
        assert not self._has_metadata
        remote_refs = OrderedDict()
        for line in Git.iter('ls-remote', git_repo_url,
                             stderr=open(os.devnull, 'w')):
            sha1, ref = line.split(None, 1)
            remote_refs[ref] = sha1
        bundle = None
        if not remote_refs:
            bundle = HTTPReader(git_repo_url)
            BUNDLE_SIGNATURE = '# v2 git bundle\n'
            signature = bundle.read(len(BUNDLE_SIGNATURE))
            if signature != BUNDLE_SIGNATURE:
                logging.error('Could not find cinnabar metadata')
                return False
            bundle = io.BufferedReader(bundle)
            while True:
                line = bundle.readline().rstrip()
                if not line:
                    break
                sha1, ref = line.split(' ', 1)
                remote_refs[ref] = sha1
        if branch:
            branches = [branch]
        else:
            branches = self._try_merge_branches(hg_repo_url)

        ref = self._find_branch(branches, remote_refs)
        if ref is None:
            logging.error('Could not find cinnabar metadata')
            return False

        if bundle:
            proc = GitProcess('index-pack', '--stdin', '-v',
                              stdin=subprocess.PIPE,
                              stdout=open(os.devnull, 'w'))
            shutil.copyfileobj(bundle, proc.stdin)
        else:
            proc = GitProcess(
                'fetch', '--no-tags', '--no-recurse-submodules', git_repo_url,
                ref + ':refs/cinnabar/fetch', stdout=sys.stdout)
        if proc.wait():
            logging.error('Failed to fetch cinnabar metadata.')
            return False

        # Do some basic validation on the metadata we just got.
        commit = GitCommit(remote_refs[ref])
        if 'cinnabar@git' not in commit.author:
            logging.error('Invalid cinnabar metadata.')
            return False

        flags = set(commit.body.split())
        if 'files-meta' not in flags or 'unified-manifests-v2' not in flags \
                or len(commit.parents) != len(self.METADATA_REFS):
            logging.error('Invalid cinnabar metadata.')
            return False

        # At this point, we'll just assume this is good enough.

        # Get replace refs.
        if commit.tree != EMPTY_TREE:
            errors = False
            by_sha1 = {}
            for k, v in remote_refs.iteritems():
                if v not in by_sha1:
                    by_sha1[v] = k
            needed = []
            for line in Git.ls_tree(commit.tree):
                mode, typ, sha1, path = line
                if sha1 in by_sha1:
                    needed.append('%s:refs/cinnabar/replace/%s' % (
                        by_sha1[sha1], path))
                else:
                    logging.error('Missing commit: %s', sha1)
                    errors = True
            if errors:
                return False

            proc = GitProcess('fetch', '--no-tags', '--no-recurse-submodules',
                              git_repo_url, *needed, stdout=sys.stdout)
            if proc.wait():
                logging.error('Failed to fetch cinnabar metadata.')
                return False

        Git.update_ref('refs/cinnabar/metadata', commit.sha1)
        self._metadata_sha1 = commit.sha1
        GitHgHelper.reload()
        Git.delete_ref('refs/cinnabar/fetch')

        # TODO: avoid the duplication of code with __init__
        metadata = self.metadata()

        if not metadata:
            # This should never happen, but just in case.
            logging.warn('Could not find cinnabar metadata')
            Git.delete_ref('refs/cinnabar/metadata')
            GitHgHelper.reload()
            return False

        metadata, refs = metadata
        self._has_metadata = True
        self._metadata_refs = refs if metadata else {}
        changesets_ref = self._metadata_refs.get('refs/cinnabar/changesets')
        if changesets_ref:
            commit = GitCommit(changesets_ref)
            for sha1, head in izip(commit.parents,
                                   commit.body.splitlines()):
                hghead, branch = head.split(' ', 1)
                self._hgheads._previous[hghead] = branch

        self._manifest_heads_orig = set(GitHgHelper.heads('manifests'))

        for line in Git.ls_tree(metadata.tree):
            mode, typ, sha1, path = line
            self._replace[path] = sha1

        return True

    def tags(self, heads):
        tags = TagSet()
        for h in heads:
            h = self.changeset_ref(h)
            tags.update(self._get_hgtags(h))
        for tag, node in tags:
            if node != NULL_NODE_ID:
                yield tag, node

    def _get_hgtags(self, head):
        tags = TagSet()
        if not self._tagcache.get(head):
            ls = one(Git.ls_tree(head, '.hgtags'))
            if not ls:
                self._tagcache[head] = NULL_NODE_ID
                return tags
            mode, typ, self._tagcache[head], path = ls
        tagfile = self._tagcache[head]
        if tagfile not in self._tags:
            if tagfile in self._tagfiles:
                data = GitHgHelper.cat_file('blob', self._tagfiles[tagfile])
                for line in data.splitlines():
                    tag, nodes = line.split('\0', 1)
                    nodes = nodes.split(' ')
                    for node in reversed(nodes):
                        tags[tag] = node
            else:
                data = GitHgHelper.cat_file('blob', tagfile) or ''
                for line in data.splitlines():
                    if not line:
                        continue
                    try:
                        node, tag = line.split(' ', 1)
                    except ValueError:
                        continue
                    tag = tag.strip()
                    try:
                        unhexlify(node)
                    except TypeError:
                        continue
                    if node != NULL_NODE_ID:
                        node = self.cached_changeset_ref(node)
                    if node:
                        tags[tag] = node
            self._tags[tagfile] = tags
        return self._tags[tagfile]

    def heads(self, branches={}):
        if not isinstance(branches, (dict, set)):
            branches = set(branches)
        return set(h for h, b in self._hgheads.iteritems()
                   if not branches or b in branches)

    def _head_branch(self, head):
        if head in self._hgheads:
            return self._hgheads[head], head
        if head in self._branches:
            return self._branches[head], head
        branch = self.changeset(head).branch or 'default'
        self._branches[head] = branch
        return branch, head

    def add_head(self, head, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        branch, head = self._head_branch(head)
        for p in (parent1, parent2):
            if p == NULL_NODE_ID:
                continue
            parent_branch, parent_head = self._head_branch(p)
            if parent_branch == branch:
                if parent_head in self._hgheads:
                    assert parent_branch == self._hgheads[parent_head]
                    del self._hgheads[parent_head]

        self._hgheads[head] = branch

    def read_changeset_data(self, obj):
        obj = str(obj)
        data = GitHgHelper.git2hg(obj)
        if data is None:
            return None
        ret = ChangesetPatcher(data)
        return ret

    def hg_changeset(self, sha1):
        data = self.read_changeset_data(sha1)
        if data:
            assert data.startswith('changeset ')
            return data[10:50]
        return None

    def hg_manifest(self, sha1):
        git_commit = GitCommit(sha1)
        assert len(git_commit.body) == 40
        return git_commit.body

    def _hg2git(self, sha1):
        if not self._has_metadata and not GitHgHelper._helper:
            return None
        gitsha1 = GitHgHelper.hg2git(sha1)
        if gitsha1 == NULL_NODE_ID:
            gitsha1 = None
        return gitsha1

    def changeset(self, sha1, include_parents=False):
        gitsha1 = self.changeset_ref(sha1)
        assert gitsha1
        return self._changeset(gitsha1, include_parents)

    def _changeset(self, git_commit, include_parents=False):
        if not isinstance(git_commit, GitCommit):
            git_commit = GitCommit(git_commit)

        metadata = self.read_changeset_data(git_commit.sha1)
        if not metadata:
            return None
        changeset = Changeset.from_git_commit(git_commit)
        changeset = metadata.apply(changeset)

        if include_parents:
            assert len(git_commit.parents) <= 2
            changeset.parents = tuple(
                self.hg_changeset(self._replace.get(p, p))
                for p in git_commit.parents)

        return changeset

    ATTR = {
        '100644': '',
        '100755': 'x',
        '120000': 'l',
    }

    @staticmethod
    def manifest_metadata_path(path):
        return '_' + path.replace('/', '/_')

    @staticmethod
    def manifest_path(path):
        return path[1:].replace('/_', '/')

    def manifest(self, sha1, include_parents=False):
        manifest = GeneratedManifestInfo(sha1)
        manifest.data = GitHgHelper.manifest(sha1)
        if include_parents:
            git_sha1 = self.manifest_ref(sha1)
            commit = GitCommit(git_sha1)
            parents = (self.hg_manifest(p) for p in commit.parents)
            manifest.set_parents(*parents)
        return manifest

    def manifest_ref(self, sha1):
        return self._hg2git(sha1)

    def changeset_ref(self, sha1):
        return self._hg2git(sha1)

    def cached_changeset_ref(self, sha1):
        try:
            return self._cached_changeset_ref[sha1]
        except KeyError:
            res = self._cached_changeset_ref[sha1] = self.changeset_ref(sha1)
            return res

    def file_meta(self, sha1):
        return GitHgHelper.file_meta(sha1)

    def file(self, sha1, file_parents=None, git_manifest_parents=None,
             path=None):
        if sha1 == HG_EMPTY_FILE:
            content = ''
        else:
            content = GitHgHelper.cat_blob(':h%s' % sha1)

        file = File(sha1)
        meta = self.file_meta(sha1)
        if meta:
            file.metadata = meta
        file.content = content
        if file_parents is not None:
            FileFindParents.set_parents(
                file, *file_parents,
                git_manifest_parents=git_manifest_parents,
                path=path)
        return file

    def git_file_ref(self, sha1):
        # Because an empty file and an empty manifest, both with no parents,
        # have the same sha1, we can't store both in the hg2git tree. So, we
        # choose to never store the file version, and make it forcibly resolve
        # to the empty blob. Which means we won't be storing an empty blob and
        # getting a mark for it, and will attempt to use it directly even if
        # it doesn't exist. The FastImport code works around this.
        # Theoretically, it is possible to have a non-modified child of the
        # empty file, and a non-modified child of the empty manifest, which
        # both would also have the same sha1, but, TTBOMK, it is only possible
        # to achieve with commands like hg debugparents.
        if sha1 == HG_EMPTY_FILE:
            return EMPTY_BLOB
        return self._hg2git(sha1)

    def git_tree(self, manifest_sha1, ref_changeset=None):
        if manifest_sha1 == NULL_NODE_ID:
            return EMPTY_TREE,
        return GitHgHelper.create_git_tree(manifest_sha1, ref_changeset)

    def store_changeset(self, instance, commit=None):
        if commit and not isinstance(commit, GitCommit):
            commit = GitCommit(commit)
        if commit is None and self._graft:
            return self._graft.graft(instance)

        if not commit:
            author = Authorship.from_hg(instance.author, instance.timestamp,
                                        instance.utcoffset)
            extra = instance.extra
            if extra and extra.get('committer'):
                committer = extra['committer']
                if committer[-1] == '>':
                    committer = Authorship.from_hg(
                        committer, instance.timestamp, instance.utcoffset)
                else:
                    committer = Authorship.from_hg_str(
                        committer, maybe_git_utcoffset=True)
                    if committer.to_hg() == committer:
                        extra = dict(instance.extra)
                        del extra['committer']
                        if not extra:
                            extra = None
            else:
                committer = author

            parents = tuple(':h%s' % p for p in instance.parents)

            body = instance.body

            # There are cases where two changesets would map to the same
            # git commit because their differences are not in information
            # stored in the git commit (different manifest node, but
            # identical tree ; different branches ; etc.)
            # In that case, add invisible characters to the commit
            # message until we find a commit that doesn't map to another
            # changeset.
            committer = committer.to_git_str()
            author = author.to_git_str()
            with GitHgHelper.commit(
                ref='refs/cinnabar/tip',
                message=body,
                committer=committer,
                author=author,
                parents=parents,
                pseudo_mark=':h%s' % instance.node,
            ) as c:
                c.filemodify('', self.git_tree(instance.manifest,
                                               *instance.parents[:1]),
                             typ='tree')

            commit = PseudoGitCommit(':1')
            commit.author = author
            commit.committer = committer
            commit.body = body

        GitHgHelper.set('changeset', instance.node, commit.sha1)
        changeset = Changeset.from_git_commit(commit)
        GitHgHelper.put_blob(
            ChangesetPatcher.from_diff(changeset, instance), want_sha1=False)
        GitHgHelper.set('changeset-metadata', instance.node, ':1')

        self._branches[instance.node] = instance.branch or 'default'
        self.add_head(instance.node, instance.parent1, instance.parent2)

    MODE = {
        '': '160644',
        'l': '160000',
        'x': '160755',
    }

    def store_manifest(self, instance):
        if getattr(instance, 'delta_node', NULL_NODE_ID) != NULL_NODE_ID:
            previous = ':h%s' % instance.delta_node
        else:
            previous = None
        parents = tuple(':h%s' % p for p in instance.parents)
        with GitHgHelper.commit(
            ref='refs/cinnabar/manifests',
            from_commit=previous,
            parents=parents,
            message=instance.node,
            pseudo_mark=':h%s' % instance.node,
        ) as commit:
            if hasattr(instance, 'delta_node'):
                for name in instance.removed:
                    commit.filedelete(self.manifest_metadata_path(name))
                modified = instance.modified.items()
            else:
                # slow
                modified = ((line.name, (line.node, line.attr))
                            for line in instance._lines)
            for name, (node, attr) in modified:
                node = str(node)
                commit.filemodify(self.manifest_metadata_path(name), node,
                                  self.MODE[attr])

        GitHgHelper.set('manifest', instance.node, ':1')

        self.check_manifest(instance)

    def check_manifest(self, instance):
        if check_enabled('manifests'):
            if not GitHgHelper.check_manifest(instance.node):
                raise Exception(
                    'sha1 mismatch for node %s with parents %s %s and '
                    'previous %s' %
                    (instance.node, instance.parent1, instance.parent2,
                     instance.delta_node)
                )

    def close(self):
        if self._closed:
            return
        if self._graft:
            self._graft.close()
        self._closed = True
        # If the helper is not running, we don't have anything to update.
        if not GitHgHelper._helper:
            return
        update_metadata = {}
        tree = GitHgHelper.store('metadata', 'hg2git')
        if tree != NULL_NODE_ID:
            hg2git = self._metadata_refs.get('refs/cinnabar/hg2git')
            with GitHgHelper.commit(
                ref='refs/cinnabar/hg2git',
            ) as commit:
                commit.write('M 040000 %s \n' % tree)
            if commit.sha1 != hg2git:
                update_metadata['refs/cinnabar/hg2git'] = commit.sha1

        tree = GitHgHelper.store('metadata', 'git2hg')
        if tree != NULL_NODE_ID:
            notes = self._metadata_refs.get('refs/notes/cinnabar')
            with GitHgHelper.commit(
                ref='refs/notes/cinnabar',
            ) as commit:
                commit.write('M 040000 %s \n' % tree)
            if commit.sha1 != notes:
                update_metadata['refs/notes/cinnabar'] = commit.sha1

        hg_changeset_heads = list(self._hgheads)
        changeset_heads = list(self.changeset_ref(h)
                               for h in hg_changeset_heads)
        if any(self._hgheads.iterchanges()):
            heads = sorted((self._hgheads[h], h, g)
                           for h, g in izip(hg_changeset_heads,
                                            changeset_heads))
            with GitHgHelper.commit(
                ref='refs/cinnabar/changesets',
                parents=list(h for _, __, h in heads),
                message='\n'.join('%s %s' % (h, b) for b, h, _ in heads),
            ) as commit:
                pass
            update_metadata['refs/cinnabar/changesets'] = commit.sha1

        changeset_heads = set(changeset_heads)

        manifest_heads = GitHgHelper.heads('manifests')
        if (set(manifest_heads) != self._manifest_heads_orig or
                ('refs/cinnabar/changesets' in update_metadata and
                 not manifest_heads)):
            with GitHgHelper.commit(
                ref='refs/cinnabar/manifests',
                parents=sorted(manifest_heads),
            ) as commit:
                pass
            update_metadata['refs/cinnabar/manifests'] = commit.sha1

        tree = GitHgHelper.store('metadata', 'files-meta')
        files_meta_ref = self._metadata_refs.get('refs/cinnabar/files-meta')
        if update_metadata and (tree != NULL_NODE_ID or not files_meta_ref):
            with GitHgHelper.commit(
                ref='refs/cinnabar/files-meta',
            ) as commit:
                if tree != NULL_NODE_ID:
                    commit.write('M 040000 %s \n' % tree)
            if commit.sha1 != files_meta_ref:
                update_metadata['refs/cinnabar/files-meta'] = commit.sha1

        replace_changed = False
        for status, ref, sha1 in self._replace.iterchanges():
            if status == VersionedDict.REMOVED:
                Git.delete_ref('refs/cinnabar/replace/%s' % ref)
            else:
                Git.update_ref('refs/cinnabar/replace/%s' % ref, sha1)
            replace_changed = True

        if update_metadata or replace_changed:
            parents = list(update_metadata.get(r) or self._metadata_refs[r]
                           for r in self.METADATA_REFS)
            if self._metadata_sha1:
                parents.append(self._metadata_sha1)
            with GitHgHelper.commit(
                ref='refs/cinnabar/metadata',
                parents=parents,
                message=' '.join(sorted(self.FLAGS)),
            ) as commit:
                for sha1, target in self._replace.iteritems():
                    commit.filemodify(sha1, target, 'commit')

        for c in self._tagcache:
            if c not in changeset_heads:
                self._tagcache[c] = False

        for c in changeset_heads:
            if c not in self._tagcache:
                tags = self._get_hgtags(c)

        files = set(self._tagcache.itervalues())
        deleted = set()
        created = {}
        for f in self._tagcache_items:
            if (f not in self._tagcache and f not in self._tagfiles or
                    f not in files and f in self._tagfiles):
                deleted.add(f)

        def tagset_lines(tags):
            for tag, value in tags:
                yield '%s\0%s %s\n' % (tag, value,
                                       ' '.join(sorted(tags.hist(tag))))

        for f, tags in self._tags.iteritems():
            if f not in self._tagfiles and f != NULL_NODE_ID:
                data = ''.join(tagset_lines(tags))
                mark = GitHgHelper.put_blob(data=data)
                created[f] = (mark, 'exec')

        if created or deleted:
            self.tag_changes = True

        for c, f in self._tagcache.iteritems():
            if (f and c not in self._tagcache_items):
                if f == NULL_NODE_ID:
                    created[c] = (f, 'commit')
                else:
                    created[c] = (f, 'regular')
            elif f is False and c in self._tagcache_items:
                deleted.add(c)

        if created or deleted:
            with GitHgHelper.commit(
                ref='refs/cinnabar/tag_cache',
                from_commit=self._tagcache_ref,
            ) as commit:
                for f in deleted:
                    commit.filedelete(f)

                for f, (filesha1, typ) in created.iteritems():
                    commit.filemodify(f, filesha1, typ)

        # refs/notes/cinnabar is kept for convenience
        for ref in update_metadata:
            if ref not in ('refs/notes/cinnabar',):
                Git.delete_ref(ref)

        GitHgHelper.close(rollback=False)
