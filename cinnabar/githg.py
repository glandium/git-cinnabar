#!/usr/bin/env python2.7

from __future__ import division
import types
from binascii import hexlify, unhexlify
from itertools import (
    chain,
    izip,
)
import hashlib
import re
import urllib
from collections import (
    Sequence,
    defaultdict,
)
from .util import (
    byte_diff,
    check_enabled,
    one,
    VersionedDict,
)
from .git import (
    EMPTY_BLOB,
    EMPTY_TREE,
    FastImport,
    Git,
    Mark,
    NULL_NODE_ID,
    sha1path,
)
from .helper import GitHgHelper
from .util import progress_iter
from .dag import gitdag
try:
    from mercurial.mdiff import textdiff
except ImportError:
    from .bdiff import bdiff as textdiff

import logging


class UpgradeException(Exception):
    def __init__(self, message=None):
        super(UpgradeException, self).__init__(
            message or
            'Git-cinnabar metadata needs upgrade. '
            'Please run `git cinnabar fsck`.'
        )


class OldUpgradeException(UpgradeException):
    def __init__(self):
        super(OldUpgradeException, self).__init__(
            'Metadata from git-cinnabar versions older than 0.3.0 is not '
            'supported.\n'
            'Please run `git cinnabar fsck` with version 0.3.x first.'
        )


# An empty mercurial file with no parent has a fixed sha1 which is that of
# "\0" * 40 (incidentally, this is the same as for an empty manifest with
# no parent.
HG_EMPTY_FILE = 'b80de5d138758541c5f05265ad144ab9fa86d1db'

RE_GIT_AUTHOR = re.compile('^(?P<name>.*?) ?(?:\<(?P<email>.*?)\>)')


def get_git_author(author):
    # check for git author pattern compliance
    a = RE_GIT_AUTHOR.match(author)

    def cleanup(x):
        return x.replace('<', '').replace('>', '')

    if a:
        return '%s <%s>' % (cleanup(a.group('name')),
                            cleanup(a.group('email')))
    if '@' in author:
        return ' <%s>' % cleanup(author)
    return '%s <>' % cleanup(author)


def get_hg_author(author):
    a = RE_GIT_AUTHOR.match(author)
    assert a
    name = a.group('name')
    email = a.group('email')
    if name and email:
        return author
    return name or '<%s>' % email


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
        from .hg.changegroup import RevDiff
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


class GeneratedFileRev(GeneratedRevChunk):
    logger = logging.getLogger('generated_file')

    def _invalid_if_new(self):
        if self.node == NULL_NODE_ID:
            raise Exception('Trying to create an invalid file. '
                            'Please open an issue with details.')

    def set_parents(self, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID,
                    git_manifest_parents=None, path=None):
        assert git_manifest_parents is not None and path is not None

        # Remove null nodes
        parents = tuple(p for p in (parent1, parent2) if p != NULL_NODE_ID)
        orig_parents = parents

        # On merges, a file with copy metadata has either no parent, or only
        # one. In that latter case, the parent is always set as second parent.
        # On non-merges, a file with copy metadata doesn't have a parent.
        if self.data.startswith('\1\n'):
            if len(parents) == 2:
                self._invalid_if_new()
            elif len(parents) == 1:
                if git_manifest_parents is not None:
                    if len(git_manifest_parents) != 2:
                        self._invalid_if_new()
                parents = (NULL_NODE_ID, parents[0])
            elif git_manifest_parents is not None:
                if len(git_manifest_parents) == 0:
                    self._invalid_if_new()
        elif len(parents) == 2:
            if git_manifest_parents is not None:
                if len(git_manifest_parents) != 2:
                    self._invalid_if_new()
            if parents[0] == parents[1]:
                parents = parents[:1]
            elif (git_manifest_parents is not None and
                  (self.node == NULL_NODE_ID or check_enabled('files'))):
                # Checking if one parent is the ancestor of another is slow.
                # So, unless we're actually creating this file, skip over
                # this by default, the fallback will work just fine.
                file_dag = gitdag()
                mapping = {}
                hg_path = 'hg/%s' % path
                for sha1, tree, fparents in GitHgHelper.rev_list(
                        '--parents', '--boundary', '--topo-order', '--reverse',
                        '%s...%s' % git_manifest_parents, '--', hg_path):
                    if sha1.startswith('-'):
                        sha1 = sha1[1:]
                    node = [
                        s
                        for mode, typ, s, p in
                        Git.ls_tree(sha1, hg_path)
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

        super(GeneratedFileRev, self).set_parents(*parents)
        if self.node != NULL_NODE_ID and self.node != self.sha1:
            if parents != orig_parents:
                if self._try_parents(*orig_parents):
                    self.logger.debug(
                        'Right parents given for %s, but they don\'t match '
                        'what modern mercurial normally would do', self.node)
                    return
            self._set_parents_fallback(parent1, parent2)

    def _set_parents_fallback(self, parent1=NULL_NODE_ID,
                              parent2=NULL_NODE_ID):
        result = (  # In some cases, only one parent is stored in a merge,
                    # because the other parent is actually an ancestor of the
                    # first one, but checking that is likely more expensive
                    # than to check if the sha1 matches with either parent.
                    self._try_parents(parent1) or
                    self._try_parents(parent2) or
                    # Some mercurial versions stores the first parent twice in
                    # merges.
                    self._try_parents(parent1, parent1) or
                    # As last resort, try without any parents.
                    self._try_parents())

        self.logger.debug('Wrong parents given for %s', self.node)
        self.logger.debug('  Got: %s %s', parent1, parent2)
        if result:
            self.logger.debug('  Expected: %s %s', self.parent1, self.parent2)

        # If none of the above worked, we failed big time
        if not result:
            raise Exception('Failed to create file. '
                            'Please open an issue with details.')

    def _try_parents(self, *parents):
        super(GeneratedFileRev, self).set_parents(*parents)
        return self.node == self.sha1


class ChangesetInfo(RevChunk):
    __slots__ = ('message', 'manifest', 'committer', 'date', 'utcoffset',
                 'extra', 'files')

    def init(self, previous_chunk):
        super(ChangesetInfo, self).init(previous_chunk)
        metadata, self.message = self.data.split('\n\n', 1)
        lines = metadata.splitlines()
        self.manifest, self.committer, date = lines[:3]
        date = date.split(' ', 2)
        self.date = int(date[0])
        self.utcoffset = int(date[1])
        if len(date) == 3:
            self.extra = ChangesetData.parse_extra(date[2])
        else:
            self.extra = None
        self.files = lines[3:]


class GeneratedChangesetInfo(ChangesetInfo, GeneratedRevChunk):
    pass


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

    def patch_data(self, data, rev_patch):
        from .hg.changegroup import RevDiff
        new = ''
        end = 0
        before_list = {}
        after_list = {}
        for diff in RevDiff(rev_patch):
            new += data[end:diff.start]
            new += diff.text_data
            end = diff.end

            start = data.rfind('\n', 0, diff.start) + 1
            if diff.end == 0 or data[diff.end - 1] == '\n':
                finish = diff.end
            else:
                finish = data.find('\n', diff.end)
            if finish != -1:
                before = data[start:finish]
            else:
                before = data[start:]
            after = before[:diff.start - start] + diff.text_data + \
                before[diff.end - start:]
            before_list.update({f.name: (f.node, f.attr)
                                for f in isplitmanifest(before)})
            after_list.update({f.name: (f.node, f.attr)
                               for f in isplitmanifest(after)})
        new += data[end:]
        self.removed = set(before_list.keys()) - set(after_list.keys())
        self.modified = after_list
        return new


class ChangesetData(object):
    FIELDS = ('changeset', 'manifest', 'author', 'extra', 'files', 'patch')

    @staticmethod
    def parse_extra(s):
        return dict(i.split(':', 1) for i in s.split('\0') if i)

    @staticmethod
    def parse(s):
        if isinstance(s, types.StringType):
            s = s.splitlines()
        data = {k: v for k, v in (l.split(' ', 1) for l in s)}
        if 'extra' in data:
            data['extra'] = ChangesetData.parse_extra(data['extra'])
        if 'files' in data:
            data['files'] = data['files'].split('\0')
        if 'patch' in data:
            data['patch'] = tuple((int(start), int(end), urllib.unquote(text))
                                  for line in data['patch'].split('\0')
                                  for start, end, text in (line.split(','),))
        return data

    @staticmethod
    def dump_extra(data):
        return '\0'.join(':'.join(i) for i in sorted(data.items()))

    @staticmethod
    def dump(data):
        def serialize(data):
            for k in ChangesetData.FIELDS:
                if k not in data:
                    continue
                if k == 'extra':
                    yield k, ChangesetData.dump_extra(data[k])
                elif k == 'files':
                    if data[k]:
                        yield k, '\0'.join(data[k])
                elif k == 'patch':
                    yield k, '\0'.join(
                        ','.join((str(start), str(end), urllib.quote(text)))
                        for start, end, text in data[k])
                else:
                    yield k, data[k]
        return '\n'.join('%s %s' % s for s in serialize(data))


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


def git_hash(type, data):
    h = hashlib.sha1('%s %d\0' % (type, len(data)))
    h.update(data)
    return h.hexdigest()


def autohexlify(h):
    if len(h) == 40:
        return h
    elif len(h) == 20:
        return hexlify(h)
    assert False


class BranchMap(object):
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
                extra = store.read_changeset_data(sha1).get('extra')
                if branch and sequenced and extra and not extra.get('close'):
                    self._tips[branch] = head
                assert head not in self._git_sha1s
                self._git_sha1s[head] = sha1
            # Use last head as tip if we didn't set one.
            if branch and heads and sequenced and branch not in self._tips:
                self._tips[branch] = head
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


class NothingToGraftException(Exception):
    pass


class AmbiguousGraftException(Exception):
    pass


class Grafter(object):
    def __init__(self, store):
        self._store = store
        self._early_history = set()
        self._graft_trees = defaultdict(list)
        self._grafted = False
        refs = ['--exclude=refs/cinnabar/*', '--all']
        if store._has_metadata:
            refs += ['--not', 'refs/cinnabar/metadata^']
        for node, tree, parents in progress_iter(
                'Reading %d graft candidates',
                GitHgHelper.rev_list('--full-history', *refs)):
            self._graft_trees[tree].append(node)
        if not self._graft_trees:
            raise NothingToGraftException()

    def _is_cinnabar_commit(self, commit):
        data = self._store.read_changeset_data(commit)
        return 'patch' not in data if data else False

    def _graft(self, changeset, parents):
        store = self._store
        tree = store.git_tree(changeset.manifest)
        do_graft = tree in self._graft_trees
        if not do_graft:
            return None

        commits = {}

        def graftable(c):
            commit = commits.get(c)
            if not commit:
                commit = commits[c] = GitCommit(c)
            if not store.hg_author_info(commit.author)[1] == changeset.date:
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
            subject = changeset.message.split('\n', 1)[0]
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
                    if (store.hg_author_info(commits[n].author)[0] ==
                        changeset.committer)
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
                store.store_changeset(changeset, commit, track_heads=False)
                sha1 = commit.sha1
                if store.read_changeset_data(sha1).get('patch'):
                    possible_nodes.append(node)
            nodes = possible_nodes

        if len(nodes) > 1:
            raise AmbiguousGraftException(
                'Cannot graft changeset %s. Candidates: %s'
                % (changeset.node, ', '.join(nodes)))

        if nodes:
            node = nodes[0]
            self._graft_trees[tree].remove(node)
            return commits[node]
        return None

    def graft(self, changeset, track_heads=True):
        # TODO: clarify this function because it's hard to follow.
        store = self._store
        parents = tuple(store.changeset_ref(p) for p in changeset.parents)
        result = self._graft(changeset, parents)
        if parents:
            is_early_history = all(p in self._early_history for p in parents)
        else:
            is_early_history = not result
        if not (is_early_history or result):
            raise NothingToGraftException()
        if is_early_history or not result:
            commit = store.changeset_ref(changeset.node, hg2git=False)
        else:
            commit = result
        store.store_changeset(changeset, commit or False, track_heads)
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
    ]

    METADATA_REFS = (
        'refs/cinnabar/changesets',
        'refs/cinnabar/manifests',
        'refs/cinnabar/hg2git',
        'refs/notes/cinnabar',
        'refs/cinnabar/files-meta',
    )

    def _metadata(self):
        metadata_ref = Git.resolve_ref('refs/cinnabar/metadata')
        if metadata_ref:
            metadata = GitCommit(metadata_ref)
            self._flags = set(metadata.body.split())
            refs = self.METADATA_REFS
            if 'files-meta' not in self._flags:
                refs = list(refs)
                refs.remove('refs/cinnabar/files-meta')
            for ref, value in zip(refs, metadata.parents):
                Git.update_ref(ref, value, store=False)
            return metadata

    def metadata(self):
        metadata = self._metadata()
        if metadata:
            if len(self._flags) > len(self.FLAGS):
                raise UpgradeException(
                    'It looks like this repository was used with a newer '
                    'version of git-cinnabar. Cannot use this version.')
            if set(self._flags) != set(self.FLAGS):
                raise UpgradeException()
        return metadata

    def __init__(self):
        self.__fast_import = None
        self._flags = set()
        self._changesets = {}
        self._manifests = {}
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
        self._git_files = {
            HG_EMPTY_FILE: EMPTY_BLOB,
        }
        self._files_meta = {}
        self._closed = False
        self._graft = None

        self._changeset_data_cache = {}

        self._hgheads = VersionedDict()

        self._replace = Git._replace
        # While doing a for_each_ref, ensure refs/notes/cinnabar is in the
        # cache.
        for sha1, ref in Git.for_each_ref('refs/cinnabar',
                                          'refs/notes/cinnabar'):
            if ref.startswith('refs/cinnabar/replace/'):
                self._replace[ref[22:]] = sha1
            elif ref.startswith('refs/cinnabar/branches/'):
                raise OldUpgradeException()
        self._replace = VersionedDict(self._replace)

        self._tagcache = {}
        self._tagfiles = {}
        self._tags = {NULL_NODE_ID: {}}
        self._tagcache_ref = Git.resolve_ref('refs/cinnabar/tag-cache')
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
        self._has_metadata = bool(metadata)
        if metadata:
            manifests_ref = Git.resolve_ref('refs/cinnabar/manifests')
            if manifests_ref:
                commit = GitCommit(manifests_ref)
                manifests = commit.parents
                if commit.body == "has-flat-manifest-tree":
                    manifests = commit.parents[1:]
            else:
                manifests = ()

            changesets_ref = Git.resolve_ref('refs/cinnabar/changesets')
            if changesets_ref:
                commit = GitCommit(changesets_ref)
                for sha1, head in izip(commit.parents,
                                       commit.body.splitlines()):
                    hghead, branch = head.split(' ', 1)
                    self._hgheads._previous[hghead] = branch

        else:
            manifests = ()

        self._manifest_dag = gitdag((m, ()) for m in manifests)
        self._manifest_heads_orig = set(self._manifest_dag.heads())

        if metadata:
            replace = {}
            for line in Git.ls_tree(metadata.tree):
                mode, typ, sha1, path = line
                replace[path] = sha1

            if self._replace and not replace:
                raise OldUpgradeException()

    def prepare_graft(self):
        self._graft = Grafter(self)

    def tags(self, heads):
        # The given heads are assumed to be ordered by mercurial
        # revision number, such that the last is the one where
        # tags are the most relevant.
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
                        node = self.changeset_ref(node)
                    if node:
                        tags[tag] = node
        self._tags[tagfile] = tags
        return tags

    def heads(self, branches={}):
        if not isinstance(branches, (dict, set)):
            branches = set(branches)
        return set(h for h, b in self._hgheads.iteritems()
                   if not branches or b in branches)

    def _head_branch(self, head):
        branch = self.read_changeset_data(self.changeset_ref(head)) \
            .get('extra', {}) \
            .get('branch', 'default')
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
                ref = self.changeset_ref(parent_head)
                if ref in self._tagcache:
                    self._tagcache[ref] = False

        self._hgheads[head] = branch
        ref = self.changeset_ref(head)
        self._tagcache[ref] = None

    @property
    def _fast_import(self):
        assert self.__fast_import is not None
        if self.__fast_import is False:
            self._fast_import = FastImport()
        return self.__fast_import

    @_fast_import.setter
    def _fast_import(self, fi):
        assert fi
        self.__fast_import = fi
        Git.register_fast_import(fi)
        fi.send_done()

    def init_fast_import(self, lazy=False):
        if self.__fast_import:
            return
        if lazy:
            self.__fast_import = False
        else:
            self._fast_import = FastImport()

    def read_changeset_data(self, obj):
        obj = str(obj)
        if obj in self._changeset_data_cache:
            return self._changeset_data_cache[obj]
        data = GitHgHelper.git2hg(obj)
        if data is None:
            return None
        ret = ChangesetData.parse(data)
        return ret

    def hg_changeset(self, sha1):
        data = self.read_changeset_data(sha1)
        if data:
            return data['changeset']
        return None

    def hg_manifest(self, sha1):
        git_commit = GitCommit(sha1)
        assert len(git_commit.body) == 40
        return git_commit.body

    def _hg2git(self, sha1):
        if not self._has_metadata and not self._closed:
            return None

        gitsha1 = GitHgHelper.hg2git(sha1)
        if gitsha1 == NULL_NODE_ID:
            gitsha1 = None
        return gitsha1

    def _git_object(self, dic, sha1, hg2git=True):
        assert sha1 != NULL_NODE_ID
        if sha1 in dic:
            return dic[sha1]
        sha1 = sha1
        if hg2git:
            gitsha1 = self._hg2git(sha1)
            if gitsha1:
                return gitsha1
        return None

    def hg_author_info(self, author_line):
        author, date, utcoffset = author_line.rsplit(' ', 2)
        date = int(date)
        utcoffset = int(utcoffset)
        sign = -cmp(utcoffset, 0)
        utcoffset = abs(utcoffset)
        utcoffset = (utcoffset // 100) * 60 + (utcoffset % 100)
        return author, date, sign * utcoffset * 60

    def changeset(self, sha1, include_parents=False):
        assert not isinstance(sha1, Mark)
        gitsha1 = self._hg2git(sha1)
        assert gitsha1
        return self._changeset(gitsha1, sha1, include_parents)

    def _changeset(self, git_commit, sha1=NULL_NODE_ID, include_parents=False,
                   skip_patch=False):
        if not isinstance(git_commit, GitCommit):
            git_commit = GitCommit(git_commit)

        metadata = self.read_changeset_data(git_commit.sha1)
        author, date, utcoffset = self.hg_author_info(git_commit.author)
        if 'author' in metadata:
            author = metadata['author']
        else:
            author = get_hg_author(author)

        extra = metadata.get('extra')
        if git_commit.committer != git_commit.author:
            if not extra or 'committer' not in extra:
                extra = dict(extra) if extra else {}
                committer = self.hg_author_info(git_commit.committer)
                extra['committer'] = '%s %d %d' % committer
        if extra is not None:
            extra = ' ' + ChangesetData.dump_extra(extra)
        changeset = ''.join(chain(
            [
                metadata['manifest'], '\n',
                author, '\n',
                str(date), ' ', str(utcoffset)
            ],
            [extra] if extra else [],
            ['\n', '\n'.join(metadata['files'])]
            if metadata.get('files') else [],
            ['\n\n'], git_commit.body))

        if 'patch' in metadata and not skip_patch:
            new = ''
            last_end = 0
            for start, end, text in metadata['patch']:
                new += changeset[last_end:start]
                new += text
                last_end = end
            changeset = new + changeset[last_end:]

        hgdata = GeneratedChangesetInfo(sha1, changeset)
        if include_parents:
            assert len(git_commit.parents) <= 2
            hgdata.set_parents(*[
                self.read_changeset_data(self._replace.get(p, p))['changeset']
                for p in git_commit.parents])
            hgdata.changeset = sha1
        return hgdata

    ATTR = {
        '100644': '',
        '100755': 'x',
        '120000': 'l',
    }

    def manifest(self, sha1, include_parents=False):
        manifest = GeneratedManifestInfo(sha1)
        gitsha1 = self._hg2git(sha1)
        assert gitsha1
        manifest.data = GitHgHelper.manifest('git:%s' % gitsha1)
        if include_parents:
            git_sha1 = self.manifest_ref(sha1)
            commit = GitCommit(git_sha1)
            parents = (self.hg_manifest(p) for p in commit.parents)
            manifest.set_parents(*parents)
        return manifest

    def manifest_ref(self, sha1):
        return self._git_object(self._manifests, sha1)

    def changeset_ref(self, sha1, hg2git=True):
        return self._git_object(self._changesets, sha1, hg2git=hg2git)

    def file_meta(self, sha1):
        if sha1 in self._files_meta:
            return self._files_meta[sha1]
        meta_ref = Git.resolve_ref('refs/cinnabar/files-meta')
        if meta_ref:
            for mode, typ, blob, path in Git.ls_tree(meta_ref, sha1path(sha1)):
                return GitHgHelper.cat_file('blob', blob)

    def file(self, sha1, file_parents=None, git_manifest_parents=None,
             path=None):
        ref = self.git_file_ref(sha1)
        if ref == EMPTY_BLOB:
            content = ''
        else:
            content = GitHgHelper.cat_file('blob', ref)

        meta = self.file_meta(sha1)
        if meta:
            content = '\1\n'.join(['', meta, content])

        file = GeneratedFileRev(sha1, content)
        if file_parents is not None:
            file.set_parents(*file_parents,
                             git_manifest_parents=git_manifest_parents,
                             path=path)
        return file

    def git_file_ref(self, sha1):
        return self._git_object(self._git_files, sha1)

    def _git_committer(self, committer, date, utcoffset):
        utcoffset = int(utcoffset)
        sign = -cmp(utcoffset, 0)
        return (get_git_author(committer), int(date),
                sign * (abs(utcoffset) // 60))

    def git_tree(self, manifest_sha1):
        if manifest_sha1 == NULL_NODE_ID:
            return EMPTY_TREE,
        manifest_commit = self.manifest_ref(manifest_sha1)
        line = one(Git.ls_tree(manifest_commit, 'git'))
        if line:
            mode, typ, tree, path = line
            assert typ == 'tree' and path == 'git'
        else:
            # If there is no git directory in the manifest tree, it means the
            # manifest tree is empty, so the corresponding git tree needs to
            # be empty too, although there is no entry for it. No need to
            # actually get the sha1 for the empty directory, since it's a fixed
            # value.
            tree = EMPTY_TREE
        return tree

    def store_changeset(self, instance, commit=None, track_heads=True):
        if not commit:
            mark = self.changeset_ref(instance.node)
        else:
            if not isinstance(commit, GitCommit):
                commit = GitCommit(commit)
            mark = commit.sha1
        if not mark and self._graft and commit is not False:
            return self._graft.graft(instance, track_heads)
        elif not commit and mark:
            return

        author = self._git_committer(instance.committer, instance.date,
                                     instance.utcoffset)
        extra = instance.extra
        if extra and extra.get('committer'):
            committer = extra['committer']
            if committer[-1] == '>':
                committer = committer, author[1], author[2]
            else:
                committer_info = committer.rsplit(' ', 2)
                # If the committer tz is in the form +xxxx or -0yyy, it is
                # obviously in git format, not in mercurial format.
                # TODO: handle -1yyy timezones.
                if committer_info[2].startswith(('+', '-0')):
                    committer = self.hg_author_info(committer)
                    committer = self._git_committer(*committer)
                else:
                    committer = self._git_committer(*committer_info)
                    extra = dict(instance.extra)
                    del extra['committer']
                    if not extra:
                        extra = None
        else:
            committer = author

        parents = tuple(self.changeset_ref(p) for p in instance.parents)

        if not mark:
            body = instance.message
            tree = self.git_tree(instance.manifest)

            # There are cases where two changesets would map to the same
            # git commit because their differences are not in information
            # stored in the git commit (different manifest node, but
            # identical tree ; different branches ; etc.)
            # In that case, add invisible characters to the commit
            # message until we find a commit that doesn't map to another
            # changeset.
            while True:
                with self._fast_import.commit(
                    ref='refs/cinnabar/tip',
                    message=body,
                    committer=committer,
                    author=author,
                    parents=parents,
                ) as c:
                    if tree != EMPTY_TREE:
                        c.filemodify('', tree, typ='tree')

                if (c.sha1 in self._changesets or
                        self.hg_changeset(c.sha1)):
                    body += '\0'
                    continue
                break
            commit = GitCommit(c.sha1)

        self._changesets[instance.node] = commit.sha1
        data = self._changeset_data_cache[commit.sha1] = {
            'changeset': instance.node,
            'manifest': instance.manifest,
        }
        if extra is not None:
            data['extra'] = extra
        if instance.files:
            data['files'] = instance.files
        if author[0] != instance.committer:
            data['author'] = instance.committer

        generated_instance = self._changeset(commit, instance.node)
        if generated_instance.data != instance.data:
            patch = tuple(byte_diff(generated_instance.data, instance.data))
            if patch:
                data['patch'] = patch
                generated_instance = self._changeset(commit, instance.node)
                assert generated_instance.data == instance.data

        if track_heads:
            self.add_head(instance.node, instance.parent1, instance.parent2)

    TYPE = {
        '': 'regular',
        'l': 'symlink',
        'x': 'exec',
    }

    def store_manifest(self, instance):
        mark = self.manifest_ref(instance.node)
        if mark:
            return
        if getattr(instance, 'delta_node', NULL_NODE_ID) != NULL_NODE_ID:
            previous = self.manifest_ref(instance.delta_node)
        else:
            previous = None
        parents = tuple(self.manifest_ref(p) for p in instance.parents)
        # Force trigger any helper requests before starting the commit.
        for node, attr in instance.modified.itervalues():
            self.git_file_ref(str(node))
        with self._fast_import.commit(
            ref='refs/cinnabar/manifests',
            from_commit=previous,
            parents=parents,
            message=instance.node,
        ) as commit:
            if hasattr(instance, 'delta_node'):
                for name in instance.removed:
                    commit.filedelete('hg/%s' % name)
                    commit.filedelete('git/%s' % name)
                modified = instance.modified.items()
            else:
                # slow
                modified = ((line.name, (line.node, line.attr))
                            for line in instance._lines)
            for name, (node, attr) in modified:
                node = str(node)
                commit.filemodify('hg/%s' % name, node, typ='commit')
                commit.filemodify('git/%s' % name,
                                  self.git_file_ref(node), typ=self.TYPE[attr])

        self._manifests[instance.node] = commit.sha1
        self._manifest_dag.add(commit.sha1, parents)

        if check_enabled('manifests'):
            if not GitHgHelper.check_manifest('git:%s' % commit.sha1):
                raise Exception(
                    'sha1 mismatch for node %s with parents %s %s and '
                    'previous %s' %
                    (instance.node, instance.parent1, instance.parent2,
                     instance.delta_node)
                )

    def store_file(self, instance):
        mark = self.git_file_ref(instance.node)
        if mark:
            return
        data = instance.data
        if data.startswith('\1\n'):
            _, metadata, data = data.split('\1\n', 2)
            assert not _
            self._files_meta[instance.node] = metadata
        self._git_files[instance.node] = self._fast_import.put_blob(data)

    def close(self):
        if self._closed:
            return
        if self._graft:
            self._graft.close()
        self._closed = True
        hg2git_files = []
        update_metadata = []
        for dic, typ in (
            (self._git_files, 'regular'),
            (self._manifests, 'commit'),
            (self._changesets, 'commit'),
        ):
            for node, mark in dic.iteritems():
                if dic is self._git_files and node == HG_EMPTY_FILE:
                    continue
                if isinstance(mark, Mark):
                    raise TypeError(node)
                hg2git_files.append((sha1path(node), mark, typ))
        if hg2git_files:
            with self._fast_import.commit(
                ref='refs/cinnabar/hg2git',
                from_commit=Git.resolve_ref('refs/cinnabar/hg2git'),
            ) as commit:
                for file in sorted(hg2git_files, key=lambda f: f[0]):
                    if file[1] is None:
                        commit.filedelete(file[0])
                    else:
                        commit.filemodify(*file)

        del hg2git_files

        removed_git2hg = [
            c for c, data in self._changeset_data_cache.iteritems()
            if data is None
        ]
        if self._changesets or removed_git2hg:
            notes = Git.resolve_ref('refs/notes/cinnabar')
            with self._fast_import.commit(
                ref='refs/notes/cinnabar',
                from_commit=notes,
            ) as commit:
                for mark in self._changesets.itervalues():
                    if mark:
                        data = self._changeset_data_cache[str(mark)]
                        commit.notemodify(mark, ChangesetData.dump(data))
                for c in removed_git2hg:
                    commit.write('N %s %s\n' % (NULL_NODE_ID, c))
                update_metadata.append('refs/notes/cinnabar')

        if any(self._hgheads.iterchanges()):
            with self._fast_import.commit(
                ref='refs/cinnabar/changesets',
                parents=(self.changeset_ref(h) for h in self._hgheads),
                message='\n'.join('%s %s' % (h, b)
                                  for h, b in self._hgheads.iteritems()),
            ) as commit:
                update_metadata.append('refs/cinnabar/changesets')

        manifest_heads = tuple(self._manifest_dag.heads())
        if (set(manifest_heads) != self._manifest_heads_orig or
                ('refs/cinnabar/changesets' in update_metadata and
                 not manifest_heads)):
            with self._fast_import.commit(
                ref='refs/cinnabar/manifests',
                parents=sorted(manifest_heads),
            ) as commit:
                update_metadata.append('refs/cinnabar/manifests')

        files_meta_ref = Git.resolve_ref('refs/cinnabar/files-meta')
        if self._files_meta or (files_meta_ref is None and update_metadata):
            with self._fast_import.commit(
                ref='refs/cinnabar/files-meta',
                from_commit=files_meta_ref,
            ) as commit:
                for sha1, content in self._files_meta.iteritems():
                    if content is None:
                        commit.filedelete(sha1path(sha1))
                    else:
                        commit.filemodify(sha1path(sha1), content=content)
                update_metadata.append('refs/cinnabar/files-meta')

        replace_changed = False
        for status, ref, sha1 in self._replace.iterchanges():
            if status == VersionedDict.REMOVED:
                Git.delete_ref('refs/cinnabar/replace/%s' % ref)
            else:
                Git.update_ref('refs/cinnabar/replace/%s' % ref, sha1)
            replace_changed = True

        if update_metadata or replace_changed:
            parents = list(Git.resolve_ref(r) for r in self.METADATA_REFS)
            metadata_ref = Git.resolve_ref('refs/cinnabar/metadata')
            if metadata_ref:
                parents.append(metadata_ref)
            with self._fast_import.commit(
                ref='refs/cinnabar/metadata',
                parents=parents,
                message=' '.join(sorted(self.FLAGS)),
            ) as commit:
                for sha1, target in self._replace.iteritems():
                    commit.filemodify(sha1, target, 'commit')

        def resolve_commit(c):
            if isinstance(c, Mark):
                c = self._fast_import.get_mark(c)
            return c

        for c, f in self._tagcache.items():
            if f is None:
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
                nodes = (resolve_commit(n) for n in tags.hist(tag))
                yield '%s\0%s %s\n' % (tag, resolve_commit(value),
                                       ' '.join(sorted(nodes)))

        self.init_fast_import(lazy=True)

        for f, tags in self._tags.iteritems():
            if f not in self._tagfiles and f != NULL_NODE_ID:
                data = ''.join(tagset_lines(tags))
                mark = self._fast_import.put_blob(data=data)
                created[f] = (mark, 'exec')

        if created or deleted:
            self.tag_changes = True

        for c, f in self._tagcache.iteritems():
            if f and isinstance(c, Mark):
                c = resolve_commit(c)
            if (f and c not in self._tagcache_items):
                if f == NULL_NODE_ID:
                    created[c] = (f, 'commit')
                else:
                    created[c] = (f, 'regular')
            elif f is False and c in self._tagcache_items:
                deleted.add(c)

        if created or deleted:
            with self._fast_import.commit(
                ref='refs/cinnabar/tag-cache',
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

        Git.close()
        GitHgHelper.close()
