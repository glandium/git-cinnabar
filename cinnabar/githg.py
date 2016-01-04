#!/usr/bin/env python2.7

from __future__ import division
import struct
import types
from binascii import hexlify, unhexlify
from itertools import (
    chain,
    izip,
)
from hashlib import sha1
import os
import re
import urllib
from collections import (
    OrderedDict,
    defaultdict,
)
from .util import (
    LazyString,
    one,
    byte_diff,
)
from .git import (
    EmptyMark,
    FastImport,
    Git,
    Mark,
    NULL_NODE_ID,
    sha1path,
)
from .helper import GitHgHelper
from .util import progress_iter
from .dag import gitdag
from mercurial import mdiff
from distutils.dir_util import mkpath

import time
import logging


class UpgradeException(Exception):
    pass


class StreamHandler(logging.StreamHandler):
    def __init__(self):
        super(StreamHandler, self).__init__()
        self._start_time = time.time()

    def emit(self, record):
        record.timestamp = record.created - self._start_time
        super(StreamHandler, self).emit(record)


logger = logging.getLogger()
handler = StreamHandler()
handler.setFormatter(logging.Formatter(
    '\r%(timestamp).3f [%(name)s] %(message)s'))
logger.addHandler(handler)

# An empty git tree has a fixed sha1 which is that of "tree 0\0"
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
# An empty git blob has a fixed sha1 which is that of "blob 0\0"
EMPTY_BLOB = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'

CHECK_ALL_NODE_IDS = False
CHECK_MANIFESTS = False

RE_GIT_AUTHOR = re.compile('^(?P<name>.*?) ?(?:\<(?P<email>.*?)\>)')


def get_git_author(author):
    # check for git author pattern compliance
    a = RE_GIT_AUTHOR.match(author)
    cleanup = lambda x: x.replace('<', '').replace('>', '')
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
    def __init__(self, chunk_data):
        self.node, self.parent1, self.parent2, self.changeset = (
            hexlify(h) for h in struct.unpack('20s20s20s20s', chunk_data[:80]))
        self._rev_data = chunk_data[80:]
        revchunk_log.debug(LazyString(lambda: '%s %s %s %s' % (
            self.node, self.parent1, self.parent2, self.changeset)))
        revchunk_log.debug(LazyString(lambda: repr(self._rev_data)))

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.node)

    def init(self, previous_chunk):
        assert self.parent1 == NULL_NODE_ID or previous_chunk
        self.data = self.patch_data(previous_chunk.data if previous_chunk
                                    else '', self._rev_data)

    def patch_data(self, data, rev_patch):
        if not rev_patch:
            return data
        new = ''
        end = 0
        diff_start = 0
        while diff_start < len(rev_patch):
            diff = RevDiff(rev_patch[diff_start:])
            new += data[end:diff.start]
            new += diff.text_data
            end = diff.end
            diff_start += len(diff)
        new += data[end:]
        return new

    @property
    def sha1(self):
        p1 = unhexlify(self.parent1)
        p2 = unhexlify(self.parent2)
        return sha1(
            min(p1, p2) +
            max(p1, p2) +
            self.data
        ).hexdigest()

    def diff(self, other):
        return mdiff.textdiff(other.data if other else '', self.data)

    def serialize(self, other):
        header = struct.pack(
            '20s20s20s20s',
            unhexlify(self.node),
            unhexlify(self.parent1),
            unhexlify(self.parent2),
            unhexlify(self.changeset),
        )
        return header + self.diff(other)

    @property
    def parents(self):
        if self.parent1 != NULL_NODE_ID:
            if self.parent2 != NULL_NODE_ID:
                return (self.parent1, self.parent2)
            return (self.parent1,)
        return ()


class GeneratedRevChunk(RevChunk):
    def __init__(self, node, data):
        self.node = node
        self.data = data

    def set_parents(self, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        self.parent1 = parent1
        self.parent2 = parent2


class GeneratedFileRev(GeneratedRevChunk):
    def set_parents(self, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        has_one_parent = parent1 != NULL_NODE_ID and parent2 != NULL_NODE_ID
        # Some mercurial versions stored a parent in some cases for copied
        # files.
        if self.data.startswith('\1\n') and has_one_parent:
            if self._try_parents():
                return
        if self._try_parents(parent1, parent2):
            return
        # In some cases, only one parent is stored in a merge, because the
        # other parent is actually an ancestor of the first one, but checking
        # that is likely more expensive than to check if the sha1 matches with
        # either parent.
        if self._try_parents(parent1):
            return
        if self._try_parents(parent2):
            return
        # Some mercurial versions stores the first parent twice in merges.
        if self._try_parents(parent1, parent1):
            return
        # If none of the above worked, just use the given parents.
        super(GeneratedFileRev, self).set_parents(parent1, parent2)

    def _try_parents(self, *parents):
        super(GeneratedFileRev, self).set_parents(*parents)
        return self.node == self.sha1


class RevDiff(object):
    def __init__(self, rev_patch):
        self.start, self.end, self.block_len = \
            struct.unpack('>lll', rev_patch[:12])
        self.text_data = rev_patch[12:12 + self.block_len]

    def __len__(self):
        return self.block_len + 12


class ChangesetInfo(RevChunk):
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
        yield ManifestLine(l[:null], l[null+1:null+41], l[null+41:])


def findline(data, offset, first=0, last=-1):
    if last == -1:
        last = len(data) - 1
    first_start = data[first].offset
    last_start = data[last].offset
    if offset >= last_start:
        return last
    if last - first == 1:
        return first

    ratio = (offset - first_start) / (last_start - first_start)
    maybe_line = int(ratio * (last - first) + first)
    if (offset >= data[maybe_line].offset and
            offset < data[maybe_line+1].offset):
        return maybe_line
    if offset < data[maybe_line].offset:
        return findline(data, offset, first, maybe_line)
    return findline(data, offset, maybe_line, last)


class ManifestInfo(RevChunk):
    def patch_data(self, data, rev_patch):
        new = ''
        end = 0
        diff_start = 0
        before_list = {}
        after_list = {}
        while diff_start < len(rev_patch):
            diff = RevDiff(rev_patch[diff_start:])
            new += data[end:diff.start]
            new += diff.text_data
            end = diff.end
            diff_start += len(diff)

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
    def __init__(self, node):
        super(GeneratedManifestInfo, self).__init__(node, '')
        if node == NULL_NODE_ID:
            self.__lines = []
        else:
            self.__lines = None
        self._data = None

    def init(self, previous_chunk):
        pass

    @property
    def data(self):
        if self._data is None and self.__lines is None:
            data = GitHgHelper.manifest(self.node)
            if isinstance(data, types.StringType):
                self._data = data
            else:
                self.__lines = data

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

    def append_line(self, line):
        self.__lines.append(line)
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
            else:
                assert not hasattr(self, typ)
                setattr(self, typ, data)
        self.parents = tuple(parents)


class GeneratedGitCommit(GitCommit):
    def __init__(self, sha1):
        self.sha1 = sha1


class GitHgStore(object):
    def __init__(self):
        self.__fast_import = None
        self._changesets = {}
        self._manifests = {}
        self._files = {}
        self._git_files = {}
        self._git_trees = {}
        self._closed = False

        self._hg2git_cache = {}
        self._previously_stored = None

        self._changeset_data_cache = {}

        self.STORE = {
            ChangesetInfo: (self._store_changeset, self.changeset,
                            self._changesets, 'commit'),
            ManifestInfo: (self._store_manifest, self.manifest,
                           self._manifests, 'commit'),
            GeneratedManifestInfo: (self._store_manifest, lambda x: None,
                                    self._manifests, 'commit'),
            RevChunk: (self._store_file, self.file, self._files, 'blob'),
        }

        self._hgheads = set()

        self._replace = {}
        self._old_branches = []
        for sha1, ref in Git.for_each_ref('refs/cinnabar'):
            if ref.startswith('refs/cinnabar/replace/'):
                self._replace[ref[22:]] = sha1
            elif ref.startswith('refs/cinnabar/branches/'):
                self._old_branches.append((sha1, ref))
        self._replace_orig = dict(self._replace)

        self._graft_trees = defaultdict(list)
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

        self._open()

    METADATA_REFS = (
        'refs/cinnabar/changesets',
        'refs/cinnabar/manifests',
        'refs/cinnabar/hg2git',
        'refs/notes/cinnabar',
    )

    def _open(self):
        metadata_ref = Git.resolve_ref('refs/cinnabar/metadata')
        if not metadata_ref and self._old_branches:
            raise UpgradeException(
                'Git-cinnabar metadata needs upgrade. '
                'Please run `git cinnabar fsck`.'
            )

        self._has_metadata = bool(metadata_ref)
        if metadata_ref:
            metadata = GitCommit(metadata_ref)
            for ref, value in zip(self.METADATA_REFS, metadata.parents):
                Git.update_ref(ref, value, store=False)

            manifests_ref = Git.resolve_ref('refs/cinnabar/manifests')
            manifests = tuple(Git.iter('rev-parse', '--revs-only',
                                       '%s^@' % manifests_ref))
            changesets_ref = Git.resolve_ref('refs/cinnabar/changesets')
            if changesets_ref:
                commit = GitCommit(changesets_ref)
                for sha1, head in izip(commit.parents,
                                       commit.body.splitlines()):
                    hghead, branch = head.split(' ', 1)
                    self._hgheads.add((branch, hghead))
                    self._changesets[hghead] = sha1

        else:
            manifests = ()

        self._manifest_dag = gitdag(manifests)
        self._manifest_heads_orig = set(self._manifest_dag.heads())

        self._hgheads_orig = set(self._hgheads)

    def prepare_graft(self, refs=[], graft_only=False):
        self._early_history = set()
        self._graft_only = graft_only
        if refs:
            refs = list(ref for sha1, ref in Git.for_each_ref(
                *(r.replace('*', '**') for r in refs)))
        else:
            refs = ['--all']
        if not refs:
            return
        exclude = ('^%s' % h for h in self._changesets.itervalues())
        for line in Git.iter('log', '--stdin', '--full-history',
                             '--format=%T %H', *refs, stdin=exclude):
            tree, node = line.split()
            self._graft_trees[tree].append(node)

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
                if isinstance(head, Mark):
                    data = self._fast_import.cat_blob(tagfile) or ''
                else:
                    data = Git.cat_file('blob', tagfile) or ''
                for line in data.splitlines():
                    node, tag = line.split(' ', 1)
                    if node != NULL_NODE_ID:
                        node = self.changeset_ref(node)
                    if node:
                        tags[tag] = node
        self._tags[tagfile] = tags
        return tags

    def heads(self, branches={}):
        if not isinstance(branches, (dict, set)):
            branches = set(branches)
        return set(h for b, h in self._hgheads
                   if not branches or b in branches)

    def _head_branch(self, head):
        branch = self.read_changeset_data(self.changeset_ref(head)) \
            .get('extra', {}) \
            .get('branch', 'default')
        return branch, head

    def add_head(self, head, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        head_branch = self._head_branch(head)
        for p in (parent1, parent2):
            if p == NULL_NODE_ID:
                continue
            parent_head_branch = self._head_branch(p)
            if parent_head_branch[0] == head_branch[0]:
                if parent_head_branch in self._hgheads:
                    self._hgheads.remove(parent_head_branch)
                ref = self.changeset_ref(parent_head_branch[1])
                if isinstance(ref, LazyString):
                    ref = str(ref)
                if ref in self._tagcache:
                    self._tagcache[ref] = False

        self._hgheads.add(head_branch)
        ref = self.changeset_ref(head)
        if isinstance(ref, LazyString):
            ref = str(ref)
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

    def _close_fast_import(self):
        if not self.__fast_import:
            return
        self._fast_import.close()

    def read_changeset_data(self, obj):
        obj = str(obj)
        if obj in self._changeset_data_cache:
            return self._changeset_data_cache[obj]
        data = GitHgHelper.git2hg(obj)
        if data is None:
            return None
        ret = self._changeset_data_cache[obj] = ChangesetData.parse(data)
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

    def _hg2git(self, expected_type, sha1):
        if not self._has_metadata and not self._closed:
            return None

        gitsha1 = self._hg2git_cache.get(sha1)
        if not gitsha1:
            gitsha1 = GitHgHelper.hg2git(sha1)
            if gitsha1 == NULL_NODE_ID:
                gitsha1 = None
            self._hg2git_cache[sha1] = gitsha1
        return gitsha1

    def _git_object(self, dic, expected_type, sha1, hg2git=True, create=True):
        assert sha1 != NULL_NODE_ID
        if sha1 in dic:
            return dic[sha1]
        sha1 = sha1
        if hg2git:
            gitsha1 = self._hg2git(expected_type, sha1)
            if gitsha1:
                dic[sha1] = gitsha1
                return gitsha1
        if create:
            mark = self._fast_import.new_mark()
            dic[sha1] = mark
            return mark
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
        gitsha1 = self._hg2git('commit', sha1)
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
        changeset = ''.join(chain([
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

        hgdata = GeneratedRevChunk(sha1, changeset)
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
        if include_parents:
            git_sha1 = self.manifest_ref(sha1)
            commit = GitCommit(git_sha1)
            parents = (self.hg_manifest(p) for p in commit.parents)
            manifest.set_parents(*parents)
        return manifest

    def manifest_ref(self, sha1, hg2git=True, create=False):
        return self._git_object(self._manifests, 'commit', sha1, hg2git=hg2git,
                                create=create)

    def changeset_ref(self, sha1, hg2git=True, create=False):
        return self._git_object(self._changesets, 'commit', sha1,
                                hg2git=hg2git, create=create)

    def file_ref(self, sha1, hg2git=True, create=False):
        return self._git_object(self._files, 'blob', sha1, hg2git=hg2git,
                                create=create)

    def file(self, sha1):
        ref = self._git_object(self._files, 'blob', sha1)
        return GeneratedFileRev(sha1, GitHgHelper.cat_file('blob', ref))

    def git_file_ref(self, sha1):
        if sha1 in self._git_files:
            return self._git_files[sha1]
        result = self.file_ref(sha1)
        if isinstance(result, Mark):
            return result
        # If the ref is not from the current import, it can be a raw hg file
        # ref, so check its content first.
        data = GitHgHelper.cat_file('blob', result)
        if data.startswith('\1\n'):
            return self._prepare_git_file(GeneratedFileRev(sha1, data))
        return result

    def store(self, instance):
        store_func, get_func, dic, typ = self.STORE[type(instance)]
        hg2git = False
        if instance.parent1 == NULL_NODE_ID or isinstance(self._git_object(
                dic, typ, instance.parent1, create=False), types.StringType):
            if instance.parent2 == NULL_NODE_ID or isinstance(self._git_object(
                    dic, typ, instance.parent2, create=False),
                    types.StringType):
                hg2git = True

        result = self._git_object(dic, typ, instance.node, hg2git=hg2git)
        logging.info(LazyString(lambda: "store %s %s %s" % (instance.node,
                                instance.previous_node, result)))
        check = CHECK_ALL_NODE_IDS
        if instance.previous_node != NULL_NODE_ID:
            if (self._previously_stored and
                    instance.previous_node == self._previously_stored.node):
                previous = self._previously_stored
            else:
                previous = get_func(instance.previous_node)
                check = True
            instance.init(previous)
        else:
            instance.init(())
        if check and instance.node != instance.sha1:
            raise Exception(
                'sha1 mismatch for node %s with parents %s %s and '
                'previous %s' %
                (instance.node, instance.parent1, instance.parent2,
                 instance.previous_node)
            )
        if isinstance(result, EmptyMark):
            result = Mark(result)
            store_func(instance, result)
        self._previously_stored = instance
        return result

    def _git_committer(self, committer, date, utcoffset):
        utcoffset = int(utcoffset)
        sign = -cmp(utcoffset, 0)
        return (get_git_author(committer), int(date),
                sign * (abs(utcoffset) // 60))

    def git_tree(self, manifest_sha1):
        if manifest_sha1 in self._git_trees:
            return self._git_trees[manifest_sha1]
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
        self._git_trees[manifest_sha1] = tree
        return tree

    def _store_changeset(self, instance, mark):
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

        tree = self.git_tree(instance.manifest)
        do_graft = tree in self._graft_trees
        if do_graft:
            commits = {}

            def graftable(c):
                commit = commits.get(c)
                if not commit:
                    commit = commits[c] = GitCommit(c)
                if not self.hg_author_info(commit.author)[1] == instance.date:
                    return False

                if commit.parents == parents:
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
                subject = instance.message.split('\n', 1)[0]
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
                        if (self.hg_author_info(commits[n].author)[0] ==
                            instance.committer)
                    )
                if len(possible_nodes) == 1:
                    nodes = possible_nodes

            if len(nodes) > 1:
                raise Exception('Cannot graft changeset %s. Candidates: %s'
                                % (instance.node, ', '.join(nodes)))

            if nodes:
                mark = nodes[0]
                self._graft_trees[tree].remove(mark)
                commit = commits[mark]
                mark = LazyString(mark)
            else:
                do_graft = False

        if do_graft:
            for p1, p2 in zip(parents, commit.parents):
                if p1 != p2:
                    self._replace[p2] = p1
        else:
            if self._graft_trees:
                if (all(p in self._early_history for p in parents)
                        or not parents):
                    self._early_history.add(mark)
                elif self._graft_only:
                    raise Exception('Not allowing non-graft import of %s'
                                    % instance.node)

            with self._fast_import.commit(
                ref='refs/cinnabar/tip',
                message=instance.message,
                committer=committer,
                author=author,
                parents=parents,
                mark=mark,
            ) as commit:
                commit.filemodify('', tree, typ='tree')

            mark = Mark(mark)
            commit = GeneratedGitCommit(mark)
            commit.sha1 = mark
            commit.committer = self._fast_import._format_committer(committer)
            commit.author = self._fast_import._format_committer(author)
            commit.body = instance.message

        self._changesets[instance.node] = mark
        data = self._changeset_data_cache[str(mark)] = {
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

        self.add_head(instance.node, instance.parent1, instance.parent2)

    TYPE = {
        '': 'regular',
        'l': 'symlink',
        'x': 'exec',
    }

    def _store_manifest(self, instance, mark):
        if instance.previous_node != NULL_NODE_ID:
            previous = self.manifest_ref(instance.previous_node)
        else:
            previous = None
        parents = tuple(self.manifest_ref(p) for p in instance.parents)
        with self._fast_import.commit(
            ref='refs/cinnabar/manifests',
            from_commit=previous,
            parents=parents,
            mark=mark,
            message=instance.node,
        ) as commit:
            for name in instance.removed:
                commit.filedelete('hg/%s' % name)
                commit.filedelete('git/%s' % name)
            for name, (node, attr) in instance.modified.items():
                node = str(node)
                commit.filemodify('hg/%s' % name, node, typ='commit')
                commit.filemodify('git/%s' % name,
                                  self.git_file_ref(node), typ=self.TYPE[attr])

        self._manifests[instance.node] = Mark(mark)
        self._manifest_dag.add(self._manifests[instance.node], parents)
        if CHECK_MANIFESTS:
            expected_tree = self._fast_import.ls(mark, 'hg')[2]
            tree = OrderedDict()
            for line in isplitmanifest(instance.data):
                path = line.name.split('/')
                root = tree
                for part in path[:-1]:
                    if part not in root:
                        root[part] = OrderedDict()
                    root = root[part]
                root[path[-1]] = line.node

            def tree_sha1(tree):
                s = ''
                h = sha1()
                for file, node in tree.iteritems():
                    if isinstance(node, OrderedDict):
                        node = tree_sha1(node)
                        attr = '40000'
                    else:
                        attr = '160000'
                    s += '%s %s\0%s' % (attr, file, unhexlify(node))

                h = sha1('tree %d\0' % len(s))
                h.update(s)
                return h.hexdigest()

            # TODO: also check git/ tree
            if tree_sha1(tree) != expected_tree:
                raise Exception(
                    'sha1 mismatch for node %s with parents %s %s and '
                    'previous %s' %
                    (instance.node, instance.parent1, instance.parent2,
                     instance.previous_node)
                )

    def _store_file(self, instance, mark):
        data = instance.data
        self._fast_import.put_blob(data=data, mark=mark)
        self._files[instance.node] = Mark(mark)
        if data.startswith('\1\n'):
            self._prepare_git_file(instance)

    def _prepare_git_file(self, instance):
        data = instance.data
        assert data.startswith('\1\n')
        data = data[data.index('\1\n', 2) + 2:]
        mark = self._fast_import.new_mark()
        self._fast_import.put_blob(data=data, mark=mark)
        mark = self._git_files[instance.node] = Mark(mark)
        return mark

    def close(self):
        if self._closed:
            return
        GitHgHelper.close()
        self._closed = True
        hg2git_files = []
        changeset_by_mark = {}
        git_dir = os.environ.get('GIT_DIR')
        if not git_dir:
            git_dir = one(Git.iter('rev-parse', '--git-dir'))
        reflog = os.path.join(git_dir, 'logs', 'refs', 'cinnabar')
        mkpath(reflog)
        open(os.path.join(reflog, 'metadata'), 'a').close()
        update_metadata = []
        for dic, typ in (
                (self._files, 'regular'),
                (self._manifests, 'commit'),
                (self._changesets, 'commit'),
                ):
            for node, mark in dic.iteritems():
                if isinstance(mark, types.StringType):
                    continue
                if isinstance(mark, EmptyMark):
                    raise TypeError(node)
                if mark in self._tagcache:
                    changeset_by_mark[mark] = node
                hg2git_files.append((sha1path(node), mark, typ))
        if hg2git_files:
            with self._fast_import.commit(
                ref='refs/cinnabar/hg2git',
                from_commit=Git.resolve_ref('refs/cinnabar/hg2git'),
                mark=self._fast_import.new_mark(),
            ) as commit:
                sha1 = Git.resolve_ref('refs/cinnabar/hg2git')
                if sha1:
                    mode, typ, tree, path = \
                        self._fast_import.ls(sha1)
                    commit.filemodify('', tree, typ='tree')
                for file in sorted(hg2git_files, key=lambda f: f[0]):
                    if file[1] is None:
                        commit.filedelete(file[0])
                    else:
                        commit.filemodify(*file)
                update_metadata.append('refs/cinnabar/hg2git')
        del hg2git_files

        git2hg_marks = [mark for mark in self._changesets.itervalues()
                        if mark and not isinstance(mark, types.StringType)]
        removed_git2hg = [
            c for c, data in self._changeset_data_cache.iteritems()
            if data is None
        ]
        if git2hg_marks or removed_git2hg:
            notes = Git.resolve_ref('refs/notes/cinnabar')
            parents = (notes,) if notes else ()
            # Using filemodify('', ..., typ='tree') doesn't work with
            # notemodify. See
            # <CALKQrgftttSpuw8kc+jC6E5RBet39wHKy3670Z5iG=KQSmrCAw@mail.gmail.com>
            # So first use traditional parenting, and rewrite.
            with self._fast_import.commit(
                ref='refs/notes/cinnabar',
                from_commit=notes,
                parents=parents,
            ) as commit:
                for mark in git2hg_marks:
                    data = self._changeset_data_cache[str(mark)]
                    commit.notemodify(mark, ChangesetData.dump(data))
                for c in removed_git2hg:
                    # That's brute force, but meh.
                    for l in range(0, 10):
                        commit.filedelete(sha1path(c, l))
                update_metadata.append('refs/notes/cinnabar')
            if parents:
                with self._fast_import.commit(
                    ref='refs/notes/cinnabar',
                    from_commit=Git.resolve_ref('refs/notes/cinnabar'),
                ) as commit:
                    pass

        manifest_heads = tuple(self._manifest_dag.heads())
        if set(manifest_heads) != self._manifest_heads_orig:
            with self._fast_import.commit(
                ref='refs/cinnabar/manifests',
                parents=manifest_heads,
            ) as commit:
                update_metadata.append('refs/cinnabar/manifests')

        if self._hgheads != self._hgheads_orig:
            with self._fast_import.commit(
                ref='refs/cinnabar/changesets',
                parents=(self.changeset_ref(h) for b, h in self._hgheads),
                message='\n'.join('%s %s' % (h, b) for b, h in self._hgheads),
            ) as commit:
                update_metadata.append('refs/cinnabar/changesets')

        if update_metadata:
            parents = list(Git.resolve_ref(r) for r in self.METADATA_REFS)
            metadata_ref = Git.resolve_ref('refs/cinnabar/metadata')
            if metadata_ref:
                parents.append(metadata_ref)
            with self._fast_import.commit(
                ref='refs/cinnabar/metadata',
                parents=parents,
            ) as commit:
                pass

        for ref in set(self._replace.keys()) | set(self._replace_orig.keys()):
            if ref in self._replace and ref in self._replace_orig:
                if self._replace[ref] != self._replace_orig[ref]:
                    Git.update_ref('refs/cinnabar/replace/%s' % ref,
                                   self._replace[ref])
            elif ref in self._replace:
                Git.update_ref('refs/cinnabar/replace/%s' % ref,
                               self._replace[ref])
            else:
                Git.delete_ref('refs/cinnabar/replace/%s' % ref)

        self._hg2git_cache.clear()

        def resolve_commit(c):
            if isinstance(c, Mark):
                c = self._hg2git('commit', changeset_by_mark[c])
            elif isinstance(c, LazyString):
                c = str(c)
            return c

        for c, f in self._tagcache.items():
            if f is None:
                tags = self._get_hgtags(c)

        files = set(self._tagcache.itervalues())
        deleted = set()
        created = {}
        for f in self._tagcache_items:
            if (f not in self._tagcache and f not in self._tagfiles
                    or f not in files and f in self._tagfiles):
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
                mark = self._fast_import.new_mark()
                self._fast_import.put_blob(data=data, mark=mark)
                created[f] = (Mark(mark), 'exec')

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
        # refs/cinnabar/hg2git is kept for the helper, which needs a ref
        # pointing to that tree.
        for ref in update_metadata:
            if ref not in ('refs/notes/cinnabar', 'refs/cinnabar/hg2git'):
                Git.delete_ref(ref)

        self._close_fast_import()
