#!/usr/bin/env python2.7

from __future__ import division
import struct
import types
from binascii import hexlify, unhexlify
from itertools import chain
from hashlib import sha1
import re
import urllib
import threading
from collections import (
    OrderedDict,
    defaultdict,
)
from git.util import (
    IOLogger,
    LazyString,
    one,
    next,
)
from git import (
    EmptyMark,
    FastImport,
    Git,
    Mark,
    split_ls_tree,
    sha1path,
)
from .helper import GitHgHelper
from mercurial import mdiff

import time
import logging


class StreamHandler(logging.StreamHandler):
    def __init__(self):
        super(StreamHandler, self).__init__()
        self._start_time = time.time()

    def emit(self, record):
        record.timestamp = record.created - self._start_time
        super(StreamHandler, self).emit(record)


logger = logging.getLogger()
handler = StreamHandler()
handler.setFormatter(logging.Formatter('\r%(timestamp).3f %(name)s %(message)s'))
logger.addHandler(handler)
#logger.setLevel(logging.INFO)
#logger.setLevel(logging.DEBUG)

#from guppy import hpy
#hp = hpy()

NULL_NODE_ID = '0' * 40

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
        name = cleanup(a.group('name'))
        email = a.group('email')
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
    return name or email


revchunk_log = logging.getLogger('revchunks')
#revchunk_log.setLevel(logging.DEBUG)

class RevChunk(object):
    def __init__(self, chunk_data):
        self.node, self.parent1, self.parent2, self.changeset = (hexlify(h)
            for h in struct.unpack('20s20s20s20s', chunk_data[:80]))
        self._rev_data = chunk_data[80:]
        revchunk_log.debug(LazyString(lambda: '%s %s %s %s' % (self.node,
            self.parent1, self.parent2, self.changeset)))
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
    start = 0
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
    if offset >= data[maybe_line].offset and offset < data[maybe_line+1].offset:
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
            before_list.update({f.name: (f.node, f.attr) for f in isplitmanifest(before)})
            after_list.update({f.name: (f.node, f.attr) for f in isplitmanifest(after)})
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
        data = { k: v for k, v in (l.split(' ', 1) for l in s) }
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
        self.__lines = None
        self._data = ''

    def init(self, previous_chunk):
        pass

    @property
    def data(self):
        if self._data is None:
            # Normally, it'd be better to use str(l), but it turns out to make
            # things significantly slower. Sigh python.
            self._data = ''.join(l._str for l in self._lines)
            self.__lines = None
        return self._data

    @data.setter
    def data(self, value):
        self._data = value
        self.__lines = None

    @property
    def _lines(self):
        if self.__lines is None:
            self.__lines = list(isplitmanifest(self.data))
            self._data = None
        return self.__lines

    @_lines.setter
    def _lines(self, value):
        self.__lines = value
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


class GitHgStore(object):
    def __init__(self):
        self.__fast_import = None
        self._changesets = {}
        self._manifests = {}
        self._files = {}
        self._git_files = {}
        self._git_trees = {}
        self._closed = False

        self._last_manifest = None
        self._hg2git_cache = {}
        self._previously_stored = None

        self._changeset_data_cache = {}

        self.STORE = {
            ChangesetInfo: (self._store_changeset, self.changeset, self._changesets, 'commit'),
            ManifestInfo: (self._store_manifest, self.manifest, self._manifests, 'commit'),
            GeneratedManifestInfo: (self._store_manifest, lambda x: None, self._manifests, 'commit'),
            RevChunk: (self._store_file, self.file, self._files, 'blob'),
        }

        self._hgheads = set()
        self._refs_orig = {}

        # Migrate refs from the old namespace.
        # refs/remote-hg/head-* are the old-old heads for upgrade
        migrated = False
        for line in Git.for_each_ref('refs/notes/remote-hg/git2hg',
                'refs/remote-hg', format='%(objectname) %(refname)'):
            migrated = True
            sha1, head = line.split()
            logging.info('%s %s' % (sha1, head))
            Git.delete_ref(head)
            if head.startswith('refs/remote-hg/branches/'):
                branch, hghead = head[24:].split('/', 1)
                if hghead != 'tip':
                    Git.update_ref('refs/cinnabar/branches/%s/%s'
                                   % (branch, hghead), sha1)
            elif head.startswith('refs/remote-hg/head-'):
                branch, hghead = self._head_branch(head[-40:])
                Git.update_ref('refs/cinnabar/branches/%s/%s'
                               % (branch, hghead), sha1)
            elif head == 'refs/notes/remote-hg/git2hg':
                Git.update_ref('refs/notes/cinnabar', sha1)
            else:
                Git.update_ref('refs/cinnabar/' + head[15:], sha1)
        # Ensure the ref updates above are available after this point.
        if migrated:
            Git.close()

        for line in Git.for_each_ref('refs/cinnabar/branches',
                                     format='%(objectname) %(refname)'):
            sha1, head = line.split()
            logging.info('%s %s' % (sha1, head))
            if head.startswith('refs/cinnabar/branches/'):
                branch, hghead = head[23:].split('/', 1)
                if hghead != 'tip':
                    self._hgheads.add((branch, hghead))
                    self._changesets[hghead] = sha1
            else:
                self._hgheads.add(self._head_branch(head[-40:]))
            self._refs_orig[head] = sha1

        self._tagcache = {}
        self._tagfiles = {}
        self._tags = { NULL_NODE_ID: {} }
        self._tagcache_ref = Git.resolve_ref('refs/cinnabar/tagcache')
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
        return set(h for b, h in self._hgheads if not branches or b in branches)

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
        assert self.__fast_import
        if callable(self.__fast_import):
            self._fast_import = self.__fast_import()
        return self.__fast_import

    @_fast_import.setter
    def _fast_import(self, fi):
        assert fi
        self.__fast_import = fi
        Git.register_fast_import(fi)
        fi.send_done()

    def init_fast_import(self, fi):
        if callable(fi):
            self.__fast_import = fi
        else:
            self._fast_import = fi

    def _close_fast_import(self):
        if not self.__fast_import or callable(self.__fast_import):
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

    def _hg2git(self, expected_type, sha1):
        if not self._refs_orig and not self._closed:
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

    def _changeset(self, gitsha1, sha1=NULL_NODE_ID, include_parents=False):
        commit = GitHgHelper.cat_file('commit', gitsha1)
        header, message = commit.split('\n\n', 1)
        commitdata = {}
        parents = []
        for line in header.splitlines():
            if line == '\n':
                break
            typ, data = line.split(' ', 1)
            if typ == 'parent':
                parents.append(data.strip())
            else:
                commitdata[typ] = data
        metadata = self.read_changeset_data(gitsha1)
        author, date, utcoffset = self.hg_author_info(commitdata['author'])
        if 'author' in metadata:
            author = metadata['author']
        else:
            author = get_hg_author(author)

        extra = metadata.get('extra')
        if commitdata['committer'] != commitdata['author']:
            if not extra or 'committer' not in extra:
                extra = dict(extra) if extra else {}
                committer = self.hg_author_info(commitdata['committer'])
                extra['committer'] = '%s %s %d' % committer
        if extra is not None:
            extra = ' ' + ChangesetData.dump_extra(extra)
        changeset = ''.join(chain([
            metadata['manifest'], '\n',
            author, '\n',
            date, ' ', str(utcoffset)
        ],
        [extra] if extra else [],
        ['\n', '\n'.join(metadata['files'])] if metadata.get('files') else [],
        ['\n\n'], message))

        if 'patch' in metadata:
            new = ''
            last_end = 0
            for start, end, text in metadata['patch']:
                new += changeset[last_end:start]
                new += text
                last_end = end
            changeset = new + changeset[last_end:]

        hgdata = GeneratedRevChunk(sha1, changeset)
        if include_parents:
            assert len(parents) <= 2
            hgdata.set_parents(*[
                self.read_changeset_data(p)['changeset'] for p in parents])
            hgdata.changeset = sha1
        return hgdata

    ATTR = {
        '100644': '',
        '100755': 'x',
        '120000': 'l',
    }

    def manifest(self, sha1):
        manifest = GeneratedManifestInfo(sha1)
        data = GitHgHelper.manifest(sha1)
        if isinstance(data, types.StringType):
            manifest.data = data
        else:
            manifest._lines = data
        return manifest

    def manifest_ref(self, sha1, hg2git=True, create=False):
        return self._git_object(self._manifests, 'commit', sha1, hg2git=hg2git,
            create=create)

    def changeset_ref(self, sha1, hg2git=True, create=False):
        return self._git_object(self._changesets, 'commit', sha1, hg2git=hg2git,
            create=create)

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
        if instance.parent1 == NULL_NODE_ID or isinstance(self._git_object(dic, typ,
                instance.parent1, create=False), types.StringType):
            if instance.parent2 == NULL_NODE_ID or isinstance(self._git_object(dic, typ,
                    instance.parent2, create=False), types.StringType):
                hg2git = True

        result = self._git_object(dic, typ, instance.node, hg2git=hg2git)
        logging.info(LazyString(lambda: "store %s %s %s" % (instance.node, instance.previous_node,
            result)))
        check = CHECK_ALL_NODE_IDS
        if instance.previous_node != NULL_NODE_ID:
            if self._previously_stored and instance.previous_node == self._previously_stored.node:
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
        parents = [NULL_NODE_ID]
        parents += [
            self.changeset_ref(p)
            for p in (instance.parent1, instance.parent2)
            if p != NULL_NODE_ID
        ]
        author = self._git_committer(instance.committer, instance.date,
                                     instance.utcoffset)
        extra = instance.extra
        if extra and extra.get('committer'):
            committer = extra['committer']
            if committer[-1] == '>':
                committer = committer, author[1], author[2]
            else:
                committer = committer.rsplit(' ', 2)
                committer = self._git_committer(*committer)
                extra = dict(instance.extra)
                del extra['committer']
                if not extra:
                    extra = None
        else:
            committer = author
        with self._fast_import.commit(
            ref='refs/cinnabar/tip',
            message=instance.message,
            committer=committer,
            author=author,
            parents=parents,
            mark=mark,
        ) as commit:
            tree = self.git_tree(instance.manifest)
            commit.filemodify('', tree, typ='tree')

        mark = self._changesets[instance.node] = Mark(mark)
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
        if instance.utcoffset % 60:
            offset = str(abs(instance.utcoffset) % 60)
            start = (42 - len(offset) + len(instance.committer)
                     + len('%d %d' % (instance.date, instance.utcoffset)))
            data['patch'] = ((start, start + len(offset), offset),)

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
        if self._last_manifest:
            if previous and previous != self._last_manifest:
                parents = (NULL_NODE_ID, self._last_manifest)
            else:
                parents = ()
        elif self._refs_orig:
            parents = (NULL_NODE_ID, 'refs/cinnabar/manifest^0',)
        else:
            parents = (NULL_NODE_ID,)
        with self._fast_import.commit(
            ref='refs/cinnabar/manifest',
            parents=parents,
            mark=mark,
        ) as commit:
            if previous and self._last_manifest != previous:
                mode, typ, tree, path = self._fast_import.ls(previous)
                commit.filemodify('', tree, typ='tree')
            self._last_manifest = mark
            for name in instance.removed:
                commit.filedelete('hg/%s' % name)
                commit.filedelete('git/%s' % name)
            for name, (node, attr) in instance.modified.items():
                node = str(node)
                commit.filemodify('hg/%s' % name, node, typ='commit')
                commit.filemodify('git/%s' % name,
                    self.git_file_ref(node), typ=self.TYPE[attr])

        self._manifests[instance.node] = Mark(mark)
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

            #TODO: also check git/ tree
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
                parents=(s for s in ('refs/cinnabar/hg2git^0',)
                         if self._refs_orig),
                mark=self._fast_import.new_mark(),
            ) as commit:
                for file in sorted(hg2git_files, key=lambda f: f[0]):
                    commit.filemodify(*file)
        del hg2git_files

        git2hg_marks = [mark for mark in self._changesets.itervalues()
                        if not isinstance(mark, types.StringType)]
        if git2hg_marks:
            with self._fast_import.commit(
                ref='refs/notes/cinnabar',
                parents=(s for s in ('refs/notes/cinnabar^0',)
                         if self._refs_orig),
            ) as commit:
                for mark in git2hg_marks:
                    data = self._changeset_data_cache[str(mark)]
                    commit.notemodify(mark, ChangesetData.dump(data))

        refs = {}
        modified = set()
        created = set()

        for branch, head in self._hgheads:
            ref = 'refs/cinnabar/branches/%s/%s' % (branch, head)
            refs[ref] = self._changesets[head]
            if ref in self._refs_orig:
                if self._refs_orig[ref] != refs[ref]:
                    modified.add(ref)
            else:
                created.add(ref)
        refs_set = set(r for r in refs)

        for ref in modified | created:
            Git.update_ref(ref, refs[ref])
        for ref in set(self._refs_orig) - refs_set:
            Git.delete_ref(ref)

        self._hg2git_cache.clear()

        def resolve_commit(c):
            if isinstance(c, Mark):
                c = self._hg2git('commit', changeset_by_mark[c])
            return c

        for c, f in self._tagcache.items():
            if f is not False:
                c = resolve_commit(c)
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

        if not self.__fast_import:
            self.init_fast_import(lambda: FastImport())

        for f, tags in self._tags.iteritems():
            if f not in self._tagfiles and f != NULL_NODE_ID:
                data = ''.join(tagset_lines(tags))
                mark = self._fast_import.new_mark()
                self._fast_import.put_blob(data=data, mark=mark)
                created[f] = (Mark(mark), 'exec')

        if created or deleted:
            self.tag_changes = True

        for c, f in self._tagcache.iteritems():
            if (f and not isinstance(c, Mark) and
                    c not in self._tagcache_items):
                if f == NULL_NODE_ID:
                    created[c] = (f, 'commit')
                else:
                    created[c] = (f, 'regular')
            elif f is False and c in self._tagcache_items:
                deleted.add(c)

        if created or deleted:
            with self._fast_import.commit(
                ref='refs/cinnabar/tagcache',
            ) as commit:
                if self._tagcache_ref:
                    mode, typ, tree, path = \
                        self._fast_import.ls(self._tagcache_ref)
                    commit.filemodify('', tree, typ='tree')
                for f in deleted:
                    commit.filedelete(f)

                for f, (sha1, typ) in created.iteritems():
                    commit.filemodify(f, sha1, typ)

        self._close_fast_import()
