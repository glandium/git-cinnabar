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
from collections import OrderedDict
from git.util import (
    IOLogger,
    LazyString,
    one,
    next,
)
from git import (
    EmptyMark,
    Git,
    Mark,
    split_ls_tree,
    sha1path,
)
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
handler.setFormatter(logging.Formatter('%(timestamp).3f %(name)s %(message)s'))
logger.addHandler(handler)
#logger.setLevel(logging.INFO)
#logger.setLevel(logging.DEBUG)

#from guppy import hpy
#hp = hpy()

NULL_NODE_ID = '0' * 40

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
            self.extra = {}
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
    FIELDS = ('changeset', 'manifest', 'author', 'extra', 'files')

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
                    yield k, '\0'.join(data[k])
                else:
                    yield k, data[k]
        return '\n'.join('%s %s' % s for s in serialize(data))

class GeneratedManifestInfo(GeneratedRevChunk, ManifestInfo):
    def __init__(self, node):
        super(GeneratedManifestInfo, self).__init__(node, '')
        self._lines = []

    def init(self, previous_chunk):
        pass

    def append(self, line):
        self._lines.append(line)

    @property
    def data(self):
        # Normally, it'd be better to use str(l), but it turns out to make
        # things significantly slower. Sigh python.
        return ''.join(l._str for l in self._lines)

    @data.setter
    def data(self, value):
        # GeneratedManifestInfo sets data and we want to ignore that.
        pass


class GitHgStore(object):
    def __init__(self):
        self.__fast_import = None
        self._changesets = {}
        self._manifests = {}
        self._files = {}
        self._git_files = {}
        self._closed = False

        self._last_manifest = None
        self._hg2git_cache = {}
        self._hg2git_cache_complete = False
        self._hg2git_calls = 0
        self._previously_stored = None
        self._thread = None

        self._changeset_data_cache = {}

        self.STORE = {
            ChangesetInfo: (self._store_changeset, self.changeset, self._changesets, 'commit'),
            ManifestInfo: (self._store_manifest, self.manifest, self._manifests, 'commit'),
            GeneratedManifestInfo: (self._store_manifest, lambda x: None, self._manifests, 'commit'),
            RevChunk: (self._store_file, self.file, self._files, 'blob'),
        }

        # TODO: handle the situation with multiple remote repos
        hgtip = Git.resolve_ref('refs/remote-hg/tip')
        self._hgtip_orig = None
        if hgtip:
            self._hgtip_orig = hgtip = self.hg_changeset(hgtip)

        self._hgheads = set()
        self._refs_orig = set()

        # refs/remote-hg/head-* are the old heads for upgrade
        # refs/remote-hg/branches/* are the new heads
        for line in Git.for_each_ref('refs/remote-hg/head-*',
                'refs/remote-hg/branches', format='%(objectname) %(refname)'):
            sha1, head = line.split()
            logging.info('%s %s' % (sha1, head))
            hghead = head[-40:]
            if head.startswith('refs/remote-hg/branches/'):
                branch = head.split('/')[3]
                self._hgheads.add((branch, hghead))
                self._changesets[hghead] = sha1
            else:
                self.add_head(hghead)
            self._refs_orig.add(head)

        self._hgtip = self._hgtip_orig
        assert (not self._hgtip or
            self._head_branch(self._hgtip) in self._hgheads)

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
            if (parent_head_branch[0] == head_branch[0] and
                    parent_head_branch in self._hgheads):
                self._hgheads.remove(parent_head_branch)

        self._hgheads.add(head_branch)
        self._hgtip = head

    @property
    def _fast_import(self):
        assert self.__fast_import
        return self.__fast_import

    def init_fast_import(self, fi):
        assert fi
        self.__fast_import = fi
        Git.register_fast_import(fi)
        fi.send_done()

    def _close_fast_import(self):
        if not self.__fast_import or callable(self.__fast_import):
            return
        self._fast_import.close()

    def read_changeset_data(self, obj):
        obj = str(obj)
        if obj in self._changeset_data_cache:
            return self._changeset_data_cache[obj]
        data = Git.read_note('refs/notes/remote-hg/git2hg', obj)
        if data is None:
            return None
        ret = self._changeset_data_cache[obj] = ChangesetData.parse(data)
        return ret

    def hg_changeset(self, sha1):
        return self.read_changeset_data(sha1)['changeset']

    def _hg2git_fill_cache(self):
        cache = {}
        logging.info('start cache')
        for mode, typ, filesha1, path in Git.ls_tree('refs/remote-hg/hg2git',
                                                     recursive=True):
            cache[path.replace('/','')] = (filesha1, intern(typ))
        logging.info('end cache')
        self._hg2git_cache = cache
        self._hg2git_cache_complete = True

    def _hg2git(self, expected_type, sha1):
        if not self._hgtip_orig:
            return None

        self._hg2git_calls += 1
        if self._hg2git_calls > 100 and not self._hg2git_cache_complete:
            if not self._thread:
                self._thread = threading.Thread(target=self._hg2git_fill_cache)
                self._thread.start()
        elif self._thread:
            logging.info(len(self._hg2git_cache))
            if self._thread.isAlive():
                self._thread.join()
            self._thread = None

        gitsha1, typ = self._hg2git_cache.get(sha1, (None, None))
        if not gitsha1 and not typ and not self._hg2git_cache_complete:
            ls = one(Git.ls_tree('refs/remote-hg/hg2git', sha1path(sha1)))
            if ls:
                mode, typ, gitsha1, path = ls
            else:
                typ, gitsha1 = 'missing', None
            self._hg2git_cache[sha1] = gitsha1, typ
        assert not gitsha1 or typ == expected_type
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
        commit = Git.cat_file('commit', gitsha1)
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
        ['\n', '\n'.join(metadata['files'])] if 'files' in metadata else [],
        ['\n\n'], message))

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

    def manifest(self, sha1, reference=None):
        assert not isinstance(sha1, Mark)
        gitsha1 = self._hg2git('commit', sha1)
        assert gitsha1
        attrs = {}
        manifest = GeneratedManifestInfo(sha1)
        # TODO: Improve this horrible mess
        if reference:
            removed = set()
            modified = {}
            created = OrderedDict()
            assert isinstance(reference, GeneratedManifestInfo)
            gitreference = self.manifest_ref(reference.node)
            for line in Git.diff_tree(gitreference, gitsha1, recursive=True):
                mode_before, mode_after, sha1_before, sha1_after, status, \
                    path = line
                if path.startswith('git/'):
                    if status != 'D':
                        attr = self.ATTR[mode_after]
                        attrs[path[4:]] = attr
                else:
                    assert path.startswith('hg/')
                    path = path[3:]
                    if status == 'D':
                        removed.add(path)
                    elif status == 'M':
                        modified[path] = (sha1_after, attrs.get(path))
                    else:
                        assert status == 'A'
                        created[path] = (sha1_after, attrs.get(path))
            for path, attr in attrs.iteritems():
                if not path in modified:
                    modified[path] = (None, attr)
            iter_created = created.iteritems()
            next_created = next(iter_created)
            for line in reference._lines:
                if line.name in removed:
                    continue
                mod = modified.get(line.name)
                if mod:
                    node, attr = mod
                    if attr is None:
                        attr = line.attr
                    if node is None:
                        node = line.node
                    line = ManifestLine(line.name, node, attr)
                while next_created and next_created[0] < line.name:
                    node, attr = next_created[1]
                    created_line = ManifestLine(next_created[0], node, attr)
                    manifest._lines.append(created_line)
                    next_created = next(iter_created)
                manifest._lines.append(line)
            while next_created:
                node, attr = next_created[1]
                created_line = ManifestLine(next_created[0], node, attr)
                manifest._lines.append(created_line)
                next_created = next(iter_created)
        else:
            for mode, typ, filesha1, path in Git.ls_tree(gitsha1,
                                                         recursive=True):
                if path.startswith('git/'):
                    attr = self.ATTR[mode]
                    if attr:
                        attrs[path[4:]] = attr
                else:
                    assert path.startswith('hg/')
                    path = path[3:]
                    line = ManifestLine(
                        name=path,
                        node=filesha1,
                        attr=attrs.get(path, ''),
                    )
                    manifest._lines.append(line)
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
        return GeneratedFileRev(sha1, self._fast_import.cat_blob(ref))

    def git_file_ref(self, sha1):
        if sha1 in self._git_files:
            return self._git_files[sha1]
        result = self.file_ref(sha1)
        if isinstance(result, Mark):
            return result
        # If the ref is not from the current import, it can be a raw hg file
        # ref, so check its content first.
        data = self._fast_import.cat_blob(result)
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
        if extra.get('committer'):
            committer = extra['committer']
            if committer[-1] == '>':
                committer = committer, author[1], author[2]
            else:
                committer = committer.rsplit(' ', 2)
                committer = self._git_committer(*committer)
                extra = dict(instance.extra)
                del extra['committer']
        else:
            committer = author
        with self._fast_import.commit(
            ref='refs/remote-hg/tip',
            message=instance.message,
            committer=committer,
            author=author,
            parents=parents,
            mark=mark,
        ) as commit:
            mode, typ, tree, path = self._fast_import.ls(self.manifest_ref(instance.manifest), 'git')
            commit.filemodify('', tree, typ='tree')

        mark = self._changesets[instance.node] = Mark(mark)
        data = self._changeset_data_cache[str(mark)] = {
            'changeset': instance.node,
            'manifest': instance.manifest,
        }
        if extra:
            data['extra'] = extra
        if instance.files:
            data['files'] = instance.files
        if author[0] != instance.committer:
            data['author'] = instance.committer
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
        elif self._hgtip:
            parents = (NULL_NODE_ID, 'refs/remote-hg/manifest^0',)
        else:
            parents = (NULL_NODE_ID,)
        with self._fast_import.commit(
            ref='refs/remote-hg/manifest',
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
        self._closed = True
        hg2git_files = []
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
                    hg2git_files.append((sha1path(node), mark, typ))
        if hg2git_files:
            with self._fast_import.commit(
                ref='refs/remote-hg/hg2git',
                parents=(s for s in ('refs/remote-hg/hg2git^0',)
                         if self._hgtip_orig)
            ) as commit:
                for file in sorted(hg2git_files, key=lambda f: f[0]):
                    commit.filemodify(*file)
        del hg2git_files

        git2hg_marks = [mark for mark in self._changesets.itervalues()
                        if not isinstance(mark, types.StringType)]
        if git2hg_marks:
            with self._fast_import.commit(
                ref='refs/notes/remote-hg/git2hg',
                parents=(s for s in ('refs/notes/remote-hg/git2hg^0',)
                         if self._hgtip_orig),
            ) as commit:
                for mark in git2hg_marks:
                    data = self._changeset_data_cache[str(mark)]
                    commit.notemodify(mark, ChangesetData.dump(data))

        refs = {}
        for branch, head in self._hgheads:
            ref = 'refs/remote-hg/branches/%s/%s' % (branch, head)
            refs[ref] = self._changesets[head]
        refs_set = set(r for r in refs)

        for ref in refs_set - self._refs_orig:
            Git.update_ref(ref, refs[ref])
        for ref in self._refs_orig - refs_set:
            Git.delete_ref(ref)

        assert self._head_branch(self._hgtip) in self._hgheads
        if self._hgtip != self._hgtip_orig:
            Git.update_ref('refs/remote-hg/tip', self._changesets[self._hgtip])

        self._close_fast_import()
        if self._thread:
            # TODO: kill the thread
            self._thread.join()
