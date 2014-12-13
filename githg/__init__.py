#!/usr/bin/env python2.7

from __future__ import division
import contextlib
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
    LazyString,
    one,
)
from git import (
    Git,
    split_ls_tree,
    sha1path,
)

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

RE_GIT_AUTHOR = re.compile('^(.*?) ?\<(.*?)(?:\>(.*))?$')

RE_GIT_SANITIZE_AUTHOR = re.compile('[<>\n]')

RE_GIT_AUTHOR_EXTRA = re.compile('^(.*?)\ ext:\((.*)\) <(.*)\>$')

def get_valid_git_username_email(name):
    r"""Sanitize usernames and emails to fit git's restrictions.

    The following is taken from the man page of git's fast-import
    command:

        [...] Likewise LF means one (and only one) linefeed [...]

        committer
            The committer command indicates who made this commit,
            and when they made it.

            Here <name> is the person's display name (for example
            "Com M Itter") and <email> is the person's email address
            ("cm@example.com[1]"). LT and GT are the literal
            less-than (\x3c) and greater-than (\x3e) symbols. These
            are required to delimit the email address from the other
            fields in the line. Note that <name> and <email> are
            free-form and may contain any sequence of bytes, except
            LT, GT and LF. <name> is typically UTF-8 encoded.

    Accordingly, this function makes sure that there are none of the
    characters <, >, or \n in any string which will be used for
    a git username or email. Before this, it first removes left
    angle brackets and spaces from the beginning, and right angle
    brackets and spaces from the end, of this string, to convert
    such things as " <john@doe.com> " to "john@doe.com" for
    convenience.

    TESTS:

    >>> from mercurial.ui import ui
    >>> g = GitHandler('', ui()).get_valid_git_username_email
    >>> g('John Doe')
    'John Doe'
    >>> g('john@doe.com')
    'john@doe.com'
    >>> g(' <john@doe.com> ')
    'john@doe.com'
    >>> g('    <random<\n<garbage\n>  > > ')
    'random???garbage?'
    >>> g('Typo in hgrc >but.hg-git@handles.it.gracefully>')
    'Typo in hgrc ?but.hg-git@handles.it.gracefully'
    """
    return RE_GIT_SANITIZE_AUTHOR.sub('?', name.lstrip('< ').rstrip('> '))

def get_git_author(author):
    # check for git author pattern compliance
    a = RE_GIT_AUTHOR.match(author)

    if a:
        name = get_valid_git_username_email(a.group(1))
        email = get_valid_git_username_email(a.group(2))
        if a.group(3) != None and len(a.group(3)) != 0:
            name += ' ext:(' + urllib.quote(a.group(3)) + ')'
        author = get_valid_git_username_email(name) + ' <' + get_valid_git_username_email(email) + '>'
    elif '@' in author:
        author = get_valid_git_username_email(author) + ' <' + get_valid_git_username_email(author) + '>'
    else:
        author = get_valid_git_username_email(author) + ' <none@none>'

#    if 'author' in ctx.extra():
#        author = "".join(apply_delta(author, ctx.extra()['author']))
    return author

def get_hg_author(author):
    if ' ext:' in author:
        m = RE_GIT_AUTHOR_EXTRA.match(author)
        if m:
            name = m.group(1)
            ex = urllib.unquote(m.group(2))
            email = m.group(3)
            return name + ' <' + email + '>' + ex

    if ' <none@none>' in author:
        return author[:-12]

    a = RE_GIT_AUTHOR.match(author)
    name = a.group(1)
    email = a.group(2)
    if name == email:
        return email
    return author

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

class GeneratedRevChunk(RevChunk):
    def __init__(self, node, data):
        self.node = node
        self.data = data

    def set_parents(self, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        self.parent1 = parent1
        self.parent2 = parent2

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
        lines = self.data.splitlines()
        self.manifest, self.committer, date = lines[:3]
        date = date.split(' ', 2)
        self.date = int(date[0])
        self.utcoffset = int(date[1])
        if len(date) == 3:
            self.extra = date[2]
        else:
            self.extra = ''
        for idx in xrange(3, len(lines) + 1):
            if not lines[idx]:
                break
        self.files = lines[3:idx]
        self.message = '\n'.join(lines[idx + 1:])


class ManifestLine(object):
    def __init__(self, name, node, attr):
        self.name = name
        self.node = node
        self.attr = attr
        assert len(self.node) == 40

    def __str__(self):
        return '%s\0%s%s\n' % (self.name, self.node, self.attr)

    def __len__(self):
        return len(self.name) + len(self.attr) + 41


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


class IOLogger(object):
    def __init__(self, logger, reader, writer=None):
        self._reader = reader
        self._writer = writer or reader
        self._logger = logger

    def read(self, length=0, level=logging.INFO):
        ret = self._reader.read(length)
        self._logger.log(level, LazyString(lambda: '<= %s' % repr(ret)))
        return ret

    def readline(self, level=logging.INFO):
        ret = self._reader.readline()
        self._logger.log(level, LazyString(lambda: '<= %s' % repr(ret)))
        return ret

    def write(self, data, level=logging.INFO):
        self._logger.log(level, LazyString(lambda: '=> %s' % repr(data)))
        return self._writer.write(data)

    def flush(self):
        self._writer.flush()


class FastImport(IOLogger):
    def __init__(self, reader, writer):
        super(FastImport, self).__init__(logging.getLogger('fast-import'),
            reader, writer)
        self._last_mark = 0
#        reader, writer = os.pipe()
#        self._reader = os.fdopen(reader)
#        self._proc = subprocess.Popen(['git', 'fast-import',
#            '--cat-blob-fd=%d' % writer], stdin=subprocess.PIPE)
#        self._writer = self._proc.stdin

        self.write(
            "feature force\n"
            "feature ls\n"
            "feature done\n"
            "feature notes\n"
        )

    def progress_iter(self, what, iter, step=1000):
        count = 0
        for count, item in enumerate(iter, start=1):
            if count % step == 0:
                self.write('progress %d %s\n' % (count, what))
#                print hp.heap()
            yield item
        if count % step:
            self.write('progress %d %s\n' % (count, what))

    def read(self, length=0, level=logging.INFO):
        self.flush()
        return super(FastImport, self).read(length, level)

    def readline(self, level=logging.INFO):
        self.flush()
        return super(FastImport, self).readline(level)

    def close(self):
        self.write('done\n')
        self.flush()
#        self._proc.wait()

    def ls(self, dataref, path=''):
        assert not path.endswith('/')
        assert dataref and not isinstance(dataref, EmptyMark)
        self.write('ls %s %s\n' % (dataref, path))
        line = self.readline()
        if line.startswith('missing '):
            return None, None, None, None
        return split_ls_tree(line[:-1])

    def cat_blob(self, dataref):
        assert dataref and not isinstance(dataref, EmptyMark)
        self.write('cat-blob %s\n' % dataref)
        sha1, blob, size = self.readline().split()
        assert blob == 'blob'
        size = int(size)
        content = self.read(size, level=logging.DEBUG)
        lf = self.read(1)
        assert lf == '\n'
        return content

    def new_mark(self):
        self._last_mark += 1
        return EmptyMark(self._last_mark)

    def cmd_mark(self, mark):
        if mark:
            self.write('mark :%d\n' % mark)

    def cmd_data(self, data):
        self.write('data %d\n' % len(data))
        self.write(data, level=logging.DEBUG)
        self.write('\n')

    def put_blob(self, data='', mark=0):
        self.write('blob\n')
        self.cmd_mark(mark)
        self.cmd_data(data)

    @contextlib.contextmanager
    def commit(self, ref, committer='<remote-hg@git>', date=(0, 0), message='',
            parents=(), mark=0):
        helper = FastImportCommitHelper(self)
        yield helper

        self.write('commit %s\n' % ref)
        self.cmd_mark(mark)
        epoch, utcoffset = date
        # TODO: properly handle errors, like from the committer being badly
        # formatted.
        self.write('committer %s %d %s%02d%02d\n' % (
            committer,
            epoch,
            '+' if utcoffset >= 0 else '-',
            abs(utcoffset) // 60,
            abs(utcoffset) % 60,
        ))
        self.cmd_data(message)
        for count, parent in enumerate(parents):
            self.write('%s %s\n' % (
                'from' if count == 0 else 'merge',
                parent,
            ))
        helper.apply()
        self.write('\n')

class FastImportCommitHelper(object):
    def __init__(self, fast_import):
        self._fast_import = fast_import
        self._command_queue = []

    def write(self, data):
        self._command_queue.append((self._fast_import.write, data))

    def cmd_data(self, data):
        self._command_queue.append((self._fast_import.cmd_data, data))

    def filedelete(self, path):
        self.write('D %s\n' % path)

    MODE = {
        'regular': '644',
        'exec': '755',
        'tree': '040000',
        'symlink': '120000',
        'commit': '160000',
    }

    def filemodify(self, path, sha1, typ='regular'):
        assert sha1 and not isinstance(sha1, EmptyMark)
        self.write('M %s %s %s\n' % (
            self.MODE[typ],
            sha1,
            path,
        ))

    def notemodify(self, commitish, note):
        self.write('N inline %s\n' % commitish)
        self.cmd_data(note)

    def apply(self):
        for fn, arg in self._command_queue:
            fn(arg)


class ChangesetData(object):
    FIELDS = ('changeset', 'manifest', 'extra', 'files')

    @staticmethod
    def parse(s):
        if isinstance(s, types.StringType):
            s = s.splitlines()
        return { k: v for k, v in (l.split(' ', 1) for l in s) }

    @staticmethod
    def dump(data):
        return '\n'.join('%s %s' % (k, data[k]) for k in ChangesetData.FIELDS
            if k in data)


class Mark(int):
    def __str__(self):
        return ':%d' % self

class EmptyMark(Mark):
    pass

class GitHgStore(object):
    def __init__(self):
        self.__fast_import = None
        self._changesets = {}
        self._changeset_metadata = {}
        self._manifests = {}
        self._manifests_by_changeset = {}
        self._files = {}
        self._git_files = {}

        self._changeset_data_cache = {}

        self.STORE = {
            ChangesetInfo: (self._store_changeset, self.changeset, self._changesets, 'commit'),
            ManifestInfo: (self._store_manifest, self.manifest, self._manifests, 'commit'),
            RevChunk: (self._store_file, self.file, self._files, 'blob'),
        }

        # TODO: only do one git_for_each_ref
        self._hgheads_orig = set()
        for line in Git.for_each_ref('refs/remote-hg/head-*',
                format='%(objectname) %(refname)'):
            sha1, head = line.split()
            logging.info('%s %s' % (sha1, head))
            hghead = head[-40:]
            self._hgheads_orig.add(hghead)
            self._changesets[hghead] = sha1
        self._hgheads = set(self._hgheads_orig)

        self._hg2git_tree = None
        sha1 = one(Git.for_each_ref('refs/remote-hg/hg2git'))
        if sha1:
            #TODO: cat-file commit?
            self._hg2git_tree = one(Git.iter('log', '-1', '--format=%T',
                'refs/remote-hg/hg2git'))
        # TODO: handle the situation with multiple remote repos
        hgtip = one(Git.for_each_ref('refs/remote-hg/tip'))
        if hgtip:
            hgtip = self.hg_changeset(hgtip)
        self._hgtip = hgtip
        assert not self._hgtip or self._hgtip in self._hgheads

        self._last_manifest = None
        self._hg2git_cache = {}
        self._hg2git_cache_complete = False
        self._hg2git_calls = 0
        self._previously_stored = None
        self._thread = None

    @property
    def _fast_import(self):
        assert self.__fast_import
        return self.__fast_import

    def init_fast_import(self, fi):
        assert fi
        self.__fast_import = fi

    def read_changeset_data(self, obj):
        if obj in self._changeset_data_cache:
            return self._changeset_data_cache[obj]
        data = Git.read_note('refs/notes/remote-hg/git2hg', obj)
        ret = self._changeset_data_cache[obj] = ChangesetData.parse(data)
        return ret

    def hg_changeset(self, sha1):
        return self.read_changeset_data(sha1)['changeset']

    def _hg2git_fill_cache(self):
        cache = {}
        logging.info('start cache')
        for mode, typ, filesha1, path in Git.ls_tree(self._hg2git_tree,
                                                     recursive=True):
            cache[path.replace('/','')] = (filesha1, intern(typ))
        logging.info('end cache')
        self._hg2git_cache = cache
        self._hg2git_cache_complete = True

    def _hg2git(self, expected_type, sha1):
        if not self._hg2git_tree:
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
            if self.__fast_import:
                mode, typ, gitsha1, path = self._fast_import.ls(
                    self._hg2git_tree, sha1path(sha1))
            else:
                ls = one(Git.ls_tree(self._hg2git_tree, sha1path(sha1)))
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

    def changeset(self, sha1, include_parents=False):
        assert not isinstance(sha1, Mark)
        gitsha1 = self._hg2git('commit', sha1)
        assert gitsha1
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
        author, date, utcoffset = commitdata['author'].rsplit(' ', 2)
        utcoffset = int(utcoffset)
        utcoffset = (utcoffset // 100) * 60 + (utcoffset % 100)

        changeset = ''.join(chain([
            metadata['manifest'], '\n',
            get_hg_author(author), '\n',
            date, ' ', str(-utcoffset * 60)
        ],
        [' ', metadata['extra']] if 'extra' in metadata else [],
        ['\n', metadata['files'].replace('\0', '\n')] if 'files' in metadata else [],
        ['\n\n'], message))

        hgdata = GeneratedRevChunk(sha1, changeset)
        if include_parents:
            assert len(parents) <= 2
            hgdata.set_parents(*[
                self.read_changeset_data(p)['changeset'] for p in parents])
        return hgdata

    ATTR = {
        '100644': '',
        '100755': 'x',
        '120000': 'l',
    }

    def manifest(self, sha1):
        assert not isinstance(sha1, Mark)
        gitsha1 = self._hg2git('commit', sha1)
        assert gitsha1
        attrs = {}
        manifest = ''
        for mode, typ, filesha1, path in Git.ls_tree(gitsha1, recursive=True):
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
                manifest += str(line)
        return GeneratedRevChunk(sha1, manifest)

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
        return GeneratedRevChunk(sha1, self._fast_import.cat_blob(ref))

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
            return self._prepare_git_file(GeneratedRevChunk(sha1, data))
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

    def _git_date(self, changeset):
        return changeset.date, -changeset.utcoffset // 60

    def _git_committer(self, committer):
        return get_git_author(committer)

    def _store_changeset(self, instance, mark):
        parents = [NULL_NODE_ID]
        parents += [
            self.changeset_ref(p)
            for p in (instance.parent1, instance.parent2)
            if p != NULL_NODE_ID
        ]
        with self._fast_import.commit(
            ref='refs/remote-hg/tip',
            date=self._git_date(instance),
            message=instance.message,
            committer=self._git_committer(instance.committer),
            parents=parents,
            mark=mark,
        ) as commit:
            mode, typ, tree, path = self._fast_import.ls(self.manifest_ref(instance.manifest), 'git')
            commit.filemodify('', tree, typ='tree')

        self._changesets[instance.node] = Mark(mark)
        self._manifests_by_changeset[instance.node] = instance.manifest
        if instance.parent1 in self._hgheads:
            self._hgheads.remove(instance.parent1)
        if instance.parent2 in self._hgheads:
            self._hgheads.remove(instance.parent2)
        self._hgheads.add(instance.node)
        self._changeset_metadata[instance.node] = (
            instance.extra,
            [intern(f) for f in instance.files],
        )

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
        with self._fast_import.commit(
            ref='refs/remote-hg/hg2git',
        ) as commit:
            if self._hg2git_tree:
                commit.filemodify('', self._hg2git_tree, typ='tree')
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
                    commit.filemodify(sha1path(node), mark, typ=typ)

        sha1 = one(Git.for_each_ref('refs/notes/remote-hg/git2hg'))
        git2hg_mark = self._fast_import.new_mark()
        with self._fast_import.commit(
            ref='refs/notes/remote-hg/git2hg',
            parents=(s for s in (sha1,) if s),
            mark=git2hg_mark,
        ) as commit:
            for node, mark in self._changesets.iteritems():
                if isinstance(mark, types.StringType):
                    continue
                data = {
                    'changeset': node,
                    'manifest': self._manifests_by_changeset[node],
                }
                extra, files = self._changeset_metadata[node]
                if extra:
                    data['extra'] = extra
                if files:
                    data['files'] = '\0'.join(files)
                commit.notemodify(mark, ChangesetData.dump(data))
        if sha1:
            with self._fast_import.commit(ref='refs/notes/remote-hg/git2hg') as commit:
                commit.filemodify('',
                    self._fast_import.ls(Mark(git2hg_mark))[2],
                        typ='tree')

        # TODO: avoid rewriting existing heads
        for head in self._hgheads:
            self._fast_import.write(
                'reset refs/remote-hg/head-%s\n'
                'from %s\n'
                % (head, self._changesets[head])
            )
        for head in self._hgheads_orig - self._hgheads:
            self._fast_import.write(
                'reset refs/remote-hg/head-%s\n'
                'from %s\n'
                % (head, NULL_NODE_ID)
            )
        self._fast_import.close()
        if self._thread:
            # TODO: kill the thread
            self._thread.join()
