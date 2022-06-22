from binascii import hexlify, unhexlify
import io
import os
import shutil
import subprocess
import sys
from urllib.parse import quote_from_bytes, unquote_to_bytes
from collections import (
    OrderedDict,
    defaultdict,
)
from collections.abc import Sequence
from urllib.error import URLError
from urllib.parse import urlparse
from cinnabar.exceptions import (
    Abort,
    AmbiguousGraftAbort,
    NothingToGraftException,
)
from cinnabar.util import (
    HTTPReader,
    Seekable,
    byte_diff,
    one,
    VersionedDict,
)
from cinnabar.git import (
    EMPTY_BLOB,
    EMPTY_TREE,
    Git,
    GitProcess,
    NULL_NODE_ID,
)
from cinnabar.hg.changegroup import (
    RawRevChunk,
    RevDiff,
)
from cinnabar.hg.objects import (
    Authorship,
    Changeset,
    File,
    Manifest,
)
from cinnabar.helper import GitHgHelper
from cinnabar.util import progress_iter
from cinnabar import util

import logging


# An empty mercurial file with no parent has a fixed sha1 which is that of
# "\0" * 40 (incidentally, this is the same as for an empty manifest with
# no parent.
HG_EMPTY_FILE = b'b80de5d138758541c5f05265ad144ab9fa86d1db'


revchunk_log = logging.getLogger('revchunks')


class FileFindParents(object):
    logger = logging.getLogger('generated_file')

    @staticmethod
    def _invalid_if_new(file):
        if file.node == NULL_NODE_ID:
            raise Exception('Trying to create an invalid file. '
                            'Please open an issue with details.')

    @staticmethod
    def set_parents(file, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        # Remove null nodes
        parents = tuple(p for p in (parent1, parent2) if p != NULL_NODE_ID)
        orig_parents = parents

        # On merges, a file with copy metadata has either no parent, or only
        # one. In that latter case, the parent is always set as second parent.
        # On non-merges, a file with copy metadata doesn't have a parent.
        if file.metadata or file.content.startswith(b'\1\n'):
            if len(parents) == 2:
                FileFindParents._invalid_if_new(file)
            elif len(parents) == 1:
                parents = (NULL_NODE_ID, parents[0])
        elif len(parents) == 2:
            if parents[0] == parents[1]:
                parents = parents[:1]

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


class ChangesetPatcher(bytes):
    class ChangesetPatch(RawRevChunk):
        __slots__ = ('patch', '_changeset')

        class Patch(RevDiff):
            class Part(object):
                __slots__ = ('start', 'end', 'text_data')

            def __init__(self, buf):
                self._buf = buf

            def __str__(self):
                raise RuntimeError('Use to_str()')

            def to_str(self):
                return self._buf

            def __iter__(self):
                for line in self._buf.split(b'\0'):
                    if line:
                        part = self.Part()
                        start, end, text_data = line.split(b',')
                        part.start = int(start)
                        part.end = int(end)
                        part.text_data = unquote_to_bytes(text_data)
                        yield part

            @classmethod
            def from_items(cls, items):
                return cls(b'\0'.join(
                    b','.join((b'%d,%d' % (start, end),
                               quote_from_bytes(text_data).encode('ascii')))
                    for start, end, text_data in items))

        def __init__(self, changeset, patch_data):
            self._changeset = changeset
            self.patch = self.Patch(patch_data)

        def __getattr__(self, name):
            if name == 'delta_node':
                name = 'node'
            return getattr(self._changeset, name)

    def apply(self, changeset):
        # Sneaky way to create a copy of the changeset
        chunk = self.ChangesetPatch(changeset, b'')
        changeset = Changeset.from_chunk(chunk, changeset)

        for k, v in (l.split(b' ', 1) for l in self.splitlines()):
            if k == b'changeset':
                changeset.node = v
            elif k == b'manifest':
                changeset.manifest = v
            elif k == b'author':
                changeset.author = v
            elif k == b'extra':
                extra = changeset.extra
                changeset.extra = v
                if extra is not None:
                    changeset.extra.update(
                        (k, v) for k, v in extra.items()
                        if k not in changeset.extra)
            elif k == b'files':
                changeset.files = v.split(b'\0')
            elif k == b'patch':
                chunk = self.ChangesetPatch(changeset, v)
                changeset = Changeset.from_chunk(chunk, changeset)

        # This should not occur in normal changeset bodies. If it occurs,
        # it likely comes from our handling of conflicting commits.
        # So in that case, adjust until we have the right sha1.
        while changeset.body.endswith(b'\0') and \
                changeset.sha1 != changeset.node:
            changeset.body = changeset.body[:-1]

        return changeset

    @classmethod
    def from_diff(cls, changeset1, changeset2):
        items = []
        if changeset1.node != changeset2.node:
            items.append(b'changeset %s' % changeset2.node)
        if changeset1.manifest != changeset2.manifest:
            items.append(b'manifest %s' % changeset2.manifest)
        if changeset1.author != changeset2.author:
            items.append(b'author %s' % changeset2.author)
        if changeset1.extra != changeset2.extra:
            if changeset2.extra is not None:
                items.append(b'extra %s' % Changeset.ExtraData({
                    k: v
                    for k, v in changeset2.extra.items()
                    if not changeset1.extra or changeset1.extra.get(k) != v
                }).to_str())
        if changeset1.files != changeset2.files:
            items.append(b'files %s' % b'\0'.join(changeset2.files))

        this = cls(b'\n'.join(items))
        new = this.apply(changeset1)
        if new.raw_data != changeset2.raw_data:
            items.append(b'patch %s' % cls.ChangesetPatch.Patch.from_items(
                byte_diff(new.raw_data, changeset2.raw_data)).to_str())
            this = cls(b'\n'.join(items))

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


class GeneratedManifestInfo(Manifest):
    __slots__ = ('delta_node', 'removed', 'modified')

    def __init__(self, node):
        super(GeneratedManifestInfo, self).__init__(node)
        self.removed = set()
        self.modified = {}

    def add(self, path, sha1=None, attr=b'', modified=False):
        super(GeneratedManifestInfo, self).add(path, sha1, attr)
        if modified:
            self.modified[path] = (sha1, attr)


class TagSet(object):
    def __init__(self):
        self._tags = OrderedDict()
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
        for key, anode in other._tags.items():
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
        return iter(self._tags.items())

    def hist(self, key):
        return iter(sorted(self._taghist[key]))


class GitCommit(object):
    __slots__ = ('sha1', 'body', 'parents', 'tree', 'author', 'committer')

    def __init__(self, sha1):
        self.sha1 = sha1
        commit = GitHgHelper.cat_file(b'commit', sha1)
        header, self.body = commit.split(b'\n\n', 1)
        parents = []
        for line in header.splitlines():
            if line == b'\n':
                break
            typ, data = line.split(b' ', 1)
            typ = typ.decode('ascii')
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
        for branch, heads in remote_branchmap.items():
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
            # Use last non-closed head as tip if there's more than one head.
            # Caveat: we don't know a head is closed until we've pulled it.
            if branch and heads and sequenced:
                for head in reversed(branch_heads):
                    self._tips[branch] = head
                    if head in self._git_sha1s:
                        changeset = store.changeset(head)
                        if changeset.close:
                            continue
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
        return self._git_sha1s.get(head, b'?')

    def tip(self, branch):
        return self._tips.get(branch, None)


class GitHgStore(object):
    FLAGS = [
        b'files-meta',
        b'unified-manifests-v2',
    ]

    METADATA_REFS = (
        b'refs/cinnabar/changesets',
        b'refs/cinnabar/manifests',
        b'refs/cinnabar/hg2git',
        b'refs/notes/cinnabar',
        b'refs/cinnabar/files-meta',
    )

    def metadata(self):
        if self._metadata_sha1:
            metadata = GitCommit(self._metadata_sha1)
            self._flags = set(metadata.body.split())
            refs = self.METADATA_REFS
            if b'files-meta' not in self._flags:
                refs = list(refs)
                refs.remove(b'refs/cinnabar/files-meta')
            return metadata, dict(zip(refs, metadata.parents))

    def __init__(self):
        self._flags = set()
        self._closed = False
        self._graft = False

        self._hgheads_orig = {}

        self._replace = Git._replace
        self._metadata_sha1 = None
        broken = None
        # While doing a for_each_ref, ensure refs/notes/cinnabar is in the
        # cache.
        for sha1, ref in Git.for_each_ref('refs/cinnabar',
                                          'refs/notes/cinnabar'):
            if ref.startswith(b'refs/cinnabar/replace/'):
                # Ignore replace refs, we'll fill from the metadata tree.
                pass
            elif ref == b'refs/cinnabar/metadata':
                self._metadata_sha1 = sha1
            elif ref == b'refs/cinnabar/broken':
                broken = sha1
        self._broken = broken and self._metadata_sha1 and \
            broken == self._metadata_sha1

        self._cached_changeset_ref = {}

        metadata = self.metadata()
        if metadata:
            metadata, refs = metadata
        self._has_metadata = bool(metadata)
        self._metadata_refs = refs if metadata else {}
        self._manifest_heads_orig = set()
        if metadata:
            self._hgheads_orig = dict(GitHgHelper.heads(b'changesets'))
            self._manifest_heads_orig = set(GitHgHelper.heads(b'manifests'))

            for line in Git.ls_tree(metadata.tree):
                mode, typ, sha1, path = line
                self._replace[path] = sha1

            # Delete old tag-cache, which may contain incomplete data.
            Git.delete_ref(b'refs/cinnabar/tag-cache')
            # Delete new-type tag_cache, we don't use it anymore.
            Git.delete_ref(b'refs/cinnabar/tag_cache')

        self._tags = dict(self.tags())

        self._replace = VersionedDict(self._replace)

    @property
    def tag_changes(self):
        return dict(self.tags()) != self._tags

    def prepare_graft(self):
        with GitHgHelper.query(b'graft', b'init'):
            pass
        self._graft = True

    @staticmethod
    def _try_merge_branches(repo_url):
        parsed_url = urlparse(repo_url)
        branches = []
        path = parsed_url.path.lstrip(b'/').rstrip(b'/')
        if path:
            parts = list(reversed(path.split(b'/')))
        else:
            parts = []
        host = parsed_url.netloc.split(b':', 1)[0]
        if host:
            parts.append(host)
        last_path = b''
        for part in parts:
            if last_path:
                last_path = b'%s/%s' % (part, last_path)
            else:
                last_path = part
            branches.append(last_path)
        branches.append(b'metadata')
        return branches

    @staticmethod
    def _find_branch(branches, remote_refs):
        for branch in branches:
            if branch in remote_refs:
                return branch
            if b'refs/cinnabar/%s' % branch in remote_refs:
                return b'refs/cinnabar/%s' % branch
            if b'refs/heads/%s' % branch in remote_refs:
                return b'refs/heads/%s' % branch

    def merge(self, git_repo_url, hg_repo_url, branch=None):
        # Eventually we'll want to handle a full merge, but for now, we only
        # handle the case where we don't have metadata to begin with.
        # The caller should avoid calling this function otherwise.
        assert not self._has_metadata
        remote_refs = OrderedDict()
        for line in Git.iter('ls-remote', os.fsdecode(git_repo_url),
                             stderr=open(os.devnull, 'wb')):
            sha1, ref = line.split(None, 1)
            remote_refs[ref] = sha1
        bundle = None
        if not remote_refs and urlparse(git_repo_url).scheme in (b'http',
                                                                 b'https'):
            try:
                bundle = HTTPReader(git_repo_url)
            except URLError as e:
                logging.error(e.reason)
                return False
            if bundle.fh.headers.get('Content-Encoding', 'identity') == 'gzip':
                from gzip import GzipFile
                bundle = Seekable(bundle, bundle.length)
                bundle = GzipFile(mode='rb', fileobj=bundle)
            BUNDLE_SIGNATURE = b'# v2 git bundle\n'
            signature = bundle.read(len(BUNDLE_SIGNATURE))
            if signature != BUNDLE_SIGNATURE:
                logging.error('Could not find cinnabar metadata')
                return False
            bundle = io.BufferedReader(bundle)
            while True:
                line = bundle.readline().rstrip()
                if not line:
                    break
                sha1, ref = line.split(b' ', 1)
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
            args = ('-v',) if util.progress else ()
            proc = GitProcess('index-pack', '--stdin', '--fix-thin', *args,
                              stdin=subprocess.PIPE,
                              stdout=open(os.devnull, 'wb'))
            shutil.copyfileobj(bundle, proc.stdin)
        else:
            fetch = ['fetch', '--no-tags', '--no-recurse-submodules', '-q']
            fetch.append('--progress' if util.progress else '--no-progress')
            fetch.append(os.fsdecode(git_repo_url))
            cmd = fetch + [os.fsdecode(ref) + ':refs/cinnabar/fetch']
            proc = GitProcess(*cmd, stdout=sys.stdout)
        if proc.wait():
            logging.error('Failed to fetch cinnabar metadata.')
            return False

        # Do some basic validation on the metadata we just got.
        commit = GitCommit(remote_refs[ref])
        if b'cinnabar@git' not in commit.author:
            logging.error('Invalid cinnabar metadata.')
            return False

        flags = set(commit.body.split())
        if b'files-meta' not in flags or b'unified-manifests-v2' not in flags \
                or len(commit.parents) != len(self.METADATA_REFS):
            logging.error('Invalid cinnabar metadata.')
            return False

        # At this point, we'll just assume this is good enough.

        # Get replace refs.
        if commit.tree != EMPTY_TREE:
            errors = False
            by_sha1 = {}
            for k, v in remote_refs.items():
                if v not in by_sha1:
                    by_sha1[v] = k
            needed = []
            for line in Git.ls_tree(commit.tree):
                mode, typ, sha1, path = line
                if sha1 in by_sha1:
                    ref = b'refs/cinnabar/replace/%s' % path
                    if bundle:
                        Git.update_ref(ref, sha1)
                    else:
                        needed.append(
                            os.fsdecode(b':'.join((by_sha1[sha1], ref))))
                else:
                    logging.error('Missing commit: %s', sha1)
                    errors = True
            if errors:
                return False

            if not bundle:
                cmd = fetch + needed
                proc = GitProcess(*cmd, stdout=sys.stdout)
                if proc.wait():
                    logging.error('Failed to fetch cinnabar metadata.')
                    return False

        Git.update_ref(b'refs/cinnabar/metadata', commit.sha1)
        self._metadata_sha1 = commit.sha1
        GitHgHelper.reload()
        Git.delete_ref(b'refs/cinnabar/fetch')

        # TODO: avoid the duplication of code with __init__
        metadata = self.metadata()

        if not metadata:
            # This should never happen, but just in case.
            logging.warn('Could not find cinnabar metadata')
            Git.delete_ref(b'refs/cinnabar/metadata')
            GitHgHelper.reload()
            return False

        metadata, refs = metadata
        self._has_metadata = True
        self._metadata_refs = refs if metadata else {}
        self._hgheads_orig = dict(GitHgHelper.heads(b'changesets'))
        self._manifest_heads_orig = set(GitHgHelper.heads(b'manifests'))

        for line in Git.ls_tree(metadata.tree):
            mode, typ, sha1, path = line
            self._replace[path] = sha1

        self._tags = dict(self.tags())

        return True

    def tags(self):
        tags = TagSet()
        if self._has_metadata:
            for (h, _) in GitHgHelper.heads(b'changesets'):
                h = self.changeset_ref(h)
                tags.update(self._get_hgtags(h))
        for tag, node in tags:
            if node != NULL_NODE_ID:
                yield tag, node

    def _get_hgtags(self, head):
        tags = TagSet()
        ls = one(Git.ls_tree(head, b'.hgtags'))
        if not ls:
            return tags
        mode, typ, tagfile, path = ls
        data = GitHgHelper.cat_file(b'blob', tagfile) or b''
        for line in data.splitlines():
            if not line:
                continue
            try:
                node, tag = line.split(b' ', 1)
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
        return tags

    def heads(self, branches={}):
        if not isinstance(branches, (dict, set)):
            branches = set(branches)
        return set(h for (h, b) in GitHgHelper.heads(b'changesets')
                   if not branches or b in branches)

    def read_changeset_data(self, obj):
        assert obj is not None
        obj = bytes(obj)
        data = GitHgHelper.git2hg(obj)
        if data is None:
            return None
        ret = ChangesetPatcher(data)
        return ret

    def hg_changeset(self, sha1):
        data = self.read_changeset_data(sha1)
        if data:
            assert data.startswith(b'changeset ')
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
        b'100644': b'',
        b'100755': b'x',
        b'120000': b'l',
    }

    @staticmethod
    def manifest_metadata_path(path):
        return b'_' + path.replace(b'/', b'/_')

    @staticmethod
    def manifest_path(path):
        return path[1:].replace(b'/_', b'/')

    def manifest(self, sha1, include_parents=False):
        manifest = GeneratedManifestInfo(sha1)
        manifest.raw_data = GitHgHelper.manifest(sha1)
        if include_parents:
            git_sha1 = self.manifest_ref(sha1)
            commit = GitCommit(git_sha1)
            parents = (self.hg_manifest(p) for p in commit.parents)
            manifest.parents = tuple(parents)
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

    def file(self, sha1, file_parents=None):
        if sha1 == HG_EMPTY_FILE:
            content = b''
        else:
            gitsha1 = GitHgHelper.hg2git(sha1)
            content = GitHgHelper.cat_file(b'blob', gitsha1)

        file = File(sha1)
        meta = self.file_meta(sha1)
        if meta:
            file.metadata = meta
        file.content = content
        if file_parents is not None:
            FileFindParents.set_parents(file, *file_parents)
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

    def store_changeset(self, instance):
        parents = tuple(self.changeset_ref(p) for p in instance.parents)
        if None in parents:
            raise NothingToGraftException()

        args = [instance.node]
        args.extend(instance.parents)
        raw_data = instance.raw_data
        args.append(str(len(raw_data)).encode('ascii'))
        with GitHgHelper.query(b'store-changeset', *args) as stdout:
            stdout.write(raw_data)
            stdout.flush()
            response = stdout.readline().strip().split()
            assert len(response) > 0

            if response[0] == b"ambiguous":
                raise AmbiguousGraftAbort(
                    'Cannot graft changeset %s. Candidates: %s'
                    % (instance.node.decode('ascii'),
                       ', '.join(n.decode('ascii')
                                 for n in sorted(response[1:]))))

            assert len(response) <= 2
            if len(response) == 2:
                self._replace[response[1]] = response[0]

    MODE = {
        b'': b'160644',
        b'l': b'160000',
        b'x': b'160755',
    }

    def close(self, refresh=()):
        if self._closed:
            return
        if self._graft:
            with GitHgHelper.query(b'graft', b'finish') as stdout:
                res = stdout.readline().strip()
                assert res in (b'ok', b'ko')
                if res == b'ko':
                    raise NothingToGraftException()
        self._closed = True
        # If the helper is not running, we don't have anything to update.
        if not GitHgHelper._helper:
            return

        bundle_blob = getattr(self, "bundle_blob", None)

        self._metadata_sha1 = GitHgHelper.store(
            b'metadata', *[bundle_blob] if bundle_blob else [])
        Git.update_ref(b'refs/cinnabar/metadata', self._metadata_sha1)
        Git.update_ref(b'refs/notes/cinnabar',
                       GitCommit(self._metadata_sha1).parents[3])

        if b'refs/cinnabar/checked' in refresh:
            Git.update_ref(b'refs/cinnabar/checked', self._metadata_sha1)

        for status, ref, sha1 in self._replace.iterchanges():
            if status == VersionedDict.REMOVED:
                Git.delete_ref(b'refs/cinnabar/replace/%s' % ref)
            else:
                Git.update_ref(b'refs/cinnabar/replace/%s' % ref, sha1)

        # refs/notes/cinnabar is kept for convenience
        for ref in self.METADATA_REFS:
            if ref not in (b'refs/notes/cinnabar',):
                Git.delete_ref(ref)

        GitHgHelper.close(rollback=False)

        # Try to detect issue #207 as early as possible.
        GitHgHelper._helper = False
        busted = False
        from .hg.repo import getbundle_params, stored_files
        for (node, (parent1, parent2)) in progress_iter(
                "Checking {} imported file root and head revisions",
                stored_files.items()):
            if not GitHgHelper.check_file(node, parent1, parent2):
                busted = True
                logging.error(
                    "Error in file %s" % node.decode('ascii', 'replace'))
        if busted:
            import json
            extra = ""
            if getbundle_params:
                extra = \
                    "If it failed, please also copy/paste the following:\n"
                extra += json.dumps(getbundle_params, sort_keys=True, indent=4)
            Git.update_ref(b'refs/cinnabar/broken', self._metadata_sha1)
            raise Abort(
                "It seems you have hit a known, rare, and difficult to "
                "reproduce issue.\n"
                "Your help would be appreciated.\n"
                "Please try either `git cinnabar rollback` followed by the "
                "same command that just\n"
                "failed, or `git cinnabar reclone`.\n"
                "Please open a new issue "
                "(https://github.com/glandium/git-cinnabar/issues/new)\n"
                "mentioning issue #207 and reporting whether the second "
                "attempt succeeded.\n" + extra + "\n"
                "Please read all the above and keep a copy of this repository."
            )
