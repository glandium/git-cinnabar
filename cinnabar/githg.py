from __future__ import absolute_import, division, unicode_literals
from binascii import hexlify, unhexlify
try:
    from itertools import izip as zip
except ImportError:
    pass
import io
import os
import shutil
import subprocess
import sys
try:
    from urllib.parse import quote_from_bytes, unquote_to_bytes
except ImportError:
    from urllib import quote as quote_from_bytes
    from urllib import unquote as unquote_to_bytes
from collections import (
    OrderedDict,
    defaultdict,
)
try:
    from collections.abc import Sequence
except ImportError:
    from collections import Sequence
try:
    from urllib2 import URLError
except ImportError:
    from urllib.error import URLError
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from .exceptions import (
    AmbiguousGraftAbort,
    NothingToGraftException,
    OldUpgradeAbort,
    UpgradeAbort,
)
from .util import (
    HTTPReader,
    Seekable,
    byte_diff,
    check_enabled,
    interval_expired,
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
    Manifest,
)
from .helper import GitHgHelper
from .util import progress_iter
from cinnabar import util
from cinnabar.util import fsdecode

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
        for key, anode in util.iteritems(other._tags):
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
        return util.iteritems(self._tags)

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
        for branch, heads in util.iteritems(remote_branchmap):
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


class Grafter(object):
    __slots__ = "_store", "_early_history", "_graft_trees", "_grafted"

    def __init__(self, store):
        self._store = store
        self._early_history = set()
        self._graft_trees = defaultdict(list)
        self._grafted = False
        refs = [
            b'--exclude=refs/cinnabar/*',
            b'--exclude=refs/notes/cinnabar',
            b'--exclude=refs/original/*',
            b'--all',
        ]
        if store._has_metadata:
            refs += [b'--not', b'refs/cinnabar/metadata^']
        for node, tree, parents in progress_iter(
                'Reading {} graft candidates',
                GitHgHelper.rev_list(b'--full-history', *refs)):
            self._graft_trees[tree].append(node)

    def _is_cinnabar_commit(self, commit):
        data = self._store.read_changeset_data(commit)
        return b'\npatch' not in data if data else False

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
            subject = changeset.body.split(b'\n', 1)[0]
            possible_nodes = tuple(
                n for n in nodes
                if commits[n].body.split(b'\n', 1)[0] == subject
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
                if b'\npatch' in patcher:
                    possible_nodes.append(node)
            nodes = possible_nodes

        if len(nodes) > 1:
            raise AmbiguousGraftAbort(
                'Cannot graft changeset %s. Candidates: %s'
                % (changeset.node.decode('ascii'),
                   ', '.join(n.decode('ascii') for n in nodes)))

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
            if result and result.sha1 != commit:
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

    def _metadata(self):
        if self._metadata_sha1:
            metadata = GitCommit(self._metadata_sha1)
            self._flags = set(metadata.body.split())
            refs = self.METADATA_REFS
            if b'files-meta' not in self._flags:
                refs = list(refs)
                refs.remove(b'refs/cinnabar/files-meta')
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
            if ref.startswith(b'refs/cinnabar/replace/'):
                self._replace[ref[22:]] = sha1
            elif ref.startswith(b'refs/cinnabar/branches/'):
                raise OldUpgradeAbort()
            elif ref == b'refs/cinnabar/metadata':
                self._metadata_sha1 = sha1
            elif ref == b'refs/cinnabar/tag_cache':
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
                if typ == b'blob':
                    if self.ATTR[mode] == b'x':
                        self._tagfiles[path] = sha1
                    else:
                        self._tagcache[path] = sha1
                elif typ == b'commit':
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
        self._generation = 0
        if metadata:
            changesets_ref = self._metadata_refs.get(
                b'refs/cinnabar/changesets')
            if changesets_ref:
                commit = GitCommit(changesets_ref)
                for n, head in enumerate(commit.body.splitlines()):
                    hghead, branch = head.split(b' ', 1)
                    self._hgheads._previous[hghead] = (branch, n)
                    self._generation = n + 1

            self._manifest_heads_orig = set(GitHgHelper.heads(b'manifests'))

            replace = {}
            for line in Git.ls_tree(metadata.tree):
                mode, typ, sha1, path = line
                replace[path] = sha1

            if self._replace and not replace:
                raise OldUpgradeAbort()

            # Delete old tag-cache, which may contain incomplete data.
            Git.delete_ref(b'refs/cinnabar/tag-cache')

    def prepare_graft(self):
        self._graft = Grafter(self)

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
        for line in Git.iter('ls-remote', fsdecode(git_repo_url),
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
            fetch.append(fsdecode(git_repo_url))
            cmd = fetch + [fsdecode(ref) + ':refs/cinnabar/fetch']
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
            for k, v in util.iteritems(remote_refs):
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
                            fsdecode(b':'.join((by_sha1[sha1], ref))))
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
        changesets_ref = self._metadata_refs.get(b'refs/cinnabar/changesets')
        self._generation = 0
        if changesets_ref:
            commit = GitCommit(changesets_ref)
            for n, head in enumerate(commit.body.splitlines()):
                hghead, branch = head.split(b' ', 1)
                self._hgheads._previous[hghead] = (branch, 1)
                self._generation = n + 1

        self._manifest_heads_orig = set(GitHgHelper.heads(b'manifests'))

        for line in Git.ls_tree(metadata.tree):
            mode, typ, sha1, path = line
            self._replace[path] = sha1

        return True

    def tags(self):
        tags = TagSet()
        heads = sorted((n, h) for h, (b, n) in util.iteritems(self._hgheads))
        for _, h in heads:
            h = self.changeset_ref(h)
            tags.update(self._get_hgtags(h))
        for tag, node in tags:
            if node != NULL_NODE_ID:
                yield tag, node

    def _get_hgtags(self, head):
        tags = TagSet()
        if not self._tagcache.get(head):
            ls = one(Git.ls_tree(head, b'.hgtags'))
            if not ls:
                self._tagcache[head] = NULL_NODE_ID
                return tags
            mode, typ, self._tagcache[head], path = ls
        tagfile = self._tagcache[head]
        if tagfile not in self._tags:
            if tagfile in self._tagfiles:
                data = GitHgHelper.cat_file(b'blob', self._tagfiles[tagfile])
                for line in data.splitlines():
                    tag, nodes = line.split(b'\0', 1)
                    nodes = nodes.split(b' ')
                    for node in reversed(nodes):
                        tags[tag] = node
            else:
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
            self._tags[tagfile] = tags
        return self._tags[tagfile]

    def heads(self, branches={}):
        if not isinstance(branches, (dict, set)):
            branches = set(branches)
        return set(h for h, (b, _) in util.iteritems(self._hgheads)
                   if not branches or b in branches)

    def _head_branch(self, head):
        if head in self._hgheads:
            return self._hgheads[head][0], head
        if head in self._branches:
            return self._branches[head], head
        branch = self.changeset(head).branch or b'default'
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
                    assert parent_branch == self._hgheads[parent_head][0]
                    del self._hgheads[parent_head]

        generation = self._generation
        self._generation += 1
        self._hgheads[head] = (branch, generation)

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
            content = GitHgHelper.cat_blob(b':h%s' % sha1)

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

    def git_tree(self, manifest_sha1, ref_changeset=None):
        if manifest_sha1 == NULL_NODE_ID:
            return EMPTY_TREE
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
            if extra and extra.get(b'committer'):
                committer = extra[b'committer']
                if committer[-1:] == b'>':
                    committer = Authorship.from_hg(
                        committer, instance.timestamp, instance.utcoffset)
                else:
                    committer = Authorship.from_hg_str(
                        committer, maybe_git_utcoffset=True)
                    if committer.to_hg() == committer:
                        extra = dict(instance.extra)
                        del extra[b'committer']
                        if not extra:
                            extra = None
            else:
                committer = author

            parents = tuple(b':h%s' % p for p in instance.parents)

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
                ref=b'refs/cinnabar/tip',
                message=body,
                committer=committer,
                author=author,
                parents=parents,
                pseudo_mark=b':h%s' % instance.node,
            ) as c:
                c.filemodify(b'', self.git_tree(instance.manifest,
                                                *instance.parents[:1]),
                             typ=b'tree')

            commit = PseudoGitCommit(b':1')
            commit.author = author
            commit.committer = committer
            commit.body = body

        GitHgHelper.set(b'changeset', instance.node, commit.sha1)
        changeset = Changeset.from_git_commit(commit)
        GitHgHelper.put_blob(
            ChangesetPatcher.from_diff(changeset, instance), want_sha1=False)
        GitHgHelper.set(b'changeset-metadata', instance.node, b':1')

        self._branches[instance.node] = instance.branch or b'default'
        self.add_head(instance.node, instance.parent1, instance.parent2)

    MODE = {
        b'': b'160644',
        b'l': b'160000',
        b'x': b'160755',
    }

    def store_manifest(self, instance):
        if getattr(instance, 'delta_node', NULL_NODE_ID) != NULL_NODE_ID:
            previous = b':h%s' % instance.delta_node
        else:
            previous = None
        parents = tuple(b':h%s' % p for p in instance.parents)
        with GitHgHelper.commit(
            ref=b'refs/cinnabar/manifests',
            from_commit=previous,
            parents=parents,
            message=instance.node,
            pseudo_mark=b':h%s' % instance.node,
        ) as commit:
            if hasattr(instance, 'delta_node'):
                for name in instance.removed:
                    commit.filedelete(self.manifest_metadata_path(name))
                modified = instance.modified.items()
            else:
                # slow
                modified = ((line.path, (line.sha1, line.attr))
                            for line in instance)
            for name, (node, attr) in modified:
                node = bytes(node)
                commit.filemodify(self.manifest_metadata_path(name), node,
                                  self.MODE[attr])

        GitHgHelper.set(b'manifest', instance.node, b':1')

        if check_enabled('manifests'):
            if not GitHgHelper.check_manifest(instance.node):
                raise Exception(
                    'sha1 mismatch for node %s with parents %s %s and '
                    'previous %s' %
                    (instance.node.decode('ascii'),
                     instance.parent1.decode('ascii'),
                     instance.parent2.decode('ascii'),
                     instance.delta_node.decode('ascii'))
                )

    def close(self, refresh=()):
        if self._closed:
            return
        if self._graft:
            self._graft.close()
        self._closed = True
        # If the helper is not running, we don't have anything to update.
        if not GitHgHelper._helper:
            return
        update_metadata = {}
        tree = GitHgHelper.store(b'metadata', b'hg2git')
        if tree != NULL_NODE_ID:
            hg2git = self._metadata_refs.get(b'refs/cinnabar/hg2git')
            with GitHgHelper.commit(
                ref=b'refs/cinnabar/hg2git',
            ) as commit:
                commit.write(b'M 040000 %s \n' % tree)
            if commit.sha1 != hg2git:
                update_metadata[b'refs/cinnabar/hg2git'] = commit.sha1

        tree = GitHgHelper.store(b'metadata', b'git2hg')
        if tree != NULL_NODE_ID:
            notes = self._metadata_refs.get(b'refs/notes/cinnabar')
            with GitHgHelper.commit(
                ref=b'refs/notes/cinnabar',
            ) as commit:
                commit.write(b'M 040000 %s \n' % tree)
            if commit.sha1 != notes:
                update_metadata[b'refs/notes/cinnabar'] = commit.sha1

        hg_changeset_heads = list(self._hgheads)
        changeset_heads = list(self.changeset_ref(h)
                               for h in hg_changeset_heads)
        if (any(self._hgheads.iterchanges()) or
                b'refs/cinnabar/changesets' in refresh):
            heads = sorted((self._hgheads[h][1], self._hgheads[h][0], h, g)
                           for h, g in zip(hg_changeset_heads,
                                           changeset_heads))
            with GitHgHelper.commit(
                ref=b'refs/cinnabar/changesets',
                parents=list(h for _, __, ___, h in heads),
                message=b'\n'.join(b'%s %s' % (h, b) for _, b, h, __ in heads),
            ) as commit:
                pass
            update_metadata[b'refs/cinnabar/changesets'] = commit.sha1

        changeset_heads = set(changeset_heads)

        manifest_heads = GitHgHelper.heads(b'manifests')
        if (set(manifest_heads) != self._manifest_heads_orig or
                (b'refs/cinnabar/changesets' in update_metadata and
                 not manifest_heads) or b'refs/cinnabar/manifests' in refresh):
            with GitHgHelper.commit(
                ref=b'refs/cinnabar/manifests',
                parents=sorted(manifest_heads),
            ) as commit:
                pass
            update_metadata[b'refs/cinnabar/manifests'] = commit.sha1

        tree = GitHgHelper.store(b'metadata', b'files-meta')
        files_meta_ref = self._metadata_refs.get(b'refs/cinnabar/files-meta')
        if update_metadata and (tree != NULL_NODE_ID or not files_meta_ref):
            with GitHgHelper.commit(
                ref=b'refs/cinnabar/files-meta',
            ) as commit:
                if tree != NULL_NODE_ID:
                    commit.write(b'M 040000 %s \n' % tree)
            if commit.sha1 != files_meta_ref:
                update_metadata[b'refs/cinnabar/files-meta'] = commit.sha1

        replace_changed = False
        for status, ref, sha1 in self._replace.iterchanges():
            if status == VersionedDict.REMOVED:
                Git.delete_ref(b'refs/cinnabar/replace/%s' % ref)
            else:
                Git.update_ref(b'refs/cinnabar/replace/%s' % ref, sha1)
            replace_changed = True

        if update_metadata or replace_changed:
            parents = list(update_metadata.get(r) or self._metadata_refs[r]
                           for r in self.METADATA_REFS)
            metadata_sha1 = (Git.config('cinnabar.previous-metadata') or
                             self._metadata_sha1)
            if metadata_sha1:
                parents.append(metadata_sha1)
            with GitHgHelper.commit(
                ref=b'refs/cinnabar/metadata',
                parents=parents,
                message=b' '.join(sorted(self.FLAGS)),
            ) as commit:
                for sha1, target in util.iteritems(self._replace):
                    commit.filemodify(sha1, target, b'commit')

        for c in self._tagcache:
            if c not in changeset_heads:
                self._tagcache[c] = False

        for c in changeset_heads:
            if c not in self._tagcache:
                tags = self._get_hgtags(c)

        files = set(util.itervalues(self._tagcache))
        deleted = set()
        created = {}
        for f in self._tagcache_items:
            if (f not in self._tagcache and f not in self._tagfiles or
                    f not in files and f in self._tagfiles):
                deleted.add(f)

        def tagset_lines(tags):
            for tag, value in tags:
                yield b'%s\0%s %s\n' % (tag, value,
                                        b' '.join(tags.hist(tag)))

        for f, tags in util.iteritems(self._tags):
            if f not in self._tagfiles and f != NULL_NODE_ID:
                data = b''.join(tagset_lines(tags))
                mark = GitHgHelper.put_blob(data=data)
                created[f] = (mark, b'exec')

        if created or deleted:
            self.tag_changes = True

        for c, f in util.iteritems(self._tagcache):
            if (f and c not in self._tagcache_items):
                if f == NULL_NODE_ID:
                    created[c] = (f, b'commit')
                else:
                    created[c] = (f, b'regular')
            elif f is False and c in self._tagcache_items:
                deleted.add(c)

        if created or deleted:
            with GitHgHelper.commit(
                ref=b'refs/cinnabar/tag_cache',
                from_commit=self._tagcache_ref,
            ) as commit:
                for f in deleted:
                    commit.filedelete(f)

                for f, (filesha1, typ) in util.iteritems(created):
                    commit.filemodify(f, filesha1, typ)

        # refs/notes/cinnabar is kept for convenience
        for ref in update_metadata:
            if ref not in (b'refs/notes/cinnabar',):
                Git.delete_ref(ref)

        if self._metadata_sha1 and update_metadata and not refresh and \
                interval_expired('fsck', 86400 * 7):
            logging.warn('Have you run `git cinnabar fsck` recently?')
        GitHgHelper.close(rollback=False)
