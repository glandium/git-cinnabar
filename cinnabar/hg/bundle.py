from __future__ import absolute_import, unicode_literals
try:
    from urllib.parse import quote_from_bytes, unquote_to_bytes
except ImportError:
    from urllib import quote as quote_from_bytes
    from urllib import unquote as unquote_to_bytes
from cinnabar.githg import (
    Changeset,
    FileFindParents,
    GitCommit,
    GitHgStore,
    GeneratedManifestInfo,
)
from cinnabar.helper import GitHgHelper
from cinnabar.git import (
    EMPTY_BLOB,
    Git,
    NULL_NODE_ID,
)
from cinnabar.util import (
    check_enabled,
    chunkbuffer,
    experiment,
    iteritems,
    progress_enum,
    progress_iter,
    sorted_merge,
)
from .changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from .objects import (
    File,
    HgObject,
)
from collections import (
    OrderedDict,
    defaultdict,
)
import logging
import struct


# We used to have a pseudo string class that didn't derive from str, and
# that was used to distinguish between mercurial sha1s that were already
# known or not. git-mozreview relies on previously unknown mercurial sha1s
# not being exactly of str type, so use a subclass to make it happy.
class PseudoString(bytes):
    pass


# TODO: Avoid a diff-tree when we already have done it to generate the
# manifest in the first place.
def manifest_diff(a, b):
    for line in GitHgHelper.diff_tree(a, b):
        mode_before, mode_after, sha1_before, sha1_after, status, path = line
        if sha1_before != sha1_after:
            yield path, sha1_after, sha1_before


def manifest_diff2(a, b, c):
    iter1 = iter(list(manifest_diff(a, c)))
    iter2 = iter(list(manifest_diff(b, c)))
    item1 = next(iter1, None)
    item2 = next(iter2, None)
    while True:
        while item1 and item2 and item1[0] < item2[0]:
            item1 = next(iter1, None)
        while item2 and item1 and item2[0] < item1[0]:
            item2 = next(iter2, None)
        if item1 is None or item2 is None:
            break
        if item1[0] == item2[0]:
            path, sha1_after1, sha1_before1 = item1
            path, sha1_after2, sha1_before2 = item2
            assert sha1_after1 == sha1_after2
            yield path, sha1_after1, (sha1_before1, sha1_before2)
            item1 = next(iter1, None)
            item2 = next(iter2, None)


def manifest_diff2_all(a, b, c):
    iter1 = iter(list(manifest_diff(a, c)))
    iter2 = iter(list(manifest_diff(b, c)))
    item1 = next(iter1, None)
    item2 = next(iter2, None)
    while True:
        while item1:
            if item2 and item1[0] >= item2[0]:
                break
            yield item1[0], item1[1], (item1[2], item1[1])
            item1 = next(iter1, None)
        while item2:
            if item1 and item2[0] >= item1[0]:
                break
            yield item2[0], item2[1], (item2[1], item2[2])
            item2 = next(iter2, None)
        if item1 is None and item2 is None:
            break
        if item1 and item2 and item1[0] == item2[0]:
            path, sha1_after1, sha1_before1 = item1
            path, sha1_after2, sha1_before2 = item2
            assert sha1_after1 == sha1_after2
            yield path, sha1_after1, (sha1_before1, sha1_before2)
            item1 = next(iter1, None)
            item2 = next(iter2, None)


def get_changes(tree, parents, all=False):
    if not parents:
        for line in Git.ls_tree(tree, recursive=True):
            mode, typ, sha1, path = line
            yield path, sha1, ()
    elif len(parents) == 1:
        for path, node, parent in manifest_diff(parents[0], tree):
            yield path, node, (parent,)
    else:
        diff = manifest_diff2_all if all else manifest_diff2
        for path, node, parents in diff(parents[0], parents[1], tree):
            yield path, node, parents


class PushStore(GitHgStore):
    @classmethod
    def adopt(cls, store, graft):
        assert isinstance(store, GitHgStore)
        store.__class__ = cls
        store._init(graft)

    def __init__(self, *args, **kwargs):
        graft = kwargs.get('graft', False)
        if 'graft' in kwargs:
            del kwargs['graft']
        super(PushStore, self).__init__(*args, **kwargs)
        self._init(graft)

    def _init(self, graft=False):
        self._pushed = set()
        self._manifest_git_tree = {}
        self._graft = bool(graft)
        self._merge_warn = 0

    def create_hg_manifest(self, commit, parents):
        manifest = GeneratedManifestInfo(NULL_NODE_ID)
        changeset_files = []

        if parents:
            parent_changeset = self.changeset(self.hg_changeset(parents[0]))
            parent_manifest = self.manifest(parent_changeset.manifest)
            parent_node = parent_manifest.node

        if len(parents) == 2:
            parent2_changeset = self.changeset(self.hg_changeset(parents[1]))
            parent2_manifest = self.manifest(parent2_changeset.manifest)
            parent2_node = parent2_manifest.node
            if parent_node == parent2_node:
                parents = parents[:1]

        if not parents:
            for line in Git.ls_tree(commit, recursive=True):
                mode, typ, sha1, path = line
                node = self.create_file(sha1, git_manifest_parents=(),
                                        path=path)
                manifest.add(path, node, self.ATTR[mode], modified=True)
                changeset_files.append(path)

            manifest.parents = []
            manifest.delta_node = NULL_NODE_ID
            return manifest, changeset_files

        elif len(parents) == 2:
            if not experiment('merge'):
                raise Exception('Pushing merges is not supported yet')
            if not self._merge_warn:
                logging.warning('Pushing merges is experimental.')
                logging.warning('This may irremediably push bad state to the '
                                'mercurial server!')
                self._merge_warn = 1
            git_manifests = (self.manifest_ref(parent_node),
                             self.manifest_ref(parent2_node))

            # TODO: this would benefit from less git queries
            changes = list(get_changes(commit, parents))

            files = [(path, mode, sha1) for mode, _, sha1, path in
                     Git.ls_tree(commit, recursive=True)]
            manifests = sorted_merge(parent_manifest, parent2_manifest,
                                     key=lambda i: i.path, non_key=lambda i: i)
            for line in sorted_merge(files, sorted_merge(changes, manifests)):
                path, f, (change, (manifest_line_p1, manifest_line_p2)) = line
                if not f:  # File was removed
                    if manifest_line_p1:
                        manifest.removed.add(path)
                        changeset_files.append(path)
                    continue
                mode, sha1 = f
                attr = self.ATTR[mode]
                if manifest_line_p1 and not manifest_line_p2:
                    file_parents = (manifest_line_p1.sha1,)
                elif manifest_line_p2 and not manifest_line_p1:
                    file_parents = (manifest_line_p2.sha1,)
                elif not manifest_line_p1 and not manifest_line_p2:
                    file_parents = ()
                elif manifest_line_p1.sha1 == manifest_line_p2.sha1:
                    file_parents = (manifest_line_p1.sha1,)
                else:
                    if self._merge_warn == 1:
                        logging.warning('This may take a while...')
                        self._merge_warn = 2
                    file_parents = (manifest_line_p1.sha1,
                                    manifest_line_p2.sha1)

                assert file_parents is not None
                f = self._create_file_internal(
                    sha1, *file_parents,
                    git_manifest_parents=git_manifests,
                    path=path
                )
                file_parents = tuple(p for p in (f.parent1, f.parent2)
                                     if p != NULL_NODE_ID)
                merged = len(file_parents) == 2
                if not merged and file_parents:
                    if self.git_file_ref(file_parents[0]) == sha1:
                        node = file_parents[0]
                    else:
                        merged = True
                if merged:
                    node = self._store_file_internal(f)
                else:
                    node = file_parents[0]

                attr_change = (manifest_line_p1 and
                               manifest_line_p1.attr != attr)
                manifest.add(path, node, attr, modified=merged or attr_change)
                if merged or attr_change:
                    changeset_files.append(path)
            if manifest.raw_data == parent_manifest.raw_data:
                return parent_manifest, []
            manifest.parents = (parent_node, parent2_node)
            return manifest, changeset_files

        def process_diff(diff):
            for (mode_before, mode_after, sha1_before, sha1_after, status,
                 path) in diff:
                if status[:1] == b'R':
                    yield status[1:], (
                        b'000000', sha1_before, NULL_NODE_ID, b'D')
                yield path, (mode_after, sha1_before, sha1_after,
                             status)
        git_diff = sorted(
            l for l in process_diff(GitHgHelper.diff_tree(
                parents[0], commit, detect_copy=True))
        )
        if not git_diff:
            return parent_manifest, []

        parent_lines = OrderedDict((l.path, l) for l in parent_manifest)
        items = manifest.items
        for line in sorted_merge(iteritems(parent_lines), git_diff,
                                 non_key=lambda i: i[1]):
            path, manifest_line, change = line
            if not change:
                items.append(manifest_line)
                continue
            mode_after, sha1_before, sha1_after, status = change
            path2 = status[1:]
            status = status[:1]
            attr = self.ATTR.get(mode_after)
            if status == b'D':
                manifest.removed.add(path)
                changeset_files.append(path)
                continue
            if status in b'MT':
                if sha1_before == sha1_after:
                    node = manifest_line.sha1
                else:
                    node = self.create_file(
                        sha1_after, manifest_line.sha1,
                        git_manifest_parents=(
                            self.manifest_ref(parent_node),),
                        path=path)
            elif status in b'RC':
                if sha1_after != EMPTY_BLOB:
                    node = self.create_copy(
                        (path2, parent_lines[path2].sha1), sha1_after,
                        git_manifest_parents=(
                            self.manifest_ref(parent_node),),
                        path=path)
                else:
                    node = self.create_file(
                        sha1_after,
                        git_manifest_parents=(
                            self.manifest_ref(parent_node),),
                        path=path)
            else:
                assert status == b'A'
                node = self.create_file(
                    sha1_after,
                    git_manifest_parents=(
                        self.manifest_ref(parent_node),),
                    path=path)
            manifest.add(path, node, attr, modified=True)
            changeset_files.append(path)
        manifest.parents = (parent_node,)
        manifest.delta_node = parent_node
        return manifest, changeset_files

    def create_hg_metadata(self, commit, parents):
        if check_enabled('bundle'):
            real_changeset = self.changeset(self.hg_changeset(commit))
        manifest, changeset_files = self.create_hg_manifest(commit, parents)
        commit_data = GitCommit(commit)

        if manifest.node == NULL_NODE_ID:
            manifest.node = manifest.sha1
            if check_enabled('bundle'):
                if real_changeset and (
                        manifest.node != real_changeset.manifest):
                    for path, created, real in sorted_merge(
                            manifest, self.manifest(real_changeset.manifest),
                            key=lambda i: i.path, non_key=lambda i: i):
                        if bytes(created) != bytes(real):
                            logging.error(
                                '%r != %r', bytes(created), bytes(real))
            self._pushed.add(manifest.node)
            self.store_manifest(manifest)
            self._manifest_git_tree[manifest.node] = commit_data.tree

        changeset = Changeset.from_git_commit(commit_data)
        changeset.parents = tuple(self.hg_changeset(p) for p in parents)
        changeset.manifest = manifest.node
        changeset.files = changeset_files

        if parents:
            parent_changeset = self.changeset(changeset.parent1)
            if parent_changeset.branch:
                changeset.branch = parent_changeset.branch

        if self._graft is True and parents and changeset.body[-1:] == b'\n':
            parent_commit = GitCommit(parents[0])
            if (parent_commit.body[-1:] == b'\n' and
                    parent_commit.body[-2] == parent_changeset.body[-1]):
                self._graft = 'true'

        if self._graft == 'true' and changeset.body[-1:] == b'\n':
            changeset.body = changeset.body[:-1]

        changeset.node = changeset.sha1
        self._pushed.add(changeset.node)
        self.store_changeset(changeset, commit_data)

        if check_enabled('bundle') and real_changeset:
            error = False
            for k in ('files', 'manifest'):
                if getattr(real_changeset, k, []) != getattr(changeset, k, []):
                    logging.error('(%s) %r != %r', k,
                                  getattr(real_changeset, k, None),
                                  getattr(changeset, k, None))
                    error = True
            if error:
                raise Exception('Changeset mismatch')

    def _create_file_internal(self, sha1, parent1=NULL_NODE_ID,
                              parent2=NULL_NODE_ID,
                              git_manifest_parents=None, path=None):
        hg_file = File()
        hg_file.content = GitHgHelper.cat_file(b'blob', sha1)
        FileFindParents.set_parents(
            hg_file, parent1, parent2,
            git_manifest_parents=git_manifest_parents,
            path=path)
        node = hg_file.node = hg_file.sha1
        GitHgHelper.set(b'file', node, sha1)
        return hg_file

    def _store_file_internal(self, hg_file):
        node = hg_file.node
        self._pushed.add(node)
        return node

    def create_file(self, sha1, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID,
                    git_manifest_parents=None, path=None):
        hg_file = self._create_file_internal(sha1, parent1, parent2,
                                             git_manifest_parents, path)
        return self._store_file_internal(hg_file)

    def create_copy(self, hg_source, sha1, git_manifest_parents=None,
                    path=None):
        path, rev = hg_source
        hg_file = File()
        hg_file.metadata = {
            b'copy': path,
            b'copyrev': rev,
        }
        hg_file.content = GitHgHelper.cat_file(b'blob', sha1)
        node = hg_file.node = hg_file.sha1
        self._pushed.add(node)
        GitHgHelper.put_blob(hg_file.metadata.to_str(), want_sha1=False)
        GitHgHelper.set(b'file-meta', node, b':1')
        GitHgHelper.set(b'file', node, sha1)
        return node

    def manifest(self, sha1, include_parents=False):
        if sha1 not in self._pushed:
            include_parents = True
        result = super(PushStore, self).manifest(sha1, include_parents)
        # Validate manifests we derive from when bundling are not corrupted.
        if sha1 not in self._pushed and result.sha1 != sha1:
            raise Exception('Sha1 mismatch for manifest %s'
                            % sha1.decode('ascii'))
        return result

    def changeset(self, sha1, include_parents=True):
        if sha1 not in self._pushed:
            include_parents = True
        result = super(PushStore, self).changeset(sha1, include_parents)
        # Validate changesets we derive from when bundling are not corrupted.
        if sha1 not in self._pushed and result.sha1 != sha1:
            raise Exception('Sha1 mismatch for changeset %s'
                            % sha1.decode('ascii'))
        return result

    def changeset_ref(self, sha1):
        # See comment about PseudoString at the beginning of this file.
        result = super(PushStore, self).changeset_ref(sha1)
        if sha1 in self._pushed:
            return PseudoString(result)
        return result

    def close(self, rollback=False):
        if rollback:
            GitHgHelper.close(rollback)
            self._closed = True
        if self._closed:
            return
        super(PushStore, self).close()


def bundle_data(store, commits):
    manifests = OrderedDict()
    files = defaultdict(list)

    for node, parents in progress_iter('Bundling {} changesets', commits):
        if len(parents) > 2:
            raise Exception(
                'Pushing octopus merges to mercurial is not supported')

        changeset_data = store.read_changeset_data(node)
        is_new = changeset_data is None or check_enabled('bundle')
        if is_new:
            store.create_hg_metadata(node, parents)
        hg_changeset = store._changeset(node, include_parents=True)
        if is_new:
            store.add_head(hg_changeset.node, hg_changeset.parent1,
                           hg_changeset.parent2)
        yield hg_changeset
        manifest = hg_changeset.manifest
        if manifest not in manifests and manifest != NULL_NODE_ID:
            if manifest not in (store.changeset(p).manifest
                                for p in hg_changeset.parents):
                manifests[manifest] = hg_changeset.node

    yield None

    for manifest, changeset in progress_iter('Bundling {} manifests',
                                             iteritems(manifests)):
        hg_manifest = store.manifest(manifest, include_parents=True)
        hg_manifest.changeset = changeset
        yield hg_manifest
        manifest_ref = store.manifest_ref(manifest)
        parents = tuple(store.manifest_ref(p) for p in hg_manifest.parents)
        changes = get_changes(manifest_ref, parents)
        for path, hg_file, hg_fileparents in changes:
            if hg_file != NULL_NODE_ID:
                files[store.manifest_path(path)].append(
                    (hg_file, hg_fileparents, changeset, parents))

    yield None

    def iter_files(files):
        count_chunks = 0
        for count_names, path in enumerate(sorted(files), 1):
            yield (count_chunks, count_names), path
            nodes = set()
            for node, parents, changeset, mn_parents in files[path]:
                if node in nodes:
                    continue
                count_chunks += 1
                nodes.add(node)
                file = store.file(node, parents, mn_parents, path)
                file.changeset = changeset
                assert file.node == file.sha1
                yield (count_chunks, count_names), file

            yield (count_chunks, count_names), None

    for chunk in progress_enum('Bundling {} revisions of {} files',
                               iter_files(files)):
        yield chunk

    yield None


_bundlepart_id = 0


def bundlepart_header(name, advisoryparams=()):
    global _bundlepart_id
    yield struct.pack('>B', len(name))
    yield name
    yield struct.pack('>I', _bundlepart_id)
    _bundlepart_id += 1
    yield struct.pack('>BB', 0, len(advisoryparams))
    for key, value in advisoryparams:
        yield struct.pack('>BB', len(key), len(value))
    for key, value in advisoryparams:
        yield key
        yield value


def bundlepart(name, advisoryparams=(), data=None):
    header = b''.join(bundlepart_header(name, advisoryparams))
    yield struct.pack('>i', len(header))
    yield header
    while data:
        chunk = data.read(4096)
        if chunk:
            yield struct.pack('>i', len(chunk))
            yield chunk
        else:
            break
    yield b'\0' * 4  # Empty chunk ending the part


def create_bundle(store, commits, bundle2caps={}):
    version = b'01'
    chunk_type = RawRevChunk01
    if bundle2caps:
        versions = bundle2caps.get(b'changegroup')
        if versions:
            if b'02' in versions:
                chunk_type = RawRevChunk02
                version = b'02'
    cg = create_changegroup(store, bundle_data(store, commits), chunk_type)
    if bundle2caps:
        yield b'HG20'
        yield b'\0' * 4  # bundle parameters length: no params
        replycaps = bundle2caps.get(b'replycaps')
        if replycaps:
            for chunk in bundlepart(b'REPLYCAPS',
                                    data=chunkbuffer([replycaps])):
                yield chunk
        for chunk in bundlepart(b'CHANGEGROUP',
                                advisoryparams=((b'version', version),),
                                data=chunkbuffer(cg)):
            yield chunk
        yield b'\0' * 4  # End of bundle
    else:
        for chunk in cg:
            yield chunk


def get_previous(store, sha1, type):
    if issubclass(type, Changeset):
        return store.changeset(sha1)
    if issubclass(type, GeneratedManifestInfo):
        return store.manifest(sha1)
    return store.file(sha1)


def prepare_chunk(store, chunk, previous, chunk_type):
    if chunk_type == RawRevChunk01:
        if previous is None and chunk.parent1 != NULL_NODE_ID:
            previous = get_previous(store, chunk.parent1, type(chunk))
        return chunk.to_chunk(chunk_type, previous)
    elif chunk_type == RawRevChunk02:
        if isinstance(chunk, Changeset):
            parents = (previous if previous
                       else get_previous(store, p, type(chunk))
                       for p in chunk.parents[:1])
        else:
            parents = (previous if previous and p == previous.node
                       else get_previous(store, p, type(chunk))
                       for p in chunk.parents)
        deltas = sorted((chunk.to_chunk(chunk_type, p) for p in parents),
                        key=len)
        if len(deltas):
            return deltas[0]
        return chunk.to_chunk(chunk_type)
    else:
        assert False


def create_changegroup(store, bundle_data, type=RawRevChunk01):
    previous = None
    for chunk in bundle_data:
        if isinstance(chunk, HgObject):
            data = prepare_chunk(store, chunk, previous, type)
        else:
            data = chunk
        size = 0 if data is None else len(data) + 4
        yield struct.pack(">l", size)
        if data:
            yield bytes(data)
        if isinstance(chunk, HgObject) or chunk is None:
            previous = chunk


def encodecaps(caps):
    return b'\n'.join(
        b'%s=%s' % (
            quote_from_bytes(k).encode('ascii'),
            b','.join(quote_from_bytes(v).encode('ascii') for v in values))
        if values else quote_from_bytes(k).encode('ascii')
        for k, values in sorted(caps.items())
    )


def decodecaps(caps):
    return {
        unquote_to_bytes(key): [unquote_to_bytes(v)
                                for v in val.split(b',')] if val else []
        for key, eq, val in (l.partition(b'=') for l in caps.splitlines())
    }
