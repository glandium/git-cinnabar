from cinnabar.githg import (
    GitCommit,
    GitHgStore,
    GeneratedFileRev,
    GeneratedManifestInfo,
    ManifestLine,
)
from cinnabar.helper import GitHgHelper
from cinnabar.git import (
    EMPTY_BLOB,
    EMPTY_TREE,
    Git,
    Mark,
    NULL_NODE_ID,
)
from cinnabar.util import (
    next,
    one,
    progress_iter,
    PseudoString,
)
from .changegroup import (
    create_changegroup,
    RawRevChunk01,
    RawRevChunk02,
)
from collections import (
    OrderedDict,
    defaultdict,
)
import struct
import types
from itertools import chain


# TODO: Avoid a diff-tree when we already have done it to generate the
# manifest in the first place.
def manifest_diff(a, b, base_path=''):
    base_path = base_path.rstrip('/')
    start = len(base_path) + bool(base_path)
    for line in Git.diff_tree(a, b, base_path, recursive=True):
        mode_before, mode_after, sha1_before, sha1_after, status, path = line
        if sha1_before != sha1_after:
            yield path[start:], sha1_after, sha1_before


def manifest_diff2(a, b, c, base_path=''):
    iter1 = iter(list(manifest_diff(a, c, base_path)))
    iter2 = iter(list(manifest_diff(b, c, base_path)))
    item1 = next(iter1)
    item2 = next(iter2)
    while True:
        while item1 and item2 and item1[0] < item2[0]:
            item1 = next(iter1)
        while item2 and item1 and item2[0] < item1[0]:
            item2 = next(iter2)
        if item1 is None or item2 is None:
            break
        if item1[0] == item2[0]:
            path, sha1_after1, sha1_before1 = item1
            path, sha1_after2, sha1_before2 = item2
            assert sha1_after1 == sha1_after2
            yield path, sha1_after1, (sha1_before1, sha1_before2)
            item1 = next(iter1)
            item2 = next(iter2)


def get_changes(tree, parents, base_path=''):
    if not parents:
        for line in Git.ls_tree(tree, base_path, recursive=True):
            mode, typ, sha1, path = line
            yield path[3:], sha1, ()
    elif len(parents) == 1:
        for path, node, parent in manifest_diff(parents[0], tree, base_path):
            yield path, node, (parent,)
    else:
        for path, node, parents in manifest_diff2(parents[0], parents[1],
                                                  tree, base_path):
            yield path, node, parents


class PushStore(GitHgStore):
    @classmethod
    def adopt(cls, store, graft):
        assert isinstance(store, GitHgStore)
        store.__class__ = cls
        store._init(graft)

    def __init__(self, *args, **kwargs):
        super(PushStore, self).__init__(*args, **kwargs)
        graft = kwargs.get('graft', False)
        self._init(graft)

    def _init(self, graft=False):
        self._push_files = {}
        self._push_manifests = OrderedDict()
        self._push_changesets = {}
        self._manifest_git_tree = {}
        self._graft = bool(graft)

    def create_hg_metadata(self, commit, parents):
        if len(parents) > 1:
            raise Exception('Pushing merges is not supported yet')

        manifest = GeneratedManifestInfo(NULL_NODE_ID)

        # TODO: share code with GitHgStore.manifest
        removed = set()
        modified = {}
        copies = {}
        created = OrderedDict()

        if parents:
            parent_changeset_data = self.read_changeset_data(parents[0])
            parent_manifest = self.manifest(parent_changeset_data['manifest'])
            parent_node = parent_manifest.node
            parent_lines = list(parent_manifest._lines)
            branch = parent_changeset_data.get('extra', {}).get('branch')

            line = None
            for line in Git.diff_tree(parents[0], commit, detect_copy=True,
                                      recursive=True):
                mode_before, mode_after, sha1_before, sha1_after, status, \
                    path = line
                status = status[0]
                if status == 'D':
                    removed.add(path)
                elif status in 'MT':
                    if sha1_before == sha1_after:
                        modified[path] = (None, self.ATTR[mode_after])
                    else:
                        modified[path] = (sha1_after, self.ATTR[mode_after])
                elif status in 'RC':
                    path1, path2 = path.split('\t', 1)
                    if status == 'R':
                        removed.add(path1)
                    if sha1_after != EMPTY_BLOB:
                        copies[path2] = path1
                    created[path2] = (sha1_after, self.ATTR[mode_after])
                else:
                    assert status == 'A'
                    created[path] = (sha1_after, self.ATTR[mode_after])
            if line is None:
                manifest = parent_manifest
                parent_lines = []
        else:
            parent_node = NULL_NODE_ID
            parent_lines = []
            branch = None

            for line in Git.ls_tree(commit, recursive=True):
                mode, typ, sha1, path = line
                created[path] = (sha1, self.ATTR[mode])

        if copies:
            copied = {k: () for k in copies.values()}
            for line in parent_lines:
                name = str(line.name)
                if name in copied:
                    copied[name] = line.node

        iter_created = created.iteritems()
        next_created = next(iter_created)
        modified_lines = []
        for line in parent_lines:
            if line.name in removed and line.name not in created:
                continue
            mod = modified.get(line.name)
            if mod:
                node, attr = mod
                if attr is None:
                    attr = line.attr
                if node is None:
                    node = PseudoString(line.node)
                else:
                    node = self.create_file(node, str(line.node))
                line = ManifestLine(line.name, node, attr)
                modified_lines.append(line)
            while next_created and next_created[0] < line.name:
                node, attr = next_created[1]
                if next_created[0] in copies:
                    copied_name = copies[next_created[0]]
                    node = self.create_copy((copied_name, copied[copied_name]),
                                            node)
                else:
                    node = self.create_file(node)
                created_line = ManifestLine(next_created[0], node, attr)
                modified_lines.append(created_line)
                manifest.append_line(created_line)
                next_created = next(iter_created)
            manifest.append_line(line)
        while next_created:
            node, attr = next_created[1]
            if next_created[0] in copies:
                copied_name = copies[next_created[0]]
                node = self.create_copy((copied_name, copied[copied_name]),
                                        node)
            else:
                node = self.create_file(node)
            created_line = ManifestLine(next_created[0], node, attr)
            modified_lines.append(created_line)
            manifest.append_line(created_line)
            next_created = next(iter_created)

        commit_data = GitCommit(commit)

        if manifest.node == NULL_NODE_ID:
            manifest.set_parents(parent_node)
            manifest.node = manifest.sha1
            manifest.removed = removed
            manifest.modified = {l.name: (l.node, l.attr)
                                 for l in modified_lines}
            manifest.delta_node = parent_node
            self._push_manifests[manifest.node] = manifest
            self.manifest_ref(manifest.node, hg2git=False, create=True)
            self._manifest_git_tree[manifest.node] = commit_data.tree

        extra = {}
        if commit_data.author != commit_data.committer:
            committer = self.hg_author_info(commit_data.committer)
            extra['committer'] = '%s %d %d' % committer

        if branch:
            extra['branch'] = branch

        changeset_data = self._changeset_data_cache[commit] = {
            'files': sorted(chain(removed, modified, created)),
            'manifest': manifest.node,
        }
        if extra:
            changeset_data['extra'] = extra
        changeset = self._changeset(commit, include_parents=True)
        if self._graft is True and parents and changeset.data[-1] == '\n':
            parent_cs = self._changeset(parents[0], skip_patch=True)
            if 'patch' not in self._changeset_data_cache[parents[0]]:
                self._graft = False
            else:
                patch = self._changeset_data_cache[parents[0]]['patch'][-1]
                self._graft = (patch[1] == len(parent_cs.data) and
                               parent_cs.data[-1] == '\n')
            if self._graft:
                self._graft = 'true'

        if self._graft == 'true' and changeset.data[-1] == '\n':
            changeset.data = changeset.data[:-1]
            changeset_data['patch'] = (
                (len(changeset.data), len(changeset.data) + 1, ''),
            )
        changeset_data['changeset'] = changeset.changeset = changeset.node = \
            changeset.sha1
        self._push_changesets[changeset.node] = changeset
        # This is a horrible way to do this, but this method is not doing much
        # better overall anyways.
        if extra:
            if 'committer' in extra:
                del extra['committer']
            if not extra:
                del changeset_data['extra']
        self._changesets[changeset.node] = PseudoString(commit)

    def create_file(self, sha1, *parents):
        hg_file = GeneratedFileRev(NULL_NODE_ID,
                                   GitHgHelper.cat_file('blob', sha1))
        hg_file.set_parents(*parents)
        node = hg_file.node = hg_file.sha1
        self._push_files[node] = hg_file
        self._files.setdefault(node, PseudoString(sha1))
        self._git_files.setdefault(node, PseudoString(sha1))
        return node

    def create_copy(self, hg_source, sha1):
        data = '\1\ncopy: %s\ncopyrev: %s\n\1\n' % hg_source
        data += GitHgHelper.cat_file('blob', sha1)
        hg_file = GeneratedFileRev(NULL_NODE_ID, data)
        hg_file.set_parents()
        node = hg_file.node = hg_file.sha1
        mark = self.file_ref(node, hg2git=False, create=True)
        self._push_files[node] = hg_file
        self._files.setdefault(node, mark)
        self._git_files.setdefault(node, PseudoString(sha1))
        return node

    def file(self, sha1):
        if sha1 in self._push_files:
            return self._push_files[sha1]
        return super(PushStore, self).file(sha1)

    def manifest(self, sha1, include_parents=False):
        if sha1 in self._push_manifests:
            return self._push_manifests[sha1]
        return super(PushStore, self).manifest(sha1, include_parents)

    def changeset(self, sha1, include_parents=False):
        if sha1 in self._push_changesets:
            return self._push_changesets[sha1]
        return super(PushStore, self).changeset(sha1, include_parents)

    def close(self, rollback=False):
        if rollback:
            self._closed = True
        if self._closed:
            return
        for manifest in self._push_manifests.itervalues():
            self.store_manifest(manifest)
            ls = one(Git.ls_tree(self.manifest_ref(manifest.node), 'git'))
            if self._manifest_git_tree[manifest.node] == EMPTY_TREE and not ls:
                pass
            else:
                mode, typ, sha1, path = ls
                assert sha1 == self._manifest_git_tree[manifest.node]

        for file in self._push_files.itervalues():
            if isinstance(self._files[file.node], Mark):
                mark = self._fast_import.new_mark()
                self._fast_import.put_blob(data=file.data, mark=mark)
                self._files[file.node] = Mark(mark)

        super(PushStore, self).close()


def bundle_data(store, commits):
    manifests = OrderedDict()
    files = defaultdict(list)

    for nodes in progress_iter('Bundling %d changesets', commits):
        parents = nodes.split()
        node = parents.pop(0)
        assert len(parents) <= 2
        changeset_data = store.read_changeset_data(node)
        is_new = changeset_data is None
        if is_new:
            store.create_hg_metadata(node, parents)
            changeset_data = store.read_changeset_data(node)
        changeset = changeset_data['changeset']
        hg_changeset = store.changeset(changeset, include_parents=True)
        if is_new:
            store.add_head(hg_changeset.node, hg_changeset.parent1,
                           hg_changeset.parent2)
        yield hg_changeset
        manifest = changeset_data['manifest']
        if manifest not in manifests and manifest != NULL_NODE_ID:
            if manifest not in (store.read_changeset_data(
                    store.changeset_ref(p))['manifest']
                    for p in hg_changeset.parents):
                manifests[manifest] = changeset

    yield None

    for manifest, changeset in progress_iter('Bundling %d manifests',
                                             manifests.iteritems()):
        hg_manifest = store.manifest(manifest, include_parents=True)
        hg_manifest.changeset = changeset
        yield hg_manifest
        manifest_ref = store.manifest_ref(manifest)
        if isinstance(manifest_ref, Mark):
            for path, (sha1, attr) in hg_manifest.modified.iteritems():
                if not isinstance(sha1, types.StringType):
                    continue
                file = store.file(sha1)
                files[path].append((sha1, file.parents, changeset))
            continue
        parents = tuple(store.manifest_ref(p) for p in hg_manifest.parents)
        changes = get_changes(manifest_ref, parents, 'hg')
        for path, hg_file, hg_fileparents in changes:
            if hg_file != NULL_NODE_ID:
                files[path].append((hg_file, hg_fileparents, changeset))

    yield None

    def iter_files(files):
        for path in sorted(files):
            yield path
            nodes = set()
            for node, parents, changeset in files[path]:
                if node in nodes:
                    continue
                nodes.add(node)
                file = store.file(node)
                file.set_parents(*parents)
                file.changeset = changeset
                assert file.node == file.sha1
                yield file

            yield None

    class Filt(object):
        def __init__(self):
            self._previous = None

        def __call__(self, chunk):
            ret = self._previous and chunk is not None
            self._previous = chunk
            return ret

    for chunk in progress_iter('Bundling %d files', iter_files(files), Filt()):
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
    header = ''.join(bundlepart_header(name, advisoryparams))
    yield struct.pack('>i', len(header))
    yield header
    while data:
        chunk = data.read(4096)
        if chunk:
            yield struct.pack('>i', len(chunk))
            yield chunk
        else:
            break
    yield '\0' * 4  # Empty chunk ending the part


def create_bundle(store, commits, bundle2caps={}):
    version = '01'
    chunk_type = RawRevChunk01
    if bundle2caps:
        versions = bundle2caps.get('changegroup')
        if versions:
            if '02' in versions:
                chunk_type = RawRevChunk02
                version = '02'
    cg = create_changegroup(store, bundle_data(store, commits), chunk_type)
    if bundle2caps:
        from mercurial.util import chunkbuffer
        yield 'HG20'
        yield '\0' * 4  # bundle parameters length: no params
        if bundle2caps.get('replycaps'):
            for chunk in bundlepart('REPLYCAPS'):
                yield chunk
        for chunk in bundlepart('CHANGEGROUP',
                                advisoryparams=(('version', version),),
                                data=chunkbuffer(cg)):
            yield chunk
        yield '\0' * 4  # End of bundle
    else:
        for chunk in cg:
            yield chunk
