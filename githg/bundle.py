from . import (
    GitHgStore,
    GeneratedFileRev,
    GeneratedManifestInfo,
    ManifestLine,
    NULL_NODE_ID,
)
from git import (
    Git,
    Mark,
)
from git.util import (
    next,
    LazyString,
)
from collections import (
    OrderedDict,
    defaultdict,
)
import struct
from itertools import chain

#import logging
#logging.getLogger('').setLevel(logging.INFO)

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
    def adopt(cls, store):
        assert isinstance(store, GitHgStore)
        store.__class__ = cls
        store._push_files = {}
        store._push_manifests = {}
        store._push_changesets = {}

    def create_hg_metadata(self, commit, parents):
        if len(parents) > 1:
            raise Exception('Pushing merges is not supported yet')
        if len(parents) == 0:
            raise Exception('Pushing a root changeset is not supported yet')

        parent_changeset_data = self.read_changeset_data(parents[0])
        parent_manifest = self.manifest(parent_changeset_data['manifest'])
        manifest = GeneratedManifestInfo(NULL_NODE_ID)

        # TODO: share code with GitHgStore.manifest
        removed = set()
        modified = {}
        created = OrderedDict()
        for line in Git.diff_tree(parents[0], commit, recursive=True):
            mode_before, mode_after, sha1_before, sha1_after, status, \
                path = line
            if status == 'D':
                removed.add(path)
            elif status == 'M':
                if sha1_before == sha1_after:
                    modified[path] = (None, self.ATTR[mode_after])
                else:
                    modified[path] = (sha1_after, self.ATTR[mode_after])
            else:
                assert status == 'A'
                created[path] = (sha1_after, self.ATTR[mode_after])

        iter_created = created.iteritems()
        next_created = next(iter_created)
        modified_lines = []
        for line in parent_manifest._lines:
            if line.name in removed:
                continue
            mod = modified.get(line.name)
            if mod:
                node, attr = mod
                if attr is None:
                    attr = line.attr
                if node is None:
                    node = line.node
                else:
                    node = self.create_file(node, line.node)
                line = ManifestLine(line.name, node, attr)
                modified_lines.append(line)
            while next_created and next_created[0] < line.name:
                node, attr = next_created[1]
                node = self.create_file(node)
                created_line = ManifestLine(next_created[0], node, attr)
                modified_lines.append(created_line)
                manifest._lines.append(created_line)
                next_created = next(iter_created)
            manifest._lines.append(line)
        while next_created and next_created[0] < line.name:
            node, attr = next_created[1]
            node = self.create_file(node)
            created_line = ManifestLine(next_created[0], node, attr)
            modified_lines.append(created_line)
            manifest._lines.append(created_line)
            next_created = next(iter_created)

        manifest.set_parents(parent_manifest.node)
        manifest.node = manifest.sha1
        manifest.removed = removed
        manifest.modified = {l.name: (l.node, l.attr) for l in modified_lines}
        manifest.previous_node = parent_manifest.node
        self._push_manifests[manifest.node] = manifest
        self.store(manifest)

        header, message = Git.cat_file('commit', commit).split('\n\n', 1)
        header_data = {}
        for line in header.splitlines():
            typ, data = line.split(' ', 1)
            if typ in ('author', 'committer'):
                header_data[typ] = data

        extra = {}
        if header_data['author'] != header_data['committer']:
            committer = self.hg_author_info(header_data['committer'])
            extra['committer'] = '%s %s %d' % committer

        branch = parent_changeset_data.get('extra', {}).get('branch')
        if branch:
            extra['branch'] = branch

        changeset_data = self._changeset_data_cache[commit] = {
            'files': sorted(chain(removed, manifest.modified)),
            'manifest': manifest.node,
            'extra': extra,
        }
        changeset = self._changeset(commit, include_parents=True)
        changeset_data['changeset'] = changeset.changeset = changeset.node = \
            changeset.sha1
        self._push_changesets[changeset.node] = changeset
        self._changesets[changeset.node] = LazyString(commit)
        self.add_head(changeset.node, changeset.parent1, changeset.parent2)

    def create_file(self, sha1, *parents):
        hg_file = GeneratedFileRev(NULL_NODE_ID, Git.cat_file('blob', sha1))
        hg_file.set_parents(*parents)
        node = hg_file.node = hg_file.sha1
        self._push_files[node] = hg_file
        self._files[node] = LazyString(sha1)
        return node

    def file(self, sha1):
        if sha1 in self._push_files:
            return self._push_files[sha1]
        return super(PushStore, self).file(sha1)

    def manifest(self, sha1, previous=None):
        if sha1 in self._push_manifests:
            return self._push_manifests[sha1]
        return super(PushStore, self).manifest(sha1, previous)

    def changeset(self, sha1, include_parents=False):
        if sha1 in self._push_changesets:
            return self._push_changesets[sha1]
        return super(PushStore, self).changeset(sha1, include_parents)


def create_bundle(store, commits):
    manifests = OrderedDict()
    files = defaultdict(list)

    PushStore.adopt(store)

    previous = None
    for nodes in commits:
        parents = nodes.split()
        node = parents.pop(0)
        assert len(parents) <= 2
        changeset_data = store.read_changeset_data(node)
        if changeset_data is None:
            store.create_hg_metadata(node, parents)
            changeset_data = store.read_changeset_data(node)
        changeset = changeset_data['changeset']
        hg_changeset = store.changeset(changeset, include_parents=True)
        if previous is None and hg_changeset.parent1 != NULL_NODE_ID:
            previous = store.changeset(hg_changeset.parent1)
        data = hg_changeset.serialize(previous)
        previous = hg_changeset
        yield struct.pack(">l", len(data) + 4)
        yield data
        manifest = changeset_data['manifest']
        if manifest not in manifests:
            manifests[manifest] = (changeset,
                tuple(store.read_changeset_data(p)['manifest']
                      for p in parents))
            if isinstance(store.manifest_ref(manifest), Mark):
                manifest = store.manifest(manifest)
                for path, (sha1, attr) in manifest.modified.iteritems():
                    file = store.file(sha1)
                    files[path].append((sha1, (file.parent1, file.parent2),
                                        changeset))

    yield '\0' * 4

    previous = None
    for manifest, (changeset, parents) in manifests.iteritems():
        if previous is None and parents and parents[0] != NULL_NODE_ID:
            previous = store.manifest(parents[0])
        hg_manifest = store.manifest(manifest, previous)
        hg_manifest.set_parents(*parents)
        hg_manifest.changeset = changeset
        data = hg_manifest.serialize(previous)
        previous = hg_manifest
        yield struct.pack(">l", len(data) + 4)
        yield data
        manifest = store.manifest_ref(manifest)
        if isinstance(manifest, Mark):
            continue
        parents = tuple(store.manifest_ref(p) for p in parents)
        changes = get_changes(manifest, parents, 'hg')
        for path, hg_file, hg_fileparents in changes:
            if hg_file != NULL_NODE_ID:
                files[path].append((hg_file, hg_fileparents, changeset))

    yield '\0' * 4

    for path in sorted(files):
        yield struct.pack(">l", len(path) + 4)
        yield path
        previous = None
        for node, parents, changeset in files[path]:
            file = store.file(node)
            file.set_parents(*parents)
            file.changeset = changeset
            assert file.node == file.sha1
            if previous is None and file.parent1 != NULL_NODE_ID:
                previous = store.file(file.parent1)
            data = file.serialize(previous)
            previous = file
            yield struct.pack(">l", len(data) + 4)
            yield data

        yield '\0' * 4

    yield '\0' * 4
