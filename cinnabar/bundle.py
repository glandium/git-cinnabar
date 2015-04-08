from githg import (
    GitHgStore,
    GeneratedFileRev,
    GeneratedManifestInfo,
    ManifestLine,
    NULL_NODE_ID,
    EMPTY_BLOB,
    EMPTY_TREE,
)
from .helper import GitHgHelper
from .git import (
    Git,
    Mark,
)
from .util import (
    next,
    one,
    LazyString,
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
    def adopt(cls, store):
        assert isinstance(store, GitHgStore)
        store.__class__ = cls
        store._push_files = {}
        store._push_manifests = OrderedDict()
        store._push_changesets = {}
        store._manifest_git_tree = {}

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
            parent_lines = parent_manifest._lines
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
                    node = LazyString(line.node)
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
                manifest._lines.append(created_line)
                next_created = next(iter_created)
            manifest._lines.append(line)
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
            manifest._lines.append(created_line)
            next_created = next(iter_created)

        header, message = GitHgHelper.cat_file('commit', commit).split(
            '\n\n', 1)
        header_data = {}
        for line in header.splitlines():
            typ, data = line.split(' ', 1)
            if typ in ('author', 'committer', 'tree'):
                header_data[typ] = data

        if manifest.node == NULL_NODE_ID:
            manifest.set_parents(parent_node)
            manifest.node = manifest.sha1
            manifest.removed = removed
            manifest.modified = {l.name: (l.node, l.attr)
                                 for l in modified_lines}
            manifest.previous_node = parent_node
            self._push_manifests[manifest.node] = manifest
            self.manifest_ref(manifest.node, hg2git=False, create=True)
            self._manifest_git_tree[manifest.node] = header_data['tree']

        extra = {}
        if header_data['author'] != header_data['committer']:
            committer = self.hg_author_info(header_data['committer'])
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
        self._changesets[changeset.node] = LazyString(commit)

    def create_file(self, sha1, *parents):
        hg_file = GeneratedFileRev(NULL_NODE_ID,
                                   GitHgHelper.cat_file('blob', sha1))
        hg_file.set_parents(*parents)
        node = hg_file.node = hg_file.sha1
        self._push_files[node] = hg_file
        self._files[node] = LazyString(sha1)
        self._git_files[node] = LazyString(sha1)
        return node

    def create_copy(self, hg_source, sha1):
        data = '\1\ncopy: %s\ncopyrev: %s\n\1\n' % hg_source
        data += GitHgHelper.cat_file('blob', sha1)
        hg_file = GeneratedFileRev(NULL_NODE_ID, data)
        hg_file.set_parents()
        node = hg_file.node = hg_file.sha1
        mark = self.file_ref(node, hg2git=False, create=True)
        self._push_files[node] = hg_file
        self._files[node] = mark
        self._git_files[node] = LazyString(sha1)
        return node

    def file(self, sha1):
        if sha1 in self._push_files:
            return self._push_files[sha1]
        return super(PushStore, self).file(sha1)

    def manifest(self, sha1):
        if sha1 in self._push_manifests:
            return self._push_manifests[sha1]
        return super(PushStore, self).manifest(sha1)

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
            self.store(manifest)
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


def create_bundle(store, commits):
    manifests = OrderedDict()
    files = defaultdict(list)

    previous = None
    for nodes in commits:
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
        if previous is None and hg_changeset.parent1 != NULL_NODE_ID:
            previous = store.changeset(hg_changeset.parent1)
        data = hg_changeset.serialize(previous)
        previous = hg_changeset
        yield struct.pack(">l", len(data) + 4)
        yield data
        manifest = changeset_data['manifest']
        if manifest not in manifests:
            manifests[manifest] = (
                changeset, tuple(store.read_changeset_data(p)['manifest']
                                 for p in parents))

    yield '\0' * 4

    previous = None
    for manifest, (changeset, parents) in manifests.iteritems():
        if previous is None and parents and parents[0] != NULL_NODE_ID:
            previous = store.manifest(parents[0])
        hg_manifest = store.manifest(manifest)
        hg_manifest.set_parents(*parents)
        hg_manifest.changeset = changeset
        data = hg_manifest.serialize(previous)
        previous = hg_manifest
        yield struct.pack(">l", len(data) + 4)
        yield data
        manifest_ref = store.manifest_ref(manifest)
        if isinstance(manifest_ref, Mark):
            for path, (sha1, attr) in hg_manifest.modified.iteritems():
                if not isinstance(sha1, types.StringType):
                    continue
                file = store.file(sha1)
                files[path].append((sha1, (file.parent1, file.parent2),
                                    changeset))
            continue
        parents = tuple(store.manifest_ref(p) for p in parents)
        changes = get_changes(manifest_ref, parents, 'hg')
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
