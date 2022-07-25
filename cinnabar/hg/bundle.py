from cinnabar.dag import gitdag
from cinnabar.githg import (
    FileFindParents,
    GitCommit,
    GitHgStore,
)
from cinnabar.helper import GitHgHelper
from cinnabar.git import (
    EMPTY_BLOB,
    NULL_NODE_ID,
)
from cinnabar.util import (
    check_enabled,
    experiment,
    sorted_merge,
)
from cinnabar.hg.changegroup import (
    RawRevChunk02,
)
from cinnabar.hg.objects import (
    File,
    Manifest,
)
from collections import OrderedDict
import functools
import logging
import sys


# TODO: Avoid a diff-tree when we already have done it to generate the
# manifest in the first place.
def manifest_diff(a, b):
    for line in GitHgHelper.diff_tree(a, b):
        mode_before, mode_after, sha1_before, sha1_after, status, path = line
        if sha1_before != sha1_after:
            yield path, sha1_after, sha1_before


class PushStore(GitHgStore):
    def __init__(self, *args, **kwargs):
        self._pushed = set()
        self._merge_warn = 0
        super(PushStore, self).__init__(*args, **kwargs)

    def create_hg_manifest(self, commit, parents):
        manifest = Manifest(NULL_NODE_ID)
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
            for line in GitHgHelper.ls_tree(b'%s:' % commit, recursive=True):
                mode, typ, sha1, path = line
                node = self.create_file(sha1)
                manifest.add(path, node, self.ATTR[mode])
                changeset_files.append(path)

            manifest.parents = []
            return manifest, changeset_files, NULL_NODE_ID

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
            file_dags = {}
            for m, tree, mparents in GitHgHelper.rev_list(
                    b'--parents', b'--topo-order',
                    b'--full-history', b'--reverse',
                    b'%s...%s' % git_manifests):
                for p in mparents:
                    for path, sha1_after, sha1_before in manifest_diff(p, m):
                        path = GitHgStore.manifest_path(path)
                        if path not in file_dags:
                            file_dags[path] = gitdag()
                        dag = file_dags[path]
                        if sha1_before == NULL_NODE_ID:
                            dag.add(sha1_after, ())
                        else:
                            dag.add(sha1_after, (sha1_before,))
            files = [(p, mode, sha1) for mode, _, sha1, p in
                     GitHgHelper.ls_tree(b'%s:' % commit, recursive=True)]
            manifests = sorted_merge(parent_manifest, parent2_manifest,
                                     key=lambda i: i.path, non_key=lambda i: i)
            for line in sorted_merge(files, manifests):
                path, f, m = line
                if not m:
                    m = (None, None)
                manifest_line_p1, manifest_line_p2 = m
                if not f:  # File was removed
                    if manifest_line_p1:
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
                    changeset_files.append(path)
                elif manifest_line_p1.sha1 == manifest_line_p2.sha1:
                    file_parents = (manifest_line_p1.sha1,)
                else:
                    if self._merge_warn == 1:
                        logging.warning('This may take a while...')
                        self._merge_warn = 2
                    file_parents = ()
                    dag = file_dags.pop(path)
                    if dag:
                        dag.tag_nodes_and_parents(
                            (manifest_line_p1.sha1,), 'a')
                        if dag._tags.get(manifest_line_p2.sha1) == 'a':
                            file_parents = (manifest_line_p1.sha1,)
                        else:
                            dag._tags.clear()
                            dag.tag_nodes_and_parents(
                                (manifest_line_p2.sha1,), 'b')
                            if dag._tags.get(manifest_line_p1.sha1) == 'b':
                                file_parents = (manifest_line_p2.sha1,)
                    if not file_parents:
                        file_parents = (manifest_line_p1.sha1,
                                        manifest_line_p2.sha1)

                assert file_parents is not None
                f = self._create_file_internal(sha1, *file_parents)
                file_parents = tuple(p for p in (f.parent1, f.parent2)
                                     if p != NULL_NODE_ID)
                merged = len(file_parents) == 2
                if not merged and file_parents:
                    if self.git_file_ref(file_parents[0]) == sha1:
                        node = file_parents[0]
                    else:
                        merged = True
                if merged or not file_parents:
                    node = self._store_file_internal(f)
                elif file_parents:
                    node = file_parents[0]

                attr_change = (manifest_line_p1 and
                               manifest_line_p1.attr != attr)
                manifest.add(path, node, attr)
                if merged or attr_change:
                    changeset_files.append(path)
            if manifest.raw_data == parent_manifest.raw_data:
                return parent_manifest, [], None
            manifest.parents = (parent_node, parent2_node)
            return manifest, changeset_files, parent_node

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
            return parent_manifest, [], None

        parent_lines = OrderedDict((l.path, l) for l in parent_manifest)
        items = manifest.items
        for line in sorted_merge(parent_lines.items(), git_diff,
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
                changeset_files.append(path)
                continue
            if status in b'MT':
                if sha1_before == sha1_after:
                    node = manifest_line.sha1
                else:
                    node = self.create_file(sha1_after, manifest_line.sha1)
            elif status in b'RC':
                if sha1_after != EMPTY_BLOB:
                    node = self.create_copy(
                        (path2, parent_lines[path2].sha1), sha1_after,
                        path=path)
                else:
                    node = self.create_file(sha1_after)
            else:
                assert status == b'A'
                node = self.create_file(sha1_after)
            manifest.add(path, node, attr)
            changeset_files.append(path)
        manifest.parents = (parent_node,)
        return manifest, changeset_files, parent_node

    def create_hg_metadata(self, commit, parents):
        if check_enabled('bundle'):
            real_changeset = self.changeset(self.hg_changeset(commit))
        manifest, changeset_files, delta_node = \
            self.create_hg_manifest(commit, parents)
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
            delta_manifest = []
            if delta_node != NULL_NODE_ID:
                delta_manifest.append(self.manifest(delta_node))
            chunk = manifest.to_chunk(RawRevChunk02, *delta_manifest)
            GitHgHelper.store(b'manifest', chunk)

        raw_files = b'\0'.join(changeset_files)
        with GitHgHelper.query(
                b'create', b'changeset', commit_data.sha1, manifest.node,
                str(len(raw_files)).encode('ascii')) as stdout:
            stdout.write(raw_files)
            stdout.flush()
            res = stdout.readline().strip()
            assert len(res) == 81
            res, metadata = res.split()

        self._pushed.add(res)

        if check_enabled('bundle') and real_changeset:
            changeset = self.changeset(res)
            assert res == changeset.node

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
                              parent2=NULL_NODE_ID):
        hg_file = File()
        hg_file.content = GitHgHelper.cat_file(b'blob', sha1)
        FileFindParents.set_parents(hg_file, parent1, parent2)
        node = hg_file.node = hg_file.sha1
        GitHgHelper.set(b'file', node, sha1)
        return hg_file

    def _store_file_internal(self, hg_file):
        node = hg_file.node
        return node

    def create_file(self, sha1, parent1=NULL_NODE_ID, parent2=NULL_NODE_ID):
        hg_file = self._create_file_internal(sha1, parent1, parent2)
        return self._store_file_internal(hg_file)

    def create_copy(self, hg_source, sha1, path=None):
        path, rev = hg_source
        hg_file = File()
        hg_file.metadata = {
            b'copy': path,
            b'copyrev': rev,
        }
        hg_file.content = GitHgHelper.cat_file(b'blob', sha1)
        node = hg_file.node = hg_file.sha1
        meta_sha1 = GitHgHelper.put_blob(hg_file.metadata.to_str())
        GitHgHelper.set(b'file-meta', node, meta_sha1)
        GitHgHelper.set(b'file', node, sha1)
        return node

    @functools.lru_cache(maxsize=3)
    def manifest(self, sha1, include_parents=False):
        if sha1 not in self._pushed:
            include_parents = True
        result = super(PushStore, self).manifest(sha1, include_parents)
        # Validate manifests we derive from when bundling are not corrupted.
        if sha1 not in self._pushed and result.sha1 != sha1:
            raise Exception('Sha1 mismatch for manifest %s'
                            % sha1.decode('ascii'))
        return result

    def changeset(self, sha1):
        result = super(PushStore, self).changeset(sha1)
        # Validate changesets we derive from when bundling are not corrupted.
        if sha1 not in self._pushed and result.sha1 != sha1:
            raise Exception('Sha1 mismatch for changeset %s'
                            % sha1.decode('ascii'))
        return result


def bundle_data(store, commits):
    for node, parents in commits:
        if len(parents) > 2:
            raise Exception(
                'Pushing octopus merges to mercurial is not supported')

        changeset_data = store.read_changeset_data(node)
        is_new = changeset_data is None or check_enabled('bundle')
        if is_new:
            store.create_hg_metadata(node, parents)
        hg_changeset = store._changeset(node)
        yield (hg_changeset.node, hg_changeset.parent1, hg_changeset.parent2,
               hg_changeset.changeset)


def create_bundle(store, commits):
    stdout = sys.stdout.buffer
    for chunk in bundle_data(store, commits):
        if isinstance(chunk, tuple):
            stdout.write(b'%s %s %s %s\n' % chunk)
    stdout.flush()
