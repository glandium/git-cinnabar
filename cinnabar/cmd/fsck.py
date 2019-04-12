import logging
import sys
from cinnabar.cmd.util import CLI
from cinnabar.githg import (
    Changeset,
    ChangesetPatcher,
    FileFindParents,
    GitCommit,
    GitHgStore,
    HG_EMPTY_FILE,
)
from cinnabar.dag import gitdag
from cinnabar.git import (
    Git,
    NULL_NODE_ID,
)
from cinnabar.util import (
    progress_iter,
)
from cinnabar.helper import GitHgHelper
from cinnabar.hg.bundle import get_changes
from collections import (
    defaultdict,
)


class FsckStatus(object):
    def __init__(self):
        self.status = 'ok'

    def __call__(self, status):
        return self.status == status

    def info(self, message):
        sys.stderr.write('\r')
        print message

    def fix(self, message):
        self.status = 'fixed'
        self.info(message)

    def report(self, message):
        self.status = 'broken'
        self.info(message)


@CLI.subcommand
@CLI.argument('--manifests', action='store_true',
              help='Validate manifests hashes')
@CLI.argument('--files', action='store_true',
              help='Validate files hashes')
@CLI.argument('commit', nargs='*',
              help='Specific commit or changeset to check')
def fsck(args):
    '''check cinnabar metadata consistency'''

    status = FsckStatus()

    store = GitHgStore()

    if args.commit:
        commits = set()
        all_git_commits = {}

        for c in args.commit:
            cs = store.hg_changeset(c)
            if cs:
                commits.add(c)
                c = cs.node
            commit = GitHgHelper.hg2git(c)
            if commit == NULL_NODE_ID and not cs:
                status.info('Unknown commit or changeset: %s' % c)
                return 1
            if not cs:
                cs = store.hg_changeset(commit)
                commits.add(commit)

        all_git_commits = GitHgHelper.rev_list('--no-walk=unsorted', *commits)
    else:
        all_refs = dict((ref, sha1)
                        for sha1, ref in Git.for_each_ref('refs/cinnabar'))

        if 'refs/cinnabar/metadata' in all_refs:
            git_heads = '%s^^@' % all_refs['refs/cinnabar/metadata']
        else:
            assert False

        all_git_commits = GitHgHelper.rev_list(
            '--topo-order', '--full-history', '--reverse', git_heads)

    dag = gitdag()

    GitHgHelper.reset_heads('manifests')

    full_file_check = FileFindParents.logger.isEnabledFor(logging.DEBUG)

    for node, tree, parents in progress_iter('Checking {} changesets',
                                             all_git_commits):
        node = store._replace.get(node, node)
        hg_node = store.hg_changeset(node)
        if not hg_node:
            status.report('Missing note for git commit: ' + node)
            continue
        GitHgHelper.seen('git2hg', node)

        changeset_data = store.changeset(hg_node)
        changeset = changeset_data.node

        GitHgHelper.seen('hg2git', changeset)
        changeset_ref = store.changeset_ref(changeset)
        if not changeset_ref:
            status.report('Missing changeset in hg2git branch: %s' % changeset)
            continue
        elif str(changeset_ref) != node:
            status.report('Commit mismatch for changeset %s\n'
                          '  hg2git: %s\n  commit: %s'
                          % (changeset, changeset_ref, node))

        hg_changeset = store.changeset(changeset, include_parents=True)
        if hg_changeset.node != hg_changeset.sha1:
            status.report('Sha1 mismatch for changeset %s' % changeset)

        dag.add(hg_changeset.node,
                (hg_changeset.parent1, hg_changeset.parent2),
                changeset_data.branch or 'default')

        raw_changeset = Changeset.from_git_commit(node)
        patcher = ChangesetPatcher.from_diff(raw_changeset, changeset_data)
        if patcher != store.read_changeset_data(node):
            status.fix('Adjusted changeset metadata for %s' % changeset)
            GitHgHelper.set('changeset', changeset, NULL_NODE_ID)
            GitHgHelper.set('changeset', changeset, node)
            GitHgHelper.put_blob(patcher, want_sha1=False)
            GitHgHelper.set('changeset-metadata', changeset, NULL_NODE_ID)
            GitHgHelper.set('changeset-metadata', changeset, ':1')

        manifest = changeset_data.manifest
        if GitHgHelper.seen('hg2git', manifest) or manifest == NULL_NODE_ID:
            continue
        manifest_ref = store.manifest_ref(manifest)
        if not manifest_ref:
            status.report('Missing manifest in hg2git branch: %s' % manifest)

        parents = tuple(
            store.changeset(p).manifest
            for p in hg_changeset.parents
        )
        git_parents = tuple(store.manifest_ref(p) for p in parents
                            if p != NULL_NODE_ID)

        # This doesn't change the value but makes the helper track the manifest
        # dag.
        GitHgHelper.set('manifest', manifest, manifest_ref)

        if args.manifests:
            if not GitHgHelper.check_manifest(manifest):
                status.report('Sha1 mismatch for manifest %s' % manifest)

        manifest_commit_parents = GitCommit(manifest_ref).parents
        if sorted(manifest_commit_parents) != sorted(git_parents):
            # TODO: better error
            status.report('%s(%s) %s != %s' % (manifest, manifest_ref,
                                               manifest_commit_parents,
                                               git_parents))

        # TODO: check that manifest content matches changeset content

        if args.files:
            changes = get_changes(manifest_ref, git_parents)
            for path, hg_file, hg_fileparents in changes:
                if hg_file != NULL_NODE_ID and (hg_file == HG_EMPTY_FILE or
                                                GitHgHelper.seen('hg2git',
                                                                 hg_file)):
                    if full_file_check:
                        file = store.file(hg_file, hg_fileparents, git_parents,
                                          store.manifest_path(path))
                        valid = file.node == file.sha1
                    else:
                        valid = GitHgHelper.check_file(hg_file,
                                                       *hg_fileparents)
                    if not valid:
                        status.report(
                            'Sha1 mismatch for file %s in manifest %s'
                            % (hg_file, manifest_ref))

    if not args.commit and not status('broken'):
        store_manifest_heads = set(store._manifest_heads_orig)
        manifest_heads = set(GitHgHelper.heads('manifests'))
        if store_manifest_heads != manifest_heads:
            def iter_manifests(a, b):
                for h in a - b:
                    yield h
                for h in b:
                    yield '^%s' % h

            for m, t, p in GitHgHelper.rev_list(
                    '--topo-order', '--full-history', '--reverse',
                    *iter_manifests(manifest_heads, store_manifest_heads)):
                status.fix('Missing manifest commit in manifest branch: %s'
                           % m)

            for m, t, p in GitHgHelper.rev_list(
                    '--topo-order', '--full-history', '--reverse',
                    *iter_manifests(store_manifest_heads, manifest_heads)):
                status.fix('Removing metadata commit %s with no corresponding '
                           'changeset' % (m))

            for h in store_manifest_heads - manifest_heads:
                if GitHgHelper.seen('hg2git', store.hg_manifest(h)):
                    status.fix('Removing non-head reference to %s in manifests'
                               ' metadata.' % h)
    dangling = ()
    if not args.commit and not status('broken'):
        dangling = GitHgHelper.dangling(
            'hg2git' if args.files else 'hg2git-no-blobs')
    for obj in dangling:
        status.fix('Removing dangling metadata for ' + obj)
        # Theoretically, we should figure out if they are files, manifests
        # or changesets and set the right variable accordingly, but in
        # practice, it makes no difference. Reevaluate when GitHgStore.close
        # is modified, though.
        GitHgHelper.set('file', obj, NULL_NODE_ID)
        GitHgHelper.set('file-meta', obj, NULL_NODE_ID)

    if not args.commit and not status('broken'):
        dangling = GitHgHelper.dangling('git2hg')
    for c in dangling:
        status.fix('Removing dangling note for commit ' + c)
        GitHgHelper.set('changeset-metadata', c, NULL_NODE_ID)

    if status('broken'):
        status.info(
            'Your git-cinnabar repository appears to be corrupted. There\n'
            'are known issues in older revisions that have been fixed.\n'
            'Please try running the following command to reset:\n'
            '  git cinnabar reclone\n\n'
            'Please note this command may change the commit sha1s. Your\n'
            'local branches will however stay untouched.\n'
            'Please report any corruption that fsck would detect after a\n'
            'reclone.')

    if not args.commit:
        status.info('Checking head references...')
        computed_heads = defaultdict(set)
        for branch, head in dag.all_heads():
            computed_heads[branch].add(head)

        for branch in sorted(dag.tags()):
            stored_heads = store.heads({branch})
            for head in computed_heads[branch] - stored_heads:
                status.fix('Adding missing head %s in branch %s' %
                           (head, branch))
                store.add_head(head)
            for head in stored_heads - computed_heads[branch]:
                status.fix('Removing non-head reference to %s in branch %s' %
                           (head, branch))
                del store._hgheads[head]

    store.close()

    if status('broken'):
        return 1
    if status('fixed'):
        return 2
    return 0
