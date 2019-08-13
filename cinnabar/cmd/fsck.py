from __future__ import print_function
import logging
import re
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
    interval_expired,
    Progress,
    progress_iter,
)
from cinnabar.helper import GitHgHelper
from cinnabar.hg.bundle import get_changes
from collections import (
    defaultdict,
    OrderedDict,
)
from itertools import izip


SHA1_RE = re.compile('[0-9a-f]{40}$')


class FsckStatus(object):
    def __init__(self):
        self.status = 'ok'

    def __call__(self, status):
        return self.status == status

    def info(self, message):
        sys.stderr.write('\r')
        print(message)

    def fix(self, message):
        self.status = 'fixed'
        self.info(message)

    def report(self, message):
        self.status = 'broken'
        self.info(message)


def fsck_quick(force=False):
    status = FsckStatus()
    store = GitHgStore()

    metadata_commit = Git.resolve_ref('refs/cinnabar/metadata')
    if not metadata_commit:
        status.info(
            'There does not seem to be any git-cinnabar metadata.\n'
            'Is this a git-cinnabar clone?'
        )
        return 1
    broken_metadata = Git.resolve_ref('refs/cinnabar/broken')
    checked_metadata = Git.resolve_ref('refs/cinnabar/checked')
    if checked_metadata == broken_metadata:
        checked_metadata = None
    if metadata_commit == checked_metadata and not force:
        status.info(
            'The git-cinnabar metadata was already checked and is '
            'presumably clean.\n'
            'Try `--force` if you want to check anyways.'
        )
        return 0
    elif force:
        checked_metadata = None

    commit = GitCommit(metadata_commit)
    if commit.body != 'files-meta unified-manifests-v2':
        status.info(
            'The git-cinnabar metadata is incompatible with this version.\n'
            'Please use the git-cinnabar version it was used with last.\n'
        )
        return 1
    if len(commit.parents) > 6 or len(commit.parents) < 5:
        status.report('The git-cinnabar metadata seems to be corrupted in '
                      'unexpected ways.\n')
        return 1
    changesets, manifests, hg2git, git2hg, files_meta = commit.parents[:5]

    commit = GitCommit(changesets)
    heads = OrderedDict(
        (node, branch)
        for node, _, branch in (d.partition(' ')
                                for d in commit.body.splitlines()))
    if len(heads) != len(commit.parents):
        status.report('The git-cinnabar metadata seems to be corrupted in '
                      'unexpected ways.\n')
        return 1

    manifest_nodes = []

    parents = None
    fix_changeset_heads = False

    def get_checked_metadata(num):
        if not checked_metadata:
            return None
        commit = Git.resolve_ref('{}^{}'.format(checked_metadata, num))
        if commit:
            return GitCommit(commit)

    checked_commit = get_checked_metadata(1)
    # TODO: Check that the recorded heads are actually dag heads.
    for c, changeset_node in progress_iter(
            'Checking {} changeset heads',
            ((c, node) for c, node in izip(commit.parents, heads)
             if not checked_commit or c not in checked_commit.parents)):
        gitsha1 = GitHgHelper.hg2git(changeset_node)
        if gitsha1 == NULL_NODE_ID:
            status.report('Missing hg2git metadata for changeset %s'
                          % changeset_node)
            continue
        if gitsha1 != c:
            if parents is None:
                parents = set(commit.parents)
            if gitsha1 not in parents:
                status.report(
                    'Inconsistent metadata:\n'
                    '  Head metadata says changeset %s maps to %s\n'
                    '  but hg2git metadata says it maps to %s'
                    % (changeset_node, c, gitsha1))
                continue
            fix_changeset_heads = True
        changeset = store._changeset(c, include_parents=True)
        if not changeset:
            status.report('Missing git2hg metadata for git commit %s' % c)
            continue
        if changeset.node != changeset_node:
            if changeset.node not in heads:
                status.report(
                    'Inconsistent metadata:\n'
                    '  Head metadata says %s maps to changeset %s\n'
                    '  but git2hg metadata says it maps to changeset %s'
                    % (c, changeset_node, changeset.node))
                continue
            fix_changeset_heads = True
        if changeset.node != changeset.sha1:
            status.report('Sha1 mismatch for changeset %s' % changeset.node)
            continue
        changeset_branch = changeset.branch or 'default'
        if heads[changeset.node] != changeset_branch:
            status.report(
                'Inconsistent metadata:\n'
                '  Head metadata says changeset %s is in branch %s\n'
                '  but git2hg metadata says it is in branch %s'
                % (changeset.node, heads[changeset.node], changeset_branch))
            continue
        manifest_nodes.append(changeset.manifest)

    if status('broken'):
        return 1

    # Rebuilding manifests benefits from limiting the difference with
    # the last rebuilt manifest. Similarly, building the list of unique
    # files in all manifests benefits from that too.
    # Unfortunately, the manifest heads are not ordered in a topological
    # relevant matter, and the differences between two consecutive manifests
    # can be much larger than they could be. The consequence is spending a
    # large amount of time rebuilding the manifests and gathering the files
    # list. It's actually faster to attempt to reorder them according to
    # some heuristics first, such that the differences are smaller.
    # Here, we use the depth from the root node(s) to reorder the manifests.
    # This doesn't give the most optimal ordering, but it's already much
    # faster. On a clone of multiple mozilla-* repositories with > 1400 heads,
    # it's close to an order of magnitude difference on the "Checking
    # manifests" loop.
    depths = {}
    roots = {}
    manifest_queue = []
    revs = []
    revs.append('{}^@'.format(manifests))
    if checked_metadata:
        revs.append('^{}^2^@'.format(checked_metadata))
    for m, _, parents in progress_iter(
            'Loading {} manifests', GitHgHelper.rev_list(
                '--topo-order', '--reverse', '--full-history', *revs)):
        manifest_queue.append((m, parents))
        if parents:
            depth = {}
            for p in parents:
                for root, num in depths.get(p, {}).iteritems():
                    if root in depth:
                        depth[root] = max(depth[root], num + 1)
                    else:
                        depth[root] = num + 1
            if depth:
                depths[m] = depth
                del depth
                continue
        depths[m] = {m: 0}
        roots[m] = parents

    if status('broken'):
        return 1

    # TODO: check that all manifest_nodes gathered above are available in the
    # manifests dag, and that the dag heads are the recorded heads.
    manifests_commit = GitCommit(manifests)
    checked_commit = get_checked_metadata(2)
    depths = [
        ([depths[p].get(r, 0) for r in roots], p)
        for p in manifests_commit.parents
        if not checked_commit or p not in checked_commit.parents
    ]
    manifests_commit_parents = [
        p for _, p in sorted(depths)
    ]
    previous = None
    all_interesting = set()
    for m in progress_iter('Checking {} manifest heads',
                           manifests_commit_parents):
        c = GitCommit(m)
        if not SHA1_RE.match(c.body):
            status.report('Invalid manifest metadata in git commit %s' % m)
            continue
        gitsha1 = GitHgHelper.hg2git(c.body)
        if gitsha1 == NULL_NODE_ID:
            status.report('Missing hg2git metadata for manifest %s' % c.body)
            continue
        if not GitHgHelper.check_manifest(c.body):
            status.report('Sha1 mismatch for manifest %s' % c.body)

        files = {}
        if previous:
            for _, _, before, after, d, path in GitHgHelper.diff_tree(
                    previous, m):
                if d in 'AM' and before != after and \
                        (path, after) not in all_interesting:
                    files[path] = after
        else:
            for _, t, sha1, path in GitHgHelper.ls_tree(m, recursive=True):
                if (path, sha1) not in all_interesting:
                    files[path] = sha1
        all_interesting.update(files.iteritems())
        previous = m

    if status('broken'):
        return 1

    # Don't check files that were already there in the previously checked
    # manifests.
    previous = None
    for parents in roots.itervalues():
        for p in parents:
            if previous:
                for _, _, before, after, d, path in GitHgHelper.diff_tree(
                        previous, p):
                    if d in 'AM' and before != after:
                        all_interesting.discard((path, after))
            else:
                for _, t, sha1, path in GitHgHelper.ls_tree(p, recursive=True):
                    all_interesting.discard((path, sha1))
            previous = p

    progress = Progress('Checking {} files')
    while all_interesting and manifest_queue:
        (m, parents) = manifest_queue.pop()
        changes = get_changes(m, parents, all=True)
        for path, hg_file, hg_fileparents in changes:
            if hg_fileparents[1:] == (hg_file,):
                continue
            elif hg_fileparents[:1] == (hg_file,):
                continue
            # Reaching here means the file received a modification compared
            # to its parents. If it's a file we're going to check below,
            # it means we don't need to check its parents if somehow they were
            # going to be checked. If it's not a file we're going to check
            # below, it's because it's either a file we weren't interested in
            # in the first place, or it's the parent of a file we have checked.
            # Either way, we aren't interested in the parents.
            for p in hg_fileparents:
                all_interesting.discard((path, p))
            if (path, hg_file) not in all_interesting:
                continue
            all_interesting.remove((path, hg_file))
            if not GitHgHelper.check_file(hg_file, *hg_fileparents):
                p = store.manifest_path(path)
                status.report(
                    'Sha1 mismatch for file %s\n'
                    '  revision %s' % (p, hg_file))

                print_parents = ' '.join(p for p in hg_fileparents
                                         if p != NULL_NODE_ID)
                if print_parents:
                    status.report('  with parent%s %s' % (
                        's' if len(print_parents) > 41 else '',
                        print_parents))
            progress.progress()
    progress.finish()
    if all_interesting:
        status.info('Could not find the following files:')
        for path, sha1 in sorted(all_interesting):
            p = store.manifest_path(path)
            status.info('  %s %s' % (sha1, path))
        status.info(
            'This might be a bug in `git cinnabar fsck`. Please open '
            'an issue, with the message above, on\n'
            'https://github.com/glandium/git-cinnabar/issues')
        return 1

    if status('broken'):
        status.info(
            'Your git-cinnabar repository appears to be corrupted.\n'
            'Please open an issue, with the information above, on\n'
            'https://github.com/glandium/git-cinnabar/issues')
        Git.update_ref('refs/cinnabar/broken', metadata_commit)
        if checked_metadata:
            status.info(
                '\nThen please try to run `git cinnabar rollback --fsck` to '
                'restore last known state, and to update from the mercurial '
                'repository.')
        else:
            status.info('\nThen please try to run `git cinnabar reclone`.')
        status.info(
            '\nPlease note this may affect the commit sha1s of mercurial '
            'changesets, and may require to rebase your local branches.')
        status.info(
            '\nAlternatively, you may start afresh with a new clone. In any '
            'case, please keep this corrupted repository around for further '
            'debugging.')
        return 1

    refresh = []
    if fix_changeset_heads:
        status.fix('Fixing changeset heads metadata order.')
        refresh.append('refs/cinnabar/changesets')
    interval_expired('fsck', 0)
    store.close(refresh=refresh)
    GitHgHelper._helper = False
    metadata_commit = Git.resolve_ref('refs/cinnabar/metadata')
    Git.update_ref('refs/cinnabar/checked', metadata_commit)
    return 0


@CLI.subcommand
@CLI.argument('--force', action='store_true',
              help='Force check, even when metadata was already checked. '
                   'Also disables incremental fsck')
@CLI.argument('--full', action='store_true',
              help='Check more thoroughly')
@CLI.argument('commit', nargs='*',
              help='Specific commit or changeset to check')
def fsck(args):
    '''check cinnabar metadata consistency'''

    if not args.commit and not args.full:
        return fsck_quick(args.force)

    status = FsckStatus()

    store = GitHgStore()

    if args.full and args.commit:
        logging.error('Cannot pass both --full and a commit')
        return 1

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

        if not GitHgHelper.check_manifest(manifest):
            status.report('Sha1 mismatch for manifest %s' % manifest)

        manifest_commit_parents = GitCommit(manifest_ref).parents
        if sorted(manifest_commit_parents) != sorted(git_parents):
            # TODO: better error
            status.report('%s(%s) %s != %s' % (manifest, manifest_ref,
                                               manifest_commit_parents,
                                               git_parents))

        # TODO: check that manifest content matches changeset content

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
        dangling = GitHgHelper.dangling('hg2git')
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

    metadata_commit = Git.resolve_ref('refs/cinnabar/metadata')
    if status('broken'):
        Git.update_ref('refs/cinnabar/broken', metadata_commit)
        return 1

    if args.full:
        Git.update_ref('refs/cinnabar/checked', metadata_commit)
    interval_expired('fsck', 0)
    store.close()

    if status('fixed'):
        return 2
    return 0
