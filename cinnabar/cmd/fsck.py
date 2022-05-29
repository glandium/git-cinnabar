import logging
import os
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


SHA1_RE = re.compile(b'[0-9a-f]{40}$')


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


def check_replace(store):
    self_refs = [r for r, s in store._replace.items() if r == s]
    for r in progress_iter('Removing {} self-referencing grafts', self_refs):
        del store._replace[r]


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
    if commit.body != b'files-meta unified-manifests-v2':
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
        for node, _, branch in (d.partition(b' ')
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
        commit = Git.resolve_ref('{}^{}'.format(
            checked_metadata.decode('ascii'), num))
        if commit:
            return GitCommit(commit)

    checked_commit = get_checked_metadata(1)
    # TODO: Check that the recorded heads are actually dag heads.
    for c, changeset_node in progress_iter(
            'Checking {} changeset heads',
            ((c, node) for c, node in zip(commit.parents, heads)
             if not checked_commit or c not in checked_commit.parents)):
        gitsha1 = GitHgHelper.hg2git(changeset_node)
        if gitsha1 == NULL_NODE_ID:
            status.report('Missing hg2git metadata for changeset %s'
                          % changeset_node.decode('ascii'))
            continue
        if gitsha1 != c:
            if parents is None:
                parents = set(commit.parents)
            if gitsha1 not in parents:
                status.report(
                    'Inconsistent metadata:\n'
                    '  Head metadata says changeset %s maps to %s\n'
                    '  but hg2git metadata says it maps to %s'
                    % (changeset_node.decode('ascii'), c.decode('ascii'),
                       gitsha1.decode('ascii')))
                continue
            fix_changeset_heads = True
        changeset = store._changeset(c, include_parents=True)
        if not changeset:
            status.report(
                'Missing git2hg metadata for git commit %s'
                % c.decode('ascii'))
            continue
        if changeset.node != changeset_node:
            if changeset.node not in heads:
                status.report(
                    'Inconsistent metadata:\n'
                    '  Head metadata says %s maps to changeset %s\n'
                    '  but git2hg metadata says it maps to changeset %s'
                    % (c.decode('ascii'), changeset_node.decode('ascii'),
                       changeset.node.decode('ascii')))
                continue
            fix_changeset_heads = True
        if changeset.node != changeset.sha1:
            status.report(
                'Sha1 mismatch for changeset %s'
                % changeset.node.decode('ascii'))
            continue
        changeset_branch = changeset.branch or b'default'
        if heads[changeset.node] != changeset_branch:
            status.report(
                'Inconsistent metadata:\n'
                '  Head metadata says changeset %s is in branch %s\n'
                '  but git2hg metadata says it is in branch %s'
                % (changeset.node.decode('ascii'),
                   os.fsdecode(heads[changeset.node]),
                   os.fsdecode(changeset_branch)))
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
    roots = set()
    manifest_queue = []
    revs = []
    revs.append(b'%s^@' % manifests)
    if checked_metadata:
        revs.append(b'^%s^2^@' % checked_metadata)
    for m, _, parents in progress_iter(
            'Loading {} manifests', GitHgHelper.rev_list(
                b'--topo-order', b'--reverse', b'--full-history', *revs)):
        manifest_queue.append((m, parents))
        for p in parents:
            if p not in depths:
                roots.add(p)
            depths[m] = max(depths.get(p, 0) + 1, depths.get(m, 0))

    if status('broken'):
        return 1

    # TODO: check that all manifest_nodes gathered above are available in the
    # manifests dag, and that the dag heads are the recorded heads.
    manifests_commit = GitCommit(manifests)
    checked_commit = get_checked_metadata(2)
    depths = [
        (depths.get(p, 0), p)
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
            status.report('Invalid manifest metadata in git commit %s'
                          % m.decode('ascii'))
            continue
        gitsha1 = GitHgHelper.hg2git(c.body)
        if gitsha1 == NULL_NODE_ID:
            status.report('Missing hg2git metadata for manifest %s'
                          % c.body.decode('ascii'))
            continue
        if not GitHgHelper.check_manifest(c.body):
            status.report('Sha1 mismatch for manifest %s'
                          % c.body.decode('ascii'))

        files = {}
        if previous:
            for _, _, before, after, d, path in GitHgHelper.diff_tree(
                    previous, m):
                if d in b'AM' and before != after and \
                        (path, after) not in all_interesting:
                    files[path] = after
        else:
            for _, t, sha1, path in GitHgHelper.ls_tree(m, recursive=True):
                if (path, sha1) not in all_interesting:
                    files[path] = sha1
        all_interesting.update(files.items())
        previous = m

    if status('broken'):
        return 1

    # Don't check files that were already there in the previously checked
    # manifests.
    previous = None
    for r in roots:
        if previous:
            for _, _, before, after, d, path in GitHgHelper.diff_tree(
                    previous, r):
                if d in b'AM' and before != after:
                    all_interesting.discard((path, after))
        else:
            for _, t, sha1, path in GitHgHelper.ls_tree(r, recursive=True):
                all_interesting.discard((path, sha1))
        previous = r

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
                    '  revision %s' % (os.fsdecode(p), hg_file.decode('ascii'))
                )

                print_parents = ' '.join(p.decode('ascii')
                                         for p in hg_fileparents
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
            status.info('  %s %s' % (sha1.decode('ascii'), os.fsdecode(p)))
        status.info(
            'This might be a bug in `git cinnabar fsck`. Please open '
            'an issue, with the message above, on\n'
            'https://github.com/glandium/git-cinnabar/issues')
        return 1

    check_replace(store)

    if status('broken'):
        status.info(
            'Your git-cinnabar repository appears to be corrupted.\n'
            'Please open an issue, with the information above, on\n'
            'https://github.com/glandium/git-cinnabar/issues')
        Git.update_ref(b'refs/cinnabar/broken', metadata_commit)
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

    refresh = [b'refs/cinnabar/checked']
    if fix_changeset_heads:
        status.fix('Fixing changeset heads metadata order.')
        refresh.append(b'refs/cinnabar/changesets')
    interval_expired('fsck', 0)
    store.close(refresh=refresh)
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
                status.info('Unknown commit or changeset: %s'
                            % c.decode('ascii'))
                return 1
            if not cs:
                cs = store.hg_changeset(commit)
                commits.add(commit)

        all_git_commits = GitHgHelper.rev_list(b'--no-walk=unsorted', *commits)
    else:
        all_refs = dict((ref, sha1)
                        for sha1, ref in Git.for_each_ref('refs/cinnabar'))

        if b'refs/cinnabar/metadata' in all_refs:
            git_heads = b'%s^^@' % all_refs[b'refs/cinnabar/metadata']
        else:
            assert False

        all_git_commits = GitHgHelper.rev_list(
            b'--topo-order', b'--full-history', b'--reverse', git_heads)

    dag = gitdag()

    GitHgHelper.reset_heads(b'manifests')

    full_file_check = FileFindParents.logger.isEnabledFor(logging.DEBUG)

    for node, tree, parents in progress_iter('Checking {} changesets',
                                             all_git_commits):
        node = store._replace.get(node, node)
        hg_node = store.hg_changeset(node)
        if not hg_node:
            status.report('Missing note for git commit: ' +
                          node.decode('ascii'))
            continue
        GitHgHelper.seen(b'git2hg', node)

        changeset_data = store.changeset(hg_node)
        changeset = changeset_data.node

        GitHgHelper.seen(b'hg2git', changeset)
        changeset_ref = store.changeset_ref(changeset)
        if not changeset_ref:
            status.report('Missing changeset in hg2git branch: %s'
                          % changeset.decode('ascii'))
            continue
        elif bytes(changeset_ref) != node:
            status.report('Commit mismatch for changeset %s\n'
                          '  hg2git: %s\n  commit: %s'
                          % (changeset.decode('ascii'),
                             changeset_ref.decode('ascii'),
                             node.decode('ascii')))

        hg_changeset = store.changeset(changeset, include_parents=True)
        if hg_changeset.node != hg_changeset.sha1:
            status.report('Sha1 mismatch for changeset %s'
                          % changeset.decode('ascii'))

        dag.add(hg_changeset.node,
                (hg_changeset.parent1, hg_changeset.parent2),
                changeset_data.branch or b'default')

        raw_changeset = Changeset.from_git_commit(node)
        patcher = ChangesetPatcher.from_diff(raw_changeset, changeset_data)
        if patcher != store.read_changeset_data(node):
            status.fix('Adjusted changeset metadata for %s'
                       % changeset.decode('ascii'))
            GitHgHelper.set(b'changeset', changeset, NULL_NODE_ID)
            GitHgHelper.set(b'changeset', changeset, node)
            sha1 = GitHgHelper.put_blob(patcher)
            GitHgHelper.set(b'changeset-metadata', changeset, NULL_NODE_ID)
            GitHgHelper.set(b'changeset-metadata', changeset, sha1)

        manifest = changeset_data.manifest
        if GitHgHelper.seen(b'hg2git', manifest) or manifest == NULL_NODE_ID:
            continue
        manifest_ref = store.manifest_ref(manifest)
        if not manifest_ref:
            status.report('Missing manifest in hg2git branch: %s'
                          % manifest.decode('ascii'))

        parents = tuple(
            store.changeset(p).manifest
            for p in hg_changeset.parents
        )
        git_parents = tuple(store.manifest_ref(p) for p in parents
                            if p != NULL_NODE_ID)

        # This doesn't change the value but makes the helper track the manifest
        # dag.
        GitHgHelper.set(b'manifest', manifest, manifest_ref)

        if not GitHgHelper.check_manifest(manifest):
            status.report('Sha1 mismatch for manifest %s'
                          % manifest.decode('ascii'))

        manifest_commit_parents = GitCommit(manifest_ref).parents
        if sorted(manifest_commit_parents) != sorted(git_parents):
            # TODO: better error
            status.report('%s(%s) %s != %s' % (
                manifest.decode('ascii'),
                manifest_ref.decode('ascii'),
                ' '.join(p.decode('ascii') for p in manifest_commit_parents),
                ' '.join(p.decode('ascii') for p in git_parents)))

        # TODO: check that manifest content matches changeset content

        changes = get_changes(manifest_ref, git_parents)
        for path, hg_file, hg_fileparents in changes:
            if hg_file != NULL_NODE_ID and (hg_file == HG_EMPTY_FILE or
                                            GitHgHelper.seen(b'hg2git',
                                                             hg_file)):
                if full_file_check:
                    file = store.file(hg_file, hg_fileparents)
                    valid = file.node == file.sha1
                else:
                    valid = GitHgHelper.check_file(hg_file,
                                                   *hg_fileparents)
                if not valid:
                    status.report(
                        'Sha1 mismatch for file %s in manifest %s'
                        % (hg_file.decode('ascii'),
                           manifest_ref.decode('ascii')))

    if not args.commit and not status('broken'):
        store_manifest_heads = set(store._manifest_heads_orig)
        manifest_heads = set(GitHgHelper.heads(b'manifests'))
        if store_manifest_heads != manifest_heads:
            def iter_manifests(a, b):
                for h in a - b:
                    yield h
                for h in b:
                    yield b'^%s' % h

            for m, t, p in GitHgHelper.rev_list(
                    b'--topo-order', b'--full-history', b'--reverse',
                    *iter_manifests(manifest_heads, store_manifest_heads)):
                status.fix('Missing manifest commit in manifest branch: %s'
                           % m.decode('ascii'))

            for m, t, p in GitHgHelper.rev_list(
                    b'--topo-order', b'--full-history', b'--reverse',
                    *iter_manifests(store_manifest_heads, manifest_heads)):
                status.fix('Removing manifest commit %s with no corresponding '
                           'changeset' % (m.decode('ascii')))

            for h in store_manifest_heads - manifest_heads:
                if GitHgHelper.seen(b'hg2git', store.hg_manifest(h)):
                    status.fix('Removing non-head reference to %s in manifests'
                               ' metadata.' % h.decode('ascii'))
    dangling = ()
    if not args.commit and not status('broken'):
        dangling = GitHgHelper.dangling(b'hg2git')
    for obj in dangling:
        status.fix('Removing dangling metadata for ' + obj.decode('ascii'))
        # Theoretically, we should figure out if they are files, manifests
        # or changesets and set the right variable accordingly, but in
        # practice, it makes no difference. Reevaluate when GitHgStore.close
        # is modified, though.
        GitHgHelper.set(b'file', obj, NULL_NODE_ID)
        GitHgHelper.set(b'file-meta', obj, NULL_NODE_ID)

    if not args.commit and not status('broken'):
        dangling = GitHgHelper.dangling(b'git2hg')
    for c in dangling:
        status.fix('Removing dangling note for commit ' + c.decode('ascii'))
        GitHgHelper.set(b'changeset-metadata', c, NULL_NODE_ID)

    check_replace(store)

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
                           (head.decode('ascii'), os.fsdecode(branch)))
                store.add_head(head)
            for head in stored_heads - computed_heads[branch]:
                status.fix('Removing non-head reference to %s in branch %s' %
                           (head.decode('ascii'), os.fsdecode(branch)))
                del store._hgheads[head]

    metadata_commit = Git.resolve_ref('refs/cinnabar/metadata')
    if status('broken'):
        Git.update_ref(b'refs/cinnabar/broken', metadata_commit)
        return 1

    if args.full:
        Git.update_ref(b'refs/cinnabar/checked', metadata_commit)
    interval_expired('fsck', 0)
    store.close()

    if status('fixed'):
        return 2
    return 0
