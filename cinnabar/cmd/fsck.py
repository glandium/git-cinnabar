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
    OldUpgradeException,
    one,
    UpgradeException,
)
from cinnabar.dag import gitdag
from cinnabar.git import (
    EMPTY_TREE,
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
    OrderedDict,
)


class UpgradeGitHgStore(GitHgStore):
    def metadata(self):
        return self._metadata()


@CLI.subcommand
@CLI.argument('--manifests', action='store_true',
              help='Validate manifests hashes')
@CLI.argument('--files', action='store_true',
              help='Validate files hashes')
@CLI.argument('commit', nargs='*',
              help='Specific commit or changeset to check')
def fsck(args):
    '''check cinnabar metadata consistency'''

    status = {
        'broken': False,
        'fixed': False,
    }

    def info(message):
        sys.stderr.write('\r')
        print message

    def fix(message):
        status['fixed'] = True
        info(message)

    def report(message):
        status['broken'] = True
        info(message)

    try:
        store = GitHgStore()
    except OldUpgradeException as e:
        print >>sys.stderr, e.message
        return 1
    except UpgradeException:
        store = UpgradeGitHgStore()

    upgrade = isinstance(store, UpgradeGitHgStore)

    if upgrade and (args.commit or args.manifests or args.files):
        if args.commit:
            what = 'specifying commit(s)'
        elif args.manifests:
            what = '--manifests'
        elif args.files:
            what = '--files'
        info('Git-cinnabar metadata needs upgrade. '
             'Please re-run without %s.' % what)
        return 1

    if upgrade:
        if not GitHgHelper.upgrade():
            print 'Cannot finish upgrading... You may need to reclone.'
            return 1

        info('Finalizing upgrade...')
        # "Reboot" the store, and run a normal fsck from the upgraded store.
        store.close()

        # Force the helper to be restarted.
        GitHgHelper._helper = False
        store = GitHgStore()

        # Force a files fsck, since we modified files metadata.
        args.files = 'upgrade'

    if args.commit:
        all_hg2git = {}
        all_notes = set()
        commits = set()
        all_git_commits = {}

        for c in args.commit:
            cs = store.hg_changeset(c)
            if cs:
                all_notes.add(c)
                commits.add(c)
                c = cs.node
            commit = GitHgHelper.hg2git(c)
            if commit == NULL_NODE_ID and not cs:
                info('Unknown commit or changeset: %s' % c)
                return 1
            if commit != NULL_NODE_ID:
                all_hg2git[c] = commit, 'commit'
            if not cs:
                cs = store.hg_changeset(commit)
                commits.add(commit)
                if cs:
                    all_notes.add(commit)

        all_git_commits = GitHgHelper.rev_list('--no-walk=unsorted', *commits)
    else:
        all_refs = set(ref for sha1, ref in Git.for_each_ref('refs/cinnabar'))

        if 'refs/cinnabar/metadata' in all_refs:
            # We rely on the store having created these refs (temporarily or
            # not).
            git_heads = '%s^@' % Git.resolve_ref('refs/cinnabar/changesets')
            manifests_rev = '%s^@' % Git.resolve_ref('refs/cinnabar/manifests')
            hg2git_rev = Git.resolve_ref('refs/cinnabar/hg2git')
            notes_rev = Git.resolve_ref('refs/notes/cinnabar')
        else:
            assert False

        all_hg2git = {
            path.replace('/', ''): (filesha1, intern(typ))
            for mode, typ, filesha1, path in
            progress_iter('Reading %d mercurial to git mappings',
                          Git.ls_tree(hg2git_rev, recursive=True))
        }

        all_notes = set(path.replace('/', '') for mode, typ, filesha1, path in
                        progress_iter(
                            'Reading %d commit to changeset mappings',
                            Git.ls_tree(notes_rev, recursive=True)))

        commit = GitCommit(Git.resolve_ref('refs/cinnabar/manifests'))
        if commit.body == 'has-flat-manifest-tree':
            revs = commit.parents[1:]
        else:
            revs = (manifests_rev,)

        manifest_commits = OrderedDict((m, p) for m, t, p in progress_iter(
            'Reading %d manifest trees',
            GitHgHelper.rev_list('--full-history', '--topo-order', '--reverse',
                                 *revs)
        ))

        all_git_commits = GitHgHelper.rev_list(
            '--topo-order', '--full-history', '--reverse', git_heads)

    seen_changesets = set()
    seen_manifests = set()
    seen_files = set()
    seen_notes = set()

    dag = gitdag()
    manifest_dag = gitdag()

    full_file_check = FileFindParents.logger.isEnabledFor(logging.DEBUG)

    for node, tree, parents in progress_iter('Checking %d changesets',
                                             all_git_commits):
        node = store._replace.get(node, node)
        if node not in all_notes:
            report('Missing note for git commit: ' + node)
            continue
        seen_notes.add(node)

        changeset_data = store.changeset(store.hg_changeset(node))
        changeset = changeset_data.node

        seen_changesets.add(changeset)
        changeset_ref = store.changeset_ref(changeset)
        if not changeset_ref:
            report('Missing changeset in hg2git branch: %s' % changeset)
            continue
        elif str(changeset_ref) != node:
            report('Commit mismatch for changeset %s\n'
                   '  hg2git: %s\n  commit: %s'
                   % (changeset, changeset_ref, node))

        hg_changeset = store.changeset(changeset, include_parents=True)
        if hg_changeset.node != hg_changeset.sha1:
            report('Sha1 mismatch for changeset %s' % changeset)

        dag.add(hg_changeset.node,
                (hg_changeset.parent1, hg_changeset.parent2),
                changeset_data.branch or 'default')

        raw_changeset = Changeset.from_git_commit(node)
        patcher = ChangesetPatcher.from_diff(raw_changeset, changeset_data)
        if patcher != store.read_changeset_data(node):
            fix('Adjusted changeset metadata for %s' % changeset)
            GitHgHelper.set('changeset', changeset, NULL_NODE_ID)
            GitHgHelper.set('changeset', changeset, node)
            store._fast_import.put_blob(patcher, want_sha1=False)
            GitHgHelper.set('changeset-metadata', changeset, NULL_NODE_ID)
            GitHgHelper.set('changeset-metadata', changeset, ':1')

        manifest = changeset_data.manifest
        if manifest in seen_manifests or manifest == NULL_NODE_ID:
            continue
        seen_manifests.add(manifest)
        manifest_ref = store.manifest_ref(manifest)
        if not manifest_ref:
            report('Missing manifest in hg2git branch: %s' % manifest)
        elif not args.commit and manifest_ref not in manifest_commits:
            fix('Missing manifest commit in manifest branch: %s' %
                manifest_ref)
            manifest_commits[manifest_ref] = GitCommit(manifest_ref).parents

        parents = tuple(
            store.changeset(p).manifest
            for p in hg_changeset.parents
        )
        git_parents = tuple(store.manifest_ref(p) for p in parents
                            if p != NULL_NODE_ID)

        manifest_dag.add(manifest_ref, git_parents)

        if args.manifests:
            if not GitHgHelper.check_manifest(manifest):
                report('Sha1 mismatch for manifest %s' % manifest)

        if args.commit:
            manifest_commit_parents = GitCommit(manifest_ref).parents
        else:
            manifest_commit_parents = manifest_commits.get(manifest_ref, ())
        if sorted(manifest_commit_parents) != sorted(git_parents):
            # TODO: better error
            report('%s(%s) %s != %s' % (manifest, manifest_ref,
                                        manifest_commit_parents,
                                        git_parents))

        git_ls = one(Git.ls_tree(manifest_ref, 'git'))
        if git_ls:
            mode, typ, sha1, path = git_ls
        else:
            if GitCommit(manifest_ref).tree == EMPTY_TREE:
                sha1 = EMPTY_TREE
            else:
                report('Missing git tree in manifest commit %s' % manifest_ref)
                sha1 = None
        if sha1 and sha1 != tree:
            report('Tree mismatch between manifest commit %s and commit %s'
                   % (manifest_ref, node))

        if args.files:
            changes = get_changes(manifest_ref, git_parents, 'hg')
            for path, hg_file, hg_fileparents in changes:
                if hg_file != NULL_NODE_ID and hg_file not in seen_files:
                    if full_file_check:
                        file = store.file(hg_file, hg_fileparents, git_parents,
                                          path)
                        valid = file.node == file.sha1
                    else:
                        valid = GitHgHelper.check_file(hg_file,
                                                       *hg_fileparents)
                    if not valid:
                        report('Sha1 mismatch for file %s in manifest %s'
                               % (hg_file, manifest_ref))
                    seen_files.add(hg_file)

    if args.files:
        all_hg2git = set(all_hg2git.iterkeys())
    else:
        all_hg2git = set(k for k, (s, t) in all_hg2git.iteritems()
                         if t == 'commit')

    if not args.commit and not status['broken']:
        store_manifest_heads = set(store._manifest_heads_orig)
        manifest_heads = set(manifest_dag.heads())
        if store_manifest_heads != manifest_heads:
            store._override_manifest_heads = manifest_heads

            def iter_manifests():
                for h in store_manifest_heads - manifest_heads:
                    yield h
                for h in manifest_heads:
                    yield '^%s' % h

            for m, t, p in GitHgHelper.rev_list(
                    '--topo-order', '--full-history', '--reverse',
                    *iter_manifests()):
                fix('Removing metadata commit %s with no corresponding '
                    'changeset' % (m))

            for h in store_manifest_heads - manifest_heads:
                if h in manifest_dag:
                    fix('Removing non-head reference to %s in manifests '
                        'metadata.' % h)
    dangling = ()
    if not status['broken']:
        dangling = all_hg2git - seen_changesets - seen_manifests - seen_files
        if HG_EMPTY_FILE in all_hg2git:
            dangling.add(HG_EMPTY_FILE)
    for obj in dangling:
        fix('Removing dangling metadata for ' + obj)
        # Theoretically, we should figure out if they are files, manifests
        # or changesets and set the right variable accordingly, but in
        # practice, it makes no difference. Reevaluate when GitHgStore.close
        # is modified, though.
        GitHgHelper.set('file', obj, NULL_NODE_ID)
        GitHgHelper.set('file-meta', hg_file, NULL_NODE_ID)

    if not status['broken']:
        dangling = all_notes - seen_notes
    for c in dangling:
        fix('Removing dangling note for commit ' + c)
        GitHgHelper.set('changeset-metadata', c, NULL_NODE_ID)

    if status['broken']:
        info('Your git-cinnabar repository appears to be corrupted. There\n'
             'are known issues in older revisions that have been fixed.\n'
             'Please try running the following command to reset:\n'
             '  git cinnabar reclone\n\n'
             'Please note this command may change the commit sha1s. Your\n'
             'local branches will however stay untouched.\n'
             'Please report any corruption that fsck would detect after a\n'
             'reclone.')

    if not args.commit:
        info('Checking head references...')
        computed_heads = defaultdict(set)
        for branch, head in dag.all_heads():
            computed_heads[branch].add(head)

        for branch in sorted(dag.tags()):
            stored_heads = store.heads({branch})
            for head in computed_heads[branch] - stored_heads:
                fix('Adding missing head %s in branch %s' %
                    (head, branch))
                store.add_head(head)
            for head in stored_heads - computed_heads[branch]:
                fix('Removing non-head reference to %s in branch %s' %
                    (head, branch))
                del store._hgheads[head]

    store.close()

    if status['broken']:
        return 1
    if status['fixed']:
        return 2
    return 0
