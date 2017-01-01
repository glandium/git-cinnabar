import sys
from cinnabar.cmd.util import CLI
from cinnabar.githg import (
    GeneratedManifestInfo,
    GitCommit,
    GitHgStore,
    HG_EMPTY_FILE,
    ManifestLine,
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
    progress_enum,
    progress_iter,
    sorted_merge,
)
from cinnabar.helper import GitHgHelper
from cinnabar.hg.bundle import get_changes
from cinnabar.hg.objects import Authorship
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

    store.init_fast_import(lazy=True)

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

    if upgrade:
        store._manifest_heads_orig = set()

        def _diff_tree(a, b, base_path):
            if not b:
                for line in Git.ls_tree(a, base_path, recursive=True):
                    mode, typ, sha1, path = line
                    path = path[len(base_path) + 1:] if base_path else path
                    yield path, sha1, mode, 'A'
            else:
                assert len(b) == 1
                for line in Git.diff_tree(b[0], a, base_path):
                    _mode, mode, _sha1, sha1, status, path = line
                    yield path, sha1, mode, status

        def manifest_git2hg(sha1):
            return GitCommit(sha1).body

        def scan_files():
            seen_files = set()
            for i, (m, p) in enumerate(manifest_commits.iteritems(), start=1):
                git_changes = _diff_tree(m, p[:1], 'git')
                hg_changes = _diff_tree(m, p[:1], 'hg')
                manifest = GeneratedManifestInfo(NULL_NODE_ID)
                manifest.node = manifest_git2hg(m)
                manifest.set_parents(*(manifest_git2hg(c) for c in p))
                manifest.delta_node = manifest.parent1
                for path, git_change, hg_change in sorted_merge(git_changes,
                                                                hg_changes):
                    if git_change:
                        git_file, mode, _ = git_change
                    else:
                        mode, _, git_file, p = one(
                            Git.ls_tree(m, 'git/%s' % path))
                    if hg_change:
                        hg_file, _, status = hg_change
                    else:
                        # The only case where a hg change would be missing is
                        # when there is an attribute change
                        status = 'M'
                        hg_file = one(Git.ls_tree(m, 'hg/%s' % path))[2]
                    if status == 'D':
                        manifest.removed.add(path)
                        continue
                    attr = store.ATTR[mode]
                    manifest.append_line(ManifestLine(path, hg_file, attr),
                                         modified=True)
                    if hg_file != NULL_NODE_ID and hg_file not in seen_files:
                        seen_files.add(hg_file)
                        yield (i, len(seen_files)), (hg_file, git_file)

                store._manifests[manifest.node] = None
                store.store_manifest(manifest)
                assert store._manifests[manifest.node] == m

        if 'files-meta' not in store._flags:
            for f in progress_enum('Upgrading %d manifests and '
                                   '%d files metadata', scan_files()):
                hg_file, git_file = f
                if hg_file == HG_EMPTY_FILE:
                    continue
                if hg_file not in all_hg2git:
                    report('Missing file in hg2git branch: %s' % hg_file)
                    continue
                hg2git_file, typ = all_hg2git[hg_file]
                if typ != 'blob':
                    report('Metadata corrupted for file %s' % hg_file)
                    continue
                if hg2git_file == git_file:
                    continue
                full_content = GitHgHelper.cat_file('blob', hg2git_file)
                content = GitHgHelper.cat_file('blob', git_file)
                metadata = full_content[:len(full_content) - len(content)]
                if (not metadata.startswith('\1\n') and
                        not metadata.endswith('\1\n')):
                    report('Metadata corrupted for file %s' % hg_file)
                store._git_files[hg_file] = git_file
                store._files_meta[hg_file] = metadata[2:-2]
        else:
            def scan_manifests():
                prev = 0
                for (i, j), _ in scan_files():
                    if i != prev:
                        yield i, None
                        prev = i
            for _ in progress_enum('Upgrading %d manifests', scan_manifests()):
                continue

        if status['broken']:
            print 'Cannot finish upgrading... You may need to reclone.'
            return 1

        # Technically, all_hg2git should be updated here, but we don't use the
        # git sha1 in there further below, so skip that.

        # "Reboot" the store, and run a normal fsck from the upgraded store.
        store.close()
        # Force the helper to be restarted.
        GitHgHelper._helper = False
        store = GitHgStore()

        # Force a files fsck, since we modified files metadata.
        args.files = True

    seen_changesets = set()
    seen_manifests = set()
    seen_files = set()
    seen_notes = set()

    dag = gitdag()
    manifest_dag = gitdag()

    for node, tree, parents in progress_iter('Checking %d changesets',
                                             all_git_commits):
        node = store._replace.get(node, node)
        if node not in all_notes:
            report('Missing note for git commit: ' + node)
            continue
        seen_notes.add(node)

        changeset_data = store.changeset(store.hg_changeset(node))
        changeset = changeset_data.node
        if changeset_data.extra:
            extra = changeset_data.extra
            commit = GitCommit(node)
            if 'committer' in extra:
                committer_info = Authorship.from_git_str(
                    commit.committer).to_hg()
                committer = ' '.join(committer_info)
                if (committer != extra['committer'] and
                        commit.committer != extra['committer'] and
                        committer_info[0] != extra['committer']):
                    report('Committer mismatch between commit and metadata for'
                           ' changeset %s' % changeset)
                if committer == extra['committer']:
                    report('Useless committer metadata for changeset %s'
                           % changeset)
            if commit.committer != commit.author and not extra:
                report('Useless empty extra metadata for changeset %s'
                       % changeset)

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

        manifest = changeset_data.manifest
        if manifest in seen_manifests or manifest == NULL_NODE_ID:
            continue
        seen_manifests.add(manifest)
        manifest_ref = store.manifest_ref(manifest)
        if not manifest_ref:
            report('Missing manifest in hg2git branch: %s' % manifest)
        elif (not args.commit and manifest_ref not in manifest_commits):
            report('Missing manifest commit in manifest branch: %s' %
                   manifest_ref)

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
            header, message = GitHgHelper.cat_file(
                'commit', manifest_ref).split('\n\n', 1)
            header = dict(l.split(' ', 1) for l in header.splitlines())
            if header['tree'] == EMPTY_TREE:
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
                    file = store.file(hg_file, hg_fileparents, git_parents,
                                      path)
                    if file.node != file.sha1:
                        report('Sha1 mismatch for file %s in manifest %s'
                               % (hg_file, manifest_ref))
                    seen_files.add(hg_file)

    if args.files:
        all_hg2git = set(all_hg2git.iterkeys())
    else:
        all_hg2git = set(k for k, (s, t) in all_hg2git.iteritems()
                         if t == 'commit')

    if not args.commit and not status['broken']:
        store_manifest_heads = set(store._manifest_dag.heads())
        manifest_heads = set(manifest_dag.heads())
        if store_manifest_heads != manifest_heads:
            store._manifest_dag = manifest_dag

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
        store._git_files[obj] = None
        store._files_meta[obj] = None

    if not status['broken']:
        dangling = all_notes - seen_notes
    for c in dangling:
        fix('Removing dangling note for commit ' + c)
        store._changeset_data_cache[c] = None

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
