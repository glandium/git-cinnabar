import hashlib
import logging
import os
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
    progress_iter,
)
from cinnabar.helper import GitHgHelper
from cinnabar.hg.bundle import get_changes
from collections import defaultdict


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


def get_replace():
    replace = {}
    for line in Git.ls_tree(Git.resolve_ref('refs/cinnabar/metadata')):
        mode, typ, sha1, path = line
        replace[path] = sha1
    return replace


def check_replace():
    self_refs = [r for r, s in get_replace().items() if r == s]
    for r in progress_iter('Removing {} self-referencing grafts', self_refs):
        GitHgHelper.set(b'replace', r, NULL_NODE_ID)


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

    assert args.commit or args.full

    status = FsckStatus()

    store = GitHgStore()

    if args.full and args.commit:
        logging.error('Cannot pass both --full and a commit')
        return 1

    if args.commit:
        commits = set()
        all_git_commits = {}

        for c in args.commit:
            c = c.encode('ascii')
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

    store_manifest_heads = set(GitHgHelper.heads(b'manifests'))
    GitHgHelper.reset_heads(b'manifests')

    full_file_check = FileFindParents.logger.isEnabledFor(logging.DEBUG)

    replace = get_replace()
    for node, tree, parents in progress_iter('Checking {} changesets',
                                             all_git_commits):
        node = replace.get(node, node)
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

        hg_changeset = store.changeset(changeset)
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

    check_replace()

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
                blob = GitHgHelper.git2hg(head)
                assert blob
                h = hashlib.sha1(b'blob %d\0' % len(blob))
                h.update(blob)
                sha1 = h.hexdigest().encode('ascii')
                GitHgHelper.set(b'changeset-head', head, sha1)
            for head in stored_heads - computed_heads[branch]:
                status.fix('Removing non-head reference to %s in branch %s' %
                           (head.decode('ascii'), os.fsdecode(branch)))
                GitHgHelper.set(b'changeset-head', head, NULL_NODE_ID)

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
