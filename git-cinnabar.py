#!/usr/bin/env python2.7

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'pythonlib'))

import argparse
from cinnabar.githg import (
    ChangesetData,
    GitHgStore,
    EMPTY_TREE,
    NULL_NODE_ID,
    one,
)
from cinnabar.dag import gitdag
from cinnabar.git import (
    Git,
    Mark,
)
from cinnabar.util import (
    LazyString,
    progress_iter,
)
from cinnabar.helper import (
    GitHgHelper,
    NoHelperException,
)
from cinnabar.bundle import get_changes
from collections import (
    defaultdict,
    OrderedDict,
)
from itertools import chain


def fsck(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--manifests', action='store_true',
        help='Validate manifests hashes')
    parser.add_argument(
        '--files', action='store_true',
        help='Validate files hashes')
    parser.add_argument(
        'commit', nargs='*',
        help='Specific commit or changeset to check')
    args = parser.parse_args(args)

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

    store = GitHgStore()
    store.init_fast_import(lazy=True)

    replace_commits = ['^%s^@' % r[22:]
                       for r in Git.for_each_ref('refs/cinnabar/replace',
                                                 format='%(refname)')]

    if args.commit:
        all_hg2git = {}
        all_notes = set()
        commits = set()
        all_git_commits = {}

        for c in args.commit:
            data = store.read_changeset_data(c)
            if data:
                all_notes.add(c)
                commits.add(c)
                c = data['changeset']
            commit = GitHgHelper.hg2git(c)
            if commit == NULL_NODE_ID and not data:
                info('Unknown commit or changeset: %s' % c)
                return 1
            if commit != NULL_NODE_ID:
                all_hg2git[c] = commit, 'commit'
            if not data:
                data = store.read_changeset_data(commit)
                commits.add(commit)
                if data:
                    all_notes.add(commit)

        all_git_commits = Git.iter(
            'log', '--no-walk=unsorted', '--stdin', '--format=%T %H',
            stdin=commits)
    else:
        all_hg2git = {
            path.replace('/', ''): (filesha1, intern(typ))
            for mode, typ, filesha1, path in
            progress_iter('Reading %d mercurial to git mappings',
                          Git.ls_tree('refs/cinnabar/hg2git', recursive=True))
        }

        all_notes = set(path.replace('/', '') for mode, typ, filesha1, path in
                        progress_iter(
                            'Reading %d commit to changeset mappings',
                            Git.ls_tree('refs/notes/cinnabar',
                                        recursive=True)))

        manifest_commits = OrderedDict((m, None) for m in progress_iter(
            'Reading %d manifest trees',
            Git.iter('rev-list', '--full-history',
                     '--topo-order', 'refs/cinnabar/manifest'))
        )

        all_git_heads = chain(
            Git.for_each_ref('refs/cinnabar/branches', format='%(refname)'),
            replace_commits,
        )

        all_git_commits = Git.iter('log', '--topo-order', '--full-history',
                                   '--reverse', '--stdin', '--format=%T %H',
                                   stdin=all_git_heads)

    store._hg2git_cache = {p: s for p, (s, t) in all_hg2git.iteritems()}

    seen_changesets = set()
    seen_manifests = set()
    seen_manifest_refs = {}
    seen_files = set()
    seen_notes = set()

    hg_manifest = None

    dag = gitdag()

    def iterate_all_commits(git_commits):
        for line in git_commits:
            tree, node = line.split(' ')
            if node in store._replace:
                git_heads = [store._replace[node]] + replace_commits
                git_commits = Git.iter('log', '--topo-order', '--full-history',
                                       '--reverse', '--stdin',
                                       '--format=%T %H', stdin=git_heads)
                for tree, node in iterate_all_commits(git_commits):
                    yield tree, node
            else:
                yield tree, node

    for tree, node in progress_iter('Checking %d changesets',
                                    iterate_all_commits(all_git_commits)):
        if node not in all_notes:
            report('Missing note for git commit: ' + node)
            continue
        seen_notes.add(node)

        changeset_data = store.read_changeset_data(node)
        changeset = changeset_data['changeset']
        if 'extra' in changeset_data:
            extra = changeset_data['extra']
            header, message = GitHgHelper.cat_file(
                'commit', node).split('\n\n', 1)
            header = dict(l.split(' ', 1) for l in header.splitlines())
            if 'committer' in extra:
                committer_info = store.hg_author_info(header['committer'])
                committer = '%s %d %d' % committer_info
                if (committer != extra['committer'] and
                        header['committer'] != extra['committer'] and
                        committer_info[0] != extra['committer']):
                    report('Committer mismatch between commit and metadata for'
                           ' changeset %s' % changeset)
                if committer == extra['committer']:
                    fix('Fixing useless committer metadata for changeset %s'
                        % changeset)
                    del changeset_data['extra']['committer']
                    store._changesets[changeset] = LazyString(node)
            if header['committer'] != header['author'] and not extra:
                fix('Fixing useless empty extra metadata for changeset %s'
                    % changeset)
                del changeset_data['extra']
                store._changesets[changeset] = LazyString(node)

        seen_changesets.add(changeset)
        changeset_ref = store.changeset_ref(changeset)
        if not changeset_ref:
            report('Missing changeset in hg2git branch: %s' % changeset)
        elif str(changeset_ref) != node:
            report('Commit mismatch for changeset %s\n'
                   '  hg2git: %s\n  commit: %s'
                   % (changeset, changeset_ref, node))

        hg_changeset = store.changeset(changeset, include_parents=True)
        sha1 = hg_changeset.sha1
        if hg_changeset.node != sha1:
            try_fixup = False
            if (changeset, sha1) in (
                ('8c557b7c03a4a753e5c163038f04862e9f65fce1',
                 '249b59139de8e08abeb6c4e261a137c756e7af0e'),
                ('ffdee4a4eb7fc7cae80dfc4cb2fe0c3178773dcf',
                 '415e9d2eac83d508bf58a4df585c5f6b2b0f44ed'),
            ):
                header = hg_changeset.data.split('\n', 4)
                start = sum(len(h) for h in header[:3]) + 1
                changeset_data['patch'] = ((start, start + 1, '1'),)
                try_fixup = True

            # Some know cases of corruptions involve a whitespace after the
            # timezone. Adding an empty extra metadata works around those.
            elif 'extra' not in changeset_data:
                changeset_data['extra'] = {}
                try_fixup = True

            if try_fixup:
                hg_changeset = store.changeset(changeset, include_parents=True)
                sha1 = hg_changeset.sha1
                if hg_changeset.node == sha1:
                    fix('Fixing known sha1 mismatch for changeset %s' %
                        changeset)
                    store._changesets[changeset] = LazyString(node)

        if hg_changeset.node != sha1:
            report('Sha1 mismatch for changeset %s' % changeset)

        dag.add(hg_changeset.node,
                (hg_changeset.parent1, hg_changeset.parent2),
                changeset_data.get('extra', {}).get('branch', 'default'))

        manifest = changeset_data['manifest']
        if manifest in seen_manifests:
            continue
        seen_manifests.add(manifest)
        manifest_ref = store.manifest_ref(manifest)
        if manifest_ref:
            seen_manifest_refs[manifest_ref] = manifest
        if not manifest_ref:
            report('Missing manifest in hg2git branch: %s' % manifest)
        elif not args.commit and manifest_ref not in manifest_commits:
            report('Missing manifest commit in manifest branch: %s' %
                   manifest_ref)

        if args.manifests or args.files:
            parents = tuple(
                store.read_changeset_data(store.changeset_ref(p))['manifest']
                for p in (hg_changeset.parent1, hg_changeset.parent2)
                if p != NULL_NODE_ID
            )

        if args.manifests:
            try:
                with GitHgHelper.query('check-manifest', manifest,
                                       *parents) as stdout:
                    if stdout.readline().strip() != 'ok':
                        report('Sha1 mismatch for manifest %s' % manifest)
            except NoHelperException:
                hg_manifest = store.manifest(manifest)
                hg_manifest.set_parents(*parents)
                if hg_manifest.node != hg_manifest.sha1:
                    report('Sha1 mismatch for manifest %s' % manifest)

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
            changes = get_changes(
                manifest_ref, tuple(store.manifest_ref(p) for p in parents),
                'hg')
            for path, hg_file, hg_fileparents in changes:
                if hg_file != NULL_NODE_ID and hg_file not in seen_files:
                    file = store.file(hg_file)
                    file.set_parents(*hg_fileparents)
                    if file.node != file.sha1:
                        report('Sha1 mismatch for file %s in manifest %s'
                               % (hg_file, manifest_ref))
                    seen_files.add(hg_file)

    if args.files:
        all_hg2git = set(all_hg2git.iterkeys())
    else:
        all_hg2git = set(k for k, (s, t) in all_hg2git.iteritems()
                         if t == 'commit')

    adjusted = {}
    if not args.commit:
        dangling = set(manifest_commits) - set(seen_manifest_refs)
        if dangling:
            def iter_manifests():
                removed_one = False
                yielded = False
                previous = None
                for obj in reversed(manifest_commits):
                    if obj in dangling:
                        fix('Removing metadata commit %s with no hg2git entry'
                            % obj)
                        removed_one = True
                    else:
                        if removed_one:
                            yield obj, previous
                            yielded = True
                        previous = obj

                if removed_one and not yielded:
                    yield obj, False

            for obj, parent in progress_iter('Adjusting %d metadata commits',
                                             iter_manifests()):
                mark = store._fast_import.new_mark()
                if parent is False:
                    Git.update_ref('refs/cinnabar/manifest', obj)
                    continue
                elif parent:
                    parents = (adjusted.get(parent, parent),)
                with store._fast_import.commit(
                        ref='refs/cinnabar/manifest',
                        parents=parents, mark=mark) as commit:
                    mode, typ, tree, path = store._fast_import.ls(obj)
                    commit.filemodify('', tree, typ='tree')
                adjusted[obj] = Mark(mark)

    dangling = all_hg2git - seen_changesets - seen_manifests - seen_files
    for obj in dangling:
        fix('Removing dangling metadata for ' + obj)
        # Theoretically, we should figure out if they are files, manifests
        # or changesets and set the right variable accordingly, but in
        # practice, it makes no difference. Reevaluate when GitHgStore.close
        # is modified, though.
        store._files[obj] = None

    for obj, mark in progress_iter(
            'Updating hg2git for %d metadata commits',
            adjusted.iteritems()):
        store._manifests[obj] = mark

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
                store._hgheads.remove((branch, head))

    store.close()

    if status['broken']:
        return 1
    if status['fixed']:
        return 2
    return 0


def main(args):
    cmd = args.pop(0)
    if cmd == 'data':
        store = GitHgStore()
        if args[0] == '-c':
            sys.stdout.write(store.changeset(args[1]).data)
        elif args[0] == '-m':
            sys.stdout.write(store.manifest(args[1]).data)
        store.close()
    elif cmd == 'fsck':
        return fsck(args)
    elif cmd == 'reclone':
        for ref in Git.for_each_ref('refs/cinnabar', 'refs/notes/cinnabar',
                                    format='%(refname)'):
            Git.delete_ref(ref)
        Git.close()

        for line in Git.iter('config', '--get-regexp', 'remote\..*\.url'):
            config, url = line.split()
            name = config[len('remote.'):-len('.url')]
            skip_pref = 'remote.%s.skipDefaultUpdate' % name
            if (url.startswith('hg::') and
                    Git.config(skip_pref, 'bool') != 'true'):
                Git.run('remote', 'update', '--prune', name)

        print 'Please note that reclone left your local branches untouched.'
        print 'They may be based on entirely different commits.'
    elif cmd == 'hg2git':
        for arg in args:
            print GitHgHelper.hg2git(arg)
    elif cmd == 'git2hg':
        for arg in args:
            data = GitHgHelper.git2hg(arg)
            if data:
                data = ChangesetData.parse(data)
                print data.get('changeset', NULL_NODE_ID)
            else:
                print NULL_NODE_ID
    elif cmd == 'python':
        import code
        code.interact()
    else:
        print >>sys.stderr, 'Unknown command:', cmd
        return 1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
