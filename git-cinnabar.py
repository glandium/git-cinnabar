#!/usr/bin/env python2.7

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'pythonlib'))

import argparse
from githg import (
    ChangesetData,
    GitHgStore,
    EMPTY_TREE,
    NULL_NODE_ID,
    split_ls_tree,
    one,
)
from git import (
    FastImport,
    Git,
    sha1path,
)
from git.util import (
    LazyString,
    progress_iter,
)
from githg.helper import (
    GitHgHelper,
    NoHelperException,
)
from githg.bundle import get_changes
import subprocess


def fsck(args):
    # TODO: Add arguments to enable more sha1 checks
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifests', action='store_true',
        help='Validate manifests hashes')
    parser.add_argument('--files', action='store_true',
        help='Validate files hashes')
    parser.add_argument('commit', nargs='*',
        help='Specific commit or changeset to check')
    args = parser.parse_args(args)

    status = { 'broken': False }

    def info(message):
        sys.stderr.write('\r')
        print message

    def report(message):
        status['broken'] = True
        info(message)

    store = GitHgStore()
    store.init_fast_import(lambda: FastImport())

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
            stdin=''.join('%s\n' % c for c in commits))
    else:
        all_hg2git = {
            path.replace('/', ''): (filesha1, intern(typ))
            for mode, typ, filesha1, path in
            progress_iter('Reading %d mercurial to git mappings',
            Git.ls_tree('refs/cinnabar/hg2git', recursive=True))
        }

        all_notes = set(path.replace('/', '') for mode, typ, filesha1, path in
            progress_iter('Reading %d commit to changeset mappings',
            Git.ls_tree('refs/notes/cinnabar', recursive=True)))

        manifest_commits = set(progress_iter('Reading %d manifest trees',
                               Git.iter('rev-list', '--full-history',
                                        'refs/cinnabar/manifest')))

        def all_git_heads():
            for ref in Git.for_each_ref('refs/cinnabar/branches',
                                        format='%(refname)'):
                yield ref + '\n'

        all_git_commits = Git.iter('log', '--topo-order', '--full-history',
                                   '--reverse', '--stdin', '--format=%T %H',
                                   stdin=all_git_heads)

    store._hg2git_cache = { p: s for p, (s, t) in all_hg2git.iteritems() }

    seen_changesets = set()
    seen_manifests = set()
    seen_manifest_refs = set()
    seen_files = set()
    seen_notes = set()

    hg_manifest = None

    for line in progress_iter('Checking %d changesets', all_git_commits):
        tree, node = line.split(' ')
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
                committer = '%s %s %d' % committer_info
                if committer != extra['committer'] and \
                        committer_info[0] != extra['committer']:
                    report('Committer mismatch between commit and metadata for'
                           ' changeset %s' % changeset)
                if committer == extra['committer']:
                    info('Fixing useless committer metadata for changeset %s' \
                         % changeset)
                    del changeset_data['extra']['committer']
                    store._changesets[changeset] = LazyString(node)
            if header['committer'] != header['author'] and not extra:
                info('Fixing useless empty extra metadata for changeset %s'
                     % changeset)
                del changeset_data['extra']
                store._changesets[changeset] = LazyString(node)

        seen_changesets.add(changeset)
        changeset_ref = store.changeset_ref(changeset)
        if not changeset_ref:
            report('Missing changeset in hg2git branch: %s' % changeset)
        if str(changeset_ref) != node:
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
                    info('Fixing known sha1 mismatch for changeset %s' %
                         changeset)
                    store._changesets[changeset] = LazyString(node)

        if hg_changeset.node != sha1:
            report('Sha1 mismatch for changeset %s' % changeset)

        manifest = changeset_data['manifest']
        if manifest in seen_manifests:
            continue
        seen_manifests.add(manifest)
        manifest_ref = store.manifest_ref(manifest)
        if manifest_ref:
            seen_manifest_refs.add(manifest_ref)
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

    for obj in all_hg2git - seen_changesets - seen_manifests - seen_files:
        info('Dangling metadata for ' + obj)

    if not args.commit:
        for obj in manifest_commits - seen_manifest_refs:
            info('Metadata commit %s with no hg2git entry' % obj)

    dangling = all_notes - seen_notes
    if dangling:
        with store._fast_import.commit(
                ref='refs/notes/cinnabar',
                parents=('refs/notes/cinnabar^0',)) as commit:
            for c in dangling:
                info('Removing dangling note for commit ' + c)
                # That's brute force, but meh.
                for l in range(0, 10):
                    commit.filedelete(sha1path(c, l))

    if status['broken']:
        info('Your git-cinnabar repository appears to be corrupted. There\n'
             'are known issues in older revisions that have been fixed.\n'
             'Please try running the following command to reset:\n'
             '  git cinnabar reclone\n\n'
             'Please note this command may change the commit sha1s. Your\n'
             'local branches will however stay untouched.\n'
             'Please report any corruption that fsck would detect after a\n'
             'reclone.')

    store.close()

    return 1 if status['broken'] else 0


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
        for ref in Git.for_each_ref('refs/cinnabar', 'refs/remote-hg',
                                    'refs/notes/cinnabar',
                                    'refs/notes/remote-hg/git2hg',
                                    format='%(refname)'):
            Git.delete_ref(ref)
        Git.close()

        for line in Git.iter('config', '--get-regexp', 'remote\..*\.url'):
            config, url = line.split()
            name = config[len('remote.'):-len('.url')]
            if url.startswith('hg::'):
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
    else:
        print >>sys.stderr, 'Unknown command:', cmd
        return 1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
