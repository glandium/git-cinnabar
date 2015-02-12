#!/usr/bin/env python2.7

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'pythonlib'))

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
)
from git.util import LazyString
from githg.dag import gitdag
from githg.helper import GitHgHelper
import subprocess

import logging
#logging.getLogger('').setLevel(logging.INFO)


def fsck(args):
    # TODO: Add arguments to enable more sha1 checks
    do_manifests = '--manifests' in args

    status = { 'broken': False }

    def report(message):
        status['broken'] = True
        print message

    store = GitHgStore()
    store.init_fast_import(FastImport())

    all_hg2git = {
        path.replace('/', ''): (filesha1, intern(typ))
        for mode, typ, filesha1, path in
        Git.ls_tree('refs/cinnabar/hg2git', recursive=True)
    }

    store._hg2git_cache = { p: s for p, (s, t) in all_hg2git.iteritems() }

    all_notes = set(path.replace('/', '') for mode, typ, filesha1, path in
        Git.ls_tree('refs/notes/cinnabar', recursive=True))

    manifest_commits = set(Git.iter('rev-list', '--full-history',
                                    'refs/cinnabar/manifest'))

    def all_git_heads():
        for ref in Git.for_each_ref('refs/cinnabar/branches',
                                    format='%(refname)'):
            yield ref + '\n'

    all_git_commits = Git.iter('log', '--topo-order', '--full-history',
                               '--reverse', '--stdin', '--format=%T %H',
                               stdin=all_git_heads)

    seen_changesets = set()
    seen_manifests = set()
    seen_manifest_refs = set()
    seen_files = set()
    seen_notes = set()

    hg_manifest = None

    for line in all_git_commits:
        tree, node = line.split(' ')
        if node not in all_notes:
            report('Missing note for git commit: ' + node)
            continue
        seen_notes.add(node)

        changeset_data = store.read_changeset_data(node)
        changeset = changeset_data['changeset']
        if 'extra' in changeset_data:
            extra = changeset_data['extra']
            if 'committer' in extra:
                header, message = GitHgHelper.cat_file(
                    'commit', node).split('\n\n', 1)
                header = dict(l.split(' ', 1) for l in header.splitlines())
                committer_info = store.hg_author_info(header['committer'])
                committer = '%s %s %d' % committer_info
                if committer != extra['committer'] and \
                        committer_info[0] != extra['committer']:
                    report('Committer mismatch between commit and metadata for'
                           ' changeset %s' % changeset)
                if committer == extra['committer']:
                    print 'Fixing useless committer metadata for changeset %s' \
                           % changeset
                    del changeset_data['extra']['committer']
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
                    print 'Fixing known sha1 mismatch for changeset %s' % (
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
        elif manifest_ref not in manifest_commits:
            report('Missing manifest commit in manifest branch: %s' %
                   manifest_ref)

        if do_manifests:
            hg_manifest = store.manifest(manifest, hg_manifest)
            parents = tuple(
                store.read_changeset_data(store.changeset_ref(p))['manifest']
                for p in (hg_changeset.parent1, hg_changeset.parent2)
                if p != NULL_NODE_ID
            )
            hg_manifest.set_parents(*parents)
            if hg_manifest.node != hg_manifest.sha1:
                report('Sha1 mismatch for manifest %s' % manifest)

        git_ls = one(Git.ls_tree(manifest_ref, 'git'))
        if not git_ls:
            git_ls = one(Git.ls_tree(manifest_ref))
            if git_ls:
                mode, typ, sha1, path = git_ls
                if sha1 != EMPTY_TREE:
                    git_ls = None
        if not git_ls:
            report('Missing git tree in manifest commit %s' % manifest_ref)
        else:
            mode, typ, sha1, path = git_ls
            if sha1 != tree:
                report('Tree mismatch between manifest commit %s and commit %s'
                       % (manifest_ref, node))

    # TODO: Check files
    all_hg2git = set(k for k, (s, t) in all_hg2git.iteritems()
                     if t == 'commit')

    for obj in all_hg2git - seen_changesets - seen_manifests - seen_files:
        print 'Dangling metadata for ' + obj

    for obj in manifest_commits - seen_manifest_refs:
        print 'Metadata commit %s with no hg2git entry' % obj

    for commit in all_notes - seen_notes:
        print 'Dangling note for commit ' + commit

    if status['broken']:
        print 'Your git-cinnabar repository appears to be corrupted. There'
        print 'are known issues in older revisions that have been fixed.'
        print 'Please try running the following command to reset:'
        print '  git cinnabar reclone'
        print '\nPlease note this command may change the commit sha1s. Your'
        print 'local branches will however stay untouched.'
        print 'Please report any corruption that fsck would detect after a'
        print 'reclone.'

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
    else:
        print >>sys.stderr, 'Unknown command:', cmd
        return 1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
