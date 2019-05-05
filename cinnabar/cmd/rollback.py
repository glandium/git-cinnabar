import logging
from cinnabar.cmd.util import CLI
from cinnabar.githg import GitCommit
from cinnabar.git import (
    Git,
    NULL_NODE_ID,
)
from cinnabar.helper import GitHgHelper
from cinnabar.util import VersionedDict


def get_previous_metadata(metadata):
    commit = GitCommit(metadata)
    flags = commit.body.split(' ')
    if len(commit.parents) == 5 + ('files-meta' in flags):
        return commit.parents[-1]


def do_rollback(ref):
    checked = Git.resolve_ref('refs/cinnabar/checked')
    if ref:
        sha1 = Git.resolve_ref(ref)
        if not sha1:
            logging.error('Invalid ref: %s', ref)
            return 1
        if sha1 != NULL_NODE_ID:
            # Validate that the sha1 is in the history of the current metadata
            metadata = Git.resolve_ref('refs/cinnabar/metadata')
            while metadata and metadata != sha1:
                previous_metadata = get_previous_metadata(metadata)
                if checked == metadata:
                    checked = previous_metadata
                metadata = previous_metadata
            if not metadata:
                logging.error('Cannot rollback to %s, it is not in the '
                              'history of the current metadata.', ref)
                return 1
    else:
        metadata = Git.resolve_ref('refs/cinnabar/metadata')
        if metadata:
            sha1 = get_previous_metadata(metadata) or NULL_NODE_ID
        else:
            sha1 = NULL_NODE_ID
        if checked and checked == metadata:
            checked = sha1

    refs = VersionedDict(
        (ref, commit)
        for commit, ref in Git.for_each_ref('refs/cinnabar',
                                            'refs/notes/cinnabar')
    )
    for ref in refs:
        if ref != 'refs/cinnabar/checked':
            del refs[ref]
    if sha1 != NULL_NODE_ID:
        refs['refs/cinnabar/metadata'] = sha1
        if checked:
            refs['refs/cinnabar/checked'] = checked
        for line in Git.ls_tree(sha1):
            mode, typ, commit, path = line
            refs['refs/cinnabar/replace/%s' % path] = commit

    for status, ref, commit in refs.iterchanges():
        if status == VersionedDict.REMOVED:
            Git.delete_ref(ref)
        else:
            Git.update_ref(ref, commit)
    GitHgHelper.close(rollback=False)

    return 0


@CLI.subcommand
@CLI.argument('--fsck', action='store_true',
              help='rollback to the last checked state')
@CLI.argument('committish', nargs='?',
              help='committish of the state to rollback to')
def rollback(args):
    '''rollback cinnabar metadata state'''
    if args.fsck and args.committish:
        logging.error('Cannot use --fsck along a commit.')
        return 1
    return do_rollback(args.committish or 'refs/cinnabar/checked')
