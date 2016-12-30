import logging
from cinnabar.cmd.util import CLI
from cinnabar.githg import GitCommit
from cinnabar.git import (
    Git,
    NULL_NODE_ID,
)
from cinnabar.util import VersionedDict


def do_rollback(ref):
    sha1 = Git.resolve_ref(ref)
    if not sha1:
        logging.error('Invalid ref: %s', ref)
        return 1
    if sha1 != NULL_NODE_ID:
        # Validate that the sha1 is in the history of the current metadata
        metadata = Git.resolve_ref('refs/cinnabar/metadata')
        while metadata:
            if sha1 == metadata:
                break
            commit = GitCommit(metadata)
            flags = commit.body.split(' ')
            if len(commit.parents) == 5 + ('files-meta' in flags):
                metadata = commit.parents[-1]
            else:
                metadata = None
        if not metadata:
            logging.error('Cannot rollback to %s, it is not in the history of '
                          'the current metadata.', ref)
            return 1

    refs = VersionedDict(
        (ref, commit)
        for commit, ref in Git.for_each_ref('refs/cinnabar',
                                            'refs/notes/cinnabar')
    )
    for ref in refs:
        del refs[ref]
    if sha1 != NULL_NODE_ID:
        refs['refs/cinnabar/metadata'] = sha1
        for line in Git.ls_tree(sha1):
            mode, typ, commit, path = line
            refs['refs/cinnabar/replace/%s' % path] = commit

    for status, ref, commit in refs.iterchanges():
        if status == VersionedDict.REMOVED:
            Git.delete_ref(ref)
        else:
            Git.update_ref(ref, commit)
    Git._close_update_ref()

    return 0


@CLI.subcommand
@CLI.argument('committish',
              help='committish of the state to rollback to')
def rollback(args):
    '''rollback cinnabar metadata state'''

    do_rollback(args.committish)
