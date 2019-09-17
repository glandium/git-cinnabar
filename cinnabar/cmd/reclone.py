from __future__ import absolute_import, print_function
from cinnabar.cmd.util import CLI
from cinnabar.git import (
    Git,
    NULL_NODE_ID,
)


@CLI.subcommand
def reclone(args):
    '''reclone all mercurial remotes'''

    from cinnabar.cmd.rollback import do_rollback
    git_config = {}
    metadata_commit = Git.resolve_ref('refs/cinnabar/metadata')
    if metadata_commit:
        git_config['cinnabar.previous-metadata'] = metadata_commit
    # TODO: Avoid resetting at all, possibly leaving the repo with no metadata
    # if this is interrupted somehow.
    do_rollback(NULL_NODE_ID)
    for line in Git.iter('config', '--get-regexp', 'remote\..*\.url'):
        config, url = line.split()
        name = config[len('remote.'):-len('.url')]
        skip_pref = 'remote.%s.skipDefaultUpdate' % name
        if (url.startswith(('hg::', 'hg://')) and
                Git.config(skip_pref) != 'true'):
            Git.run('remote', 'update', '--prune', name, config=git_config)
            git_config = {}

    print('Please note that reclone left your local branches untouched.')
    print('They may be based on entirely different commits.')
