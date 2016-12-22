from cinnabar.cmd.util import CLI
from cinnabar.git import (
    Git,
    NULL_NODE_ID,
)


@CLI.subcommand
def reclone(args):
    '''reclone all mercurial remotes'''

    from cinnabar.cmd.rollback import do_rollback
    do_rollback(NULL_NODE_ID)
    for line in Git.iter('config', '--get-regexp', 'remote\..*\.url'):
        config, url = line.split()
        name = config[len('remote.'):-len('.url')]
        skip_pref = 'remote.%s.skipDefaultUpdate' % name
        if (url.startswith(('hg::', 'hg://')) and
                Git.config(skip_pref) != 'true'):
            Git.run('remote', 'update', '--prune', name)

    print 'Please note that reclone left your local branches untouched.'
    print 'They may be based on entirely different commits.'
