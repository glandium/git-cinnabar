from cinnabar.cmd.util import CLI
from cinnabar.git import (
    Git,
    NULL_NODE_ID,
)
from cinnabar.helper import GitHgHelper


@CLI.subcommand
@CLI.argument('sha1', nargs='+', help='mercurial sha1')
def hg2git(args):
    '''convert mercurial sha1 to corresponding git sha1'''

    for arg in args.sha1:
        print GitHgHelper.hg2git(arg)


@CLI.subcommand
@CLI.argument('sha1', nargs='+', help='git sha1')
def git2hg(args):
    '''convert git sha1 to corresponding mercurial sha1'''

    for sha1, ref in Git.for_each_ref('refs/cinnabar/replace'):
        Git._replace[ref[22:]] = sha1
    for arg in args.sha1:
        data = GitHgHelper.git2hg(arg)
        if data:
            assert data.startswith('changeset ')
            print data[10:50]
        else:
            print NULL_NODE_ID
