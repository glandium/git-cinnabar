import re
import sys
from binascii import hexlify
from cinnabar.cmd.util import CLI
from cinnabar.git import (
    Git,
    GitProcess,
)
from cinnabar.hg.repo import (
    get_repo,
    Remote,
)


@CLI.subcommand
@CLI.argument('remote', help='mercurial remote name or url')
@CLI.argument('rev', help='mercurial changeset to fetch')
def fetch(args):
    '''fetch a changeset from a mercurial remote'''

    remote = args.remote
    rev = args.rev
    if not re.match('[0-9a-f]{40}$', rev.lower()):
        if remote.startswith('hg:'):
            url = remote
        else:
            url = Git.config('remote.%s.url' % remote)
        if not url:
            print >>sys.stderr, "Unknown remote:", remote
            return 1
        if url.startswith('hg::'):
            url = url[4:]
        repo = get_repo(Remote(remote, url))
        if repo.capable('lookup'):
            rev = hexlify(repo.lookup(rev))
        else:
            print >>sys.stderr, (
                'Remote repository does not support the "lookup" command. '
                'Please use a non-abbreviated mercurial revision.')
            return 1

    proc = GitProcess('fetch', remote, 'hg/revs/%s' % rev, stdout=sys.stdout,
                      config={'cinnabar.fetch': rev})
    return proc.wait()
