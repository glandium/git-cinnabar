from __future__ import absolute_import, print_function, unicode_literals
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
from cinnabar.util import fsencode


@CLI.subcommand
@CLI.argument('remote', help='mercurial remote name or url')
@CLI.argument('revs', nargs='+', help='mercurial changeset to fetch')
def fetch(args):
    '''fetch a changeset from a mercurial remote'''

    remote = args.remote
    revs = args.revs
    full_revs = []
    for rev in revs:
        if not re.match('[0-9a-f]{40}$', rev.lower()):
            if remote.startswith('hg:'):
                url = fsencode(remote)
            else:
                url = Git.config('remote.%s.url' % remote)
            if not url:
                print("Unknown remote:", remote, file=sys.stderr)
                return 1
            if url.startswith(b'hg::'):
                url = url[4:]
            repo = get_repo(Remote(fsencode(remote), url))
            if repo.capable(b'lookup'):
                rev = hexlify(repo.lookup(fsencode(rev)))
            else:
                print('Remote repository does not support the "lookup" '
                      'command. Please use a non-abbreviated mercurial '
                      'revision.',
                      file=sys.stderr)
                return 1
        full_revs.append(rev.decode('ascii'))

    refs = ['hg/revs/%s' % r for r in full_revs]

    proc = GitProcess('fetch', remote, *refs, stdout=sys.stdout,
                      config={'cinnabar.fetch': ' '.join(full_revs)})
    return proc.wait()
