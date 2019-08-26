from __future__ import print_function
import sys
from cinnabar.cmd.util import CLI
from cinnabar.githg import GitHgStore


@CLI.subcommand
@CLI.argument('-c', '--changeset', action='store_true',
              help='open changelog')
@CLI.argument('-m', '--manifest', action='store_true',
              help='open manifest')
@CLI.argument('rev', help='revision')
def data(args):
    '''dump the contents of a mercurial revision'''

    store = GitHgStore()
    if args.changeset and args.manifest:
        print('Cannot use both -c and -m.', file=sys.stderr)
        return 1
    if args.changeset:
        sys.stdout.write(store.changeset(args.rev).raw_data)
    elif args.manifest:
        sys.stdout.write(store.manifest(args.rev).data)
    else:
        sys.stdout.write(store.file(args.rev).raw_data)
    store.close()
