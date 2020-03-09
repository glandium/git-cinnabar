from __future__ import absolute_import, print_function, unicode_literals
import argparse
import re
import sys
from cinnabar.cmd.util import CLI
from cinnabar.githg import GitHgStore
from cinnabar.util import bytes_stdout


SHA1_RE = re.compile(r'[0-9a-fA-F]{1,40}$')


def sha1_value(value):
    if not SHA1_RE.match(value):
        raise argparse.ArgumentTypeError("must be a sha1")
    return value.encode('ascii')


@CLI.subcommand
@CLI.argument('-c', '--changeset', action='store_true',
              help='open changelog')
@CLI.argument('-m', '--manifest', action='store_true',
              help='open manifest')
@CLI.argument('rev', type=sha1_value, help='revision')
def data(args):
    '''dump the contents of a mercurial revision'''

    store = GitHgStore()
    if args.changeset and args.manifest:
        print('Cannot use both -c and -m.', file=sys.stderr)
        return 1
    if args.changeset:
        bytes_stdout.write(store.changeset(args.rev).raw_data)
    elif args.manifest:
        bytes_stdout.write(store.manifest(args.rev).raw_data)
    else:
        bytes_stdout.write(store.file(args.rev).raw_data)
    store.close()
