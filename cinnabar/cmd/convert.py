from __future__ import absolute_import, print_function, unicode_literals
import argparse
import re
from cinnabar.cmd.util import CLI
from cinnabar.git import NULL_NODE_ID
from cinnabar.helper import GitHgHelper
from cinnabar.util import (
    bytes_stdin,
    bytes_stdout,
)


class AbbrevAction(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS,
                 help="show a partial prefix"):
        super(AbbrevAction, self).__init__(
            option_strings=option_strings, dest=dest, default=40,
            nargs='?', metavar='N', help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        abbrev = None
        if values and len(values) <= 2:
            try:
                abbrev = int(values)
            except ValueError:
                pass

        if values and abbrev is None:
            # There is no way, with argparse, to only take the --foo[=FOO]
            # form of a nargs='?' argument, and if the argument is not last,
            # it will always consume the next argument if it doesn't start
            # with '--'. So we re-inject it in the namespace... which is
            # overwritten by the default actions for the sha1 arguments, so
            # we also have our custom action to avoid that happening.
            if namespace.sha1 is None:
                namespace.sha1 = []
            namespace.sha1.append(values)

        namespace.abbrev = min(abbrev or 12, 40)


class SHA1Action(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if namespace.sha1 is None:
            namespace.sha1 = []
        namespace.sha1.extend(values)


SHA1_RE = re.compile(r'[0-9a-fA-F]{1,40}$')


def sha1_value(value):
    if not SHA1_RE.match(value):
        raise argparse.ArgumentTypeError("must be a sha1")
    return value.encode('ascii')


def do_all(args, callback):
    for arg in args.sha1:
        callback(arg)

    if args.batch:
        bytes_stdout.flush()
        while True:
            line = bytes_stdin.readline()
            if not line:
                break
            for arg in line.split():
                callback(arg)
            bytes_stdout.flush()


@CLI.subcommand
@CLI.argument('--abbrev', action=AbbrevAction)
@CLI.argument('--batch', action='store_true', help='read sha1s on stdin')
@CLI.argument('sha1', action=SHA1Action, nargs='*', type=sha1_value,
              help='mercurial sha1')
def hg2git(args):
    '''convert mercurial sha1 to corresponding git sha1'''

    def do_one(arg):
        bytes_stdout.write(
            GitHgHelper.hg2git(arg)[:args.abbrev])
        bytes_stdout.write(b'\n')

    do_all(args, do_one)


@CLI.subcommand
@CLI.argument('--abbrev', action=AbbrevAction)
@CLI.argument('--batch', action='store_true', help='read sha1s on stdin')
@CLI.argument('sha1', action=SHA1Action, nargs='*', help='git sha1')
def git2hg(args):
    '''convert git sha1 to corresponding mercurial sha1'''

    def do_one(arg):
        data = GitHgHelper.git2hg(arg.encode('ascii'))
        if data:
            assert data.startswith(b'changeset ')
            bytes_stdout.write(data[10:10 + args.abbrev])
        else:
            bytes_stdout.write(NULL_NODE_ID[:args.abbrev])
        bytes_stdout.write(b'\n')

    do_all(args, do_one)
