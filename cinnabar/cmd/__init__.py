from __future__ import absolute_import, print_function, unicode_literals
from cinnabar.cmd.fsck import fsck  # noqa: F401
from cinnabar.cmd.upgrade import upgrade  # noqa: F401
from cinnabar.cmd.bundle import bundle  # noqa: F401
from cinnabar.cmd.python import python  # noqa: F401

from cinnabar.cmd.util import CLI  # noqa: F401


CLI.helper_subcommand(
    'data',
    help='dump the contents of a mercurial revision')

CLI.helper_subcommand(
    'reclone',
    help='reclone all mercurial remotes')

CLI.helper_subcommand(
    'fetch',
    help='fetch a changeset from a mercurial remote')

CLI.helper_subcommand(
    'hg2git',
    help='convert mercurial sha1 to corresponding git sha1')

CLI.helper_subcommand(
    'git2hg',
    help='convert git sha1 to corresponding mercurial sha1')

CLI.helper_subcommand(
    'rollback',
    help='rollback cinnabar metadata state')
