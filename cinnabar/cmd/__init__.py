from __future__ import absolute_import, print_function, unicode_literals
from .fsck import fsck  # noqa: F401
from .upgrade import upgrade  # noqa: F401
from .bundle import bundle  # noqa: F401
from .rollback import rollback  # noqa: F401
from .python import python  # noqa: F401
from .download import download  # noqa: F401

from .util import CLI  # noqa: F401


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
