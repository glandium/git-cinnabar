from __future__ import absolute_import, print_function, unicode_literals
from cinnabar.cmd.util import CLI


CLI.helper_subcommand(
    'reclone',
    help='reclone all mercurial remotes')
