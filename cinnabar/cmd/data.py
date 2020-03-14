from __future__ import absolute_import, unicode_literals
from cinnabar.cmd.util import CLI


CLI.helper_subcommand(
    'data',
    help='dump the contents of a mercurial revision')
