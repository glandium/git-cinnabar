from __future__ import absolute_import, unicode_literals
from cinnabar.cmd.util import CLI


CLI.helper_subcommand(
    'hg2git',
    help='convert mercurial sha1 to corresponding git sha1')


CLI.helper_subcommand(
    'git2hg',
    help='convert git sha1 to corresponding mercurial sha1')
