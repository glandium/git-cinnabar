from __future__ import absolute_import, unicode_literals
import os
import sys
import argparse
from cinnabar.cmd.util import CLI


@CLI.subcommand
@CLI.argument('flags', nargs=argparse.REMAINDER,
              help='flags to pass down to python')
def python(args):
    '''open a python shell with the cinnabar module in sys.path'''

    args = list(args.flags)
    env = os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join(sys.path)
    args.append(env)
    if sys.platform != 'win32':
        os.execle(sys.executable, sys.executable, *args)
    else:
        import subprocess
        return subprocess.call([sys.executable] + args)
