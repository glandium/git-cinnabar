#!/bin/sh
''':'
py="$GIT_CINNABAR_PYTHON"
if test -z "$py"; then
  for py in python3 python python2.7 python2; do
    command -v "$py" > /dev/null && break
    py=python3
  done
fi
exec "$py" "$0" "$@"
exit 1
'''
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__)))

from cinnabar.cmd import CLI
from cinnabar.util import run


if __name__ == '__main__':
    argv = sys.argv[1:]
    if argv[:1] != ["download"]:
        argv.insert(0, "download")
    args = CLI.parser.parse_args(argv)
    run(args.callback, args)
