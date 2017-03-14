#!/usr/bin/env python2.7

import os
import sys
from coverage.cmdline import main as coverage_main


def main():
    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    sys.exit(coverage_main([
        'run',
        '--append',
        os.path.join(script_path, '..', os.path.basename(sys.argv[0])),
    ] + sys.argv[1:]))
