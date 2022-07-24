import os
import subprocess


def build_commit(head='HEAD'):
    return subprocess.check_output(
        ['git', '-C', os.path.join(os.path.dirname(__file__), '..'),
         'rev-parse', '--verify', head], text=True,
        stderr=open(os.devnull, 'wb')).strip()
