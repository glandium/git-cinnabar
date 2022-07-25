import os
import sys

from cinnabar.hg.bundle import (
    PushStore,
    create_bundle,
)


class GitRemoteHelper(object):
    def __init__(self, store, stdin=sys.stdin.buffer,
                 stdout=sys.stdout.buffer):
        self._store = store
        self._helper_in = stdin
        self._helper = stdout

    def bundle(self):
        bundle_commits = []
        while True:
            line = self._helper_in.readline().strip()
            if not line:
                break
            commit, _, parents = line.partition(b' ')
            bundle_commits.append(
                (commit, parents.split(b' ') if parents else []))

        create_bundle(self._store, bundle_commits)


def main(args):
    if sys.platform == 'win32':
        # By default, sys.stdout on Windows will transform \n into \r\n, which
        # the calling git process won't recognize in our answers.
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    store = PushStore()

    helper = GitRemoteHelper(store)

    getattr(helper, args[0])(*args[1:])
