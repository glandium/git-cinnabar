import os
import sys

from cinnabar.helper import GitHgHelper, HgRepoHelper
from cinnabar.hg.repo import push
from cinnabar.hg.bundle import (
    PushStore,
    create_bundle,
)
from cinnabar.git import NULL_NODE_ID


class GitRemoteHelper(object):
    def __init__(self, store, stdin=sys.stdin.buffer,
                 stdout=sys.stdout.buffer):
        self._store = store
        self._helper_in = stdin
        self._helper = stdout

    def bundle(self, bundlespec, path):
        bundle_commits = []
        while True:
            line = self._helper_in.readline().strip()
            if not line:
                break
            commit, _, parents = line.partition(b' ')
            bundle_commits.append(
                (commit, parents.split(b' ') if parents else []))

        create_bundle(
            self._store, bundle_commits, bundlespec=bundlespec.encode('ascii'),
            path=os.fsencode(path))

    def push(self, dry_run=None):
        GitHgHelper._ensure_helper()

        refspecs = []
        while True:
            line = self._helper_in.readline().strip()
            if not line:
                break
            refspecs.append(line)
        state = HgRepoHelper.state()
        branchmap = state['branchmap']
        heads = state['heads']
        if heads == [NULL_NODE_ID]:
            heads = []

        pushes = list((s.lstrip(b'+'), d, s.startswith(b'+'))
                      for s, d in (r.split(b':', 1) for r in refspecs))
        if not push(self._store, pushes, heads, branchmap.keys(), dry_run):
            sys.exit(1)


def main(args):
    if sys.platform == 'win32':
        # By default, sys.stdout on Windows will transform \n into \r\n, which
        # the calling git process won't recognize in our answers.
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    store = PushStore()

    helper = GitRemoteHelper(store)

    getattr(helper, args[0])(*args[1:])
