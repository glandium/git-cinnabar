import os
import sys

from cinnabar.helper import GitHgHelper, HgRepoHelper
from cinnabar.hg.repo import (
    push,
    Remote,
)
from cinnabar.hg.bundle import (
    PushStore,
    create_bundle,
)
from cinnabar.git import NULL_NODE_ID

from urllib.parse import unquote_to_bytes


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
        name = self._helper_in.readline().strip()
        url = self._helper_in.readline().strip()
        bookmark_prefix = self._helper_in.readline().strip()
        remote = Remote(name, url)
        assert remote.url != b'hg::tags:'

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
        bookmarks = state['bookmarks']

        pushes = list((s.lstrip(b'+'), d, s.startswith(b'+'))
                      for s, d in (r.split(b':', 1) for r in refspecs))
        pushed = push(self._store, pushes, heads, branchmap.keys(), dry_run)

        status = {}
        for source, dest, _ in pushes:
            if dest.startswith(b'refs/tags/'):
                if source:
                    status[dest] = b'Pushing tags is unsupported'
                else:
                    status[dest] = \
                        b'Deleting remote tags is unsupported'
                continue
            if not bookmark_prefix or not dest.startswith(bookmark_prefix):
                if source:
                    status[dest] = bool(len(pushed))
                else:
                    status[dest] = \
                        b'Deleting remote branches is unsupported'
                continue
            name = unquote_to_bytes(dest[len(bookmark_prefix):])
            if source:
                source = self._store.hg_changeset(source)
            status[dest] = HgRepoHelper.pushkey(
                b'bookmarks', name, bookmarks.get(name, b''),
                source or b'')

        for source, dest, force in pushes:
            if status[dest] is True:
                self._helper.write(b'ok %s\n' % dest)
            elif status[dest]:
                self._helper.write(b'error %s %s\n' % (dest, status[dest]))
            else:
                self._helper.write(b'error %s nothing changed on remote\n'
                                   % dest)
        self._helper.write(b'\n')
        self._helper.flush()


def main(args):
    if sys.platform == 'win32':
        # By default, sys.stdout on Windows will transform \n into \r\n, which
        # the calling git process won't recognize in our answers.
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    store = PushStore()

    helper = GitRemoteHelper(store)

    getattr(helper, args[0])(*args[1:])
