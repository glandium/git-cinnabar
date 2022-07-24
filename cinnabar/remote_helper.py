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
import logging
from cinnabar.git import (
    Git,
    InvalidConfig,
    NULL_NODE_ID,
)
from cinnabar.util import ConfigSetFunc

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
        self._store.close(rollback=True)

    def push(self, dry_run=None):
        GitHgHelper._ensure_helper()
        name = self._helper_in.readline().strip()
        url = self._helper_in.readline().strip()
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

        refs_style = None
        refs_styles = ('bookmarks', 'heads', 'tips')
        if heads:
            refs_config = 'cinnabar.refs'
            if Git.config('cinnabar.pushrefs', remote=remote.name):
                refs_config = 'cinnabar.pushrefs'

            refs_style = ConfigSetFunc(refs_config, refs_styles,
                                       remote=remote.name,
                                       default='all')

        refs_style = refs_style or (lambda x: True)

        if refs_style('bookmarks'):
            if refs_style('heads') or refs_style('tips'):
                bookmark_prefix = b'refs/heads/bookmarks/'
            else:
                bookmark_prefix = b'refs/heads/'
        else:
            bookmark_prefix = b''

        try:
            values = {
                None: b'phase',
                b'': b'phase',
                b'never': b'never',
                b'phase': b'phase',
                b'always': b'always',
            }
            data = Git.config('cinnabar.data', remote.name, values=values)
        except InvalidConfig as e:
            logging.error(str(e))
            return 1

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

        if not pushed or dry_run:
            data = False
        elif data == b'always':
            data = True
        elif data == b'phase':
            phases = HgRepoHelper.listkeys(b'phases')
            drafts = {}
            if not phases.get(b'publishing', False):
                drafts = set(p for p, is_draft in phases.items()
                             if int(is_draft))
            if not drafts:
                data = True
            else:
                def draft_commits():
                    for d in drafts:
                        c = self._store.changeset_ref(d)
                        if c:
                            yield b'^%s^@' % c
                    for h in pushed.heads():
                        yield h

                args = [b'--ancestry-path', b'--topo-order']
                args.extend(draft_commits())

                pushed_drafts = tuple(
                    c for c, t, p in GitHgHelper.rev_list(*args))

                # Theoretically, we could have commits with no
                # metadata that the remote declares are public, while
                # the rest of our push is in a draft state. That is
                # however so unlikely that it's not worth the effort
                # to support partial metadata storage.
                data = not bool(pushed_drafts)
        elif data == b'never':
            data = False

        self._store.close(rollback=not data)


def main(args):
    if sys.platform == 'win32':
        # By default, sys.stdout on Windows will transform \n into \r\n, which
        # the calling git process won't recognize in our answers.
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    store = PushStore()

    helper = GitRemoteHelper(store)

    getattr(helper, args[0])(*args[1:])

    store.close()
