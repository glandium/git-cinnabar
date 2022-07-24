from cinnabar.helper import (
    GitHgHelper,
    HgRepoHelper,
)
from itertools import chain
import logging
from cinnabar.git import NULL_NODE_ID
from cinnabar.hg.bundle import create_bundle


def push(store, what, repo_heads, repo_branches, dry_run=False):
    def heads():
        for sha1 in store.heads(repo_branches):
            yield b'^%s' % store.changeset_ref(sha1)

    def local_bases():
        h = chain(heads(), (w for w, _, _ in what if w))
        for c, t, p in GitHgHelper.rev_list(b'--topo-order', b'--full-history',
                                            b'--boundary', *h):
            if c[:1] != b'-':
                continue
            if c[1:] == b"shallow":
                raise Exception("Pushing git shallow clones is not supported.")
            yield store.hg_changeset(c[1:])

        for w, _, _ in what:
            if w:
                rev = store.hg_changeset(w)
                if rev:
                    yield rev

    local_bases = set(local_bases())
    pushing_anything = any(src for src, _, _ in what)
    force = all(v for _, _, v in what)
    if pushing_anything and not local_bases and repo_heads:
        fail = True
        if store._has_metadata and force:
            cinnabar_roots = [
                store.hg_changeset(c)
                for c, _, _ in GitHgHelper.rev_list(
                    b'--topo-order', b'--full-history', b'--boundary',
                    b'--max-parents=0', b'refs/cinnabar/metadata^')
            ]
            if any(HgRepoHelper.known(cinnabar_roots)):
                fail = False
        if fail:
            raise Exception(
                'Cannot push to this remote without pulling/updating first.')
    common = HgRepoHelper.find_common(local_bases)
    logging.info('common: %s', common)

    def revs():
        for sha1 in common:
            yield b'^%s' % store.changeset_ref(sha1)

    revs = chain(revs(), (w for w, _, _ in what if w))
    push_commits = list((c, p) for c, t, p in GitHgHelper.rev_list(
        b'--topo-order', b'--full-history', b'--parents', b'--reverse', *revs))

    pushed = False
    if push_commits:
        has_root = any(not p for (c, p) in push_commits)
        if has_root and repo_heads:
            if not force:
                raise Exception('Cannot push a new root')
            else:
                logging.warn('Pushing a new root')
        if force:
            repo_heads = [b'force']
        else:
            if not repo_heads:
                repo_heads = [NULL_NODE_ID]
    if push_commits and not dry_run:
        create_bundle(store, push_commits, b'connection')
        reply = HgRepoHelper.unbundle(repo_heads)
        pushed = reply != 0
    return bool(push_commits) if pushed or dry_run else False
