import re
import sys
from urllib.parse import quote_from_bytes, unquote_to_bytes
from cinnabar.helper import (
    GitHgHelper,
    HgRepoHelper,
)
from binascii import (
    hexlify,
    unhexlify,
)
from itertools import chain
from urllib.parse import (
    ParseResult,
    urlparse,
    urlunparse,
)
import logging
from cinnabar.dag import gitdag
from cinnabar.git import NULL_NODE_ID
from cinnabar.hg.bundle import (
    create_bundle,
    encodecaps,
    decodecaps,
)


class HelperRepo(object):
    __slots__ = ("_url", "_branchmap", "_heads", "_bookmarks", "_ui", "remote",
                 "_helper")

    def __init__(self, helper, url, remote=None):
        self._helper = helper
        self._url = url
        self._branchmap = None
        self._heads = None
        self._bookmarks = None
        self._ui = None
        self.remote = remote

    def init_state(self):
        state = self._helper.state()
        self._branchmap = {
            unquote_to_bytes(branch): [unhexlify(h)
                                       for h in heads.split(b' ')]
            for line in state['branchmap'].splitlines()
            for branch, heads in (line.split(b' ', 1),)
        }
        self._heads = [unhexlify(h)
                       for h in state['heads'][:-1].split(b' ')]
        self._bookmarks = self._decode_keys(state['bookmarks'])

    def url(self):
        return self._url

    def _decode_keys(self, data):
        return dict(
            line.split(b'\t', 1)
            for line in data.splitlines()
        )

    def capable(self, capability):
        if capability == b'bundle2':
            return quote_from_bytes(
                self._helper.capable(b'bundle2') or b'').encode('ascii')
        if capability in (b'clonebundles', b'cinnabarclone', b'unbundle'):
            return self._helper.capable(capability) is not None
        return capability == b'getbundle'

    def batch(self):
        raise NotImplementedError()

    def heads(self):
        if self._heads is None:
            self.init_state()
        return self._heads

    def branchmap(self):
        if self._branchmap is None:
            self.init_state()
        return self._branchmap

    def listkeys(self, namespace):
        if namespace == b'bookmarks':
            if self._bookmarks is None:
                self.init_state()
            return self._bookmarks
        return self._decode_keys(self._helper.listkeys(namespace))

    def known(self, nodes):
        result = self._helper.known(hexlify(n) for n in nodes)
        return [b == b'1'[0] for b in result]

    def pushkey(self, namespace, key, old, new):
        return self._helper.pushkey(namespace, key, old, new)

    def unbundle(self, heads, *args, **kwargs):
        return self._helper.unbundle((hexlify(h) if h != b'force' else h
                                      for h in heads))

    def find_common(self, heads):
        return self._helper.find_common(heads)


def getbundle(repo, heads, branch_names):
    with repo._helper.query(b"get_bundle", repo._helper.connected,
                            b','.join(heads), *branch_names) as stdout:
        res = stdout.readline().strip()
        if res != b'ok':
            raise Exception(res)


def push(repo, store, what, repo_heads, repo_branches, dry_run=False):
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
                unhexlify(store.hg_changeset(c))
                for c, _, _ in GitHgHelper.rev_list(
                    b'--topo-order', b'--full-history', b'--boundary',
                    b'--max-parents=0', b'refs/cinnabar/metadata^')
            ]
            if any(repo.known(cinnabar_roots)):
                fail = False
        if fail:
            raise Exception(
                'Cannot push to this remote without pulling/updating first.')
    common = repo.find_common(local_bases)
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
            repo_heads = [unhexlify(h) for h in repo_heads]
    if push_commits and not dry_run:
        b2caps = repo.capable(b'bundle2') or {}
        if b2caps:
            b2caps = decodecaps(unquote_to_bytes(b2caps))
        logging.getLogger('bundle2').debug('%r', b2caps)
        kwargs = {}
        if b2caps:
            kwargs['bundlespec'] = b'none-v2'
            versions = b2caps.get(b'changegroup')
            if versions and b'02' in versions:
                kwargs['cg_version'] = b'02'
            else:
                kwargs['cg_version'] = b'01'
            kwargs['replycaps'] = encodecaps({b'error': [b'abort']})
        else:
            kwargs['bundlespec'] = b'raw'
            kwargs['cg_version'] = b'01'
        create_bundle(store, push_commits, **kwargs)
        reply = repo.unbundle(repo_heads, b'')
        pushed = reply != 0
    return gitdag(push_commits) if pushed or dry_run else ()


def munge_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        # For urls without a scheme, try again with a normalized url with
        # no double-slashes.
        parsed_url = urlparse(re.sub(b'//+', b'/', url))
    # On Windows, assume that a one-letter scheme and no host means we
    # originally had something like c:/foo.
    if not parsed_url.scheme or (
            sys.platform == 'win32' and not parsed_url.netloc and
            len(parsed_url.scheme) == 1):
        if parsed_url.scheme:
            path = b'%s:%s' % (parsed_url.scheme, parsed_url.path)
        else:
            path = parsed_url.path
        return ParseResult(
            b'file',
            parsed_url.netloc,
            path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment)

    if parsed_url.scheme != b'hg':
        return parsed_url

    proto = b'https'
    host = parsed_url.netloc
    if b':' in host:
        host, port = host.rsplit(b':', 1)
        if b'.' in port:
            port, proto = port.split(b'.', 1)
        if not port.isdigit():
            proto = port
            port = None
        if port:
            host = host + b':' + port
    return ParseResult(proto, host, parsed_url.path, parsed_url.params,
                       parsed_url.query, parsed_url.fragment)


class Remote(object):
    def __init__(self, remote, url):
        if remote.startswith((b'hg::', b'hg://')):
            self.name = None
        else:
            self.name = remote
        self.url = urlunparse(munge_url(url))


def get_repo(remote):
    if remote.name:
        HgRepoHelper.connect(remote.url, remote.name)
    else:
        HgRepoHelper.connect(remote.url)
    return HelperRepo(HgRepoHelper, remote.url, remote.name)
