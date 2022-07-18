import os
import re
import sys
from urllib.parse import quote_from_bytes, unquote_to_bytes
from cinnabar.helper import (
    GitHgHelper,
    HgRepoHelper,
    BundleHelper,
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
import random
from cinnabar.dag import gitdag
from cinnabar.git import (
    Git,
    NULL_NODE_ID,
)
from cinnabar.util import (
    check_enabled,
)
from cinnabar.hg.bundle import (
    create_bundle,
    encodecaps,
    decodecaps,
)


def _sample(l, size):
    if len(l) <= size:
        return l
    return random.sample(l, size)


# TODO: this algorithm is not very smart and might as well be completely wrong
def findcommon(repo, store, hgheads):
    logger = logging.getLogger('findcommon')
    logger.debug(hgheads)
    if not hgheads:
        logger.info('no requests')
        return set()

    sample_size = 100

    sample = _sample(hgheads, sample_size)
    requests = 1
    known = repo.known(unhexlify(h) for h in sample)
    known = set(h for h, k in zip(sample, known) if k)

    logger.debug('initial sample size: %d', len(sample))

    if len(known) == len(hgheads):
        logger.debug('all heads known')
        logger.info('1 request')
        return hgheads

    git_heads = set(store.changeset_ref(h) for h in hgheads)
    git_known = set(store.changeset_ref(h) for h in known)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug('known (sub)set: (%d) %s', len(known), sorted(git_known))

    args = [b'--topo-order', b'--full-history', b'--parents']

    def revs():
        for h in git_known:
            yield b'^%s' % h
        for h in git_heads:
            if h not in git_known:
                yield h

    args.extend(revs())
    revs = ((c, parents) for c, t, parents in GitHgHelper.rev_list(*args))
    dag = gitdag(chain(revs, ((k, ()) for k in git_known)))
    dag.tag_nodes_and_parents(git_known, 'known')

    def log_dag(tag):
        if not logger.isEnabledFor(logging.DEBUG):
            return
        logger.debug('%s dag size: %d', tag,
                     sum(1 for n in dag.iternodes(tag)))
        heads = sorted(dag.heads(tag))
        logger.debug('%s dag heads: (%d) %s', tag, len(heads), heads)
        roots = sorted(dag.roots(tag))
        logger.debug('%s dag roots: (%d) %s', tag, len(roots), roots)

    log_dag('unknown')
    log_dag('known')

    while True:
        unknown = set(chain(dag.heads(), dag.roots()))
        if not unknown:
            break

        sample = set(_sample(unknown, sample_size))
        if len(sample) < sample_size:
            sample |= set(_sample(set(dag.iternodes()),
                                  sample_size - len(sample)))

        sample = list(sample)
        hg_sample = [store.hg_changeset(h) for h in sample]
        requests += 1
        known = repo.known(unhexlify(h) for h in hg_sample)
        unknown = set(h for h, k in zip(sample, known) if not k)
        known = set(h for h, k in zip(sample, known) if k)
        logger.debug('next sample size: %d', len(sample))
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('known (sub)set: (%d) %s', len(known), sorted(known))
            logger.debug('unknown (sub)set: (%d) %s', len(unknown),
                         sorted(unknown))

        dag.tag_nodes_and_parents(known, 'known')
        dag.tag_nodes_and_children(unknown, 'unknown')
        log_dag('unknown')
        log_dag('known')

    logger.info('%d requests', requests)
    return [store.hg_changeset(h) for h in dag.heads('known')]


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

    def _call(self, command, *args):
        if command == b'cinnabarclone':
            return self._helper.cinnabarclone()
        raise NotImplementedError()

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

    def get_store_bundle(self, name, heads, common, *args, **kwargs):
        heads = [hexlify(h) for h in heads]
        common = [hexlify(c) for c in common]
        return self._helper.get_store_bundle(heads, common)

    def pushkey(self, namespace, key, old, new):
        return self._helper.pushkey(namespace, key, old, new)

    def unbundle(self, heads, *args, **kwargs):
        return self._helper.unbundle((hexlify(h) if h != b'force' else h
                                      for h in heads))


def get_clonebundle_url(repo):
    with HgRepoHelper.query(
            b'get_clonebundle_url', HgRepoHelper.connected) as stdout:
        url = stdout.readline().strip()
        if url:
            return url


def get_store_clonebundle(repo):
    url = Git.config('cinnabar.clonebundle', remote=repo.remote)
    if not url:
        url = get_clonebundle_url(repo)

    if not url:
        return None

    sys.stderr.write('Getting clone bundle from %s\n' % os.fsdecode(url))
    return get_store_bundle(url)


def get_store_bundle(url):
    BundleHelper.connect(url)
    result = HelperRepo(BundleHelper, url).get_store_bundle(b'bundle', [], [])
    BundleHelper.close()
    return result


def do_cinnabarclone(repo, manifest, store, limit_schemes=True):
    with HgRepoHelper.query(
            b'get_cinnabarclone_url', HgRepoHelper.connected) as stdout:
        stdout.write(b"%d\n" % len(manifest))
        stdout.write(manifest)
        stdout.flush()
        url = stdout.readline().strip()
        branch = stdout.readline().strip()

    if not url:
        logging.warn('Server advertizes cinnabarclone but didn\'t provide '
                     'a git repository url to fetch from.')
        return False

    parsed_url = urlparse(url)
    if limit_schemes and parsed_url.scheme not in (b'http', b'https', b'git'):
        logging.warn('Server advertizes cinnabarclone but provided a non '
                     'http/https git repository. Skipping.')
        return False
    sys.stderr.write('Fetching cinnabar metadata from %s\n' % os.fsdecode(url))
    sys.stderr.flush()
    return store.merge(url, repo.url(), branch)


def getbundle(repo, store, heads, branch_names):
    common = findcommon(repo, store, store.heads(branch_names))
    logging.info('common: %s', common)
    got_partial = False
    if not common:
        if not store._has_metadata:
            manifest = Git.config('cinnabar.clone', remote=repo.remote)
            limit_schemes = False
            if manifest is None and repo.capable(b'cinnabarclone'):
                # If no cinnabar.clone config was given, but a
                # cinnabar.clonebundle config was, act as if an empty
                # cinnabar.clone config had been given, and proceed with
                # the mercurial clonebundle.
                if not Git.config('cinnabar.clonebundle',
                                  remote=repo.remote):
                    manifest = repo._call(b'cinnabarclone')
                    limit_schemes = True
            if manifest:
                got_partial = do_cinnabarclone(repo, manifest, store,
                                               limit_schemes)
                if not got_partial:
                    if check_enabled('cinnabarclone'):
                        raise Exception('cinnabarclone failed.')
                    logging.warn('Falling back to normal clone.')
        if not got_partial and repo.capable(b'clonebundles'):
            got_partial = bool(get_store_clonebundle(repo))
            if not got_partial and check_enabled('clonebundles'):
                raise Exception('clonebundles failed.')
    if got_partial:
        # Eliminate the heads that we got from the clonebundle or
        # cinnabarclone.
        heads = [h for h in heads if not store.changeset_ref(h)]
        if not heads:
            return
        common = findcommon(repo, store, store.heads(branch_names))
        logging.info('common: %s', common)

    repo.get_store_bundle(
        b'bundle', heads=[unhexlify(h) for h in heads],
        common=[unhexlify(h) for h in common])


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
    common = findcommon(repo, store, local_bases)
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
        self.parsed_url = munge_url(url)
        self.url = urlunparse(self.parsed_url)
        self.git_url = url if url.startswith(b'hg://') else b'hg::%s' % url


def get_repo(remote):
    if remote.name:
        HgRepoHelper.connect(remote.url, remote.name)
    else:
        HgRepoHelper.connect(remote.url)
    return HelperRepo(HgRepoHelper, remote.url, remote.name)
