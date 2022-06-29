import os
import re
import ssl
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
from io import BytesIO
from urllib.parse import (
    ParseResult,
    urlparse,
    urlunparse,
)
import logging
import struct
import random
from cinnabar.dag import gitdag
from cinnabar.git import (
    Git,
    InvalidConfig,
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


class unbundle20(object):
    def __init__(self, fh):
        self.fh = fh
        params_len = readexactly(fh, 4)
        assert params_len == b'\0\0\0\0'

    def iterparts(self):
        while True:
            d = readexactly(self.fh, 4)
            length = struct.unpack('>i', d)[0]
            if length == 0:
                break
            assert length > 0
            header = readexactly(self.fh, length)
            part = Part(header, self.fh)
            yield part
            part.consume()


class Part(object):
    def __init__(self, rawheader, fh):
        rawheader = memoryview(rawheader)
        part_type_len = struct.unpack('>B', rawheader[:1])[0]
        self.type = rawheader[1:part_type_len + 1].tobytes().lower()
        rawheader = rawheader[part_type_len + 5:]
        params_count1, params_count2 = struct.unpack('>BB', rawheader[:2])
        rawheader = rawheader[2:]
        count = params_count1 + params_count2
        param_sizes = struct.unpack(
            '>' + ('BB' * count), rawheader[:2 * count])
        rawheader = rawheader[2 * count:]
        data = []
        for size in param_sizes:
            data.append(rawheader[:size])
            rawheader = rawheader[size:]
        assert len(rawheader) == 0
        self.params = {
            k.tobytes(): v.tobytes()
            for k, v in zip(data[::2], data[1::2])
        }
        self.fh = fh
        self.chunk_offset = 0
        self.chunk_size = 0
        self.consumed = False

    def read(self, size=None):
        ret = b''
        while (size is None or size > 0) and not self.consumed:
            if self.chunk_size == self.chunk_offset:
                d = readexactly(self.fh, 4)
                self.chunk_size = struct.unpack('>i', d)[0]
                if self.chunk_size == 0:
                    self.consumed = True
                    break
                # TODO: handle -1, which is a special value
                assert self.chunk_size > 0
                self.chunk_offset = 0

            wanted = self.chunk_size - self.chunk_offset
            if size is not None:
                wanted = min(size, wanted)
            data = readexactly(self.fh, wanted)
            if size is not None:
                size -= len(data)
            self.chunk_offset += len(data)
            ret += data
        return ret

    def consume(self):
        while not self.consumed:
            self.read(32768)


# The following function was copied from the # mercurial source code.
# Copyright 2006 Matt Mackall <mpm@selenic.com> and others
def readexactly(stream, n):
    '''read n bytes from stream.read and abort if less was available'''
    s = stream.read(n)
    if len(s) < n:
        raise Exception("stream ended unexpectedly (got %d bytes, expected %d)"
                        % (len(s), n))
    return s


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


getbundle_params = {}


class HelperRepo(object):
    __slots__ = ("_url", "_branchmap", "_heads", "_bookmarks", "_ui", "remote",
                 "_helper")

    def __init__(self, helper, url):
        self._helper = helper
        self._url = url
        self._branchmap = None
        self._heads = None
        self._bookmarks = None
        self._ui = None
        self.remote = None

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
        if command == b'clonebundles':
            return self._helper.clonebundles()
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
        bundlecaps = b','.join(kwargs.get('bundlecaps', ()))
        getbundle_params["heads"] = [
            h.decode('ascii', 'replace') for h in heads]
        getbundle_params["common"] = [
            c.decode('ascii', 'replace') for c in common]
        getbundle_params["bundlecaps"] = bundlecaps.decode('utf-8', 'replace')
        return self._helper.get_store_bundle(heads, common, bundlecaps)

    def pushkey(self, namespace, key, old, new):
        return self._helper.pushkey(namespace, key, old, new)

    def unbundle(self, cg, heads, *args, **kwargs):
        data = self._helper.unbundle(cg, (hexlify(h) if h != b'force' else h
                                          for h in heads))
        if isinstance(data, str) and data.startswith(b'HG20'):
            data = unbundle20(BytesIO(data[4:]))
        return data


def get_clonebundle_url(repo):
    bundles = repo._call(b'clonebundles')

    supported_bundles = (b'v1', b'v2')
    supported_compressions = (b'none', b'gzip', b'bzip2', b'zstd')

    has_sni = getattr(ssl, 'HAS_SNI', False)

    logger = logging.getLogger('clonebundle')

    for line in bundles.splitlines():
        attrs = line.split()
        if not attrs:
            continue
        url = attrs.pop(0)
        logger.debug(url)
        attrs = {
            unquote_to_bytes(k): unquote_to_bytes(v)
            for k, _, v in (a.partition(b'=') for a in attrs)
        }
        logger.debug(attrs)
        if b'REQUIRESNI' in attrs and not has_sni:
            logger.debug('Skip because of REQUIRESNI, but SNI unsupported')
            continue

        spec = attrs.get(b'BUNDLESPEC')
        if not spec:
            logger.debug('Skip because missing BUNDLESPEC')
            continue

        typ, _, params = spec.partition(b';')
        compression, _, version = typ.partition(b'-')

        if compression not in supported_compressions:
            logger.debug('Skip because unsupported compression (%s)',
                         compression)
            continue
        if version not in supported_bundles:
            logger.debug('Skip because unsupported bundle type (%s)',
                         version)
            continue

        params_dict = {}
        for p in params.split(b':'):
            k, _, v = p.partition(b'=')
            params_dict[k] = v

        if b'stream' in params_dict:
            logger.debug('Skip because stream bundles are not supported')
            continue

        return url


def get_store_clonebundle(repo):
    url = Git.config('cinnabar.clonebundle', remote=repo.remote)
    limit_schemes = False
    if not url:
        url = get_clonebundle_url(repo)
        limit_schemes = True

    if not url:
        return None

    parsed_url = urlparse(url)
    if limit_schemes and parsed_url.scheme not in (b'http', b'https'):
        logging.warn('Server advertizes clone bundle but provided a non '
                     'http/https url. Skipping.')
        return None

    sys.stderr.write('Getting clone bundle from %s\n' % os.fsdecode(url))
    return get_store_bundle(url)


def get_store_bundle(url):
    BundleHelper.connect(url)
    result = HelperRepo(BundleHelper, url).get_store_bundle(b'bundle', [], [])
    BundleHelper.close()
    return result


SHA1_RE = re.compile(b'[0-9a-fA-F]{1,40}$')


def do_cinnabarclone(repo, manifest, store, limit_schemes=True):
    GRAFT = {
        None: None,
        b'false': False,
        b'true': True,
    }
    try:
        enable_graft = Git.config(
            'cinnabar.graft', remote=repo.remote, values=GRAFT)
    except InvalidConfig:
        enable_graft = None

    url = None
    candidates = []
    for line in manifest.splitlines():
        line = line.strip()
        if not line:
            continue
        spec, _, params = line.partition(b' ')
        params = {
            k: v
            for k, _, v in (p.partition(b'=') for p in params.split())
        }
        graft = params.pop(b'graft', None)
        if params:
            # Future proofing: ignore lines with unknown params, even if we
            # support some that are present.
            continue
        # When grafting, ignore lines without a graft revision.
        if store._graft and not graft:
            continue
        # When explicitly disabling graft, ignore lines with a graft revision.
        if enable_graft is False and graft:
            continue

        graft = graft.split(b',') if graft else []
        graft_u = []
        for g in graft:
            if SHA1_RE.match(g):
                graft_u.append(g.decode('ascii'))
        if len(graft) != len(graft_u):
            continue
        if graft:
            revs = list(Git.iter('rev-parse', '--revs-only', *graft_u))
            if len(revs) != len(graft):
                continue
            # We apparently have all the grafted revisions locally, ensure
            # they're actually reachable.
            if not any(Git.iter(
                    'rev-list', '--branches', '--tags', '--remotes',
                    '--max-count=1', '--ancestry-path', '--stdin',
                    stdin=(b'^%s^@' % c for c in graft),
                    stderr=open(os.devnull, 'wb'))):
                continue

        candidates.append((spec, len(graft) != 0))

    if enable_graft is not False:
        graft_filters = [True, False]
    else:
        graft_filters = [False]
    for graft_filter in graft_filters:
        for spec, graft in candidates:
            if graft == graft_filter:
                url, _, branch = spec.partition(b'#')
                url, branch = (url.split(b'#', 1) + [None])[:2]
                if url:
                    break
        if url:
            break

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

    kwargs = {}
    if repo.capable(b'bundle2'):
        bundle2caps = {
            b'HG20': (),
            b'changegroup': (b'01', b'02'),
        }
        kwargs['bundlecaps'] = set((
            b'HG20',
            b'bundle2=%s' % quote_from_bytes(
                encodecaps(bundle2caps)).encode('ascii')))

    repo.get_store_bundle(
        b'bundle', heads=[unhexlify(h) for h in heads],
        common=[unhexlify(h) for h in common], **kwargs)


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
        if b2caps:
            b2caps[b'replycaps'] = encodecaps({b'error': [b'abort']})
        cg = create_bundle(store, push_commits, b2caps)
        reply = repo.unbundle(cg, repo_heads, b'')
        if isinstance(reply, unbundle20):
            parts = iter(reply.iterparts())
            for part in parts:
                logging.getLogger('bundle2').debug('part: %s', part.type)
                logging.getLogger('bundle2').debug('params: %r', part.params)
                if part.type == b'output':
                    sys.stderr.write(os.fsdecode(part.read()))
                elif part.type == b'reply:changegroup':
                    # TODO: should check params['in-reply-to']
                    reply = int(part.params[b'return'])
                elif part.type == b'error:abort':
                    message = part.params[b'message'].decode('utf-8')
                    hint = part.params.get(b'hint')
                    if hint:
                        message += '\n\n' + hint.decode('utf-8')
                    raise Exception(message)
                else:
                    logging.getLogger('bundle2').warning(
                        'ignoring bundle2 part: %s', part.type)
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
    repo = _get_repo(remote)
    repo.remote = remote.name
    return repo


def _get_repo(remote):
    HgRepoHelper.connect(remote.url)
    return HelperRepo(HgRepoHelper, remote.url)
