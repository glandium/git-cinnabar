from __future__ import absolute_import, division, unicode_literals
import os
import ssl
import sys
try:
    from urllib.parse import quote_from_bytes, unquote_to_bytes
except ImportError:
    from urllib import quote as quote_from_bytes
    from urllib import unquote as unquote_to_bytes
try:
    from urllib2 import HTTPError
except ImportError:
    from urllib.error import HTTPError
from cinnabar.exceptions import NothingToGraftException
from cinnabar.githg import Changeset
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
try:
    from itertools import izip as zip
except ImportError:
    pass
from io import BytesIO
try:
    from urlparse import (
        ParseResult,
        urlparse,
        urlunparse,
    )
except ImportError:
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
    NULL_NODE_ID,
)
from cinnabar.util import (
    HTTPReader,
    check_enabled,
    chunkbuffer,
    experiment,
    fsdecode,
    progress_enum,
    progress_iter,
)
from collections import (
    defaultdict,
    deque,
)
from .bundle import (
    create_bundle,
    encodecaps,
    decodecaps,
)
from .changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)


try:
    if check_enabled('no-mercurial'):
        raise ImportError('Do not use mercurial')
    # Old versions of mercurial use an old version of socketutil that tries to
    # assign a local PROTOCOL_SSLv2, copying it from the ssl module, without
    # ever using it. It shouldn't hurt to set it here.
    if not hasattr(ssl, 'PROTOCOL_SSLv2'):
        ssl.PROTOCOL_SSLv2 = 0
    if not hasattr(ssl, 'PROTOCOL_SSLv3'):
        ssl.PROTOCOL_SSLv3 = 1

    from mercurial import (
        changegroup,
        error,
        hg,
        ui,
        url,
        util,
    )
    try:
        from mercurial.sshpeer import instance as sshpeer
    except ImportError:
        from mercurial.sshrepo import instance as sshpeer
    try:
        from mercurial.utils import procutil
    except ImportError:
        from mercurial import util as procutil
except ImportError:
    changegroup = unbundle20 = False

if changegroup:
    try:
        from mercurial.changegroup import cg1unpacker
    except ImportError:
        from mercurial.changegroup import unbundle10 as cg1unpacker

    try:
        if check_enabled('no-bundle2'):
            raise ImportError('Do not use bundlev2')
        from mercurial.bundle2 import capabilities
        if b'HG20' not in capabilities:
            raise ImportError('Mercurial may have unbundle20 but insufficient')
        from mercurial.bundle2 import unbundle20
    except ImportError:
        unbundle20 = False

    url_passwordmgr = url.passwordmgr

    class passwordmgr(url_passwordmgr):
        def find_user_password(self, realm, authuri):
            try:
                return url_passwordmgr.find_user_password(self, realm,
                                                          authuri)
            except error.Abort:
                # Assume error.Abort is only thrown from the base class's
                # find_user_password itself, which reflects that authentication
                # information is missing and mercurial would want to get it
                # from user input, but can't because the ui isn't interactive.
                credentials = dict(
                    line.split(b'=', 1)
                    for line in Git.iter('credential', 'fill',
                                         stdin=b'url=%s' % authuri)
                )
                username = credentials.get(b'username')
                password = credentials.get(b'password')
                if not username or not password:
                    raise
                return username, password

    url.passwordmgr = passwordmgr
else:
    def cg1unpacker(fh, alg):
        assert alg == b'UN'
        return fh


if not unbundle20 and not check_enabled('no-bundle2'):
    class unbundle20(object):
        def __init__(self, ui, fh):
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
                yield Part(header, self.fh)

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

        def read(self, size):
            ret = b''
            while size and not self.consumed:
                if self.chunk_size == self.chunk_offset:
                    d = readexactly(self.fh, 4)
                    self.chunk_size = struct.unpack('>i', d)[0]
                    if self.chunk_size == 0:
                        self.consumed = True
                        break
                    # TODO: handle -1, which is a special value
                    assert self.chunk_size > 0
                    self.chunk_offset = 0

                data = readexactly(
                    self.fh, min(size, self.chunk_size - self.chunk_offset))
                size -= len(data)
                self.chunk_offset += len(data)
                ret += data
            return ret


# The following two functions (readexactly, getchunk) were copied from the
# mercurial source code.
# Copyright 2006 Matt Mackall <mpm@selenic.com> and others
def readexactly(stream, n):
    '''read n bytes from stream.read and abort if less was available'''
    s = stream.read(n)
    if len(s) < n:
        raise Exception("stream ended unexpectedly (got %d bytes, expected %d)"
                        % (len(s), n))
    return s


def getchunk(stream):
    """return the next chunk from stream as a string"""
    d = readexactly(stream, 4)
    length = struct.unpack(">l", d)[0]
    if length <= 4:
        if length:
            raise Exception("invalid chunk length %d" % length)
        return ""
    return readexactly(stream, length - 4)


chunks_logger = logging.getLogger('chunks')


def chunks_in_changegroup(chunk_type, bundle, category=None):
    previous_node = None
    while True:
        chunk = getchunk(bundle)
        if not chunk:
            return
        chunk = chunk_type(chunk)
        if isinstance(chunk, RawRevChunk01):
            chunk.delta_node = previous_node or chunk.parent1
        if category and chunks_logger.isEnabledFor(logging.DEBUG):
            chunks_logger.debug(
                '%s %s',
                category,
                chunk.node,
            )
        yield chunk
        previous_node = chunk.node


def iter_chunks(chunks, cls):
    for chunk in chunks:
        yield cls(chunk)


def iterate_files(chunk_type, bundle):
    while True:
        name = getchunk(bundle)
        if not name:
            return
        for chunk in chunks_in_changegroup(chunk_type, bundle, name):
            yield name, chunk


def iter_initialized(get_missing, iterable, init=None):
    previous = None
    check = check_enabled('nodeid')
    for instance in iterable:
        if instance.delta_node != NULL_NODE_ID:
            if not previous or instance.delta_node != previous.node:
                previous = get_missing(instance.delta_node)
            if init:
                instance = init(instance, previous)
            else:
                instance.init(previous)
        elif init:
            instance = init(instance)
        else:
            instance.init(())
        if check and instance.node != instance.sha1:
            raise Exception(
                'sha1 mismatch for node %s with parents %s %s and '
                'previous %s' %
                (instance.node, instance.parent1, instance.parent2,
                 instance.delta_node)
            )
        yield instance
        previous = instance


class ChunksCollection(object):
    def __init__(self, iterator):
        self._chunks = deque()

        for chunk in iterator:
            self._chunks.append(chunk)

    def __iter__(self):
        while True:
            try:
                yield self._chunks.popleft()
            except IndexError:
                return

    def iter_initialized(self, cls, get_missing, init=None):
        return iter_initialized(get_missing, iter_chunks(self, cls),
                                init=init)


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
    __slots__ = "_url", "_branchmap", "_heads", "_bookmarks", "_ui"

    def __init__(self, url):
        self._url = url
        self._branchmap = None
        self._heads = None
        self._bookmarks = None
        self._ui = None

    @property
    def ui(self):
        if not self._ui:
            self._ui = get_ui()
        return self._ui

    def init_state(self):
        state = HgRepoHelper.state()
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
            return HgRepoHelper.clonebundles()
        if command == b'cinnabarclone':
            return HgRepoHelper.cinnabarclone()
        raise NotImplementedError()

    def capable(self, capability):
        if capability == b'bundle2':
            return quote_from_bytes(
                HgRepoHelper.capable(b'bundle2') or b'').encode('ascii')
        if capability in (b'clonebundles', b'cinnabarclone'):
            return HgRepoHelper.capable(capability) is not None
        return capability in (b'getbundle', b'unbundle', b'lookup')

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
        return self._decode_keys(HgRepoHelper.listkeys(namespace))

    def known(self, nodes):
        result = HgRepoHelper.known(hexlify(n) for n in nodes)
        return [b == b'1'[0] for b in result]

    def getbundle(self, name, heads, common, *args, **kwargs):
        data = HgRepoHelper.getbundle((hexlify(h) for h in heads),
                                      (hexlify(c) for c in common),
                                      b','.join(kwargs.get(b'bundlecaps', ())))
        header = readexactly(data, 4)
        if header == b'HG20':
            return unbundle20(self.ui, data)

        class Reader(object):
            def __init__(self, header, data):
                self.header = header
                self.data = data

            def read(self, length):
                result = self.header[:length]
                self.header = self.header[length:]
                if length > len(result):
                    result += self.data.read(length - len(result))
                return result

        if header == b'err\n':
            return Reader(b'', BytesIO())
        return Reader(header, data)

    def pushkey(self, namespace, key, old, new):
        return HgRepoHelper.pushkey(namespace, key, old, new)

    def unbundle(self, cg, heads, *args, **kwargs):
        data = HgRepoHelper.unbundle(cg, (hexlify(h) if h != b'force' else h
                                          for h in heads))
        if isinstance(data, str) and data.startswith(b'HG20'):
            data = unbundle20(self.ui, BytesIO(data[4:]))
        return data

    def local(self):
        return None

    def lookup(self, key):
        data = HgRepoHelper.lookup(key)
        if data:
            return unhexlify(data)
        raise Exception('Unknown revision %s' % key)


def unbundle_fh(fh, path):
    header = readexactly(fh, 4)
    magic, version = header[0:2], header[2:4]
    if magic != b'HG':
        raise Exception('%s: not a Mercurial bundle' % path)
    if version == b'10':
        alg = readexactly(fh, 2)
        return cg1unpacker(fh, alg)
    elif unbundle20 and version.startswith(b'2'):
        return unbundle20(get_ui(), fh)
    else:
        raise Exception('%s: unsupported bundle version %s' % (path,
                        version))


# Mercurial's bundlerepo completely unwraps bundles in $TMPDIR but we can be
# smarter than that.
class bundlerepo(object):
    def __init__(self, path, fh=None):
        self._url = path
        if fh is None:
            fh = open(path, 'rb')
        self._bundle = unbundle_fh(fh, path)
        self._file = os.path.basename(path)

    def url(self):
        return self._url

    def init(self, store):
        self._store = store

    def _ensure_ready(self):
        assert hasattr(self, '_store')
        if self._store is None:
            return
        store = self._store
        self._store = None

        raw_unbundler = unbundler(self._bundle)
        self._dag = gitdag()
        branches = set()

        chunks = []

        def iter_and_store(iterator):
            for item in iterator:
                chunks.append(item)
                yield item

        changeset_chunks = ChunksCollection(progress_iter(
            'Analyzing {} changesets from ' + fsdecode(self._file),
            iter_and_store(next(raw_unbundler, None))))

        for chunk in changeset_chunks.iter_initialized(lambda x: x,
                                                       store.changeset,
                                                       Changeset.from_chunk):
            extra = chunk.extra or {}
            branch = extra.get(b'branch', b'default')
            branches.add(branch)
            self._dag.add(chunk.node,
                          tuple(p for p in (chunk.parent1, chunk.parent2)
                                if p != NULL_NODE_ID), branch)
        self._heads = tuple(reversed(
            [unhexlify(h) for h in self._dag.all_heads(with_tags=False)]))
        self._branchmap = defaultdict(list)
        for tag, node in self._dag.all_heads():
            self._branchmap[tag].append(unhexlify(node))

        def repo_unbundler():
            yield iter(chunks)
            yield next(raw_unbundler, None)
            yield next(raw_unbundler, None)
            if next(raw_unbundler, None) is not None:
                assert False

        self._unbundler = repo_unbundler()

    def heads(self):
        self._ensure_ready()
        return self._heads

    def branchmap(self):
        self._ensure_ready()
        return self._branchmap

    def capable(self, capability):
        return False

    def listkeys(self, namespace):
        return {}

    def known(self, heads):
        self._ensure_ready()
        return [h in self._dag for h in heads]


def unbundler(bundle):
    if unbundle20 and isinstance(bundle, unbundle20):
        parts = iter(bundle.iterparts())
        for part in parts:
            if part.type != b'changegroup':
                logging.getLogger('bundle2').warning(
                    'ignoring bundle2 part: %s', part.type)
                continue
            logging.getLogger('bundle2').debug('part: %s', part.type)
            logging.getLogger('bundle2').debug('params: %r', part.params)
            version = part.params.get(b'version', b'01')
            if version == b'01':
                chunk_type = RawRevChunk01
            elif version == b'02':
                chunk_type = RawRevChunk02
            else:
                raise Exception('Unknown changegroup version %s' % version)
            cg = part
            break
        else:
            raise Exception('No changegroups in the bundle')
    else:
        chunk_type = RawRevChunk01
        cg = bundle

    yield chunks_in_changegroup(chunk_type, cg, 'changeset')
    yield chunks_in_changegroup(chunk_type, cg, 'manifest')
    yield iterate_files(chunk_type, cg)

    if unbundle20 and isinstance(bundle, unbundle20):
        for part in parts:
            logging.getLogger('bundle2').warning(
                'ignoring bundle2 part: %s', part.type)


def get_clonebundle_url(repo):
    bundles = repo._call(b'clonebundles')

    try:
        if check_enabled('no-mercurial'):
            raise ImportError('Do not use mercurial')
        from mercurial.exchange import (
            parseclonebundlesmanifest,
            filterclonebundleentries,
        )
    except ImportError:
        parseclonebundlesmanifest = False

    if parseclonebundlesmanifest:
        class dummy(object):
            pass

        fakerepo = dummy()
        fakerepo.requirements = set()
        fakerepo.supportedformats = set()
        fakerepo.ui = repo.ui

        entries = parseclonebundlesmanifest(fakerepo, bundles)
        if not entries:
            return None

        entries = filterclonebundleentries(fakerepo, entries)
        if not entries:
            return None

        return entries[0].get(b'URL')

    supported_bundles = (b'v1', b'v2')
    supported_compressions = tuple(
        k for k, v in (
            (b'none', b'UN'),
            (b'gzip', b'GZ'),
            (b'bzip2', b'BZ'),
            (b'zstd', b'ZS'),
        ) if HgRepoHelper.supports((b'compression', v))
    )

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

        return url


def get_clonebundle(repo):
    url = Git.config('cinnabar.clonebundle')
    if not url:
        url = get_clonebundle_url(repo)

    if not url:
        return None

    parsed_url = urlparse(url)
    if parsed_url.scheme not in (b'http', b'https'):
        logging.warn('Server advertizes clone bundle but provided a non '
                     'http/https url. Skipping.')
        return None

    sys.stderr.write('Getting clone bundle from %s\n' % fsdecode(url))
    return get_bundle(url)


def get_bundle(url):
    reader = None
    if not changegroup:
        reader = BundleHelper.connect(url)
        if not reader:
            BundleHelper.close()
    if not reader:
        reader = HTTPReader(url)
    return unbundle_fh(reader, url)


# TODO: Get the changegroup stream directly and send it, instead of
# recreating a stream we parsed.
def store_changegroup(changegroup):
    changesets = next(changegroup, None)
    first_changeset = next(changesets, None)
    version = 1
    if isinstance(first_changeset, RawRevChunk02):
        version = 2
    with GitHgHelper.store_changegroup(version) as fh:
        def iter_chunks(iter):
            for chunk in iter:
                fh.write(struct.pack('>l', len(chunk) + 4))
                fh.write(chunk)
                yield chunk
            fh.write(struct.pack('>l', 0))

        yield iter_chunks(chain((first_changeset,), changesets))
        yield iter_chunks(next(changegroup, None))

        def iter_files(iter):
            last_name = None
            for name, chunk in iter:
                if name != last_name:
                    if last_name is not None:
                        fh.write(struct.pack('>l', 0))
                    fh.write(struct.pack('>l', len(name) + 4))
                    fh.write(name)
                last_name = name
                fh.write(struct.pack('>l', len(chunk) + 4))
                fh.write(chunk)
                yield name, chunk
            if last_name is not None:
                fh.write(struct.pack('>l', 0))
            fh.write(struct.pack('>l', 0))

        yield iter_files(next(changegroup, None))

        if next(changegroup, None) is not None:
            assert False


class BundleApplier(object):
    def __init__(self, bundle):
        self._bundle = store_changegroup(bundle)

    def __call__(self, store):
        changeset_chunks = ChunksCollection(progress_iter(
            'Reading {} changesets', next(self._bundle, None)))

        for rev_chunk in progress_iter(
                'Reading and importing {} manifests',
                next(self._bundle, None)):
            pass

        def enumerate_files(iter):
            last_name = None
            count_names = 0
            for count_chunks, (name, chunk) in enumerate(iter, start=1):
                if name != last_name:
                    count_names += 1
                last_name = name
                yield (count_chunks, count_names), chunk

        for rev_chunk in progress_enum(
                'Reading and importing {} revisions of {} files',
                enumerate_files(next(self._bundle, None))):
            pass

        if next(self._bundle, None) is not None:
            assert False
        del self._bundle

        for cs in progress_iter(
                'Importing {} changesets',
                changeset_chunks.iter_initialized(lambda x: x, store.changeset,
                                                  Changeset.from_chunk)):
            try:
                store.store_changeset(cs)
            except NothingToGraftException:
                logging.warn('Cannot graft %s, not importing.', cs.node)


def do_cinnabarclone(repo, manifest, store):
    url = None
    for line in manifest.splitlines():
        line = line.strip()
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
        if store._graft:
            # When grafting, ignore lines without a graft revision.
            if not graft:
                continue
            graft = graft.split(b',')
            revs = list(Git.iter('rev-parse', '--revs-only', *graft))
            if len(revs) != len(graft):
                continue
            # We apparently have all the grafted revisions locally, ensure
            # they're actually reachable.
            if not any(Git.iter(
                    'rev-list', '--branches', '--tags', '--remotes',
                    '--max-count=1', '--ancestry-path', '--stdin',
                    stdin=('^{}^@'.format(c) for c in graft))):
                continue
        url, _, branch = spec.partition(b'#')
        url, branch = (url.split(b'#', 1) + [None])[:2]
        if url:
            break

    if not url:
        logging.warn('Server advertizes cinnabarclone but didn\'t provide '
                     'a git repository url to fetch from.')
        return False

    parsed_url = urlparse(url)
    if parsed_url.scheme not in (b'http', b'https', b'git'):
        logging.warn('Server advertizes cinnabarclone but provided a non '
                     'http/https git repository. Skipping.')
        return False
    sys.stderr.write('Fetching cinnabar metadata from %s\n' % fsdecode(url))
    sys.stderr.flush()
    return store.merge(url, repo.url(), branch)


def getbundle(repo, store, heads, branch_names):
    if isinstance(repo, bundlerepo):
        bundle = repo._unbundler
    else:
        common = findcommon(repo, store, store.heads(branch_names))
        logging.info('common: %s', common)
        bundle = None
        got_partial = False
        if not common:
            if not store._has_metadata:
                manifest = Git.config('cinnabar.clone')
                if manifest is None and repo.capable(b'cinnabarclone'):
                    manifest = repo._call(b'cinnabarclone')
                if manifest:
                    got_partial = do_cinnabarclone(repo, manifest, store)
                    if not got_partial:
                        if check_enabled('cinnabarclone'):
                            raise Exception('cinnabarclone failed.')
                        logging.warn('Falling back to normal clone.')
            if not got_partial and repo.capable(b'clonebundles'):
                bundle = get_clonebundle(repo)
                got_partial = bool(bundle)
                if not got_partial and check_enabled('clonebundles'):
                    raise Exception('clonebundles failed.')
        if bundle:
            bundle = unbundler(bundle)
            # Manual move semantics
            apply_bundle = BundleApplier(bundle)
            del bundle
            apply_bundle(store)
            if not changegroup:
                BundleHelper.close()
        if got_partial:
            # Eliminate the heads that we got from the clonebundle or
            # cinnabarclone.
            heads = [h for h in heads if not store.changeset_ref(h)]
            if not heads:
                return
            common = findcommon(repo, store, store.heads(branch_names))
            logging.info('common: %s', common)

        kwargs = {}
        if unbundle20 and repo.capable(b'bundle2'):
            bundle2caps = {
                b'HG20': (),
                b'changegroup': (b'01', b'02'),
            }
            kwargs['bundlecaps'] = set((
                b'HG20',
                b'bundle2=%s' % quote_from_bytes(
                    encodecaps(bundle2caps)).encode('ascii')))

        bundle = repo.getbundle(b'bundle', heads=[unhexlify(h) for h in heads],
                                common=[unhexlify(h) for h in common],
                                **kwargs)

        bundle = unbundler(bundle)

    # Manual move semantics
    apply_bundle = BundleApplier(bundle)
    del bundle
    apply_bundle(store)


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
            yield store.hg_changeset(c[1:])

        for w, _, _ in what:
            if w:
                rev = store.hg_changeset(w)
                if rev:
                    yield rev

    common = findcommon(repo, store, set(local_bases()))
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
        force = all(v for _, _, v in what)
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
        if repo.local():
            repo.local().ui.setconfig(b'server', b'validate', True)
        if unbundle20:
            b2caps = repo.capable(b'bundle2') or {}
        else:
            b2caps = {}
        if b2caps:
            b2caps = decodecaps(unquote_to_bytes(b2caps))
        logging.getLogger('bundle2').debug('%r', b2caps)
        if b2caps:
            b2caps[b'replycaps'] = encodecaps({b'error': [b'abort']})
        cg = create_bundle(store, push_commits, b2caps)
        if not isinstance(repo, HelperRepo):
            cg = chunkbuffer(cg)
            if not b2caps:
                cg = cg1unpacker(cg, b'UN')
        reply = repo.unbundle(cg, repo_heads, b'')
        if unbundle20 and isinstance(reply, unbundle20):
            parts = iter(reply.iterparts())
            for part in parts:
                logging.getLogger('bundle2').debug('part: %s', part.type)
                logging.getLogger('bundle2').debug('params: %r', part.params)
                if part.type == b'output':
                    sys.stderr.write(fsdecode(part.read()))
                elif part.type == b'reply:changegroup':
                    # TODO: should check params['in-reply-to']
                    reply = int(part.params[b'return'])
                elif part.type == b'error:abort':
                    raise error.Abort(part.params[b'message'],
                                      hint=part.params.get(b'hint'))
                else:
                    logging.getLogger(b'bundle2').warning(
                        'ignoring bundle2 part: %s', part.type)
        pushed = reply != 0
    return gitdag(push_commits) if pushed or dry_run else ()


def get_ui():
    if not changegroup:
        return None
    ui_ = ui.ui()
    ui_.fout = ui_.ferr
    ui_.setconfig(b'ui', b'interactive', False)
    ui_.setconfig(b'progress', b'disable', True)
    ssh = os.environ.get('GIT_SSH_COMMAND')
    if not ssh:
        ssh = os.environ.get('GIT_SSH')
        if ssh:
            ssh = procutil.shellquote(ssh)
    if ssh:
        ui_.setconfig(b'ui', b'ssh', ssh)
    return ui_


def munge_url(url):
    parsed_url = urlparse(url)
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
            b'',
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


if changegroup:
    def localpeer(ui, path):
        ui.setconfig(b'ui', b'ssh', b'')

        has_checksafessh = hasattr(util, 'checksafessh')

        sshargs = procutil.sshargs
        shellquote = procutil.shellquote
        quotecommand = procutil.quotecommand
        url = util.url
        if has_checksafessh:
            checksafessh = util.checksafessh

        procutil.sshargs = lambda *a: b''
        procutil.shellquote = lambda x: x
        if has_checksafessh:
            util.checksafessh = lambda x: None

        # In very old versions of mercurial, shellquote was not used, and
        # double quotes were hardcoded. Remove them by overriding
        # quotecommand.
        def override_quotecommand(cmd):
            cmd = cmd.lstrip()
            if cmd.startswith(b'"'):
                cmd = cmd[1:-1]
            return quotecommand(cmd)
        procutil.quotecommand = override_quotecommand

        class override_url(object):
            def __init__(self, *args, **kwargs):
                self.scheme = b'ssh'
                self.host = b'localhost'
                self.port = None
                self.path = path
                self.user = b'user'
                self.passwd = None
        util.url = override_url

        repo = sshpeer(ui, path, False)

        if has_checksafessh:
            util.checksafessh = checksafessh
        util.url = url
        procutil.quotecommand = quotecommand
        procutil.shellquote = shellquote
        procutil.sshargs = sshargs

        return repo


def get_repo(remote):
    if not changegroup or experiment('wire'):
        if not changegroup and not check_enabled('no-mercurial'):
            logging.warning('Mercurial libraries not found. Falling back to '
                            'experimental native access.')

        stream = HgRepoHelper.connect(remote.url)
        if stream:
            return bundlerepo(remote.url, stream)
        return HelperRepo(remote.url)

    if remote.parsed_url.scheme == b'file':
        # Make file://c:/... paths work by taking the netloc
        path = remote.parsed_url.netloc + remote.parsed_url.path
        if sys.platform == 'win32':
            # TODO: This probably needs more thought.
            path = path.lstrip(b'/')
        if not os.path.isdir(path):
            return bundlerepo(path)
    ui = get_ui()
    if changegroup and remote.parsed_url.scheme == b'file':
        repo = localpeer(ui, path)
    else:
        try:
            repo = hg.peer(ui, {}, remote.url)
        except (error.RepoError, HTTPError, IOError):
            return bundlerepo(remote.url, HTTPReader(remote.url))

    assert repo.capable(b'getbundle')

    return repo
