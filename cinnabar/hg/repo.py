from __future__ import division
import os
import sys
import urllib
import urllib2
from cinnabar.exceptions import NothingToGraftException
from cinnabar.githg import Changeset
from cinnabar.helper import (
    GitHgHelper,
    HgRepoHelper,
)
from binascii import (
    hexlify,
    unhexlify,
)
from itertools import (
    chain,
    izip,
)
from io import BytesIO
from urlparse import (
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
    progress_enum,
    progress_iter,
)
from collections import (
    defaultdict,
    deque,
)
from .bundle import create_bundle
from .changegroup import (
    RawRevChunk01,
    RawRevChunk02,
)
from cStringIO import StringIO

try:
    if check_enabled('no-mercurial'):
        raise ImportError('Do not use mercurial')
    # Old versions of mercurial use an old version of socketutil that tries to
    # assign a local PROTOCOL_SSLv2, copying it from the ssl module, without
    # ever using it. It shouldn't hurt to set it here.
    import ssl
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
        from mercurial.bundle2 import (
            bundle2caps,
            encodecaps,
            unbundle20,
            getunbundler,
        )
        from mercurial.changegroup import cg2unpacker
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
                    line.split('=', 1)
                    for line in Git.iter('credential', 'fill',
                                         stdin='url=%s' % authuri)
                )
                username = credentials.get('username')
                password = credentials.get('password')
                if not username or not password:
                    raise
                return username, password

    url.passwordmgr = passwordmgr
else:
    def cg1unpacker(fh, alg):
        assert alg == 'UN'
        return fh


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


def RawRevChunkType(bundle):
    if unbundle20 and isinstance(bundle, cg2unpacker):
        return RawRevChunk02
    if hasattr(bundle, 'read') or isinstance(bundle, cg1unpacker):
        return RawRevChunk01
    raise Exception('Unknown changegroup type %s' % type(bundle).__name__)


chunks_logger = logging.getLogger('chunks')


def chunks_in_changegroup(bundle, category=None):
    previous_node = None
    chunk_type = RawRevChunkType(bundle)
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


def iterate_files(bundle):
    while True:
        name = getchunk(bundle)
        if not name:
            return
        for chunk in chunks_in_changegroup(bundle, name):
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
        return set()

    sample_size = 100

    sample = _sample(hgheads, sample_size)
    known = repo.known(unhexlify(h) for h in sample)
    known = set(h for h, k in izip(sample, known) if k)

    logger.info('initial sample size: %d', len(sample))

    if len(known) == len(hgheads):
        logger.info('all heads known')
        return hgheads

    git_heads = set(store.changeset_ref(h) for h in hgheads)
    git_known = set(store.changeset_ref(h) for h in known)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug('known (sub)set: (%d) %s', len(known), sorted(git_known))

    args = ['--topo-order', '--full-history', '--parents']

    def revs():
        for h in git_known:
            yield '^%s' % h
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
        known = repo.known(unhexlify(h) for h in hg_sample)
        unknown = set(h for h, k in izip(sample, known) if not k)
        known = set(h for h, k in izip(sample, known) if k)
        logger.info('next sample size: %d', len(sample))
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('known (sub)set: (%d) %s', len(known), sorted(known))
            logger.debug('unknown (sub)set: (%d) %s', len(unknown),
                         sorted(unknown))

        dag.tag_nodes_and_parents(known, 'known')
        dag.tag_nodes_and_children(unknown, 'unknown')
        log_dag('unknown')
        log_dag('known')

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
            urllib.unquote(branch): [unhexlify(h)
                                     for h in heads.split(' ')]
            for line in state['branchmap'].splitlines()
            for branch, heads in (line.split(' ', 1),)
        }
        self._heads = [unhexlify(h)
                       for h in state['heads'][:-1].split(' ')]
        self._bookmarks = self._decode_keys(state['bookmarks'])

    def url(self):
        return self._url

    def _decode_keys(self, data):
        return dict(
            line.split('\t', 1)
            for line in data.splitlines()
        )

    def _call(self, command, *args):
        if command == 'clonebundles':
            return HgRepoHelper.clonebundles()
        if command == 'cinnabarclone':
            return HgRepoHelper.cinnabarclone()
        raise NotImplementedError()

    def capable(self, capability):
        if capability == 'bundle2':
            return urllib.quote(HgRepoHelper.capable('bundle2') or '')
        if capability in ('clonebundles', 'cinnabarclone'):
            return HgRepoHelper.capable(capability) is not None
        return capability in ('getbundle', 'unbundle', 'lookup')

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
        if namespace == 'bookmarks':
            if self._bookmarks is None:
                self.init_state()
            return self._bookmarks
        return self._decode_keys(HgRepoHelper.listkeys(namespace))

    def known(self, nodes):
        result = HgRepoHelper.known(hexlify(n) for n in nodes)
        return [bool(int(b)) for b in result]

    def getbundle(self, name, heads, common, *args, **kwargs):
        data = HgRepoHelper.getbundle((hexlify(h) for h in heads),
                                      (hexlify(c) for c in common),
                                      ','.join(kwargs.get('bundlecaps', ())))
        header = readexactly(data, 4)
        if header == 'HG20':
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

        if header == 'err\n':
            return Reader('', BytesIO())
        return Reader(header, data)

    def pushkey(self, namespace, key, old, new):
        return HgRepoHelper.pushkey(namespace, key, old, new)

    def unbundle(self, cg, heads, *args, **kwargs):
        data = HgRepoHelper.unbundle(cg, (hexlify(h) if h != 'force' else h
                                          for h in heads))
        if isinstance(data, str) and data.startswith('HG20'):
            data = unbundle20(self.ui, StringIO(data[4:]))
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
    if magic != 'HG':
        raise Exception('%s: not a Mercurial bundle' % path)
    if version == '10':
        alg = readexactly(fh, 2)
        return cg1unpacker(fh, alg)
    elif unbundle20 and version.startswith('2'):
        return getunbundler(get_ui(), fh, header)
    else:
        raise Exception('%s: unsupported bundle version %s' % (path,
                        version))


# Mercurial's bundlerepo completely unwraps bundles in $TMPDIR but we can be
# smarter than that.
class bundlerepo(object):
    def __init__(self, path, fh=None):
        self._url = path
        if fh is None:
            fh = open(path, 'r')
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
            'Analyzing {} changesets from ' + self._file,
            iter_and_store(next(raw_unbundler, None))))

        for chunk in changeset_chunks.iter_initialized(lambda x: x,
                                                       store.changeset,
                                                       Changeset.from_chunk):
            extra = chunk.extra or {}
            branch = extra.get('branch', 'default')
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
            if part.type != 'changegroup':
                logging.getLogger('bundle2').warning(
                    'ignoring bundle2 part: %s', part.type)
                continue
            logging.getLogger('bundle2').debug('part: %s', part.type)
            logging.getLogger('bundle2').debug('params: %r', part.params)
            version = part.params.get('version', '01')
            if version == '01':
                cg = cg1unpacker(part, 'UN')
            elif version == '02':
                cg = cg2unpacker(part, 'UN')
            else:
                raise Exception('Unknown changegroup version %s' % version)
            break
        else:
            raise Exception('No changegroups in the bundle')
    else:
        cg = bundle

    yield chunks_in_changegroup(cg, 'changeset')
    yield chunks_in_changegroup(cg, 'manifest')
    yield iterate_files(cg)

    if unbundle20 and isinstance(bundle, unbundle20):
        for part in parts:
            logging.getLogger('bundle2').warning(
                'ignoring bundle2 part: %s', part.type)


def get_clonebundle(repo):
    url = Git.config('cinnabar.clonebundle')
    if not url:
        try:
            if check_enabled('no-mercurial'):
                raise ImportError('Do not use mercurial')
            from mercurial.exchange import (
                parseclonebundlesmanifest,
                filterclonebundleentries,
            )
        except ImportError:
            return None

        bundles = repo._call('clonebundles')

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

        url = entries[0].get('URL')

    if not url:
        return None

    sys.stderr.write('Getting clone bundle from %s\n' % url)

    return unbundle_fh(HTTPReader(url), url)


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
        self._bundle = bundle
        self._use_store_changegroup = False
        if GitHgHelper.supports(GitHgHelper.STORE_CHANGEGROUP) and \
                experiment('store-changegroup'):
            self._use_store_changegroup = True
            self._bundle = store_changegroup(bundle)

    def __call__(self, store):
        changeset_chunks = ChunksCollection(progress_iter(
            'Reading {} changesets', next(self._bundle, None)))

        for rev_chunk in progress_iter(
                'Reading and importing {} manifests',
                next(self._bundle, None)):
            if not self._use_store_changegroup:
                GitHgHelper.store('manifest', rev_chunk)

        def enumerate_files(iter):
            last_name = None
            count_names = 0
            for count_chunks, (name, chunk) in enumerate(iter):
                if name != last_name:
                    count_names += 1
                last_name = name
                yield (count_chunks, count_names), chunk

        for rev_chunk in progress_enum(
                'Reading and importing {} revisions of {} files',
                enumerate_files(next(self._bundle, None))):
            if not self._use_store_changegroup:
                GitHgHelper.store('file', rev_chunk)

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
    data = manifest.splitlines()
    if not data:
        logging.warn('Server advertizes cinnabarclone but didn\'t provide '
                     'a git repository url to fetch from.')
        return False
    if len(data) > 1:
        logging.warn('cinnabarclone from multiple git repositories is not '
                     'supported yet.')
        return False

    url = data[0]
    url, branch = (url.split('#', 1) + [None])[:2]
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ('http', 'https', 'git'):
        logging.warn('Server advertizes cinnabarclone but provided a non '
                     'http/https git repository. Skipping.')
        return False
    sys.stderr.write('Fetching cinnabar metadata from %s\n' % url)
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
                if not manifest and experiment('git-clone') and \
                        repo.capable('cinnabarclone'):
                    manifest = repo._call('cinnabarclone')
                if manifest:
                    got_partial = do_cinnabarclone(repo, manifest, store)
                    if not got_partial:
                        if check_enabled('cinnabarclone'):
                            raise Exception('cinnabarclone failed.')
                        logging.warn('Falling back to normal clone.')
            if not got_partial and repo.capable('clonebundles'):
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
        if got_partial:
            # Eliminate the heads that we got from the clonebundle or
            # cinnabarclone.
            heads = [h for h in heads if not store.changeset_ref(h)]
            if not heads:
                return
            common = findcommon(repo, store, store.heads(branch_names))
            logging.info('common: %s', common)

        kwargs = {}
        if unbundle20 and repo.capable('bundle2'):
            bundle2caps = {
                'HG20': (),
                'changegroup': ('01', '02'),
            }
            kwargs['bundlecaps'] = set((
                'HG20', 'bundle2=%s' % urllib.quote(encodecaps(bundle2caps))))

        bundle = repo.getbundle('bundle', heads=[unhexlify(h) for h in heads],
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
            yield '^%s' % store.changeset_ref(sha1)

    def local_bases():
        h = chain(heads(), (w for w in what if w))
        for c, t, p in GitHgHelper.rev_list('--topo-order', '--full-history',
                                            '--boundary', *h):
            if c[0] != '-':
                continue
            yield store.hg_changeset(c[1:])

        for w in what:
            rev = store.hg_changeset(w)
            if rev:
                yield rev

    common = findcommon(repo, store, set(local_bases()))
    logging.info('common: %s', common)

    def revs():
        for sha1 in common:
            yield '^%s' % store.changeset_ref(sha1)

    revs = chain(revs(), (w for w in what if w))
    push_commits = list((c, p) for c, t, p in GitHgHelper.rev_list(
        '--topo-order', '--full-history', '--parents', '--reverse', *revs))

    pushed = False
    if push_commits:
        has_root = any(len(p) == 40 for p in push_commits)
        force = all(v[1] for v in what.values())
        if has_root and repo_heads:
            if not force:
                raise Exception('Cannot push a new root')
            else:
                logging.warn('Pushing a new root')
        if force:
            repo_heads = ['force']
        else:
            if not repo_heads:
                repo_heads = [NULL_NODE_ID]
            repo_heads = [unhexlify(h) for h in repo_heads]
    if push_commits and not dry_run:
        if repo.local():
            repo.local().ui.setconfig('server', 'validate', True)
        b2caps = bundle2caps(repo) if unbundle20 else {}
        logging.getLogger('bundle2').debug('%r', b2caps)
        if b2caps:
            b2caps['replycaps'] = encodecaps({'error': ['abort']})
        cg = create_bundle(store, push_commits, b2caps)
        if not isinstance(repo, HelperRepo):
            cg = chunkbuffer(cg)
            if not b2caps:
                cg = cg1unpacker(cg, 'UN')
        reply = repo.unbundle(cg, repo_heads, '')
        if unbundle20 and isinstance(reply, unbundle20):
            parts = iter(reply.iterparts())
            for part in parts:
                logging.getLogger('bundle2').debug('part: %s', part.type)
                logging.getLogger('bundle2').debug('params: %r', part.params)
                if part.type == 'output':
                    sys.stderr.write(part.read())
                elif part.type == 'reply:changegroup':
                    # TODO: should check params['in-reply-to']
                    reply = int(part.params['return'])
                elif part.type == 'error:abort':
                    raise error.Abort(part.params['message'],
                                      hint=part.params.get('hint'))
                else:
                    logging.getLogger('bundle2').warning(
                        'ignoring bundle2 part: %s', part.type)
        pushed = reply != 0
    return gitdag(push_commits) if pushed or dry_run else ()


def get_ui():
    ui_ = ui.ui()
    ui_.fout = ui_.ferr
    ui_.setconfig('ui', 'interactive', False)
    ui_.setconfig('progress', 'disable', True)
    ssh = os.environ.get('GIT_SSH_COMMAND')
    if not ssh:
        ssh = os.environ.get('GIT_SSH')
        if ssh:
            ssh = util.shellquote(ssh)
    if ssh:
        ui_.setconfig('ui', 'ssh', ssh)
    return ui_


def munge_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return ParseResult('file', '', parsed_url.path, '', '', '')

    if parsed_url.scheme != 'hg':
        return parsed_url

    proto = 'https'
    host = parsed_url.netloc
    if ':' in host:
        host, port = host.rsplit(':', 1)
        if '.' in port:
            port, proto = port.split('.', 1)
        if not port.isdigit():
            proto = port
            port = None
        if port:
            host = host + ':' + port
    return ParseResult(proto, host, parsed_url.path, parsed_url.params,
                       parsed_url.query, parsed_url.fragment)


class Remote(object):
    def __init__(self, remote, url):
        if remote.startswith(('hg::', 'hg://')):
            self.name = None
        else:
            self.name = remote
        self.parsed_url = munge_url(url)
        self.url = urlunparse(self.parsed_url)
        self.git_url = url if url.startswith('hg://') else 'hg::%s' % url


if changegroup:
    def localpeer(ui, path):
        ui.setconfig('ui', 'ssh', '')

        has_checksafessh = hasattr(util, 'checksafessh')

        sshargs = procutil.sshargs
        shellquote = procutil.shellquote
        quotecommand = procutil.quotecommand
        url = util.url
        if has_checksafessh:
            checksafessh = util.checksafessh

        procutil.sshargs = lambda *a: ''
        procutil.shellquote = lambda x: x
        if has_checksafessh:
            util.checksafessh = lambda x: None

        # In very old versions of mercurial, shellquote was not used, and
        # double quotes were hardcoded. Remove them by overriding
        # quotecommand.
        def override_quotecommand(cmd):
            cmd = cmd.lstrip()
            if cmd.startswith('"'):
                cmd = cmd[1:-1]
            return quotecommand(cmd)
        procutil.quotecommand = override_quotecommand

        class override_url(object):
            def __init__(self, *args, **kwargs):
                self.scheme = 'ssh'
                self.host = 'localhost'
                self.port = None
                self.path = path
                self.user = 'user'
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
                            'native access.')
        logging.warning(
            'Native access to mercurial repositories is experimental!')

        stream = HgRepoHelper.connect(remote.url)
        if stream:
            return bundlerepo(remote.url, stream)
        return HelperRepo(remote.url)

    if remote.parsed_url.scheme == 'file':
        path = remote.parsed_url.path
        if sys.platform == 'win32':
            # TODO: This probably needs more thought.
            path = path.lstrip('/')
        if not os.path.isdir(path):
            return bundlerepo(path)
    ui = get_ui()
    if changegroup and remote.parsed_url.scheme == 'file':
        repo = localpeer(ui, path)
    else:
        try:
            repo = hg.peer(ui, {}, remote.url)
        except (error.RepoError, urllib2.HTTPError, IOError):
            return bundlerepo(remote.url, HTTPReader(remote.url))

    assert repo.capable('getbundle')

    return repo
