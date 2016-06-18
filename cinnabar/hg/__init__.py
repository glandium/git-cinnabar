from __future__ import division
import os
import sys
import urllib
sys.path.append(os.path.join(os.path.dirname(__file__), 'pythonlib'))

from cinnabar.githg import (
    NothingToGraftException,
    RevChunk,
    ChangesetInfo,
    ManifestInfo,
)
from cinnabar.helper import (
    HgRepoHelper,
    NoHelperException,
)
from binascii import (
    hexlify,
    unhexlify,
)
from itertools import (
    chain,
    izip,
)
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
    git_dir,
    NULL_NODE_ID,
)
from cinnabar.util import (
    check_enabled,
    LazyCall,
    next,
    progress_iter,
)
from collections import (
    defaultdict,
    deque,
)
from .bundle import bundle_data
from .changegroup import (
    create_changegroup,
    RawRevChunk01,
    RawRevChunk02,
)

try:
    from mercurial import (
        changegroup,
        error,
        hg,
        ui,
        url,
        util,
    )
except ImportError:
    changegroup = unbundle20 = False

if changegroup:
    try:
        from mercurial.changegroup import cg1unpacker
    except ImportError:
        from mercurial.changegroup import unbundle10 as cg1unpacker

    try:
        from mercurial.bundle2 import (
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
    l = struct.unpack(">l", d)[0]
    if l <= 4:
        if l:
            raise Exception("invalid chunk length %d" % l)
        return ""
    return readexactly(stream, l - 4)


def RawRevChunkType(bundle):
    if unbundle20 and isinstance(bundle, cg2unpacker):
        return RawRevChunk02
    if hasattr(bundle, 'read') or isinstance(bundle, cg1unpacker):
        return RawRevChunk01
    raise Exception('Unknown changegroup type %s' % type(bundle).__name__)


def chunks_in_changegroup(bundle):
    previous_node = None
    chunk_type = RawRevChunkType(bundle)
    while True:
        chunk = getchunk(bundle)
        if not chunk:
            return
        chunk = chunk_type(chunk)
        if isinstance(chunk, RawRevChunk01):
            chunk.delta_node = previous_node or chunk.parent1
        yield chunk
        previous_node = chunk.node


def iter_chunks(chunks, cls):
    for chunk in chunks:
        yield cls(chunk)


def iterate_files(bundle):
    while True:
        name_chunk = getchunk(bundle)
        if not name_chunk:
            return
        for instance in iter_chunks(chunks_in_changegroup(bundle), RevChunk):
            yield instance


def iter_initialized(get_missing, iterable):
    previous = None
    always_check = check_enabled('nodeid')
    for instance in iterable:
        check = always_check
        if instance.delta_node != NULL_NODE_ID:
            if previous and instance.delta_node == previous.node:
                instance.init(previous)
            else:
                instance.init(get_missing(instance.delta_node))
                check = True
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

        # Indicate which chunks to keep around (key: chunk node, value:
        # last chunk node requiring it)
        self._keep = {}

        # key: chunk node, value: instance of class given to iter_initialized
        self._kept = {}

        previous_node = None
        for chunk in iterator:
            node = chunk.node
            if not isinstance(chunk, RawRevChunk01) and previous_node:
                if chunk.delta_node != previous_node:
                    self._keep[chunk.delta_node] = node
            self._chunks.append(chunk)
            previous_node = node

    def __iter__(self):
        while True:
            try:
                yield self._chunks.popleft()
            except IndexError:
                return

    def iter_initialized(self, cls, get_missing):
        if not self._keep:
            return iter_initialized(get_missing, iter_chunks(self, cls))

        def wrap_iter_chunks(self, cls):
            for chunk in iter_chunks(self, cls):
                node = chunk.node
                if node in self._keep:
                    self._kept[node] = chunk
                yield chunk
                delta_node = chunk.delta_node
                last_use = self._keep.get(delta_node)
                if node == last_use:
                    del self._keep[delta_node]
                    # We don't try to distinguish between the chunks with
                    # a delta_node from the bundle and those with a
                    # delta_node from the local repo, so we can end up
                    # not having delta_node in self._kept.
                    try:
                        del self._kept[delta_node]
                    except KeyError:
                        pass

        def wrap_get_missing(node):
            if node not in self._kept:
                return get_missing(node)
            chunk = self._kept[node]
            return chunk

        return iter_initialized(wrap_get_missing, wrap_iter_chunks(self, cls))


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

    logger.info('initial sample size: %d' % len(sample))

    if len(known) == len(hgheads):
        logger.info('all heads known')
        return hgheads

    git_heads = set(store.changeset_ref(h) for h in hgheads)
    git_known = set(store.changeset_ref(h) for h in known)

    logger.debug('known (sub)set: (%d) %s', len(known),
                 LazyCall(sorted, git_known))

    args = ['rev-list', '--topo-order', '--full-history', '--parents',
            '--stdin']

    def revs():
        for h in git_known:
            yield '^%s' % h
        for h in git_heads:
            if h not in git_known:
                yield h

    dag = gitdag(chain(Git.iter(*args, stdin=revs()), git_known))
    dag.tag_nodes_and_parents(git_known, 'known')

    def log_dag(tag):
        if not logger.isEnabledFor(logging.DEBUG):
            return
        logger.debug('%s dag size: %d' % (
            tag, sum(1 for n in dag.iternodes(tag))))
        heads = sorted(dag.heads(tag))
        logger.debug('%s dag heads: (%d) %s' % (tag, len(heads), heads))
        roots = sorted(dag.roots(tag))
        logger.debug('%s dag roots: (%d) %s' % (tag, len(roots), roots))

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
        logger.info('next sample size: %d' % len(sample))
        logger.debug('known (sub)set: (%d) %s', len(known),
                     LazyCall(sorted, known))
        logger.debug('unknown (sub)set: (%d) %s', len(unknown),
                     LazyCall(sorted, unknown))

        dag.tag_nodes_and_parents(known, 'known')
        dag.tag_nodes_and_children(unknown, 'unknown')
        log_dag('unknown')
        log_dag('known')

    return [store.hg_changeset(h) for h in dag.heads('known')]


class HelperRepo(object):
    def __init__(self, url):
        connect_result = HgRepoHelper.connect(url)
        self._branchmap = {
            urllib.unquote(branch): [unhexlify(h)
                                     for h in heads.split(' ')]
            for line in connect_result['branchmap'].splitlines()
            for branch, heads in (line.split(' ', 1),)
        }
        self._heads = [unhexlify(h)
                       for h in connect_result['heads'][:-1].split(' ')]
        self._bookmarks = self._decode_keys(connect_result['bookmarks'])

    def _decode_keys(self, data):
        return dict(
            line.split('\t', 1)
            for line in data.splitlines()
        )

    def capable(self, capability):
        return capability in ('getbundle', 'unbundle')

    def batch(self):
        raise NotImplementedError()

    def heads(self):
        return self._heads

    def branchmap(self):
        return self._branchmap

    def listkeys(self, namespace):
        if namespace == 'bookmarks':
            return self._bookmarks
        return self._decode_keys(HgRepoHelper.listkeys(namespace))

    def known(self, nodes):
        result = HgRepoHelper.known(hexlify(n) for n in nodes)
        return [bool(int(b)) for b in result]

    def getbundle(self, name, heads, common, *args, **kwargs):
        return HgRepoHelper.getbundle((hexlify(h) for h in heads),
                                      (hexlify(c) for c in common))

    def pushkey(self, namespace, key, old, new):
        return HgRepoHelper.pushkey(namespace, key, old, new)

    def unbundle(self, cg, heads, *args, **kwargs):
        return HgRepoHelper.unbundle(cg, (hexlify(h) if h != 'force' else h
                                          for h in heads))

    def local(self):
        return None


# Mercurial's bundlerepo completely unwraps bundles in $TMPDIR but we can be
# smarter than that.
class bundlerepo(object):
    def __init__(self, path):
        fh = open(path, 'r')
        header = readexactly(fh, 4)
        magic, version = header[0:2], header[2:4]
        if magic != 'HG':
            raise Exception('%s: not a Mercurial bundle' % path)
        if version == '10':
            alg = readexactly(fh, 2)
            self._bundle = cg1unpacker(fh, alg)
        elif unbundle20 and version.startswith('2'):
            self._bundle = getunbundler(get_ui(), fh, magicstring=header)
        else:
            raise Exception('%s: unsupported bundle version %s' % (path,
                            version))
        self._file = os.path.basename(path)

    def init(self, store):
        raw_unbundler = unbundler(self._bundle)
        self._dag = gitdag()
        branches = set()

        chunks = []

        def iter_and_store(iterator):
            for item in iterator:
                chunks.append(item)
                yield item

        changeset_chunks = ChunksCollection(progress_iter(
            'Analyzing %d changesets from ' + self._file,
            iter_and_store(next(raw_unbundler))))

        for chunk in changeset_chunks.iter_initialized(ChangesetInfo,
                                                       store.changeset):
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
        self._tip = unhexlify(chunk.node)

        def repo_unbundler():
            yield chunks
            yield next(raw_unbundler)
            yield next(raw_unbundler)
            if next(raw_unbundler) is not None:
                assert False

        self._unbundler = repo_unbundler()

    def heads(self):
        return self._heads

    def branchmap(self):
        return self._branchmap

    def capable(self, capability):
        return False

    def listkeys(self, namespace):
        return {}

    def known(self, heads):
        return [h in self._dag for h in heads]


def unbundler(bundle):
    if unbundle20 and isinstance(bundle, unbundle20):
        parts = iter(bundle.iterparts())
        for part in parts:
            if part.type != 'changegroup':
                logging.getLogger('bundle2').warning(
                    'ignoring bundle2 part: %s', part.type)
                continue
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

    yield chunks_in_changegroup(cg)
    yield chunks_in_changegroup(cg)
    yield iterate_files(cg)

    if unbundle20 and isinstance(bundle, unbundle20):
        for part in parts:
            logging.getLogger('bundle2').warning(
                'ignoring bundle2 part: %s', part.type)


def getbundle(repo, store, heads, branch_names):
    if isinstance(repo, bundlerepo):
        bundle = repo._unbundler
    else:
        common = findcommon(repo, store, store.heads(branch_names))
        logging.info('common: %s' % common)
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

    changeset_chunks = ChunksCollection(progress_iter(
        'Reading %d changesets', next(bundle)))

    manifest_chunks = ChunksCollection(progress_iter(
        'Reading %d manifests', next(bundle)))

    for rev_chunk in progress_iter(
            'Reading and importing %d files', iter_initialized(
                store.file, next(bundle))):
        store.store_file(rev_chunk)

    if next(bundle) is not None:
        assert False
    del bundle

    with store.batch_store_manifest():
        for mn in progress_iter(
                'Importing %d manifests',
                manifest_chunks.iter_initialized(ManifestInfo,
                                                 store.manifest)):
            store.store_manifest(mn)

    del manifest_chunks

    for cs in progress_iter(
            'Importing %d changesets',
            changeset_chunks.iter_initialized(ChangesetInfo, store.changeset)):
        try:
            store.store_changeset(cs)
        except NothingToGraftException:
            logging.warn('Cannot graft %s, not importing.' % cs.node)
            pass


def push(repo, store, what, repo_heads, repo_branches):
    store.init_fast_import()

    def heads():
        for sha1 in store.heads(repo_branches):
            yield '^%s' % store.changeset_ref(sha1)

    def local_bases():
        for c in Git.iter('rev-list', '--stdin', '--topo-order',
                          '--full-history', '--boundary',
                          *(w for w in what if w), stdin=heads()):
            if c[0] != '-':
                continue
            yield store.hg_changeset(c[1:])

        for w in what:
            rev = store.hg_changeset(w)
            if rev:
                yield rev

    common = findcommon(repo, store, set(local_bases()))
    logging.info('common: %s' % common)

    def revs():
        for sha1 in common:
            yield '^%s' % store.changeset_ref(sha1)

    push_commits = list(Git.iter('rev-list', '--stdin', '--topo-order',
                                 '--full-history', '--parents', '--reverse',
                                 *(w for w in what if w), stdin=revs()))

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
        if repo.local():
            repo.local().ui.setconfig('server', 'validate', True)
        cg = create_changegroup(store, bundle_data(store, push_commits))
        if not isinstance(repo, HelperRepo):
            chunks = util.chunkbuffer(cg)
            cg = cg1unpacker(chunks, 'UN')
        pushed = repo.unbundle(cg, repo_heads, '') != 0
    return gitdag(push_commits) if pushed else ()


def get_ui():
    ui_ = ui.ui()
    ui_.fout = ui_.ferr
    ui_.setconfig('ui', 'interactive', False)
    ui_.setconfig('progress', 'disable', True)
    ui_.readconfig(os.path.join(git_dir, 'hgrc'))
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


def get_repo(remote):
    if remote.parsed_url.scheme == 'file':
        path = remote.parsed_url.path
        if sys.platform == 'win32':
            # TODO: This probably needs more thought.
            path = path.lstrip('/')
        if not os.path.isdir(path):
            return bundlerepo(path)
    if not changegroup or Git.config('cinnabar.experiments') == 'true':
        if not changegroup:
            logging.warning('Mercurial libraries not found. Falling back to '
                            'native access.')
        logging.warning(
            'Native access to mercurial repositories is experimental!')
        try:
            return HelperRepo(remote.url)
        except NoHelperException:
            raise Exception('Native access to mercurial repositories requires '
                            'the helper.')
    repo = hg.peer(get_ui(), {}, remote.url)
    assert repo.capable('getbundle')

    return repo
