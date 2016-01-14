#!/usr/bin/env python2.7

from __future__ import division
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'pythonlib'))

from .githg import (
    LazyString,
    NothingToGraftException,
    RevChunk,
    ChangesetInfo,
    ManifestInfo,
)
from .bundle import create_bundle
from binascii import unhexlify
from mercurial import (
    changegroup,
    hg,
    ui,
    util,
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
import random
from .dag import gitdag
from .git import (
    Git,
    NULL_NODE_ID,
)
from .util import (
    check_enabled,
    progress_iter,
)
from collections import defaultdict

try:
    from mercurial.changegroup import cg1unpacker
except ImportError:
    from mercurial.changegroup import unbundle10 as cg1unpacker


def readbundle(fh):
    header = changegroup.readexactly(fh, 4)
    magic, version = header[0:2], header[2:4]
    if magic != 'HG':
        raise Exception('%s: not a Mercurial bundle' % fh.name)
    if version != '10':
        raise Exception('%s: unsupported bundle version %s' % (fh.name,
                        version))
    alg = changegroup.readexactly(fh, 2)
    return cg1unpacker(fh, alg)


def chunks_in_changegroup(bundle):
    while True:
        chunk = changegroup.getchunk(bundle)
        if not chunk:
            return
        yield chunk


def iter_chunks(chunks, cls):
    previous_node = None
    for chunk in chunks:
        instance = cls(chunk)
        instance.previous_node = previous_node or instance.parent1
        yield instance
        previous_node = instance.node


def iterate_files(bundle):
    while True:
        name_chunk = changegroup.getchunk(bundle)
        if not name_chunk:
            return
        for instance in iter_chunks(chunks_in_changegroup(bundle), RevChunk):
            yield instance


def iter_initialized(get_missing, iterable):
    previous = None
    always_check = check_enabled('nodeid')
    for instance in iterable:
        check = always_check
        if instance.previous_node != NULL_NODE_ID:
            if previous and instance.previous_node == previous.node:
                instance.init(previous)
            else:
                instance.init(get_missing(instance.previous_node))
                check = True
        else:
            instance.init(())
        if check and instance.node != instance.sha1:
            raise Exception(
                'sha1 mismatch for node %s with parents %s %s and '
                'previous %s' %
                (instance.node, instance.parent1, instance.parent2,
                 instance.previous_node)
            )
        yield instance
        previous = instance


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

    logger.debug(LazyString('known (sub)set: (%d) %s'
                            % (len(known), sorted(git_known))))

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
        logger.debug(LazyString('known (sub)set: (%d) %s'
                                % (len(known), sorted(known))))
        logger.debug(LazyString('unknown (sub)set: (%d) %s'
                                % (len(unknown), sorted(unknown))))

        dag.tag_nodes_and_parents(known, 'known')
        dag.tag_nodes_and_children(unknown, 'unknown')
        log_dag('unknown')
        log_dag('known')

    return [store.hg_changeset(h) for h in dag.heads('known')]


# Mercurial's bundlerepo completely unwraps bundles in $TMPDIR but we can be
# smarter than that.
class bundlerepo(object):
    def __init__(self, path):
        self._bundle = readbundle(open(path, 'r'))

    def init(self, store):
        self._changeset_chunks = []

        def _iter_chunks():
            for chunk in progress_iter(
                    'Reading %d changesets',
                    chunks_in_changegroup(self._bundle)):
                yield chunk
                self._changeset_chunks.append(chunk)

        self._dag = gitdag()
        branches = set()
        for chunk in iter_initialized(store.changeset,
                                      iter_chunks(_iter_chunks(),
                                                  ChangesetInfo)):
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


def getbundle(repo, store, heads, branch_names):
    if isinstance(repo, bundlerepo):
        changeset_chunks = repo._changeset_chunks
        bundle = repo._bundle
    else:
        common = findcommon(repo, store, store.heads(branch_names))
        logging.info('common: %s' % common)
        bundle = repo.getbundle('bundle', heads=[unhexlify(h) for h in heads],
                                common=[unhexlify(h) for h in common])

        changeset_chunks = list(progress_iter(
            'Reading %d changesets', chunks_in_changegroup(bundle)))

    manifest_chunks = list(progress_iter(
        'Reading %d manifests', chunks_in_changegroup(bundle)))

    for rev_chunk in progress_iter(
            'Reading and importing %d files', iter_initialized(
                store.file, iterate_files(bundle))):
        store.store_file(rev_chunk)

    del bundle

    manifest_sha1s = []
    for mn in progress_iter('Importing %d manifests',
                            iter_initialized(store.manifest,
                                             iter_chunks(manifest_chunks,
                                                         ManifestInfo))):
        manifest_sha1s.append(mn.node)
        store.store_manifest(mn)

    del manifest_chunks

    # Storing changesets involves reading the manifest git tree from
    # fast-import, but fast-import's ls command, used to get the tree's
    # sha1, triggers a munmap/mmap cycle on the fast-import pack if it's
    # used after something was written in the pack, which storing
    # changesets does. On OSX, this has a dramatic performance impact,
    # where every cycle can take tens of milliseconds (!). Multiply that
    # by the number of changeset in mozilla-central and storing changesets
    # takes hours instead of seconds.
    # So read all the git manifest trees now. This will at most trigger
    # one munmap/mmap cycle. store.git_tree caches the results so that it
    # reuses that when it needs them during store.store_changeset.
    for sha1 in manifest_sha1s:
        store.git_tree(sha1)

    for cs in progress_iter('Importing %d changesets',
                            iter_initialized(store.changeset,
                                             iter_chunks(changeset_chunks,
                                                         ChangesetInfo))):
        try:
            store.store_changeset(cs)
        except NothingToGraftException:
            logging.warn('Cannot graft %s, not importing.' % cs.node)
            pass

    del changeset_chunks


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
        chunks = util.chunkbuffer(create_bundle(store, push_commits))
        cg = cg1unpacker(chunks, 'UN')
        if force:
            repo_heads = ['force']
        else:
            if not repo_heads:
                repo_heads = [NULL_NODE_ID]
            repo_heads = [unhexlify(h) for h in repo_heads]
        if repo.local():
            repo.local().ui.setconfig('server', 'validate', True)
        pushed = repo.unbundle(cg, repo_heads, '') != 0
    return gitdag(push_commits) if pushed else ()


def get_ui():
    ui_ = ui.ui()
    ui_.fout = ui_.ferr
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


def get_repo(url):
    parsed_url = munge_url(url)
    if parsed_url.scheme == 'file':
        path = parsed_url.path
        if sys.platform == 'win32':
            # TODO: This probably needs more thought.
            path = path.lstrip('/')
        if not os.path.isdir(path):
            return bundlerepo(path)
    url = urlunparse(parsed_url)
    repo = hg.peer(get_ui(), {}, url)
    assert repo.capable('getbundle')
    return repo
