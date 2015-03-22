#!/usr/bin/env python2.7

from __future__ import division
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'pythonlib'))

from githg import (
    GitHgStore,
    IOLogger,
    LazyString,
    one,
    RevChunk,
    ChangesetInfo,
    ManifestInfo,
    NULL_NODE_ID,
)
from githg.bundle import (
    create_bundle,
    PushStore,
)
from binascii import hexlify, unhexlify
from mercurial import (
    changegroup,
    hg,
    ui,
    util,
)
from collections import (
    OrderedDict,
    defaultdict,
    deque,
)
from itertools import (
    chain,
    izip,
)
from urlparse import (
    urlparse,
    urlunparse,
)
import logging
import random
import subprocess
from distutils.dir_util import mkpath
from githg.dag import gitdag
from git import (
    FastImport,
    Git,
)
from git.util import progress_iter
import git.util
import time

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
            yield '^%s\n' % h
        for h in git_heads:
            if h not in git_known:
                yield '%s\n' % h

    dag = gitdag(chain(Git.iter(*args, stdin=revs), git_known))
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
            sample |= set(_sample(set(dag.iternodes()), sample_size - len(sample)))

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
        self._changeset_chunks = list(progress_iter('Reading %d changesets',
            chunks_in_changegroup(self._bundle)))

        heads = OrderedDict()
        previous = None
        for chunk in iter_chunks(self._changeset_chunks, ChangesetInfo):
            chunk.init(previous)
            previous = chunk
            extra = chunk.extra or {}
            branch = extra.get('branch', 'default')
            for p in (chunk.parent1, chunk.parent2):
                if p in heads and heads[p] == branch:
                    del heads[p]
            heads[chunk.node] = branch
        self._heads = tuple(unhexlify(h) for h in heads)
        self._branchmap = {}
        for k, v in heads.iteritems():
            self._branchmap.setdefault(v, []).append(unhexlify(k))
        self._tip = unhexlify(chunk.node)

    def heads(self):
        return self._heads

    def branchmap(self):
        return self._branchmap

    def capable(self, capability):
        return False

    def listkeys(self, namespace):
        return {}


def getbundle(repo, store, heads, branchmap):
    if isinstance(repo, bundlerepo):
        changeset_chunks = repo._changeset_chunks
        bundle = repo._bundle
    else:
        common = findcommon(repo, store, store.heads(branchmap.names()))
        logging.info('common: %s' % common)
        bundle = repo.getbundle('bundle', heads=[unhexlify(h) for h in heads],
            common=[unhexlify(h) for h in common])

        changeset_chunks = list(progress_iter('Reading %d changesets',
            chunks_in_changegroup(bundle)))

    manifest_chunks = list(progress_iter('Reading %d manifests',
        chunks_in_changegroup(bundle)))

    for rev_chunk in progress_iter('Reading and importing %d files',
            iterate_files(bundle)):
        store.store(rev_chunk)

    del bundle

    manifest_sha1s = []
    for mn in progress_iter('Importing %d manifests',
            iter_chunks(manifest_chunks, ManifestInfo)):
        manifest_sha1s.append(mn.node)
        store.store(mn)

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
    # reuses that when it needs them during store.store.
    for sha1 in manifest_sha1s:
        store.git_tree(sha1)

    heads = { h: n for n, h in enumerate(branchmap.heads()) }
    num = -1
    reported = False
    for cs in progress_iter('Importing %d changesets',
            iter_chunks(changeset_chunks, ChangesetInfo)):
        if not reported:
            prev = num
            num = heads.get(cs.node, prev)
            if prev > num:
                sys.stderr.write(
                    'The mercurial repository reported heads in a different '
                    'order than they\n'
                    'appear in the bundle it created. This breaks assumptions '
                    'in git-cinnabar\'s\n'
                    'support for tags. Please report the issue on\n'
                    '  https://github.com/glandium/git-cinnabar/issues\n'
                )
                # Mercurial itself somehow relies on the orders to match, so if
                # a future version of mercurial actually changes the heads
                # order, tag inconsistencies will happen with mercurial too.
                reported = True
        store.store(cs)

    del changeset_chunks


def push(repo, store, what, repo_heads, repo_branches):
    fast_import = FastImport()
    store.init_fast_import(fast_import)

    def heads():
        for sha1 in store.heads(repo_branches):
            yield '^%s\n' % store.changeset_ref(sha1)

    def local_bases():
        for c in Git.iter('rev-list', '--stdin', '--topo-order',
                          '--full-history', '--boundary',
                          *(w for w in what if w), stdin=heads):
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
            yield '^%s\n' % store.changeset_ref(sha1)

    push_commits = list(Git.iter('rev-list', '--stdin', '--topo-order',
                                 '--full-history', '--parents', '--reverse',
                                 *(w for w in what if w), stdin=revs))

    pushed = False
    if push_commits:
        chunks = util.chunkbuffer(create_bundle(store, push_commits))
        cg = cg1unpacker(chunks, 'UN')
        if all(v[1] for v in what.values()):
            repo_heads = ['force']
        else:
            repo_heads = [unhexlify(h) for h in repo_heads]
        if repo.local():
            repo.local().ui.setconfig('server', 'validate', True)
        pushed = repo.unbundle(cg, repo_heads, '') != 0
    return gitdag(push_commits) if pushed else ()


def read_cmd(fileobj):
    line = fileobj.readline().strip()
    if not line:
        return None, None
    line = line.split(' ')
    return line[0], line[1:]


class BranchMap(object):
    def __init__(self, store, remote_branchmap, remote_heads):
        self._heads = {}
        self._all_heads = tuple(hexlify(h) for h in reversed(remote_heads))
        self._tips = {}
        self._git_sha1s = {}
        local_heads = store.heads()
        for branch, heads in remote_branchmap.iteritems():
            branch_heads = []
            for head in heads:
                head = hexlify(head)
                branch_heads.append(head)
                sha1 = store.changeset_ref(head)
                if not sha1:
                    continue
                extra = store.read_changeset_data(sha1).get('extra')
                if extra and not extra.get('close'):
                    self._tips[branch] = head
                assert head not in self._git_sha1s
                self._git_sha1s[head] = sha1
                if head not in local_heads:
                    # When the local store still has old heads, it can
                    # have some branch heads missing because they don't
                    # appear in repo.heads() as they are not topological
                    # heads. In that case, add the remote head "manually"
                    # if we have it locally.
                    store.add_head(head)
            # Use last head as tip if we didn't set one.
            if heads and branch not in self._tips:
                self._tips[branch] = head
            self._heads[branch] = tuple(branch_heads)

    def names(self):
        return self._heads.keys()

    def heads(self, branch=None):
        if branch:
            return self._heads.get(branch, ())
        return self._all_heads

    def git_sha1(self, head):
        return self._git_sha1s.get(head, '?')

    def tip(self, branch):
        return self._tips.get(branch, None)


def main(args):
    logger = logging.getLogger('-')
    logger.info(args)
    assert len(args) == 2
    remote, url = args
    if Git.config('core.ignorecase', 'bool') == 'true':
        sys.stderr.write(
            'Your git configuration has core.ignorecase set to "true".\n'
            'Usually, this means git detected the file system is case '
            'insensitive.\n'
            'Git-cinnabar does not support this setup.\n'
            'Either use a case sensitive file system or set '
            'core.ignorecase to "false".\n'
        )
        git_dir = os.environ['GIT_DIR']
        git_work_tree = os.path.dirname(os.environ['GIT_DIR'])
        if os.path.abspath(os.getcwd() + os.sep).startswith(
                os.path.abspath(git_work_tree) + os.sep) or \
                remote == 'hg::' + url or tuple(
                Git.for_each_ref('refs/remotes/%s' % remote)):
            sys.stderr.write(
                'Use the following command to reclone:\n'
                '  git cinnabar reclone\n'
            )
        else:
            sys.stderr.write(
                'Use the following command to clone:\n'
                '  git -c core.ignorecase=false clone%(args)s hg::%(url)s %(dir)s\n'
                % {
                    'dir': git_work_tree,
                    'url': url,
                    'args': ' -o ' + remote if remote != 'origin' else ''
                }
            )
        return 1
    parsed_url = urlparse(url)
    logger.info(parsed_url)
    if not parsed_url.scheme:
        url = urlunparse(('file', '', parsed_url.path, '', '', ''))
    ui_ = ui.ui()
    ui_.fout = ui_.ferr
    if (not parsed_url.scheme or parsed_url.scheme == 'file') and \
            not os.path.isdir(parsed_url.path):
        repo = bundlerepo(parsed_url.path)
    else:
        repo = hg.peer(ui_, {}, url)
        assert repo.capable('getbundle')
    store = GitHgStore()
    logger.info(LazyString(lambda: '%s' % store.heads()))
    helper = IOLogger(logging.getLogger('remote-helper'),
        sys.stdin, sys.stdout)
    branchmap = None
    bookmarks = {}
    HEAD = 'branches/default/tip'

    while True:
        cmd, args = read_cmd(helper)
        if not cmd:
            break

        if cmd == 'capabilities':
            assert not args
            helper.write(
                'option\n'
                'import\n'
                'bidi-import\n'
                'push\n'
                'refspec refs/heads/branches/*:refs/cinnabar/refs/heads/branches/*\n'
                'refspec refs/heads/bookmarks/*:refs/cinnabar/refs/heads/bookmarks/*\n'
                'refspec HEAD:refs/cinnabar/HEAD\n'
                '\n'
            )
            helper.flush()
        elif cmd == 'list':
            assert not args or args == ['for-push']

            if repo.capable('batch'):
                batch = repo.batch()
                branchmap = batch.branchmap()
                heads = batch.heads()
                bookmarks = batch.listkeys('bookmarks')
                batch.submit()
                branchmap = branchmap.value
                heads = heads.value
                bookmarks = bookmarks.value
            else:
                while True:
                    branchmap = repo.branchmap()
                    heads = repo.heads()
                    if heads == ['\0' * 20]:
                        heads = []
                    # Some branch heads can be non-heads topologically, but if
                    # some heads don't appear in the branchmap, then something
                    # was pushed to the repo between branchmap() and heads()
                    if set(heads).issubset(set(chain(*branchmap.values()))):
                        break
                bookmarks = repo.listkeys('bookmarks')

            branchmap = BranchMap(store, branchmap, heads)
            unknowns = False
            for branch in sorted(branchmap.names()):
                branch_tip = branchmap.tip(branch)
                for head in sorted(branchmap.heads(branch)):
                    sha1 = branchmap.git_sha1(head)
                    if sha1 == '?':
                        unknowns = True
                    if head == branch_tip:
                        continue
                    helper.write('%s refs/heads/branches/%s/%s\n' % (
                        sha1,
                        branch,
                        head,
                    ))
                if branch_tip:
                    helper.write('%s refs/heads/branches/%s/tip\n' % (
                        branchmap.git_sha1(branch_tip),
                        branch,
                    ))
            for name, sha1 in sorted(bookmarks.iteritems()):
                ref = store.changeset_ref(sha1)
                helper.write(
                    '%s refs/heads/bookmarks/%s\n'
                    % (ref if ref else '?', name)
                )
            if not unknowns:
                for tag, ref in sorted(store.tags(branchmap.heads())):
                    helper.write('%s refs/tags/%s\n' % (ref, tag))

            if '@' in bookmarks:
                HEAD = 'bookmarks/@'
            helper.write(
                '@refs/heads/%s HEAD\n'
                '\n'
                % HEAD
            )
            helper.flush()
        elif cmd == 'option':
            assert len(args) == 2
            name, value = args
            if name == 'progress':
                if value == 'true':
                    git.util.progress = True
                    helper.write('ok\n')
                elif value == 'false':
                    git.util.progress = False
                    helper.write('ok\n')
                else:
                    helper.write('unsupported\n')
            else:
                helper.write('unsupported\n')
            helper.flush()
        elif cmd == 'import':
            try:
                reflog = os.path.join(os.environ['GIT_DIR'], 'logs', 'refs',
                    'cinnabar')
                mkpath(reflog)
                open(os.path.join(reflog, 'hg2git'), 'a').close()
                open(os.path.join(reflog, 'manifest'), 'a').close()
                assert len(args) == 1
                refs = args
                while cmd:
                    assert cmd == 'import'
                    cmd, args = read_cmd(helper)
                    assert args is None or len(args) == 1
                    if args:
                        refs.extend(args)
            except:
                # If anything wrong happens before we got all the import
                # commands, we risk git picking the existing refs/cinnabar
                # refs. Remove them.
                for line in Git.for_each_ref('refs/cinnabar/refs/heads',
                                             'refs/cinnabar/HEAD',
                                             format='%(refname)'):
                    Git.delete_ref(ref)
                raise

            try:
                def resolve_head(head):
                    if head.startswith('refs/heads/branches/'):
                        head = head[20:]
                        if head[-4:] == '/tip':
                            return branchmap.tip(head[:-4])
                        return head[-40:]
                    if head.startswith('refs/heads/bookmarks/'):
                        head = head[21:]
                        return bookmarks[head]
                    if head == 'HEAD':
                        return bookmarks.get('@') or branchmap.tip('default')
                    return None

                wanted_refs = {k: v for k, v in (
                               (h, resolve_head(h)) for h in refs) if v}
                heads = wanted_refs.values()
                if not heads:
                    heads = branchmap.heads()

                # Older versions would create a symbolic ref for
                # refs/remote-hg/HEAD. Newer versions don't, and
                # Git.update_ref doesn't remove the symbolic ref, so it needs
                # to be removed first.
                # Since git symbolic-ref only throws an error when the ref is
                # not symbolic, just try to remove the symbolic ref every time
                # and ignore errors.
                tuple(Git.iter('symbolic-ref', '-d', 'refs/remote-hg/HEAD',
                               stderr=open(os.devnull, 'wb')))

                refs_orig = {}
                for line in Git.for_each_ref('refs/cinnabar/refs/heads',
                                             'refs/cinnabar/HEAD',
                                             format='%(objectname) %(refname)'):
                    sha1, ref = line.split(' ', 1)
                    refs_orig[ref] = sha1
            except:
                # If anything wrong happens before we actually pull, we risk
                # git pucking the existing refs/cinnabar refs. Remove them.
                # Unlike in the case above, we now have the list of refs git
                # is expected, so we can just remove those.
                for ref in refs:
                    Git.delete_ref('refs/cinnabar/' + ref)
                raise

            try:
                store.init_fast_import(FastImport(sys.stdin, sys.stdout))
                getbundle(repo, store, heads, branchmap)
            except:
                wanted_refs = {}
                raise
            finally:
                for ref, value in wanted_refs.iteritems():
                    ref = 'refs/cinnabar/' + ref
                    if ref not in refs_orig or refs_orig[ref] != value:
                        Git.update_ref(ref, store.changeset_ref(value))
                for ref in refs_orig:
                    if ref[14:] not in wanted_refs:
                        Git.delete_ref(ref)

            store.close()

            if not remote.startswith('hg::'):
                prune = 'remote.%s.prune' % remote
                if (Git.config(prune) != 'true' and
                        Git.config('fetch.prune') != 'true'):
                    sys.stderr.write(
                        'It is recommended that you set "%(conf)s" or '
                        '"fetch.prune" to "true".\n'
                        '  git config %(conf)s true\n'
                        'or\n'
                        '  git config fetch.prune true\n'
                        % { 'conf': prune }
                    )

            if store.tag_changes:
                sys.stderr.write('\nRun the following command to update remote tags:\n')
                if not remote.startswith('hg::'):
                    sys.stderr.write('  git remote update %s\n' % remote)
                else:
                    sys.stderr.write('  git fetch --tags %s\n' % remote)

        elif cmd == 'push':
            if not remote.startswith('hg::'):
                data_pref = 'remote.%s.cinnabar-data' % remote
                data = Git.config(data_pref) or 'phase'
            else:
                data = 'phase'

            if data not in ('never', 'phase', 'always'):
                sys.stderr.write('Invalid value for %s: %s\n'
                                 % (data_pref, data))
                return 1

            refspecs = []
            refspecs.extend(args)
            while True:
                cmd, args = read_cmd(helper)
                if not cmd:
                    break
                assert cmd == 'push'
                refspecs.extend(args)
            pushes = {s.lstrip('+'): (d, s.startswith('+'))
                      for s, d in (r.split(':', 1) for r in refspecs)}
            if isinstance(repo, bundlerepo):
                for source, (dest, force) in pushes.iteritems():
                    helper.write('error %s Cannot push to a bundle file\n'
                                 % (dest, error))
                helper.write('\n')
                helper.flush()
            else:
                repo_heads = branchmap.heads()
                PushStore.adopt(store)
                pushed = push(repo, store, pushes, repo_heads, branchmap.names())

                status = {}
                for source, (dest, _) in pushes.iteritems():
                    if dest.startswith('refs/tags/'):
                        if source:
                            status[dest] = 'Pushing tags is unsupported'
                        else:
                            status[dest] = \
                                'Deleting remote tags is unsupported'
                        continue
                    if not dest.startswith('refs/heads/bookmarks/'):
                        if source:
                            status[dest] = bool(len(pushed))
                        else:
                            status[dest] = \
                                'Deleting remote branches is unsupported'
                        continue
                    name = dest[21:]
                    if source:
                        source = store.hg_changeset(Git.resolve_ref(source)) \
                            or ''
                    status[dest] = repo.pushkey(
                        'bookmarks', name, bookmarks.get(name, ''), source)

                for source, (dest, force) in pushes.iteritems():
                    if status[dest] is True:
                        helper.write('ok %s\n' % dest)
                    elif status[dest]:
                        helper.write('error %s %s\n' % (dest, status[dest]))
                    else:
                        helper.write('error %s nothing changed on remote\n' % dest)
                helper.write('\n')
                helper.flush()

                if not pushed:
                    data = False
                elif data == 'always':
                    data = True
                elif data == 'phase':
                    phases = repo.listkeys('phases')
                    drafts = {}
                    if not phases.get('publishing', False):
                        drafts = set(p for p, is_draft in phases.iteritems()
                                     if int(is_draft))
                    if not drafts:
                        data = True
                    else:
                        def draft_commits():
                            for d in drafts:
                                c = store.changeset_ref(d)
                                if c:
                                    yield '^%s^@\n' % c
                            for h in pushed.heads():
                                yield '%s\n' % h

                        args = ['rev-list', '--ancestry-path', '--topo-order',
                                '--stdin']

                        pushed_drafts = tuple(
                            Git.iter(*args, stdin=draft_commits))

                        # Theoretically, we could have commits with no
                        # metadata that the remote declares are public, while
                        # the rest of our push is in a draft state. That is
                        # however so unlikely that it's not worth the effort
                        # to support partial metadata storage.
                        data = not bool(pushed_drafts)
                elif data == 'never':
                    data = False

                store.close(rollback=not data)

    store.close()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
