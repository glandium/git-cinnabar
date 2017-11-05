#!/usr/bin/env python2.7

from __future__ import division
from binascii import unhexlify
import sys

from cinnabar.githg import (
    BranchMap,
)
from cinnabar.helper import GitHgHelper
from cinnabar.hg.repo import (
    bundlerepo,
    getbundle,
    get_repo,
    push,
)
from cinnabar.hg.bundle import (
    PushStore,
)
from itertools import chain
import logging
from cinnabar.git import (
    Git,
    InvalidConfig,
    NULL_NODE_ID,
)
from cinnabar.util import (
    IOLogger,
    VersionedDict,
)
import cinnabar.util
from urllib import unquote


def sanitize_branch_name(name):
    '''Valid characters in mercurial branch names are not necessarily valid
    in git ref names. This function replaces unsupported characters with a
    urlquote escape such that the name can be reversed straightforwardly with
    urllib.unquote.'''
    # TODO: Actually sanitize all the conflicting cases, see
    # git-check-ref-format(1).
    return name.replace('%', '%25').replace(' ', '%20')


class BaseRemoteHelper(object):
    def __init__(self, stdin=sys.stdin, stdout=sys.stdout):
        self._dry_run = False
        self._helper = IOLogger(logging.getLogger('remote-helper'),
                                stdin, stdout)

    def run(self):
        while True:
            line = self._helper.readline().strip()
            if not line:
                break

            if ' ' in line:
                cmd, arg = line.split(' ', 1)
                args = [arg]
            else:
                cmd = line
                args = []

            if cmd in ('import', 'push'):
                while True:
                    line = self._helper.readline().strip()
                    if not line:
                        break
                    _, arg = line.split(' ', 1)
                    args.append(arg)

            elif cmd == 'option':
                assert args
                args = args[0].split(' ', 1)

            if cmd in (
                'capabilities',
                'list',
                'option',
                'import',
                'push',
            ):
                if cmd == 'import':
                    # Can't have a method named import
                    cmd = 'import_'
                func = getattr(self, cmd, None)
            assert func
            func(*args)

    def option(self, name, value):
        if name == 'progress' and value in ('true', 'false'):
            cinnabar.util.progress = value == 'true'
            self._helper.write('ok\n')
        elif name == 'dry-run' and value in ('true', 'false'):
            self._dry_run = value == 'true'
            self._helper.write('ok\n')
        else:
            self._helper.write('unsupported\n')
        self._helper.flush()


class TagsRemoteHelper(BaseRemoteHelper):
    def __init__(self, store, stdin=sys.stdin, stdout=sys.stdout):
        super(TagsRemoteHelper, self).__init__(stdin, stdout)
        self._store = store

    def capabilities(self):
        self._helper.write(
            'option\n'
            'import\n'
            'refspec HEAD:refs/cinnabar/HEAD\n'
            '\n'
        )
        self._helper.flush()

    def list(self, arg=None):
        for tag, ref in sorted(self._store.tags(self._store.heads())):
            self._helper.write('%s refs/tags/%s\n' % (ref, tag))
        self._helper.write('\n')
        self._helper.flush()


class GitRemoteHelper(BaseRemoteHelper):
    def __init__(self, store, remote, stdin=sys.stdin, stdout=sys.stdout):
        super(GitRemoteHelper, self).__init__(stdin, stdout)
        self._store = store
        self._repo = get_repo(remote)
        if isinstance(self._repo, bundlerepo):
            self._repo.init(self._store)
        self._remote = remote

        self._branchmap = None
        self._bookmarks = {}
        self._HEAD = 'branches/default/tip'
        self._has_unknown_heads = False

        GRAFT = {
            None: False,
            'false': False,
            'true': True,
        }
        try:
            self._graft = Git.config('cinnabar.graft', remote=remote.name,
                                     values=GRAFT)
        except InvalidConfig as e:
            logging.error(e.message)
            return 1
        if Git.config('cinnabar.graft-refs') is not None:
            logging.warn(
                'The cinnabar.graft-refs configuration is deprecated.\n'
                'Please unset it.'
            )

    def capabilities(self):
        self._helper.write(
            'option\n'
            'import\n'
            'push\n'
            'refspec refs/heads/branches/*:'
            'refs/cinnabar/refs/heads/branches/*\n'
            'refspec refs/heads/bookmarks/*:'
            'refs/cinnabar/refs/heads/bookmarks/*\n'
            'refspec hg/*:refs/cinnabar/hg/*\n'
            'refspec HEAD:refs/cinnabar/HEAD\n'
            '\n'
        )
        self._helper.flush()

    def list(self, arg=None):
        assert not arg or arg == 'for-push'

        fetch = Git.config('cinnabar.fetch')
        if fetch:
            heads = [unhexlify(fetch)]
            branchmap = {None: heads}
            bookmarks = {}

        elif self._repo.capable('batch'):
            if hasattr(self._repo, 'iterbatch'):
                batch = self._repo.iterbatch()
                batch.branchmap()
                batch.heads()
                batch.listkeys('bookmarks')
                batch.submit()
                branchmap, heads, bookmarks = batch.results()
            else:
                batch = self._repo.batch()
                branchmap = batch.branchmap()
                heads = batch.heads()
                bookmarks = batch.listkeys('bookmarks')
                batch.submit()
                branchmap = branchmap.value
                heads = heads.value
                bookmarks = bookmarks.value
            if heads == ['\0' * 20]:
                heads = []
        else:
            while True:
                branchmap = self._repo.branchmap()
                heads = self._repo.heads()
                if heads == ['\0' * 20]:
                    heads = []
                # Some branch heads can be non-heads topologically, but if
                # some heads don't appear in the branchmap, then something
                # was pushed to the repo between branchmap() and heads()
                if set(heads).issubset(set(chain(*branchmap.values()))):
                    break
            bookmarks = self._repo.listkeys('bookmarks')

        self._bookmarks = bookmarks
        branchmap = self._branchmap = BranchMap(self._store, branchmap,
                                                heads)
        self._has_unknown_heads = bool(self._branchmap.unknown_heads())
        if self._graft and self._has_unknown_heads and not arg:
            self._store.prepare_graft()
            get_heads = set(branchmap.heads()) & branchmap.unknown_heads()
            getbundle(self._repo, self._store, get_heads, branchmap.names())
            # We may have failed to graft all changesets, in which case we
            # skipped them. If that's what happened, we want to create a
            # new branchmap containing all we do know about, so that we can
            # avoid telling git about things we don't know, because if we
            # didn't, it would ask for them, and subsequently fail because
            # they are missing.
            # Since we can't know for sure what the right tips might be for
            # each branch, we won't expose the tips. This means we don't
            # need to care about the order of the heads for the new
            # branchmap.
            self._has_unknown_heads = any(not(self._store.changeset_ref(h))
                                          for h in get_heads)
            if self._has_unknown_heads:
                new_branchmap = {
                    branch: set(h for h in branchmap.heads(branch))
                    for branch in branchmap.names()
                }
                new_branchmap = {
                    branch: set(h for h in branchmap.heads(branch)
                                if h not in branchmap.unknown_heads())
                    for branch in branchmap.names()
                }
                new_heads = set(h for h in branchmap.heads()
                                if h not in branchmap.unknown_heads())
                for status, head, branch in self._store._hgheads.iterchanges():
                    branch_heads = new_branchmap.get(branch)
                    if status == VersionedDict.REMOVED:
                        if branch_heads and head in branch_heads:
                            branch_heads.remove(head)
                        if head in new_heads:
                            new_heads.remove(head)
                    else:
                        if not branch_heads:
                            branch_heads = new_branchmap[branch] = set()
                        branch_heads.add(head)
                        new_heads.add(head)

                branchmap = self._branchmap = BranchMap(
                    self._store, new_branchmap, list(new_heads))

        refs = {}
        for branch in sorted(branchmap.names()):
            branch_tip = branchmap.tip(branch)
            for head in sorted(branchmap.heads(branch)):
                if head == branch_tip:
                    continue
                refs['refs/heads/branches/%s/%s' % (branch, head)] = head
            if branch_tip:
                refs['refs/heads/branches/%s/tip' % branch] = branch_tip

        for name, sha1 in sorted(bookmarks.iteritems()):
            if sha1 == NULL_NODE_ID:
                continue
            ref = self._store.changeset_ref(sha1)
            if self._graft and not ref:
                continue
            refs['refs/heads/bookmarks/%s' % name] = sha1
        if fetch:
            refs['hg/revs/%s' % fetch] = fetch

        if '@' in bookmarks:
            self._HEAD = 'bookmarks/@'
        head = bookmarks.get('@', branchmap.tip('default'))
        if self._graft and head:
            head = self._store.changeset_ref(head)
        if head:
            refs['HEAD'] = '@refs/heads/%s' % self._HEAD

        self._refs = {sanitize_branch_name(k): v
                      for k, v in refs.iteritems()}

        for k, v in sorted(self._refs.iteritems()):
            if k.startswith('refs/heads/branches/'):
                v = self._store.changeset_ref(v) or self._branchmap.git_sha1(v)
            elif not v.startswith('@'):
                v = self._store.changeset_ref(v) or '?'
            self._helper.write('%s %s\n' % (v, k))

        self._helper.write('\n')
        self._helper.flush()

    def import_(self, *refs):
        # If anything wrong happens at any time, we risk git picking
        # the existing refs/cinnabar refs, so remove them preventively.
        for sha1, ref in Git.for_each_ref('refs/cinnabar/refs/heads',
                                          'refs/cinnabar/hg',
                                          'refs/cinnabar/HEAD'):
            Git.delete_ref(ref)

        def resolve_head(head):
            resolved = self._refs.get(head)
            if resolved is None:
                return resolved
            if resolved.startswith('@'):
                return self._refs.get(resolved[1:])
            return resolved

        wanted_refs = {k: v for k, v in (
                       (h, resolve_head(h)) for h in refs) if v}
        heads = wanted_refs.values()
        if not heads:
            heads = self._branchmap.heads()

        try:
            # Mercurial can be an order of magnitude slower when creating
            # a bundle when not giving topological heads, which some of
            # the branch heads might not be.
            # http://bz.selenic.com/show_bug.cgi?id=4595
            # So, when we're pulling all branch heads, just ask for the
            # topological heads instead.
            # `heads` might contain known heads, if e.g. the remote has
            # never been pulled from, but we happen to have some of its
            # heads locally already.
            if self._has_unknown_heads:
                unknown_heads = self._branchmap.unknown_heads()
                if set(heads).issuperset(unknown_heads):
                    heads = set(self._branchmap.heads()) & unknown_heads
                getbundle(self._repo, self._store, heads,
                          self._branchmap.names())
        except:
            wanted_refs = {}
            raise
        finally:
            for ref, value in wanted_refs.iteritems():
                ref = 'refs/cinnabar/' + ref
                Git.update_ref(ref, self._store.changeset_ref(value))

        self._store.close()

        self._helper.write('done\n')
        self._helper.flush()

        if self._remote.name:
            if Git.config('fetch.prune', self._remote.name) != 'true':
                prune = 'remote.%s.prune' % self._remote.name
                sys.stderr.write(
                    'It is recommended that you set "%(conf)s" or '
                    '"fetch.prune" to "true".\n'
                    '  git config %(conf)s true\n'
                    'or\n'
                    '  git config fetch.prune true\n'
                    % {'conf': prune}
                )

        if self._store.tag_changes:
            sys.stderr.write(
                '\nRun the following command to update tags:\n')
            sys.stderr.write('  git fetch --tags hg::tags: tag "*"\n')

    def push(self, *refspecs):
        try:
            default = 'never' if self._graft else 'phase'
            values = {
                None: default,
                '': default,
                'never': 'never',
                'phase': 'phase',
                'always': 'always',
            }
            data = Git.config('cinnabar.data', self._remote.name,
                              values=values)
        except InvalidConfig as e:
            logging.error(e.message)
            return 1

        pushes = {s.lstrip('+'): (d, s.startswith('+'))
                  for s, d in (r.split(':', 1) for r in refspecs)}
        if not self._repo.capable('unbundle'):
            for source, (dest, force) in pushes.iteritems():
                self._helper.write(
                    'error %s Remote does not support the "unbundle" '
                    'capability\n' % dest)
            self._helper.write('\n')
            self._helper.flush()
        else:
            repo_heads = self._branchmap.heads()
            PushStore.adopt(self._store, self._graft)
            pushed = push(self._repo, self._store, pushes, repo_heads,
                          self._branchmap.names(), self._dry_run)

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
                name = unquote(dest[21:])
                if source:
                    source = self._store.hg_changeset(Git.resolve_ref(source))\
                        or ''
                status[dest] = self._repo.pushkey(
                    'bookmarks', name, self._bookmarks.get(name, ''), source)

            for source, (dest, force) in pushes.iteritems():
                if status[dest] is True:
                    self._helper.write('ok %s\n' % dest)
                elif status[dest]:
                    self._helper.write('error %s %s\n' % (dest, status[dest]))
                else:
                    self._helper.write('error %s nothing changed on remote\n'
                                       % dest)
            self._helper.write('\n')
            self._helper.flush()

            if not pushed or self._dry_run:
                data = False
            elif data == 'always':
                data = True
            elif data == 'phase':
                phases = self._repo.listkeys('phases')
                drafts = {}
                if not phases.get('publishing', False):
                    drafts = set(p for p, is_draft in phases.iteritems()
                                 if int(is_draft))
                if not drafts:
                    data = True
                else:
                    def draft_commits():
                        for d in drafts:
                            c = self._store.changeset_ref(d)
                            if c:
                                yield '^%s^@' % c
                        for h in pushed.heads():
                            yield h

                    args = ['--ancestry-path', '--topo-order']
                    args.extend(draft_commits())

                    pushed_drafts = tuple(
                        c for c, t, p in GitHgHelper.rev_list(*args))

                    # Theoretically, we could have commits with no
                    # metadata that the remote declares are public, while
                    # the rest of our push is in a draft state. That is
                    # however so unlikely that it's not worth the effort
                    # to support partial metadata storage.
                    data = not bool(pushed_drafts)
            elif data == 'never':
                data = False

            self._store.close(rollback=not data)
