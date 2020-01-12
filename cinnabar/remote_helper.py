#!/usr/bin/env python2.7

from __future__ import absolute_import, division, unicode_literals
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
    bytes_stdin,
    bytes_stdout,
    ConfigSetFunc,
    fsdecode,
    IOLogger,
    iteritems,
    strip_suffix,
    VersionedDict,
)
import cinnabar.util
try:
    from urllib.parse import unquote_to_bytes
except ImportError:
    from urllib import unquote as unquote_to_bytes


def sanitize_branch_name(name):
    '''Valid characters in mercurial branch names are not necessarily valid
    in git ref names. This function replaces unsupported characters with a
    urlquote escape such that the name can be reversed straightforwardly with
    urllib.unquote.'''
    # TODO: Actually sanitize all the conflicting cases, see
    # git-check-ref-format(1).
    return name.replace(b'%', b'%25').replace(b' ', b'%20')


class BaseRemoteHelper(object):
    def __init__(self, stdin=bytes_stdin, stdout=bytes_stdout):
        self._dry_run = False
        self._helper = IOLogger(logging.getLogger('remote-helper'),
                                stdin, stdout)

    def run(self):
        while True:
            line = self._helper.readline().strip()
            if not line:
                break

            if b' ' in line:
                cmd, arg = line.split(b' ', 1)
                args = [arg]
            else:
                cmd = line
                args = []

            if cmd in (b'import', b'push'):
                while True:
                    line = self._helper.readline().strip()
                    if not line:
                        break
                    _, arg = line.split(b' ', 1)
                    args.append(arg)

            elif cmd == b'option':
                assert args
                args = args[0].split(b' ', 1)

            if cmd in (
                b'capabilities',
                b'list',
                b'option',
                b'import',
                b'push',
            ):
                if cmd == b'import':
                    # Can't have a method named import
                    cmd = b'import_'
                func = getattr(self, cmd.decode('ascii'), None)
            assert func
            func(*args)

    def option(self, name, value):
        if name == b'progress' and value in (b'true', b'false'):
            cinnabar.util.progress = value == b'true'
            self._helper.write(b'ok\n')
        elif name == b'dry-run' and value in (b'true', b'false'):
            self._dry_run = value == b'true'
            self._helper.write(b'ok\n')
        else:
            self._helper.write(b'unsupported\n')
        self._helper.flush()


class TagsRemoteHelper(BaseRemoteHelper):
    def __init__(self, store, stdin=bytes_stdin, stdout=bytes_stdout):
        super(TagsRemoteHelper, self).__init__(stdin, stdout)
        self._store = store

    def capabilities(self):
        self._helper.write(
            b'option\n'
            b'import\n'
            b'refspec HEAD:refs/cinnabar/HEAD\n'
            b'\n'
        )
        self._helper.flush()

    def list(self, arg=None):
        for tag, ref in sorted(self._store.tags(self._store.heads())):
            self._helper.write(b'%s refs/tags/%s\n' % (ref, tag))
        self._helper.write(b'\n')
        self._helper.flush()


class GitRemoteHelper(BaseRemoteHelper):
    def __init__(self, store, remote, stdin=bytes_stdin, stdout=bytes_stdout):
        super(GitRemoteHelper, self).__init__(stdin, stdout)
        self._store = store
        self._repo = get_repo(remote)
        if isinstance(self._repo, bundlerepo):
            self._repo.init(self._store)
        self._remote = remote

        self._head_template = None
        self._tip_template = None
        self._bookmark_template = None

        self._branchmap = None
        self._bookmarks = {}
        self._has_unknown_heads = False

        GRAFT = {
            None: False,
            b'false': False,
            b'true': True,
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
            b'option\n'
            b'import\n'
            b'push\n'
            b'refspec refs/heads/*:refs/cinnabar/refs/heads/*\n'
            b'refspec hg/*:refs/cinnabar/hg/*\n'
            b'refspec HEAD:refs/cinnabar/HEAD\n'
            b'\n'
        )
        self._helper.flush()

    def list(self, arg=None):
        assert not arg or arg == b'for-push'

        fetch = (Git.config('cinnabar.fetch') or b'').split()
        if fetch:
            heads = [unhexlify(f) for f in fetch]
            branchmap = {None: heads}
            bookmarks = {}

        elif self._repo.capable(b'batch'):
            if hasattr(self._repo, 'commandexecutor'):
                with self._repo.commandexecutor() as e:
                    branchmap = e.callcommand(b'branchmap', {})
                    heads = e.callcommand(b'heads', {})
                    bookmarks = e.callcommand(b'listkeys', {
                        b'namespace': b'bookmarks'
                    })
                branchmap = branchmap.result()
                heads = heads.result()
                bookmarks = bookmarks.result()
            elif hasattr(self._repo, b'iterbatch'):
                batch = self._repo.iterbatch()
                batch.branchmap()
                batch.heads()
                batch.listkeys(b'bookmarks')
                batch.submit()
                branchmap, heads, bookmarks = batch.results()
            else:
                batch = self._repo.batch()
                branchmap = batch.branchmap()
                heads = batch.heads()
                bookmarks = batch.listkeys(b'bookmarks')
                batch.submit()
                branchmap = branchmap.value
                heads = heads.value
                bookmarks = bookmarks.value
            if heads == [b'\0' * 20]:
                heads = []
        else:
            while True:
                branchmap = self._repo.branchmap()
                heads = self._repo.heads()
                if heads == [b'\0' * 20]:
                    heads = []
                # Some branch heads can be non-heads topologically, but if
                # some heads don't appear in the branchmap, then something
                # was pushed to the repo between branchmap() and heads()
                if set(heads).issubset(
                        set(chain(*(v for _, v in iteritems(branchmap))))):
                    break
            bookmarks = self._repo.listkeys(b'bookmarks')

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

        refs_style = None
        refs_styles = ('bookmarks', 'heads', 'tips')
        if not fetch and branchmap.heads():
            refs_config = 'cinnabar.refs'
            if arg == b'for-push':
                if Git.config('cinnabar.pushrefs', remote=self._remote.name):
                    refs_config = 'cinnabar.pushrefs'

            refs_style = ConfigSetFunc(refs_config, refs_styles,
                                       remote=self._remote.name,
                                       default='all')

        refs_style = refs_style or (lambda x: True)
        self._refs_style = refs_style

        refs = {}
        if refs_style('heads') or refs_style('tips'):
            if refs_style('heads') and refs_style('tips'):
                self._head_template = b'refs/heads/branches/%s/%s'
                self._tip_template = b'refs/heads/branches/%s/tip'
            elif refs_style('heads') and refs_style('bookmarks'):
                self._head_template = b'refs/heads/branches/%s/%s'
            elif refs_style('heads'):
                self._head_template = b'refs/heads/%s/%s'
            elif refs_style('tips') and refs_style('bookmarks'):
                self._tip_template = b'refs/heads/branches/%s'
            elif refs_style('tips'):
                self._tip_template = b'refs/heads/%s'

            for branch in sorted(branchmap.names()):
                branch_tip = branchmap.tip(branch)
                if refs_style('heads'):
                    for head in sorted(branchmap.heads(branch)):
                        if head == branch_tip and refs_style('tips'):
                            continue
                        refs[self._head_template % (branch, head)] = head
                if branch_tip and refs_style('tips'):
                    refs[self._tip_template % branch] = branch_tip

        if refs_style('bookmarks'):
            if refs_style('heads') or refs_style('tips'):
                self._bookmark_template = b'refs/heads/bookmarks/%s'
            else:
                self._bookmark_template = b'refs/heads/%s'
            for name, sha1 in sorted(iteritems(bookmarks)):
                if sha1 == NULL_NODE_ID:
                    continue
                ref = self._store.changeset_ref(sha1)
                if self._graft and not ref:
                    continue
                refs[self._bookmark_template % name] = sha1

        for f in fetch:
            refs[b'hg/revs/%s' % f] = f

        head_ref = None
        if refs_style('bookmarks') and b'@' in bookmarks:
            head_ref = self._bookmark_template % b'@'
        elif refs_style('tips'):
            head_ref = self._tip_template % b'default'
        elif refs_style('heads'):
            head_ref = self._head_template % (
                b'default', branchmap.tip(b'default'))

        if head_ref:
            head = refs.get(head_ref)
            if self._graft and head:
                head = self._store.changeset_ref(head)
            if head:
                refs[b'HEAD'] = b'@%s' % head_ref

        self._refs = {sanitize_branch_name(k): v
                      for k, v in iteritems(refs)}

        head_prefix = strip_suffix((self._head_template or b''), b'%s/%s')
        for k, v in sorted(iteritems(self._refs)):
            if head_prefix and k.startswith(head_prefix):
                v = self._store.changeset_ref(v) or self._branchmap.git_sha1(v)
            elif not v.startswith(b'@'):
                v = self._store.changeset_ref(v) or b'?'
            if not self._graft or v != b'?':
                self._helper.write(b'%s %s\n' % (v, k))

        self._helper.write(b'\n')
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
            if resolved.startswith(b'@'):
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
        except Exception:
            wanted_refs = {}
            raise
        finally:
            for ref, value in iteritems(wanted_refs):
                ref = b'refs/cinnabar/' + ref
                Git.update_ref(ref, self._store.changeset_ref(value))

        self._store.close()

        self._helper.write(b'done\n')
        self._helper.flush()

        if self._remote.name and self._refs_style('heads'):
            if Git.config('fetch.prune', self._remote.name) != b'true':
                prune = 'remote.%s.prune' % fsdecode(self._remote.name)
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
            default = b'never' if self._graft else b'phase'
            values = {
                None: default,
                b'': default,
                b'never': b'never',
                b'phase': b'phase',
                b'always': b'always',
            }
            data = Git.config('cinnabar.data', self._remote.name,
                              values=values)
        except InvalidConfig as e:
            logging.error(e.message)
            return 1

        pushes = list((Git.resolve_ref(fsdecode(s.lstrip(b'+'))), d,
                       s.startswith(b'+'))
                      for s, d in (r.split(b':', 1) for r in refspecs))
        if not self._repo.capable(b'unbundle'):
            for source, dest, force in pushes:
                self._helper.write(
                    b'error %s Remote does not support the "unbundle" '
                    b'capability\n' % dest)
            self._helper.write(b'\n')
            self._helper.flush()
        else:
            repo_heads = self._branchmap.heads()
            PushStore.adopt(self._store, self._graft)
            pushed = push(self._repo, self._store, pushes, repo_heads,
                          self._branchmap.names(), self._dry_run)

            status = {}
            for source, dest, _ in pushes:
                if dest.startswith(b'refs/tags/'):
                    if source:
                        status[dest] = b'Pushing tags is unsupported'
                    else:
                        status[dest] = \
                            b'Deleting remote tags is unsupported'
                    continue
                bookmark_prefix = strip_suffix(
                    (self._bookmark_template or b''), b'%s')
                if not bookmark_prefix or not dest.startswith(bookmark_prefix):
                    if source:
                        status[dest] = bool(len(pushed))
                    else:
                        status[dest] = \
                            b'Deleting remote branches is unsupported'
                    continue
                name = unquote_to_bytes(dest[len(bookmark_prefix):])
                if source:
                    source = self._store.hg_changeset(source)
                status[dest] = self._repo.pushkey(
                    b'bookmarks', name, self._bookmarks.get(name, b''),
                    source or b'')

            for source, dest, force in pushes:
                if status[dest] is True:
                    self._helper.write(b'ok %s\n' % dest)
                elif status[dest]:
                    self._helper.write(b'error %s %s\n' % (dest, status[dest]))
                else:
                    self._helper.write(b'error %s nothing changed on remote\n'
                                       % dest)
            self._helper.write(b'\n')
            self._helper.flush()

            if not pushed or self._dry_run:
                data = False
            elif data == b'always':
                data = True
            elif data == b'phase':
                phases = self._repo.listkeys(b'phases')
                drafts = {}
                if not phases.get(b'publishing', False):
                    drafts = set(p for p, is_draft in iteritems(phases)
                                 if int(is_draft))
                if not drafts:
                    data = True
                else:
                    def draft_commits():
                        for d in drafts:
                            c = self._store.changeset_ref(d)
                            if c:
                                yield b'^%s^@' % c
                        for h in pushed.heads():
                            yield h

                    args = [b'--ancestry-path', b'--topo-order']
                    args.extend(draft_commits())

                    pushed_drafts = tuple(
                        c for c, t, p in GitHgHelper.rev_list(*args))

                    # Theoretically, we could have commits with no
                    # metadata that the remote declares are public, while
                    # the rest of our push is in a draft state. That is
                    # however so unlikely that it's not worth the effort
                    # to support partial metadata storage.
                    data = not bool(pushed_drafts)
            elif data == b'never':
                data = False

            self._store.close(rollback=not data)
