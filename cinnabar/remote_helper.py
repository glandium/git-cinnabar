import os
import sys

from cinnabar.exceptions import Abort
from cinnabar.githg import (
    BranchMap,
    GitHgStore,
)
from cinnabar.helper import GitHgHelper, HgRepoHelper
from cinnabar.hg.repo import (
    getbundle,
    push,
    Remote,
)
from cinnabar.hg.bundle import (
    PushStore,
)
import logging
from cinnabar.git import (
    Git,
    InvalidConfig,
    NULL_NODE_ID,
)
from cinnabar.util import (
    ConfigSetFunc,
    strip_suffix,
)

from urllib.parse import unquote_to_bytes


def sanitize_branch_name(name):
    '''Valid characters in mercurial branch names are not necessarily valid
    in git ref names. This function replaces unsupported characters with a
    urlquote escape such that the name can be reversed straightforwardly with
    urllib.unquote.'''
    # TODO: Actually sanitize all the conflicting cases, see
    # git-check-ref-format(1).
    return name.replace(b'%', b'%25').replace(b' ', b'%20')


class BaseRemoteHelper(object):
    def __init__(self, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer):
        self._dry_run = False
        self._helper_in = stdin
        self._helper = stdout

    def run(self):
        while True:
            line = self._helper_in.readline().strip()
            if not line:
                break

            if b' ' in line:
                cmd, arg = line.split(b' ', 1)
                args = [arg]
            else:
                cmd = line
                args = []

            if cmd in (b'import', b'push'):
                GitHgHelper._ensure_helper()
                while True:
                    line = self._helper_in.readline().strip()
                    if not line:
                        break
                    _, arg = line.split(b' ', 1)
                    args.append(arg)

            elif cmd == b'option':
                assert args
                args = args[0].split(b' ', 1)

            if cmd == b'import':
                # Can't have a method named import, so we use import_
                try:
                    self.import_(*args)
                except Exception:
                    # The Exception will eventually get us to return an error
                    # code, but git actually ignores it. So we send it a
                    # command it doesn't know over the helper/fast-import
                    # protocol, so that it emits an error.
                    # Alternatively, we could send `feature done` before doing
                    # anything, and on the `done` command not being sent when
                    # an exception is thrown, triggering an error, but that
                    # requires git >= 1.7.7.
                    self._helper.write(b'error\n')
                    raise
            else:
                func = getattr(self, cmd.decode('ascii'), None)
                assert func
                func(*args)

    def option(self, name, value):
        if name == b'dry-run' and value in (b'true', b'false'):
            self._dry_run = value == b'true'
            self._helper.write(b'ok\n')
        else:
            self._helper.write(b'unsupported\n')
        self._helper.flush()


class GitRemoteHelper(BaseRemoteHelper):
    def __init__(self, store, remote, stdin=sys.stdin.buffer,
                 stdout=sys.stdout.buffer):
        super(GitRemoteHelper, self).__init__(stdin, stdout)
        self._store = store
        self._remote = remote

        self._head_template = None
        self._tip_template = None
        self._bookmark_template = None

        self._branchmap = None
        self._bookmarks = {}
        self._has_unknown_heads = False

    def list(self, arg=None):
        assert not arg or arg == b'for-push'

        fetch = (Git.config('cinnabar.fetch') or b'').split()
        if fetch:
            heads = fetch
            branchmap = {None: heads}
            bookmarks = {}

        else:
            state = HgRepoHelper.state()
            branchmap = state['branchmap']
            heads = state['heads']
            if heads == [NULL_NODE_ID]:
                heads = []
            bookmarks = state['bookmarks']

        self._bookmarks = bookmarks
        branchmap = self._branchmap = BranchMap(self._store, branchmap,
                                                heads)
        self._has_unknown_heads = bool(self._branchmap.unknown_heads())
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
            for name, sha1 in sorted(bookmarks.items()):
                if sha1 == NULL_NODE_ID:
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
            if head:
                refs[b'HEAD'] = b'@%s' % head_ref

        self._refs = {sanitize_branch_name(k): v
                      for k, v in refs.items()}

    def import_(self, *refs):
        self.list()
        if self._store._broken:
            raise Abort('Cannot fetch with broken metadata. '
                        'Please fix your clone first.\n')

        # If anything wrong happens at any time, we risk git picking
        # the existing refs/cinnabar refs, so remove them preventively.
        for sha1, ref in Git.for_each_ref('refs/cinnabar/refs/heads',
                                          'refs/cinnabar/hg',
                                          'refs/cinnabar/HEAD'):
            Git.delete_ref(ref)

        def resolve_head(head):
            resolved = self._refs.get(head)
            if resolved is None:
                raise Abort(
                    "couldn't find remote ref {}".format(head.decode()))
            if resolved.startswith(b'@'):
                return self._refs.get(resolved[1:])
            return resolved

        wanted_refs = {k: v for k, v in (
                       (h, resolve_head(h)) for h in refs) if v}
        heads = wanted_refs.values()
        if not heads:
            heads = self._branchmap.heads()

        GRAFT = {
            None: False,
            b'false': False,
            b'true': True,
        }
        try:
            graft = Git.config('cinnabar.graft', remote=self._remote.name,
                               values=GRAFT)
        except InvalidConfig as e:
            logging.error(str(e))
            return 1
        if Git.config('cinnabar.graft-refs') is not None:
            logging.warn(
                'The cinnabar.graft-refs configuration is deprecated.\n'
                'Please unset it.'
            )

        if graft:
            self._store.prepare_graft()

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
                getbundle(heads, self._branchmap.names())
        except:  # noqa: E722
            wanted_refs = {}
            raise
        finally:
            for ref, value in wanted_refs.items():
                ref = b'refs/cinnabar/' + ref
                Git.update_ref(ref, self._store.changeset_ref(value))

        self._store.close()

        self._helper.write(b'done\n')
        self._helper.flush()

        if self._remote.name and self._refs_style('heads'):
            if Git.config('fetch.prune', self._remote.name) != b'true':
                prune = 'remote.%s.prune' % os.fsdecode(self._remote.name)
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
        self.list(b'for-push')
        try:
            values = {
                None: b'phase',
                b'': b'phase',
                b'never': b'never',
                b'phase': b'phase',
                b'always': b'always',
            }
            data = Git.config('cinnabar.data', self._remote.name,
                              values=values)
        except InvalidConfig as e:
            logging.error(str(e))
            return 1

        pushes = list((Git.resolve_ref(os.fsdecode(s.lstrip(b'+'))), d,
                       s.startswith(b'+'))
                      for s, d in (r.split(b':', 1) for r in refspecs))
        if self._store._broken or not HgRepoHelper.capable(b'unbundle'):
            for source, dest, force in pushes:
                if self._store._broken:
                    self._helper.write(
                        b'error %s Cannot push with broken metadata. '
                        b'Please fix your clone first.\n' % dest)
                else:
                    self._helper.write(
                        b'error %s Remote does not support the "unbundle" '
                        b'capability\n' % dest)
            self._helper.write(b'\n')
            self._helper.flush()
        else:
            repo_heads = self._branchmap.heads()
            PushStore.adopt(self._store)
            pushed = push(self._store, pushes, repo_heads,
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
                status[dest] = HgRepoHelper.pushkey(
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
                phases = HgRepoHelper.listkeys(b'phases')
                drafts = {}
                if not phases.get(b'publishing', False):
                    drafts = set(p for p, is_draft in phases.items()
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


def main(args):
    if sys.platform == 'win32':
        # By default, sys.stdout on Windows will transform \n into \r\n, which
        # the calling git process won't recognize in our answers.
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    assert len(args) == 2
    remote = Remote(*(os.fsencode(a) for a in args))

    store = GitHgStore()

    if remote.url == b'hg::tags:':
        helper = BaseRemoteHelper()
    else:
        helper = GitRemoteHelper(store, remote)
    helper.run()

    store.close()
