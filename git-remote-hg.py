#!/usr/bin/env python2.7

from __future__ import division
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'pythonlib'))

from cinnabar.githg import (
    GitHgStore,
    LazyString,
)
from cinnabar.hg import (
    bundlerepo,
    getbundle,
    get_repo,
    push,
)
from cinnabar.bundle import (
    PushStore,
)
from binascii import hexlify
from itertools import chain
import logging
from distutils.dir_util import mkpath
from cinnabar.git import (
    FastImport,
    Git,
)
from cinnabar.util import IOLogger
import cinnabar.util


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
    git_dir = os.environ.get('GIT_DIR')
    if Git.config('core.ignorecase', 'bool') == 'true':
        sys.stderr.write(
            'Your git configuration has core.ignorecase set to "true".\n'
            'Usually, this means git detected the file system is case '
            'insensitive.\n'
            'Git-cinnabar does not support this setup.\n'
            'Either use a case sensitive file system or set '
            'core.ignorecase to "false".\n'
        )
        git_work_tree = os.path.dirname(git_dir)
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
                '  git -c core.ignorecase=false clone%(args)s hg::%(url)s '
                '%(dir)s\n'
                % {
                    'dir': git_work_tree,
                    'url': url,
                    'args': ' -o ' + remote if remote != 'origin' else ''
                }
            )
        return 1
    repo = get_repo(url)
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
                'refspec refs/heads/branches/*:'
                'refs/cinnabar/refs/heads/branches/*\n'
                'refspec refs/heads/bookmarks/*:'
                'refs/cinnabar/refs/heads/bookmarks/*\n'
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
                    cinnabar.util.progress = True
                    helper.write('ok\n')
                elif value == 'false':
                    cinnabar.util.progress = False
                    helper.write('ok\n')
                else:
                    helper.write('unsupported\n')
            else:
                helper.write('unsupported\n')
            helper.flush()
        elif cmd == 'import':
            try:
                reflog = os.path.join(git_dir, 'logs', 'refs', 'cinnabar')
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
                for line in Git.for_each_ref(
                        'refs/cinnabar/refs/heads', 'refs/cinnabar/HEAD',
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
                        % {'conf': prune}
                    )

            if store.tag_changes:
                sys.stderr.write(
                    '\nRun the following command to update remote tags:\n')
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
                                 % dest)
                helper.write('\n')
                helper.flush()
            else:
                repo_heads = branchmap.heads()
                PushStore.adopt(store)
                pushed = push(repo, store, pushes, repo_heads,
                              branchmap.names())

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
                        helper.write('error %s nothing changed on remote\n'
                                     % dest)
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
