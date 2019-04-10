# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

"""Advertize pre-generated git-cinnabar clones

"cinnabarclone" is a mercurial server-side extension used to advertize the
existence of pre-generated, externally hosted git repository providing
git-cinnabar metadata corresponding to the mercurial repository.
Cloning from such a git repository can be faster than cloning from
mercurial directly.

This extension will look for a `.hg/cinnabar.manifest` file on the server
side to serve to clients requesting a `cinnabarclone`.

The file contains a list of git repository or bundles urls to be pulled
from, one after the other. Each line has the format:

   `<url>[#<branch>]`

where `<url>` is the URL of the git repository or bundle, and `<branch>`
(optional) is the name of the branch to fetch. The branch can be a full
qualified ref name (`refs/heads/branch`), or a simple name (`branch`). In
the latter case, the client will fetch the `refs/cinnabar/<branch>` ref
if it exists, or the `refs/heads/<branch>` ref otherwise.

If <branch> is ommitted, the client will try names matching the mercurial
repository url, or `metadata` as last resort.

For a mercurial repository url like `proto://server/dir_a/dir_b/repo`,
it will try the following branches:
  - repo
  - dir_b/repo
  - dir_a/dir_b/repo
  - server/dir_a/dir_b/repo
  - metadata

"""

from __future__ import absolute_import
import errno
import os


def get_vfs(repo):
    try:
        return repo.vfs
    except AttributeError:
        return repo.opener


def add_cinnabar_cap(repo, caps):
    vfs = get_vfs(repo)
    try:
        exists = vfs.exists
    except AttributeError:
        def exists(path):
            return os.path.exists(os.path.join(vfs.base, path))
    if exists('cinnabar.manifest'):
        caps.append('cinnabarclone')


def _capabilities(orig, repo, proto):
    caps = orig(repo, proto)
    add_cinnabar_cap(repo, caps)
    return caps


def capabilities(orig, repo, proto):
    caps = orig(repo, proto).split()
    add_cinnabar_cap(repo, caps)
    return ' '.join(caps)


def cinnabar(repo, proto):
    vfs = get_vfs(repo)
    try:
        return vfs.tryread('cinnabar.manifest')
    except AttributeError:
        try:
            return vfs.read('cinnabar.manifest')
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise
    return ''


def extsetup(ui):
    try:
        from mercurial import wireproto
    except:
        from mercurial import wireprotov1server as wireproto
    from mercurial import extensions

    try:
        extensions.wrapfunction(wireproto, '_capabilities', _capabilities)
    except AttributeError:
        extensions.wrapcommand(
            wireproto.commands, 'capabilities', capabilities)

    def wireprotocommand(name, args='', permission='push'):
        if hasattr(wireproto, 'wireprotocommand'):
            try:
                return wireproto.wireprotocommand(name, args, permission)
            except TypeError:
                if hasattr(wireproto, 'permissions'):
                    wireproto.permissions[name] = permission
                return wireproto.wireprotocommand(name, args)

        def register(func):
            commands = wireproto.commands
            assert name not in commands
            commands[name] = (func, args)

        return register

    wireprotocommand('cinnabarclone', permission='pull')(cinnabar)
