# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Advertize pre-generated git-cinnabar clones

"cinnabarclone" is a mercurial server-side extension used to advertize the
existence of pre-generated, externally hosted git repository or bundle
providing git-cinnabar metadata corresponding to the mercurial repository.
Cloning from such a git repository can be faster than cloning from
mercurial directly.

This extension will look for a `.hg/cinnabar.manifest` file in the
repository on the server side to serve to clients requesting a
`cinnabarclone`.

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

To create a git repository or bundle for use with this extension, first
clone the mercurial repository with git-cinnabar. For a git repository,
push the `refs/cinnabar/metadata` ref to the git repository, renaming it
as necessary to match the optional `<branch>` name configured in the
`cinnabar.manifest` file. For a bundle, use a command like `git bundle
create <bundle-file> refs/cinnabar/metadata`, and upload the resulting
bundle-file to a HTTP/HTTPS server.
"""

from __future__ import absolute_import, unicode_literals

import errno
import os

testedwith = (
    "1.9 2.0 2.1 2.2 2.3 2.4 2.5 2.6 2.7 2.8 2.9 "
    "3.0 3.1 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 "
    "4.0 4.1 4.2 4.3 4.4 4.5 4.6 4.7 4.8 4.9 "
    "5.0 5.1 5.2 5.3 5.4 5.5 5.6 5.7 5.8 5.9 "
    "6.0 6.1 6.2 6.3 6.4 6.5 6.6 6.7 6.8"
)


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

    if exists(b"cinnabar.manifest"):
        caps.append(b"cinnabarclone")


def _capabilities(orig, repo, proto):
    caps = orig(repo, proto)
    add_cinnabar_cap(repo, caps)
    return caps


def capabilities(orig, repo, proto):
    caps = orig(repo, proto).split()
    add_cinnabar_cap(repo, caps)
    return b" ".join(caps)


def cinnabar(repo, proto):
    vfs = get_vfs(repo)
    try:
        return vfs.tryread(b"cinnabar.manifest")
    except AttributeError:
        try:
            return vfs.read(b"cinnabar.manifest")
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise
    return b""


def extsetup(ui):
    try:
        from mercurial import wireproto
    except ImportError:
        from mercurial import wireprotov1server as wireproto
    from mercurial import extensions

    try:
        extensions.wrapfunction(wireproto, "_capabilities", _capabilities)
    except AttributeError:
        extensions.wrapcommand(wireproto.commands, "capabilities", capabilities)

    def wireprotocommand(name, args=b"", permission=b"push"):
        if hasattr(wireproto, "wireprotocommand"):
            try:
                return wireproto.wireprotocommand(name, args, permission)
            except TypeError:
                if hasattr(wireproto, "permissions"):
                    wireproto.permissions[name] = permission
                return wireproto.wireprotocommand(name, args)

        def register(func):
            commands = wireproto.commands
            assert name not in commands
            commands[name] = (func, args)

        return register

    wireprotocommand(b"cinnabarclone", permission=b"pull")(cinnabar)
