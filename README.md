git-cinnabar 0.6
================

*cinnabar is the common natural form in which mercury can be found on Earth.
It contains mercury sulfide and its powder is used to make the vermillion
pigment.*

git-cinnabar is a git remote helper to interact with mercurial repositories.
Contrary to other such helpers
([[1]](https://github.com/felipec/git-remote-hg)
 [[2]](https://github.com/rfk/git-remote-hg)
 [[3]](https://github.com/cosmin/git-hg)
 [[4]](https://github.com/todesschaf/git-hg)
 [[5]](https://github.com/msysgit/msysgit/wiki/Guide-to-git-remote-hg)
 [[6]](https://github.com/buchuki/gitifyhg/)), it doesn't use a local
mercurial clone under the hood.

The main focus at the moment is to make it work with mozilla-central and
related mercurial repositories and support Mozilla workflows (try server,
etc.).

Repositories last used with versions lower than 0.5.0 are not supported.
Please run `git cinnabar upgrade` with version 0.5.0 first.

License:
--------

The git-cinnabar source code is distributed under the terms of the Mozilla Public
License version 2.0 (see the MPL-2.0 file), with parts (the git-core subdirectory)
distributed under the terms of the GNU General Public License version 2.0 (see the
git-core/COPYING file).

As a consequence, git-cinnabar binary executables are distributed under the terms
of the GNU General Public License version 2.0.

Requirements:
-------------

- Git (any version should work ; cinnabarclone bundles require 1.4.4).
- In order to build from source:
  - Rust 1.60.0 or newer.
  - GCC or clang.

Setup:
------

### Prebuilt binaries

- Assuming a prebuilt binary is available for your system, get the
  [download.py script](https://raw.githubusercontent.com/glandium/git-cinnabar/master/download.py)
  and run it (requires python 3.6 or newer) with:

  ```
  $ ./download.py
  ```

- Add the directory where the download happened to your PATH. If you have
  another git-remote-hg project in your PATH already, make sure the
  git-cinnabar path comes before.

### Cargo

- Run the following:

  ```
  $ cargo install git-cinnabar
  $ git cinnabar setup
  ```

### Build manually

- Run the following:

  ```
  $ git clone https://github.com/glandium/git-cinnabar
  $ cd git-cinnabar
  $ make
  ```

- Add the git-cinnabar directory to your PATH.

Usage:
------

`$ git clone hg::<mercurial repo>`

where `<mercurial repo>` can be a path to a local directory containing a
mercurial repository, or a http, https or ssh url.

Essentially, use git like you would for a git repository, but use a `hg::` url
where you would use a `git://` url.

See https://github.com/glandium/git-cinnabar/wiki/Mozilla:-A-git-workflow-for-Gecko-development
for an example workflow for Mozilla repositories.

Remote refs styles:
-------------------

Mercurial has two different ways to handle what git would call branches:
branches and bookmarks. Mercurial branches are permanent markers on each
changeset that belongs to them, and bookmarks are similar to git branches.

You may choose how to interact with those with the `cinnabar.refs`
configuration. The following values are supported, either individually or
combined in a comma-separated list:

- `bookmarks`: in this mode, the mercurial repository's bookmarks are exposed
  as `refs/heads/$bookmark`. Practically speaking, this means the mercurial
  bookmarks appear as the remote git branches.

- `tips`: in this mode, the most recent head of each mercurial branch is
  exposed as `refs/heads/$branch`. Any other head of the same branch is not
  exposed. This mode can be useful when branches have no more than one head.

- `heads`: in this mode, the mercurial repository's heads are exposed as
  `refs/heads/$branch/$head`, where `$branch` is the mercurial branch name
  and `$head` is the full changeset sha1 of that head.

When these values are used in combinations, the branch mappings are varied
accordingly to make the type of each remote ref explicit and to avoid name
collisions.

- When combining `bookmarks` and `heads`, bookmarks are exposed as
  `refs/heads/bookmarks/$bookmark` and branch heads are exposed as
  `refs/heads/branches/$branch/$head` (where `$head` is the full changeset
  sha1 of the head).

- When combining `bookmarks` and `tips`, bookmarks are exposed as
  `refs/heads/bookmarks/$bookmark` and branch tips are exposed as
  `refs/heads/branches/$branch`. Any other heads of the same branch are not
  exposed.

- When combining all of `bookmarks`, `heads`, and `tips`, bookmarks are
  exposed as `refs/heads/bookmarks/$bookmark`, branch heads are exposed as
  `refs/heads/branches/$branch/$head` (where `$head` is the full changeset
  sha1 of the head), except for the branch tips, which are exposed as
  `refs/heads/branches/$branch/tip`.

The shorthand `all` (also the default), is the combination of `bookmarks`,
`heads`, and `tips`.

The refs style can also be configured per remote with the
`remote.$remote.cinnabar-refs` configuration. It is also possible to use
`cinnabar.pushrefs` or `remote.$remote.cinnabar-pushrefs` to use a different
scheme for pushes only.

Tags:
-----

Because mercurial stores tags in a file in the repository, it is not possible
for git-cinnabar to know them when git asks for them, except when the
repository has already been updated. Until version 0.4.0, git-cinnabar would
try to get tags in a best effort way.

Furthermore, the way tags are tracked across branches in mercurial can make it
awkward when pulling from multiple mercurial repositories. For example, pulling
tags from mozilla-release, mozilla-beta, and mozilla-esr\* repositories is messy.

So, as of 0.5.0, tags are not associated with mercurial remotes anymore, and one
needs to setup a separate remote that consolidates all mercurial tags tracked by
git-cinnabar. That remote can be set like the following:

`$ git remote add tags hg::tags:`

And tags can be updated with, e.g.:

`$ git fetch tags`

Fetching a specific mercurial changeset:
----------------------------------------

It can sometimes be useful to fetch a specific mercurial changeset from a
remote server, without fetching the entire repository. This can be done with a command line such as:

`$ git cinnabar fetch hg::<mercurial repo> <changeset sha1>`

Translating git commits to mercurial changesets and vice-versa:
---------------------------------------------------------------

When dealing with a remote repository that doesn't use the same identifiers,
things can easily get complicated. Git-cinnabar comes with commands to know the
mercurial changeset a git commit represents and the other way around.

The following command will give you the git commit corresponding to the given
mercurial changeset sha1:

`$ git cinnabar hg2git <changeset>`

The following command will give you the mercurial changeset corresponding to
the given git commit sha1:

`$ git cinnabar git2hg <commit>`

Both commands allow abbreviated forms, as long as they are unambiguous
(no need for all the 40 hex digits of the sha1).

Avoiding metadata:
------------------

In some cases, it is not desirable to have git-cinnabar create metadata for all
pushed commits. Notably, for volatile commits such as those used on the Mozilla
try repository.

By default, git-cinnabar doesn't store metadata when pushing to non-publishing
repositories. It does otherwise.

This behavior can be changed per-remote with a `remote.$remote.cinnabar-data`
preference with one of the following values:
- `always`
- `never`
- `phase`

`phase` is the default described above. `always` and `never` are
self-explanatory.

Cinnabar clone:
---------------

For large repositories, an initial clone can take a large amount of time.
A Mercurial server operator can install the extension provided in
`mercurial/cinnabarclone.py`, and point to a git repository or bundle
containing pre-generated git-cinnabar metadata. See details in the
extension file.

Users cloning the repository would automatically get the metadata from
the git repository or bundle, and then pull the missing changesets from
the Mercurial repository.

Limitations:
------------

At the moment, push is limited to non-merge commits.

There is no support for the following mercurial features:
- obsolescence markers
- phases
- namespaces

Checking corruptions:
---------------------

Git-cinnabar is still in early infancy, and its metadata might get corrupted
for some reason.

The following command allows to detect various types of metadata corruption:

`git cinnabar fsck`

This command will fix the corruptions it can, as well as adjust some of the
metadata that contains items that became unnecessary in newer versions.

The `--full` option may be added for a more thorough validation of the metadata
contents. Using this option adds a significant amount of work, and the command
can take more than half an hour on repositories the size of mozilla-central.

`hg://` urls:
-----------

The msys shell (not msys2) doesn't keep hg::url intact when crossing the
msys/native boundary, so when running cinnabar in a msys shell with a native
git, the url is munged as `hg;;proto;\host\path\`, which git doesn't understand
and doesn't even start redirecting to git-remote-hg.

To allow such setups to still work, `hg://` urls are supported. But since
mercurial can be either on many different protocols, we abuse the port in the
given url to pass the protocol.

A `hg://` url thus looks like:

`hg://<host>[:[<port>.]<protocol>]/<path>`

The default protocol is https, and the port can be omitted.

- `hg::https://hg.mozilla.org/mozilla-central` becomes
  `hg://hg.mozilla.org/mozilla-central`

- `hg::http://hg.mozilla.org/mozilla-central` becomes
  `hg://hg.mozilla.org:http/mozilla-central`

- `hg::ssh://hg.mozilla.org/mozilla-central` becomes
  `hg://hg.mozilla.org:ssh/mozilla-central`

- `hg::file:///some/path` becomes (awkward) `hg://:file/some/path`

- `hg::http://localhost:8080/foo` becomes `hg://localhost:8080.http/foo`

- `hg::tags:` becomes `hg://:tags`

Experimental features:
----------------------

Git-cinnabar has a set of experimental features that can be enabled
independently. You can set the `cinnabar.experiments` git configuration to a
comma-separated list of those features to enable the selected ones, or to
`all` to enable them all. The available features are:

- **merge**

  Git-cinnabar currently doesn’t allow to push merge commits. The main
  reason for this is that generating the correct mercurial data for those
  merges is tricky, and needs to be gotten right.

  The main caveat with this experimental support for pushing merges is that it
  currently doesn’t handle the case where a file was moved on one of the
  branches the same way mercurial would (i.e. the information would be lost to
  mercurial users).
