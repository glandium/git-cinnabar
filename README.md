git-cinnabar 0.5
================

When you update, please read this file again, it may contain important notes.

*cinnabar is the common natural form in which mercury can be found on Earth.
It contains mercury sulfide and its powder is used to make the vermillion
pigment.*

git-cinnabar is a git remote helper to interact with mercurial repositories.
Contrary to other such helpers\*, it doesn't use a local mercurial clone under
the hood, although it currently does require mercurial to be installed for some
of its libraries.

\* This applies to the following tools:
  - https://github.com/felipec/git-remote-hg
  - https://github.com/rfk/git-remote-hg
  - https://github.com/cosmin/git-hg
  - https://github.com/todesschaf/git-hg
  - https://github.com/msysgit/msysgit/wiki/Guide-to-git-remote-hg
  - https://github.com/buchuki/gitifyhg/

The main focus at the moment is to make it work with mozilla-central and
related mercurial repositories and support Mozilla workflows (try server,
etc.).

Repositories last used with versions lower than 0.3.0 are not supported.
Please run `git cinnabar fsck` with version 0.3.0 first.

Requirements:
-------------

- Git (any version should work)
- Mercurial version 1.9 or newer

Setup:
------

- Add this directory to your PATH. If you have another git-remote-hg project in
  your PATH already, make sure the git-cinnabar path comes before.

- A native helper is used for faster operations. You can download a prebuilt
  binary with the following command (assuming one is available for your system):

  ```
  $ git cinnabar download
  ```

  Alternatively, you can do the following to build it:

  ```
  $ make helper
  ```

Or see `git-core/INSTALL` after initializing the submodule, for build/install
instructions, but run the commands in this directory. This will build/install
git as well as the tools from this directory. Note that if you have a
non-standard Python installation location (for example if you are on macOS and
have installed it using homebrew) you need to pass
`--with-python=/path/to/python` to the configure script or set the
`PYTHON_PATH` environment variable to your Python installation path when using
make to build this tool.

Usage:
------

`$ git clone hg::<mercurial repo>`

where `<mercurial repo>` can be a path to a local directory containing a
mercurial repository, or a http, https or ssh url.

Essentially, use git like you would for a git repository, but use a `hg::` url
where you would use a `git://` url.

Mercurial bookmarks are exposed as `refs/heads/bookmarks/$bookmark` remote
refs. If you want to interact exclusively with mercurial with bookmarks, you
can use a refspec like `refs/heads/bookmarks/*:refs/remotes/$remote/*`.

Mercurial branches are exposed as namespaces under `refs/heads/branches/`. As
mercurial branches can have multiple heads, each head is exposed as
`refs/heads/branches/$branch/$head`, where `$head` is the mercurial sha1 of the
head changeset. There is however an exception to that pattern, for the tip
changeset of the branch, which is exposed as `refs/heads/branches/$branch/tip`.
If you only care about the tip changeset of each branch, you can use a refspec
like `refs/heads/branches/*/tip:ref/remotes/$remote/*`.

See https://github.com/glandium/git-cinnabar/wiki/Mozilla:-A-git-workflow-for-Gecko-development
for an example workflow for Mozilla repositories.

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

The `--manifests` and `--files` options may be added for additional validation
on manifests and files. Using either or both adds a significant amount of work,
and the command can take more than half an hour on repositories the size of
mozilla-central.

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

- `hg::https://hg.mozilla.org/mozilla-central`

  becomes

  `hg://hg.mozilla.org/mozilla-central`

- `hg::http://hg.mozilla.org/mozilla-central`

  becomes

  `hg://hg.mozilla.org:http/mozilla-central`

- `hg::ssh://hg.mozilla.org/mozilla-central`

  becomes

  `hg://hg.mozilla.org:ssh/mozilla-central`

- `hg::file:///some/path`

  becomes (awkward)

  `hg://:file/some/path`

- `hg::http://localhost:8080/foo`

  becomes

  `hg://localhost:8080.http/foo`

- `hg::tags:`

  becomes

  `hg://:tags`
