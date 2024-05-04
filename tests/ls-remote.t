#!/usr/bin/env cram

  $ PATH=$TESTDIR/..:$PATH

  $ n=0
  $ create() {
  >   echo $1 > $1
  >   hg add $1
  >   hg commit -m $1 -u nobody -d "$n 0" > /dev/null
  >   n=$(expr $n + 1)
  > }

  $ hg init repo
  $ REPO=$(pwd)/repo

  $ git ls-remote hg::$REPO
  $ git -c cinnabar.refs=tips ls-remote hg::$REPO
  $ git -c cinnabar.refs=heads ls-remote hg::$REPO
  $ git -c cinnabar.refs=bookmarks ls-remote hg::$REPO

  $ cd repo
  $ for f in a b; do create $f; done
  $ hg update -r 0 > /dev/null
  $ for f in c d; do create $f; done
  $ hg update -r 2 > /dev/null
  $ hg branch foo > /dev/null
  $ for f in e f; do create $f; done
  $ cd ..

  $ git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  0000000000000000000000000000000000000000	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/default
  0000000000000000000000000000000000000000	refs/heads/foo

  $ git -c cinnabar.refs=heads ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks ls-remote hg::$REPO

  $ git -c cinnabar.refs=bookmarks,tips ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/branches/default
  0000000000000000000000000000000000000000	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  0000000000000000000000000000000000000000	refs/heads/branches/foo/tip

  $ git clone -q hg::$REPO repo-git
  It is recommended that you set "remote.origin.prune" or "fetch.prune" to "true".
    git config remote.origin.prune true
  or
    git config fetch.prune true

  $ git -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo

  $ git -c cinnabar.refs=heads -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks -C repo-git ls-remote hg::$REPO

  $ git -c cinnabar.refs=bookmarks,tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ cd repo
  $ hg bookmark bar -r 1
  $ hg bookmark qux -r 2
  $ hg bookmark fooz -r 5
  $ cd ..

  $ git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  0000000000000000000000000000000000000000	refs/heads/bookmarks/fooz
  0000000000000000000000000000000000000000	refs/heads/bookmarks/qux
  0000000000000000000000000000000000000000	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  0000000000000000000000000000000000000000	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/default
  0000000000000000000000000000000000000000	refs/heads/foo

  $ git -c cinnabar.refs=heads ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks ls-remote hg::$REPO
  0000000000000000000000000000000000000000	refs/heads/bar
  0000000000000000000000000000000000000000	refs/heads/fooz
  0000000000000000000000000000000000000000	refs/heads/qux

  $ git -c cinnabar.refs=bookmarks,tips ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  0000000000000000000000000000000000000000	refs/heads/bookmarks/fooz
  0000000000000000000000000000000000000000	refs/heads/bookmarks/qux
  0000000000000000000000000000000000000000	refs/heads/branches/default
  0000000000000000000000000000000000000000	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  0000000000000000000000000000000000000000	refs/heads/bookmarks/fooz
  0000000000000000000000000000000000000000	refs/heads/bookmarks/qux
  0000000000000000000000000000000000000000	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  0000000000000000000000000000000000000000	refs/heads/bookmarks/fooz
  0000000000000000000000000000000000000000	refs/heads/bookmarks/qux
  0000000000000000000000000000000000000000	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  0000000000000000000000000000000000000000	refs/heads/branches/foo/tip

  $ git -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo

  $ git -c cinnabar.refs=heads -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks -C repo-git ls-remote hg::$REPO
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/qux

  $ git -c cinnabar.refs=bookmarks,tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ cd repo
  $ hg update -r 1 > /dev/null
  $ for f in g h; do create $f; done
  $ cd ..

  $ git -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo

  $ git -c cinnabar.refs=heads -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks -C repo-git ls-remote hg::$REPO
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/qux

  $ git -c cinnabar.refs=bookmarks,tips -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  0000000000000000000000000000000000000000	refs/heads/branches/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ hg -R repo bookmark bar -f -r 7 > /dev/null

  $ git -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo

  $ git -c cinnabar.refs=heads -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	refs/heads/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/qux

  $ git -c cinnabar.refs=bookmarks,tips -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  0000000000000000000000000000000000000000	refs/heads/branches/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips -C repo-git ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -c fetch.prune=true -C repo-git remote update
  From hg::.*/ls-remote.t/repo (re)
   - \[deleted\]         \(none\)     *-> origin/branches/default/636e60525868096cbdc961870493510558f41d2f (re)
   + 5c5b259...445bd26 branches/default/tip -> origin/branches/default/tip  (forced update)
   * [new branch]      bookmarks/bar        -> origin/bookmarks/bar
   * [new branch]      bookmarks/fooz       -> origin/bookmarks/fooz
   * [new branch]      bookmarks/qux        -> origin/bookmarks/qux
   * [new branch]      branches/default/7937e1a594596ae25c637d317503d775767671b5 -> origin/branches/default/7937e1a594596ae25c637d317503d775767671b5

  $ git -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo

  $ git -c cinnabar.refs=heads -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/qux

  $ git -c cinnabar.refs=bookmarks,tips -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ hg -R repo bookmark @ -r 3

  $ git -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/@
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -c cinnabar.refs=tips -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo

  $ git -c cinnabar.refs=heads -C repo-git ls-remote hg::$REPO
  445bd26f53d0d2b946eda781eae0e11cf665493d	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/@
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/qux

  $ git -c cinnabar.refs=bookmarks,tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/@
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo

  $ git -c cinnabar.refs=bookmarks,heads -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/@
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default/8bb4ccecc30b8db9a6f524f40be0d4c2dbc78a07
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/312a5a9c675e3ce302a33bd4605205a6be36d561

  $ git -c cinnabar.refs=bookmarks,heads,tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/@
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/bookmarks/bar
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/fooz
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/7937e1a594596ae25c637d317503d775767671b5
  445bd26f53d0d2b946eda781eae0e11cf665493d	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ cd repo
  $ hg update -r foo > /dev/null
  $ hg commit --close-branch -m close -u nobody -d "$n 0" > /dev/null
  $ hg update -r default > /dev/null
  $ hg commit --close-branch -m close -u nobody -d "$n 0" > /dev/null
  $ cd ..

  $ git -c fetch.prune=true -C repo-git remote update
  From hg::.*/ls-remote.t/repo (re)
     445bd26..66e3a05  branches/default/tip -> origin/branches/default/tip
   * [new branch]      bookmarks/@          -> origin/bookmarks/@
     23bcc26..98c3f74  branches/foo/tip     -> origin/branches/foo/tip

  $ git -c cinnabar.refs=heads,tips -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  66e3a05b3f4cc64ecdd41a4a2c4ac3913ca905bd	refs/heads/default/3af330d6b3b174311a550ed9246a104ceeda8c28
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/default/tip
  98c3f7495c17d6fcae8cfaa894c8af0da9668863	refs/heads/foo/tip
