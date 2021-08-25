#!/usr/bin/env cram

  $ PATH=$TESTDIR/..:$PATH

Test repository setup.

  $ n=0
  $ create() {
  >   echo $1 > $1
  >   hg add $1
  >   hg commit -q -m $1 -u nobody -d "$n 0"
  >   n=$(expr $n + 1)
  > }

  $ hg init repo
  $ REPO=$(pwd)/repo

  $ cd repo
  $ for f in a b; do create $f; done
  $ hg update -q -r 0
  $ for f in c d; do create $f; done
  $ hg update -q -r 2
  $ hg branch -q foo
  $ for f in e f; do create $f; done
  $ cd ..

  $ hg -R $REPO log -G --template '{node} {branch} {desc}'
  @  312a5a9c675e3ce302a33bd4605205a6be36d561 foo f
  |
  o  872d4a0c72d8c2b915a4d85b4f31ca4a12c882eb foo e
  |
  | o  7937e1a594596ae25c637d317503d775767671b5 default d
  |/
  o  ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 default c
  |
  | o  636e60525868096cbdc961870493510558f41d2f default b
  |/
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
Create a git clone of the above repository.

  $ git -c fetch.prune=true clone -n -q hg::$REPO repo-git

Ensure the repository looks like what we assume further below.

  $ git -C repo-git ls-remote hg::$REPO
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -C repo-git log --graph --remotes --oneline --no-abbrev-commit
  * 23bcc26b9fea7e37426260465bed35eac54af5e1 f
  * ceb496b41c51e93d51a8d6b211ddd0c6458975ed e
  | * 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 d
  |/  
  * 7688446e0a5d5b6108443632be74c9bca72d31b1 c
  | * d04f6df4abe2870ceb759263ee6aaa9241c4f93c b
  |/  
  * 8b86a58578d5270969543e287634e3a2f122a338 a

And another clone with no cinnabar metadata.

  $ git init -q repo-git2
  $ git -C repo-git2 fetch -q ../repo-git refs/remotes/origin/*:refs/remotes/origin/*
  $ git -C repo-git2 ls-remote hg::$REPO
  0000000000000000000000000000000000000000	HEAD
  0000000000000000000000000000000000000000	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/tip
  0000000000000000000000000000000000000000	refs/heads/branches/foo/tip

Create empty mercurial repositories where we are going to push.

  $ hg init $REPO-from-hg
  $ hg init $REPO-from-git
  $ hg init $REPO-from-git2

  $ echo "[paths]" > $REPO/.hg/hgrc
  $ echo "default = $REPO-from-hg" >> $REPO/.hg/hgrc
  $ git -C repo-git remote set-url origin hg::$REPO-from-git
  $ git -C repo-git2 remote add origin hg::$REPO-from-git2

Pushing `a` and `c` to the default branch.

  $ hg -R $REPO push -r ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 2 changesets with 2 changes to 2 files

  $ git -C repo-git push origin 7688446e0a5d5b6108443632be74c9bca72d31b1:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push-refs.t/repo-from-git (re)
   * [new branch]      7688446e0a5d5b6108443632be74c9bca72d31b1 -> branches/default/tip

  $ git -C repo-git2 push origin 7688446e0a5d5b6108443632be74c9bca72d31b1:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push-refs.t/repo-from-git2 (re)
   * [new branch]      7688446e0a5d5b6108443632be74c9bca72d31b1 -> branches/default/tip

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  7688446e0a5d5b6108443632be74c9bca72d31b1	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  7688446e0a5d5b6108443632be74c9bca72d31b1	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/tip

  $ git -C repo-git2 ls-remote
  From hg::.*/push-refs.t/repo-from-git2 (re)
  7688446e0a5d5b6108443632be74c9bca72d31b1	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/tip

Pushing `b` fails because it would add a new head to the branch.

  $ hg -R $REPO push -r 636e60525868096cbdc961870493510558f41d2f
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  abort: push creates new remote head 636e60525868!? (re)
  \(merge or see ['"]hg help push["'] for details about pushing new heads\) (re)
  [255]

  $ git -C repo-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  To hg::.*/push-refs.t/repo-from-git (re)
   ! [rejected]        d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip (non-fast-forward)
  error: failed to push some refs to 'hg::.*/push-refs.t/repo-from-git' (re)
  hint: Updates were rejected because the tip of your current branch is behind
  hint: its remote counterpart. Integrate the remote changes (e.g.
  hint: 'git pull ...') before pushing again.
  hint: See the 'Note about fast-forwards' in 'git push --help' for details.
  [1]

  $ git -C repo-git2 push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  To hg::.*/push-refs.t/repo-from-git2 (re)
   ! [rejected]        d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip (non-fast-forward)
  error: failed to push some refs to 'hg::.*/push-refs.t/repo-from-git2' (re)
  hint: Updates were rejected because a pushed branch tip is behind its remote
  hint: counterpart. Check out this branch and integrate the remote changes
  hint: (e.g. 'git pull ...') before pushing again.
  hint: See the 'Note about fast-forwards' in 'git push --help' for details.
  [1]

TODO: this should fail too
#  $ git -C repo-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/new-head
#  $ git -C repo-git2 push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/new-head

Force push `b`.

  $ hg -R $REPO push -f -r 636e60525868096cbdc961870493510558f41d2f
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 1 changesets with 1 changes to 1 files (+1 heads)

  $ git -C repo-git push origin -f d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git (re)
   + 7688446...d04f6df d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip (forced update)

  $ git -C repo-git2 push origin -f d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git2 (re)
   + 7688446...d04f6df d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip (forced update)

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

  $ git -C repo-git2 ls-remote
  From hg::.*/push-refs.t/repo-from-git2 (re)
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

Add a changeset to the repository we are pushing to.

  $ for repo in $REPO-from-hg $REPO-from-git $REPO-from-git2; do
  >   cd $repo
  >   hg update -q -r ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  >   create g
  >   n=$(expr $n - 1)
  >   cd ..
  > done

  $ hg -R $REPO-from-hg log -G --template '{node} {branch} {desc}'
  @  a08654acdc93834f96695eff2760efaa4e3562bc default g
  |
  | o  636e60525868096cbdc961870493510558f41d2f default b
  | |
  o |  ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 default c
  |/
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
  $ hg -R $REPO-from-git log -G --template '{node} {branch} {desc}'
  @  a08654acdc93834f96695eff2760efaa4e3562bc default g
  |
  | o  636e60525868096cbdc961870493510558f41d2f default b
  | |
  o |  ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 default c
  |/
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
  $ hg -R $REPO-from-git2 log -G --template '{node} {branch} {desc}'
  @  a08654acdc93834f96695eff2760efaa4e3562bc default g
  |
  | o  636e60525868096cbdc961870493510558f41d2f default b
  | |
  o |  ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 default c
  |/
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
Pushing `d` fails because it would add a new head to the branch because of the
changeset added above.

  $ hg -R $REPO push -r 7937e1a594596ae25c637d317503d775767671b5
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  remote has heads on branch 'default' that are not known locally: a08654acdc93
  abort: push creates new remote head 7937e1a59459!? (re)
  \(pull and merge or see ['"]hg help push["'] for details about pushing new heads\) (re)
  [255]

TODO: this should fail like mercurial does above.
#  $ git -C repo-git push origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/branches/default/tip
#  $ git -C repo-git2 push origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/branches/default/tip

TODO: this should fail too.
#  $ git -C repo-git push origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/branches/default/new-head
#  $ git -C repo-git2 push origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/branches/default/new-head

Force push `d`.

  $ hg -R $REPO push -f -r 7937e1a594596ae25c637d317503d775767671b5
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 1 changesets with 1 changes to 1 files (+1 heads)

  $ git -C repo-git push origin -f 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/branches/default/new-head
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git (re)
   * [new branch]      5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 -> branches/default/new-head

  $ git -C repo-git2 push origin -f 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/branches/default/new-head
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git2 (re)
   * [new branch]      5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 -> branches/default/new-head

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip

  $ git -C repo-git2 ls-remote
  From hg::.*/push-refs.t/repo-from-git2 (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip

Push `f`.

  $ hg -R $REPO push -r 312a5a9c675e3ce302a33bd4605205a6be36d561
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  abort: push creates new remote branches: foo!? (re)
  (use 'hg push --new-branch' to create new remote branches)
  [255]

TODO: this should fail like mercurial does above.
#  $ git -C repo-git push origin 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/branches/foo/tip
#  $ git -C repo-git2 push origin 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/branches/foo/tip

TODO: this should fail because of the branch name mismatch
(not doing it for repo-git2 because it would assign a branch name to the
commits with no cinnabar metadata)
#  $ git -C repo-git push origin 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/branches/default/other-head

Force push `f`.

  $ hg -R $REPO push -f -r 312a5a9c675e3ce302a33bd4605205a6be36d561
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 2 changesets with 2 changes to 2 files (+1 heads)

  $ git -C repo-git push origin -f 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/branches/foo/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git (re)
   * [new branch]      23bcc26b9fea7e37426260465bed35eac54af5e1 -> branches/foo/tip

TODO: this should either fail because creating the branch is not supported,
or work and create the branch
#  $ git -C repo-git2 push origin -f 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/branches/foo/tip

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

Removing heads or branches is not supported.

  $ git -C repo-git push origin :branches/default/636e60525868096cbdc961870493510558f41d2f
  To hg::.*/push-refs.t/repo-from-git (re)
   ! [remote rejected] branches/default/636e60525868096cbdc961870493510558f41d2f (Deleting remote branches is unsupported)
  error: failed to push some refs to 'hg::.*/push-refs.t/repo-from-git' (re)
  [1]

Reset target mercurial repositories.

  $ rm -rf $REPO-from-hg $REPO-from-git $REPO-from-git2
  $ hg init $REPO-from-hg
  $ hg init $REPO-from-git
  $ hg init $REPO-from-git2

Reset cinnabar metadata in repo-git2.

  $ git -C repo-git2 cinnabar rollback 0000000000000000000000000000000000000000

Push everything at once.

  $ hg -R $REPO push
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 6 changesets with 6 changes to 6 files (+2 heads)

  $ git -C repo-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/head1 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/branches/default/head2 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/branches/foo/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 6 changesets with 6 changes to 6 files (+2 heads)
  To hg::.*/push-refs.t/repo-from-git (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/head1
   * [new branch]      5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 -> branches/default/head2
   * [new branch]      23bcc26b9fea7e37426260465bed35eac54af5e1 -> branches/foo/tip

TODO: this should either fail for the foo branch because creating the branch
is not supported, or work and create the branch
#  $ git -C repo-git2 push origin 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/branches/foo/tip

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

Reset target mercurial repositories again.

  $ rm -rf $REPO-from-hg $REPO-from-git $REPO-from-git2
  $ hg init $REPO-from-hg
  $ hg init $REPO-from-git
  $ hg init $REPO-from-git2

Reset cinnabar metadata in repo-git2 again.

  $ git -C repo-git2 cinnabar rollback 0000000000000000000000000000000000000000

Push a bookmark on `c`.

  $ hg -R $REPO bookmark qux -r ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  $ hg -R $REPO push -B qux
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 2 changesets with 2 changes to 2 files
  exporting bookmark qux

  $ git -C repo-git push origin 7688446e0a5d5b6108443632be74c9bca72d31b1:refs/heads/bookmarks/qux
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push-refs.t/repo-from-git (re)
   * [new branch]      7688446e0a5d5b6108443632be74c9bca72d31b1 -> bookmarks/qux

  $ git -C repo-git2 push origin 7688446e0a5d5b6108443632be74c9bca72d31b1:refs/heads/bookmarks/qux
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push-refs.t/repo-from-git2 (re)
   * [new branch]      7688446e0a5d5b6108443632be74c9bca72d31b1 -> bookmarks/qux

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  7688446e0a5d5b6108443632be74c9bca72d31b1	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  7688446e0a5d5b6108443632be74c9bca72d31b1	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/tip

  $ git -C repo-git2 ls-remote
  From hg::.*/push-refs.t/repo-from-git2 (re)
  7688446e0a5d5b6108443632be74c9bca72d31b1	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/bookmarks/qux
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/tip

Push the same bookmark, pointing to `b`.

  $ hg -R $REPO bookmark qux -f -r 636e60525868096cbdc961870493510558f41d2f
  $ hg -R $REPO push -B qux
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  abort: push creates new remote head 636e60525868 with bookmark 'qux'!? (re)
  \(merge or see ['"]hg help push["'] for details about pushing new heads\) (re)
  [255]

  $ git -C repo-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/bookmarks/qux
  To hg::.*/push-refs.t/repo-from-git (re)
   ! [rejected]        d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> bookmarks/qux (non-fast-forward)
  error: failed to push some refs to 'hg::.*/push-refs.t/repo-from-git' (re)
  hint: Updates were rejected because a pushed branch tip is behind its remote
  hint: counterpart. Check out this branch and integrate the remote changes
  hint: (e.g. 'git pull ...') before pushing again.
  hint: See the 'Note about fast-forwards' in 'git push --help' for details.
  [1]

  $ git -C repo-git2 push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/bookmarks/qux
  To hg::.*/push-refs.t/repo-from-git2 (re)
   ! [rejected]        d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> bookmarks/qux (non-fast-forward)
  error: failed to push some refs to 'hg::.*/push-refs.t/repo-from-git2' (re)
  hint: Updates were rejected because a pushed branch tip is behind its remote
  hint: counterpart. Check out this branch and integrate the remote changes
  hint: (e.g. 'git pull ...') before pushing again.
  hint: See the 'Note about fast-forwards' in 'git push --help' for details.
  [1]

Force push the bookmark to `b`.

  $ hg -R $REPO push -f -B qux
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 1 changesets with 1 changes to 1 files (+1 heads)
  updating bookmark qux

  $ git -C repo-git push origin -f d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/bookmarks/qux
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git (re)
   + 7688446...d04f6df d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> bookmarks/qux (forced update)

  $ git -C repo-git2 push origin -f d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/bookmarks/qux
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git2 (re)
   + 7688446...d04f6df d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> bookmarks/qux (forced update)

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/qux
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/qux
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

  $ git -C repo-git2 ls-remote
  From hg::.*/push-refs.t/repo-from-git2 (re)
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/qux
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

Remove the bookmark pushed above.

  $ hg -R $REPO bookmark -d qux
  $ hg -R $REPO push -B qux
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  no changes found
  deleting remote bookmark qux
  [1]

  $ git -C repo-git push origin :bookmarks/qux
  To hg::.*/push-refs.t/repo-from-git (re)
   - [deleted]         bookmarks/qux

  $ git -C repo-git2 push origin :bookmarks/qux
  To hg::.*/push-refs.t/repo-from-git2 (re)
   - [deleted]         bookmarks/qux

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

  $ git -C repo-git2 ls-remote
  From hg::.*/push-refs.t/repo-from-git2 (re)
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	HEAD
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/heads/branches/default/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/tip

Add a changeset to the repository we are pushing to and make the `qux`
bookmark point to it.

  $ for repo in $REPO-from-hg $REPO-from-git $REPO-from-git2; do
  >   cd $repo
  >   hg update -q -r ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  >   create g
  >   n=$(expr $n - 1)
  >   hg bookmark qux -r tip
  >   cd ..
  > done

Pushing the same bookmark, pointing to `d` fails.

  $ hg -R $REPO bookmark qux -r 7937e1a594596ae25c637d317503d775767671b5
  $ hg -R $REPO push -B qux
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  remote has heads on branch 'default' that are not known locally: a08654acdc93
  abort: push creates new remote head 7937e1a59459 with bookmark 'qux'!? (re)
  \(pull and merge or see ['"]hg help push["'] for details about pushing new heads\) (re)
  [255]

TODO: this should fail like mercurial does above.
#  $ git -C repo-git push origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/bookmarks/qux
#  $ git -C repo-git2 push origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/bookmarks/qux

Force push the same bookmark.

  $ hg -R $REPO push -f -B qux
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 1 changesets with 1 changes to 1 files (+1 heads)
  updating bookmark qux

  $ git -C repo-git push -f origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/bookmarks/qux
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git (re)
   * [new branch]      5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 -> bookmarks/qux

  $ git -C repo-git2 push -f origin 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/bookmarks/qux
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push-refs.t/repo-from-git2 (re)
   * [new branch]      5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 -> bookmarks/qux

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip

  $ git -C repo-git2 ls-remote
  From hg::.*/push-refs.t/repo-from-git2 (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  0000000000000000000000000000000000000000	refs/heads/branches/default/a08654acdc93834f96695eff2760efaa4e3562bc
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip

Reset target mercurial repositories again.

  $ rm -rf $REPO-from-hg $REPO-from-git $REPO-from-git2
  $ hg init $REPO-from-hg
  $ hg init $REPO-from-git
  $ hg init $REPO-from-git2

Reset cinnabar metadata in repo-git2 again.

  $ git -C repo-git2 cinnabar rollback 0000000000000000000000000000000000000000

Push everything at once, with bookmarks.

  $ hg -R $REPO bookmark fuga -r 636e60525868096cbdc961870493510558f41d2f
  $ hg -R $REPO bookmark hoge -r 312a5a9c675e3ce302a33bd4605205a6be36d561

(The qux bookmark still points to `d`)

  $ hg -R $REPO push -B fuga -B hoge -B qux
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  adding changesets
  adding manifests
  adding file changes
  added 6 changesets with 6 changes to 6 files (+2 heads)
  exporting bookmark fuga
  exporting bookmark hoge
  exporting bookmark qux

  $ git -C repo-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/bookmarks/fuga 23bcc26b9fea7e37426260465bed35eac54af5e1:refs/heads/bookmarks/hoge 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611:refs/heads/bookmarks/qux
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 6 changesets with 6 changes to 6 files (+2 heads)
  To hg::.*/push-refs.t/repo-from-git (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> bookmarks/fuga
   * [new branch]      23bcc26b9fea7e37426260465bed35eac54af5e1 -> bookmarks/hoge
   * [new branch]      5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 -> bookmarks/qux

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/fuga
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/hoge
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/bookmarks/fuga
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/bookmarks/hoge
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

Remote multiple bookmarks.

  $ hg -R $REPO bookmark -d fuga
  $ hg -R $REPO bookmark -d hoge
  $ hg -R $REPO push -B fuga -B hoge
  pushing to .*/push-refs.t/repo-from-hg (re)
  searching for changes
  no changes found
  deleting remote bookmark fuga
  deleting remote bookmark hoge
  [1]

  $ git -C repo-git push origin :bookmarks/fuga :bookmarks/hoge
  To hg::.*/push-refs.t/repo-from-git (re)
   - [deleted]         bookmarks/fuga
   - [deleted]         bookmarks/hoge

  $ git -C repo-git ls-remote hg::$REPO-from-hg
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip

  $ git -C repo-git ls-remote
  From hg::.*/push-refs.t/repo-from-git (re)
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/bookmarks/qux
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip
