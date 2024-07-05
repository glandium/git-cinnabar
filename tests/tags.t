#!/usr/bin/env cram

  $ PATH=$TESTDIR/..:$PATH
  $ export GIT_CINNABAR_EXPERIMENTS=tag

Test repository setup.

  $ echo 0 > $CRAMTMP/n
  $ gen_date() {
  >   n=$(cat $CRAMTMP/n)
  >   echo "$n 0"
  >   echo $(expr $n + 1) > $CRAMTMP/n
  > }
  $ create() {
  >   echo $1 > $1
  >   hg add $1
  >   hg commit -q -m $1 -u nobody -d "$(gen_date)"
  > }

  $ hg init repo
  $ REPO=$(pwd)/repo

  $ cd repo
  $ for f in a b; do create $f; done
  $ hg update -q -r 0
  $ for f in c d; do create $f; done
  $ hg update -q -r 1
  $ hg tag -u nobody -m "tag a" -r 0 -d "$(gen_date)" TAG_A
  $ hg tag -u nobody -m "tag b" -r 1 -d "$(gen_date)" TAG_B

Mistakenly tag c on the wrong changeset on purpose

  $ hg tag -u nobody -m "tag c" -r 3 -d "$(gen_date)" TAG_C
  $ hg update -q -r 2
  $ hg tag -u nobody -m "retag c" -r 2 -d "$(gen_date)" -f TAG_C
  $ hg tag -u nobody -m "tag d" -r 3 -d "$(gen_date)" TAG_D
  $ hg update -q -r 6
  $ hg tag -u nobody -m "remove tag d" --remove -d "$(gen_date)" TAG_D
  $ cd ..

There might be more convoluted ways tags can be set across branches, but
this should be enough.

  $ hg -R $REPO log -G --template '{node} {branch} {desc}'
  @  b49e7d7fa6707b4dae20f223afb04b4a20e53ecd default remove tag d
  |
  | o  3a3255e0075a5e92ba5f6eec30a2d378cd47d071 default tag d
  | |
  | o  9a446a6e34a9824a8e2786217edb1c5d8037b09c default retag c
  | |
  o |  f8e96ded3f478cebfb8e28b02f1c1234ae885ca7 default tag c
  | |
  o |  d97cd2d420ae287a6fb5a6eee34689afcc64a7ae default tag b
  | |
  o |  a312c958e712e9c1848fab0818d3c1e8368eb9b5 default tag a
  | |
  | | o  7937e1a594596ae25c637d317503d775767671b5 default d
  | |/
  | o  ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 default c
  | |
  o |  636e60525868096cbdc961870493510558f41d2f default b
  |/
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
Create a git clone of the above repository.

  $ git -c fetch.prune=true clone -n -q hg::$REPO repo-git
  
  Run the following command to update tags:
    git cinnabar fetch --tags

  $ git -C repo-git ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C

  $ git -C repo-git cinnabar tag -l
  TAG_A
  TAG_B
  TAG_C
  $ git -C repo-git cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C

Now try the partial cases and see if that matches what mercurial says.

  $ git init -q repo-git2
  $ hg init repo2
  $ git -C repo-git2 remote add origin hg::$REPO
  $ git -C repo-git2 cinnabar fetch origin 636e60525868096cbdc961870493510558f41d2f 7937e1a594596ae25c637d317503d775767671b5
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/636e60525868096cbdc961870493510558f41d2f -> FETCH_HEAD
   * branch            hg/revs/7937e1a594596ae25c637d317503d775767671b5 -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r 636e60525868096cbdc961870493510558f41d2f -r 7937e1a594596ae25c637d317503d775767671b5
  $ hg -R repo2 tags | grep -v ^tip
  [1]
  $ git -C repo-git2 ls-remote hg::tags:
  $ git -C repo-git2 cinnabar tag -l

  $ git -C repo-git2 cinnabar fetch origin a312c958e712e9c1848fab0818d3c1e8368eb9b5
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/a312c958e712e9c1848fab0818d3c1e8368eb9b5 -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r a312c958e712e9c1848fab0818d3c1e8368eb9b5
  $ hg -R repo2 tags | grep -v ^tip
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A

  $ git -C repo-git2 cinnabar fetch origin d97cd2d420ae287a6fb5a6eee34689afcc64a7ae
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/d97cd2d420ae287a6fb5a6eee34689afcc64a7ae -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r d97cd2d420ae287a6fb5a6eee34689afcc64a7ae
  $ hg -R repo2 tags | grep -v ^tip
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B

  $ git -C repo-git2 cinnabar fetch origin f8e96ded3f478cebfb8e28b02f1c1234ae885ca7
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/f8e96ded3f478cebfb8e28b02f1c1234ae885ca7 -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r f8e96ded3f478cebfb8e28b02f1c1234ae885ca7
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              3:7937e1a59459
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 7937e1a594596ae25c637d317503d775767671b5 TAG_C

  $ git -C repo-git2 cinnabar fetch origin 9a446a6e34a9824a8e2786217edb1c5d8037b09c
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/9a446a6e34a9824a8e2786217edb1c5d8037b09c -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r 9a446a6e34a9824a8e2786217edb1c5d8037b09c
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              2:ae078ae353a9
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C


  $ git -C repo-git2 cinnabar fetch origin 3a3255e0075a5e92ba5f6eec30a2d378cd47d071
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/3a3255e0075a5e92ba5f6eec30a2d378cd47d071 -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r 3a3255e0075a5e92ba5f6eec30a2d378cd47d071
  $ hg -R repo2 tags | grep -v ^tip
  TAG_D                              3:7937e1a59459
  TAG_C                              2:ae078ae353a9
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/tags/TAG_D
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 7937e1a594596ae25c637d317503d775767671b5 TAG_D

  $ git -C repo-git2 cinnabar fetch origin b49e7d7fa6707b4dae20f223afb04b4a20e53ecd
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/b49e7d7fa6707b4dae20f223afb04b4a20e53ecd -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r b49e7d7fa6707b4dae20f223afb04b4a20e53ecd
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              2:ae078ae353a9
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C

Try again by pulling the last tag update first.

  $ git -C repo-git2 cinnabar rollback refs/cinnabar/metadata^6^6^6
  $ hg -R repo2 debugstrip -q -r 7:

  $ git -C repo-git2 cinnabar fetch origin b49e7d7fa6707b4dae20f223afb04b4a20e53ecd
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/b49e7d7fa6707b4dae20f223afb04b4a20e53ecd -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r b49e7d7fa6707b4dae20f223afb04b4a20e53ecd
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              3:7937e1a59459
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611 7937e1a594596ae25c637d317503d775767671b5 TAG_C

  $ git -C repo-git2 cinnabar fetch origin 9a446a6e34a9824a8e2786217edb1c5d8037b09c
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/9a446a6e34a9824a8e2786217edb1c5d8037b09c -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r 9a446a6e34a9824a8e2786217edb1c5d8037b09c
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              2:ae078ae353a9
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C

  $ git -C repo-git2 cinnabar fetch origin 3a3255e0075a5e92ba5f6eec30a2d378cd47d071
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/3a3255e0075a5e92ba5f6eec30a2d378cd47d071 -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r 3a3255e0075a5e92ba5f6eec30a2d378cd47d071
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              2:ae078ae353a9
  TAG_B                              1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C
