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

Let's also test tagging with the default messages

  $ hg tag -u nobody -r 1 -d "$(gen_date)" TAG_A2
  $ hg tag -u nobody -r 0 -d "$(gen_date)" -f TAG_A2
  $ hg tag -u nobody --remove -d "$(gen_date)" -f TAG_A2
  $ cd ..

There might be more convoluted ways tags can be set across branches, but
this should be enough.

  $ hg -R $REPO log -G --template '{node} {branch} {desc}'
  @  b9548531c62204564dc8a52a5da33d049db6dbbc default Removed tag TAG_A2
  |
  o  a6885b5b988766a82c6e9d3ae398c778bfa1d38f default Added tag TAG_A2 for changeset f92470d7f696
  |
  o  1236c210158e4bb29b3cd7ca1d5145396fd48cdc default Added tag TAG_A2 for changeset 636e60525868
  |
  o  b49e7d7fa6707b4dae20f223afb04b4a20e53ecd default remove tag d
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

  $ git -C repo-git2 cinnabar fetch origin 1236c210158e4bb29b3cd7ca1d5145396fd48cdc
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/1236c210158e4bb29b3cd7ca1d5145396fd48cdc -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r 1236c210158e4bb29b3cd7ca1d5145396fd48cdc
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              2:ae078ae353a9
  TAG_B                              1:636e60525868
  TAG_A2                             1:636e60525868
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_A2
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_A2
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C

  $ git -C repo-git2 cinnabar fetch origin a6885b5b988766a82c6e9d3ae398c778bfa1d38f
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/a6885b5b988766a82c6e9d3ae398c778bfa1d38f -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r a6885b5b988766a82c6e9d3ae398c778bfa1d38f
  $ hg -R repo2 tags | grep -v ^tip
  TAG_C                              2:ae078ae353a9
  TAG_B                              1:636e60525868
  TAG_A2                             0:f92470d7f696
  TAG_A                              0:f92470d7f696
  $ git -C repo-git2 ls-remote hg::tags:
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A
  8b86a58578d5270969543e287634e3a2f122a338	refs/tags/TAG_A2
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/tags/TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1	refs/tags/TAG_C
  $ git -C repo-git2 cinnabar tag -l --format="%(objectname) %(hg::objectname) %(tagname)"
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A
  8b86a58578d5270969543e287634e3a2f122a338 f92470d7f6966a39dfbced6a525fe81ebf5c37b9 TAG_A2
  d04f6df4abe2870ceb759263ee6aaa9241c4f93c 636e60525868096cbdc961870493510558f41d2f TAG_B
  7688446e0a5d5b6108443632be74c9bca72d31b1 ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 TAG_C

  $ git -C repo-git2 cinnabar fetch origin b9548531c62204564dc8a52a5da33d049db6dbbc
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/b9548531c62204564dc8a52a5da33d049db6dbbc -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r b9548531c62204564dc8a52a5da33d049db6dbbc
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

Try again by pulling the last retag and tag removal first.

  $ git -C repo-git2 cinnabar rollback refs/cinnabar/metadata^6^6^6^6^6^6
  $ hg --config extensions.strip= -R repo2 strip -q -r 7:

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

  $ git -C repo-git2 cinnabar fetch origin b9548531c62204564dc8a52a5da33d049db6dbbc
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/b9548531c62204564dc8a52a5da33d049db6dbbc -> FETCH_HEAD
  $ hg -R repo2 pull -q $REPO -r b9548531c62204564dc8a52a5da33d049db6dbbc
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

Prepare another repository.

  $ git init -q repo-git3
  $ git -C repo-git3 remote add origin hg::$REPO
  $ git -C repo-git3 cinnabar fetch origin 636e60525868096cbdc961870493510558f41d2f 7937e1a594596ae25c637d317503d775767671b5
  From hg::(.*)/tags.t/repo (re)
   * branch            hg/revs/636e60525868096cbdc961870493510558f41d2f -> FETCH_HEAD
   * branch            hg/revs/7937e1a594596ae25c637d317503d775767671b5 -> FETCH_HEAD

Run a sequence equivalent to the original hg tagging command sequence, with
`git cinnabar tag`.

  $ git -C repo-git3 checkout -q d04f6df4abe2870ceb759263ee6aaa9241c4f93c

  $ export GIT_COMMITTER_NAME=nobody
  $ export GIT_COMMITTER_EMAIL=
  $ export GIT_AUTHOR_NAME=nobody
  $ export GIT_AUTHOR_EMAIL=

  $ n=4
  $ set_date() {
  >   export GIT_COMMITTER_DATE="@$n +0000"
  >   export GIT_AUTHOR_DATE="@$n +0000"
  >   n=$(expr $n + 1)
  > }
  $ set_date
  $ git -C repo-git3 cinnabar tag -m "tag a" TAG_A 8b86a58578d5270969543e287634e3a2f122a338
  Updating d04f6df..3180ce8
  Fast-forward
   .hgtags | 1 +
   1 file changed, 1 insertion(+)
   create mode 100644 .hgtags
  $ set_date
  $ git -C repo-git3 cinnabar tag -m "tag b" TAG_B d04f6df4abe2870ceb759263ee6aaa9241c4f93c
  Updating 3180ce8..af55568
  Fast-forward
   .hgtags | 1 +
   1 file changed, 1 insertion(+)
  $ set_date
  $ git -C repo-git3 cinnabar tag -m "tag c" TAG_C 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d1761
  Updating af55568..43a3b94
  Fast-forward
   .hgtags | 1 +
   1 file changed, 1 insertion(+)

For now, editing existing tags requires to push to a Mercurial repository
first. But because `git cinnabar tag` is expected to create the same thing
as we did in the Mercurial repo, there are actually no changes pushed as
far as the Mercurial server goes.

  $ git -C repo-git3 push hg::$REPO HEAD:branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 0 changesets with 0 changes to 1 files
  To hg::(.*)/tags.t/repo (re)
   * [new branch]      HEAD -> branches/default/tip

  $ git -C repo-git3 branch tags 7688446e0a5d5b6108443632be74c9bca72d31b1
  $ set_date
  $ git -C repo-git3 cinnabar tag -m "retag c" TAG_C 7688446e0a5d5b6108443632be74c9bca72d31b1 --onto tags
  \r (no-eol) (esc)
  ERROR tag 'TAG_C' already exists
  [1]
  $ git -C repo-git3 cinnabar tag -m "retag c" -f TAG_C 7688446e0a5d5b6108443632be74c9bca72d31b1 --onto refs/heads/tags
  $ set_date
  $ git -C repo-git3 cinnabar tag -m "tag d" TAG_D 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d1761 --onto refs/heads/tags

  $ git -C repo-git3 push hg::$REPO tags:branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 0 changesets with 0 changes to 1 files
  To hg::(.*)/tags.t/repo (re)
   * [new branch]      tags -> branches/default/tip

  $ set_date
  $ git -C repo-git3 cinnabar tag -m "remove tag d" -d TAG_D
  Updating 43a3b94..e58ff3d
  Fast-forward
   .hgtags | 2 ++
   1 file changed, 2 insertions(+)

Use the last few items from the sequence to also test using Mercurial
changeset ids when tagging.

  $ set_date
  $ git -C repo-git3 cinnabar tag TAG_A2 636e60525868096cbdc961870493510558f41d2f
  Updating e58ff3d..6fd1477
  Fast-forward
   .hgtags | 1 +
   1 file changed, 1 insertion(+)
  $ git -C repo-git3 push hg::$REPO HEAD:branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 0 changesets with 0 changes to 1 files
  To hg::(.*)/tags.t/repo (re)
   * [new branch]      HEAD -> branches/default/tip

  $ set_date
  $ git -C repo-git3 cinnabar tag -f TAG_A2 f92470d7f696
  Updating 6fd1477..272c9ee
  Fast-forward
   .hgtags | 2 ++
   1 file changed, 2 insertions(+)
  $ git -C repo-git3 push hg::$REPO HEAD:branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 0 changesets with 0 changes to 1 files
  To hg::(.*)/tags.t/repo (re)
   * [new branch]      HEAD -> branches/default/tip

  $ set_date
  $ git -C repo-git3 cinnabar tag -d TAG_A2
  Updating 272c9ee..4044542
  Fast-forward
   .hgtags | 2 ++
   1 file changed, 2 insertions(+)

  $ git -C repo-git3 push hg::$REPO HEAD:branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 0 changesets with 0 changes to 1 files
  To hg::(.*)/tags.t/repo (re)
   * [new branch]      HEAD -> branches/default/tip

Both the repository cloned from the original Mercurial repo and the one
that recreated the tags from scratch are expected to be identical.

  $ git -C repo-git2 log --oneline --graph refs/cinnabar/metadata^^@
  * 4044542 Removed tag TAG_A2
  * 272c9ee Added tag TAG_A2 for changeset f92470d7f696
  * 6fd1477 Added tag TAG_A2 for changeset 636e60525868
  * e58ff3d remove tag d
  * 43a3b94 tag c
  * af55568 tag b
  * 3180ce8 tag a
  * d04f6df b
  | * f4bd7e5 tag d
  | * e4345f9 retag c
  | | * 5c5b259 d
  | |/  
  | * 7688446 c
  |/  
  * 8b86a58 a

  $ git -C repo-git3 log --oneline --graph refs/cinnabar/metadata^^@
  * 4044542 Removed tag TAG_A2
  * 272c9ee Added tag TAG_A2 for changeset f92470d7f696
  * 6fd1477 Added tag TAG_A2 for changeset 636e60525868
  * e58ff3d remove tag d
  * 43a3b94 tag c
  * af55568 tag b
  * 3180ce8 tag a
  * d04f6df b
  | * f4bd7e5 tag d
  | * e4345f9 retag c
  | | * 5c5b259 d
  | |/  
  | * 7688446 c
  |/  
  * 8b86a58 a

