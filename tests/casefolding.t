#!/usr/bin/env cram

  $ PATH=$TESTDIR/..:$PATH

Test repository setup.

  $ hg init repo
  $ REPO=$(pwd)/repo

  $ cd repo
  $ echo a > a
  $ hg add a
  $ hg commit -q -m a -u nobody -d "0 0"
  $ hg rename a A
  $ hg commit -q -m A -u nobody -d "1 0"
  $ cd ..

  $ hg -R $REPO log -G --template '{node} {branch} {desc}'
  @  f41ff502981ad8ecccd91bfea3acadd068e2a875 default A
  |
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
  $ cat > $REPO/.hg/hgrc <<EOF
  > [extensions]
  > x = $TESTDIR/../CI/hg-serve-exec.py
  > [web]
  > accesslog = /dev/null
  > errorlog = /dev/null
  > EOF

Independent of the core.ignorecase config, the repo should be cloned correctly.

  $ hg -R $REPO serve-and-exec -- git -c core.ignorecase=true -c fetch.prune=true clone -n -q hg::http://localhost:8000/ $REPO-git
  $ git -C $REPO-git cinnabar fsck --full 2>/dev/null

Likewise for incremental updates

  $ rm -rf $REPO-git
  $ git init -q $REPO-git
  $ git -C $REPO-git cinnabar fetch hg::$REPO f92470d7f6966a39dfbced6a525fe81ebf5c37b9
  From hg::.*/casefolding.t/repo (re)
   * branch            hg/revs/f92470d7f6966a39dfbced6a525fe81ebf5c37b9 -> FETCH_HEAD
  $ hg -R $REPO serve-and-exec -- git -C $REPO-git -c core.ignorecase=true fetch -q hg::http://localhost:8000/
  $ git -C $REPO-git cinnabar fsck --full 2>/dev/null
