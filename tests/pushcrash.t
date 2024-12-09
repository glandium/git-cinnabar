#!/usr/bin/env cram

  $ PATH=$TESTDIR/..:$PATH

Test repository setup.

  $ n=0
  $ createhg() {
  >   echo $1 > $1
  >   hg add $1
  >   hg commit -q -m $1 -u nobody -d "$n 0"
  >   n=$(expr $n + 1)
  > }
  $ creategit() {
  >   echo $1 > $1
  >   git add $1
  >   GIT_COMMITTER_DATE="1970-01-01 0:0:$n" git -c user.name=Nobody -c user.email=nobody@nowhere commit -q -m $1 --date "1970-01-01 0:0:$n"
  >   n=$(expr $n + 1)
  > }

Create an hg repository with an initial commit:

  $ hg init repo.hg
  $ cd repo.hg
  $ createhg x
  $ cd ..
  $ hg -R repo.hg log -G
  @  changeset:   0:2642976da98a
     tag:         tip
     user:        nobody
     date:        Thu Jan 01 00:00:00 1970 +0000
     summary:     x
  

Clone it with git-cinnabar:

  $ git -c fetch.prune=true clone -n -q hg::$(pwd)/repo.hg repo.git
  $ git -C repo.git log --graph --decorate=short branches/default/tip
  * commit d51ea055a776dc74cc3d013441af88d26b68ab88 (HEAD -> branches/default/tip, origin/branches/default/tip, origin/HEAD)
    Author: nobody <>
    Date:   Thu Jan 1 00:00:00 1970 +0000
    
        x

Configure the hg repository with a broken hook so it crashes:

  $ cat <<EOF >repo.hg/.hg/hgrc
  > [hooks]
  > pretxnclose = python:/nonexistent:fail
  > EOF

Commit something in the git clone:

  $ cd repo.git
  $ creategit z
  $ cd ..

XXX git-cinnabar failure is a bit ungraceful!
git push fails gracefully with nonzero exit status:

  $ git -C repo.git push origin
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: loading pretxnclose hook failed:
  remote: transaction abort!
  remote: rollback completed
  remote: abort: No such file or directory: '/nonexistent'
  fatal: called `Result::unwrap()` on an `Err` value: Error { kind: UnexpectedEof, message: "failed to fill whole buffer" }
  Run the command again with `git -c cinnabar.check=traceback <command>` to see the full traceback.
  error: git-remote-hg died of signal 6
  error: failed to push some refs to 'hg::*/cramtests-*/pushcrash.t/repo.hg' (glob)
  [1]

The change does not appear in the hg repository:

  $ hg -R repo.hg log -G
  @  changeset:   0:2642976da98a
     tag:         tip
     user:        nobody
     date:        Thu Jan 01 00:00:00 1970 +0000
     summary:     x
  

The git-cinnabar remote does not reflect the failed push:

  $ git -C repo.git log --graph --decorate=short origin/branches/default/tip
  * commit d51ea055a776dc74cc3d013441af88d26b68ab88 (origin/branches/default/tip, origin/HEAD)
    Author: nobody <>
    Date:   Thu Jan 1 00:00:00 1970 +0000
    
        x
