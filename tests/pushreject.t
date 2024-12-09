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

Add another commit to the hg repository:

  $ cd repo.hg
  $ createhg y
  $ cd ..

Configure the hg repository to reject new heads:

  $ cat <<EOF >repo.hg/.hg/hgrc
  > [hooks]
  > pretxnclose.reject_new_heads = python:hgext.hooklib.reject_new_heads.hook
  > EOF

Create a new commit in the git clone:

  $ cd repo.git
  $ creategit z
  $ cd ..

XXX git push does not actually fail!
git push fails with nonzero exit status:

  $ git -C repo.git push origin
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: error: pretxnclose.reject_new_heads hook failed: Changes on branch 'default' resulted in multiple heads
  remote: transaction abort!
  remote: rollback completed
  \r (no-eol) (esc)
  ERROR Changes on branch 'default' resulted in multiple heads
  To hg::*/cramtests-*/pushreject.t/repo.hg (glob)
   * [new branch]      branches/default/tip -> branches/default/tip

The change does not appear in the hg repository:

  $ hg -R repo.hg log -G
  @  changeset:   1:8cceae1d5053
  |  tag:         tip
  |  user:        nobody
  |  date:        Thu Jan 01 00:00:01 1970 +0000
  |  summary:     y
  |
  o  changeset:   0:2642976da98a
     user:        nobody
     date:        Thu Jan 01 00:00:00 1970 +0000
     summary:     x
  

XXX git-cinnabar does reflect the update!
The git-cinnabar remote does not reflect the failed push:

  $ git -C repo.git log --graph --decorate=short origin/branches/default/tip
  * commit 0d4b28bacd083cba7b065183072be0940b0157fe (HEAD -> branches/default/tip, origin/branches/default/tip, origin/HEAD)
  | Author: Nobody <nobody@nowhere>
  | Date:   Thu Jan 1 00:00:02 1970 +0000
  | 
  |     z
  | 
  * commit d51ea055a776dc74cc3d013441af88d26b68ab88
    Author: nobody <>
    Date:   Thu Jan 1 00:00:00 1970 +0000
    
        x
