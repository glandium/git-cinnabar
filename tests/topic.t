#!/usr/bin/env cram

  $ PATH=$TESTDIR/..:$PATH

  $ cat >hgrc <<EOF
  > [extensions]
  > topic = 
  > [phases]
  > publish = false
  > EOF
  $ export HGRCPATH=$(pwd)/hgrc

  $ n=0
  $ create() {
  >   echo $1 > $1
  >   hg add $1
  >   hg commit -q -m $1 -u nobody -d "$n 0"
  >   n=$(expr $n + 1)
  > }
  $ hg init abc
  $ ABC=$(pwd)/abc
  $ cd abc
  $ for f in a b c; do create $f; done
  $ hg -q topic test-topic
  $ create d
  $ cd ..
  $ hg -R abc log -G
  @  changeset:   3:c8e7b9c226ba
  |  tag:         tip
  |  topic:       test-topic
  |  user:        nobody
  |  date:        Thu Jan 01 00:00:03 1970 +0000
  |  summary:     d
  |
  o  changeset:   2:bd623dea9393
  |  user:        nobody
  |  date:        Thu Jan 01 00:00:02 1970 +0000
  |  summary:     c
  |
  o  changeset:   1:636e60525868
  |  user:        nobody
  |  date:        Thu Jan 01 00:00:01 1970 +0000
  |  summary:     b
  |
  o  changeset:   0:f92470d7f696
     user:        nobody
     date:        Thu Jan 01 00:00:00 1970 +0000
     summary:     a
  
  $ git -c fetch.prune=true -c cinnabar.refs=topics clone -n -q hg::$ABC abc-git
  $ git -C abc-git -c cinnabar.refs=topics ls-remote hg::$ABC
  687e015f9f646bb19797d991f2f53087297fbe14	HEAD
  687e015f9f646bb19797d991f2f53087297fbe14	refs/heads/branches/default
  f0a1cba4d5a6919f6ba44b775278734fb5e30f78	refs/heads/topics/default/test-topic
  $ git -C abc-git for-each-ref refs/remotes/origin
  687e015f9f646bb19797d991f2f53087297fbe14 commit	refs/remotes/origin/HEAD
  687e015f9f646bb19797d991f2f53087297fbe14 commit	refs/remotes/origin/branches/default
  f0a1cba4d5a6919f6ba44b775278734fb5e30f78 commit	refs/remotes/origin/topics/default/test-topic
  $ git -C abc-git switch -q --guess topics/default/test-topic
  $ cd abc-git
  $ git branch -vvv
    branches/default          687e015 [origin/branches/default] c
  * topics/default/test-topic f0a1cba [origin/topics/default/test-topic] d
  $ echo e > e
  $ git add e
  $ GIT_COMMITTER_DATE="1970-01-01 0:0:0$n" git -c user.name=Nobody -c user.email=nobody@nowhere commit -q -m e --date "1970-01-01 0:0:$n"
  $ n=$(expr $n + 1)
  $ cd ..
  $ git -C abc-git -c cinnabar.refs=topics -c cinnabar.experiments=branch push origin
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/topic.t/abc (re)
     f0a1cba..dc5dded  topics/default/test-topic -> topics/default/test-topic
  $ hg -R abc log -G
  o  changeset:   4:e18393ddcc87
  |  tag:         tip
  |  topic:       test-topic
  |  user:        Nobody <nobody@nowhere>
  |  date:        Thu Jan 01 00:00:04 1970 +0000
  |  summary:     e
  |
  @  changeset:   3:c8e7b9c226ba
  |  topic:       test-topic
  |  user:        nobody
  |  date:        Thu Jan 01 00:00:03 1970 +0000
  |  summary:     d
  |
  o  changeset:   2:bd623dea9393
  |  user:        nobody
  |  date:        Thu Jan 01 00:00:02 1970 +0000
  |  summary:     c
  |
  o  changeset:   1:636e60525868
  |  user:        nobody
  |  date:        Thu Jan 01 00:00:01 1970 +0000
  |  summary:     b
  |
  o  changeset:   0:f92470d7f696
     user:        nobody
     date:        Thu Jan 01 00:00:00 1970 +0000
     summary:     a
  
