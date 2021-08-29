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

  $ hg init abc
  $ hg init def
  $ ABC=$(pwd)/abc
  $ DEF=$(pwd)/def

  $ cd abc
  $ for f in a b c; do create $f; done
  $ cd ..

  $ cd def
  $ for f in d e f; do create $f; done
  $ cd ..

  $ hg -R $ABC log -G --template '{node} {branch} {desc}'
  @  bd623dea939349b06a47d5dce064255e5f1d9ec1 default c
  |
  o  636e60525868096cbdc961870493510558f41d2f default b
  |
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
  $ hg -R $DEF log -G --template '{node} {branch} {desc}'
  @  90f6163d2820561ebe0f6c28e87d766ef619e43c default f
  |
  o  5a5a59832ce5d1b0fb626f8ad892b26a1159c4c0 default e
  |
  o  65e4d734633a67ccf3440b9551b0253644f7175d default d
  
Create git clones of the above repositories.

  $ git -c fetch.prune=true clone -n -q hg::$ABC abc-git
  $ git -c fetch.prune=true clone -n -q hg::$DEF def-git

Ensure the repositories look like what we assume further below.

  $ git -C abc-git ls-remote hg::$ABC
  687e015f9f646bb19797d991f2f53087297fbe14	HEAD
  687e015f9f646bb19797d991f2f53087297fbe14	refs/heads/branches/default/tip

  $ git -C abc-git log --graph --remotes --oneline --no-abbrev-commit
  * 687e015f9f646bb19797d991f2f53087297fbe14 c
  * d04f6df4abe2870ceb759263ee6aaa9241c4f93c b
  * 8b86a58578d5270969543e287634e3a2f122a338 a

  $ git -C def-git ls-remote hg::$DEF
  62326f34fea5b80510f57599da9fd6e5997c0ca4	HEAD
  62326f34fea5b80510f57599da9fd6e5997c0ca4	refs/heads/branches/default/tip

  $ git -C def-git log --graph --remotes --oneline --no-abbrev-commit
  * 62326f34fea5b80510f57599da9fd6e5997c0ca4 f
  * 39160e5291e6e10fc9c701b007732e69416340f0 e
  * 7ca6a3c32ec0dbcbcd155b2be6e2f4505012c273 d

Create an empty mercurial repository where we are going to push.

  $ hg init repo
  $ REPO=$PWD/repo
  $ git -C abc-git remote set-url origin hg::$REPO
  $ git -C def-git remote set-url origin hg::$REPO

Pushing from a repo with cinnabar metadata to an empty mercurial repo works

  $ git -C abc-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push.t/repo (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip

Pushing from a repo without cinnabar metadata to an empty mercurial repo works

  $ git -C abc-git cinnabar rollback 0000000000000000000000000000000000000000
  $ rm -rf $REPO/.hg
  $ hg init $REPO
  $ git -C abc-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push.t/repo (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip

Pushing from a repo without cinnabar metadata to a non-empty mercurial repo
requires pulling first.

  $ git -C abc-git cinnabar rollback 0000000000000000000000000000000000000000
  $ git -C abc-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  ERROR Cannot push to this remote without pulling/updating first.
  Run the command again with `git -c cinnabar.check=traceback <command>` to see the full traceback.
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

Same, even when forced.

  $ git -C abc-git push -f origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  ERROR Cannot push to this remote without pulling/updating first.
  Run the command again with `git -c cinnabar.check=traceback <command>` to see the full traceback.
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

However, after pulling, we have a shared root, and we can push

  $ git -c fetch.prune=true -C abc-git remote update origin
  Fetching origin

  $ git -C abc-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/push.t/repo (re)
     d04f6df..687e015  687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip

Pushing from a repo without cinnabar metadata to a non-empty mercurial repo
with different contents requires pulling first.

  $ git -C def-git cinnabar rollback 0000000000000000000000000000000000000000
  $ git -C def-git push origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  ERROR Cannot push to this remote without pulling/updating first.
  Run the command again with `git -c cinnabar.check=traceback <command>` to see the full traceback.
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

Same, even when forced.

  $ git -C def-git push -f origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  ERROR Cannot push to this remote without pulling/updating first.
  Run the command again with `git -c cinnabar.check=traceback <command>` to see the full traceback.
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

After pulling, we have cinnabar metadata, but we still have an unrelated tree
and can't push, but that's caught by git itself.

  $ git -c fetch.prune=true -C def-git remote update origin
  Fetching origin
  From hg::.*/push.t/repo (re)
   + 62326f3...687e015 branches/default/tip -> origin/branches/default/tip  (forced update)

  $ git -c advice.pushnonffcurrent=true -c advice.pushupdaterejected=true -C def-git push origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [rejected]        62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (non-fast-forward)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  hint: Updates were rejected because the tip of your current branch is behind
  hint: its remote counterpart. Integrate the remote changes (e.g.
  hint: 'git pull ...') before pushing again.
  hint: See the 'Note about fast-forwards' in 'git push --help' for details.
  [1]

This time, forced push is allowed.

  $ git -c advice.pushnonffcurrent=true -c advice.pushupdaterejected=true -C def-git push origin -f 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  WARNING Pushing a new root
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 3 changesets with 3 changes to 3 files (+1 heads)
  To hg::.*/push.t/repo (re)
   + 687e015...62326f3 62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (forced update)
