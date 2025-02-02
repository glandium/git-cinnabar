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
  $ hg init xyz
  $ hg init uvw
  $ ABC=$(pwd)/abc
  $ DEF=$(pwd)/def
  $ XYZ=$(pwd)/xyz
  $ UVW=$(pwd)/uvw

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
  $ git -c init.defaultBranch=main -c fetch.prune=true clone -n -q hg::$XYZ xyz-git
  warning: You appear to have cloned an empty repository.
  $ git -c init.defaultBranch=main -c fetch.prune=true clone -n -q hg::$UVW uvw-git
  warning: You appear to have cloned an empty repository.

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

  $ git -C abc-git push --dry-run origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip
  $ git -C abc-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push.t/repo (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip

Pushing from a repo without cinnabar metadata to an empty mercurial repo works

  $ git -C abc-git cinnabar clear
  $ rm -rf $REPO/.hg
  $ hg init $REPO
  $ git -C abc-git push --dry-run origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip
  $ git -C abc-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push.t/repo (re)
   * [new branch]      d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip

Pushing from a repo without cinnabar metadata to a non-empty mercurial repo
requires pulling first.

  $ git -C abc-git cinnabar clear
  $ git -C abc-git push --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C abc-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

Same, even when forced.

  $ git -C abc-git push -f --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C abc-git push -f origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

However, after pulling, we have a shared root, and we can push

  $ git -c fetch.prune=true -C abc-git remote update origin
  Fetching origin

  $ git -C abc-git push --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
     d04f6df..687e015  687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip
  $ git -C abc-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/push.t/repo (re)
     d04f6df..687e015  687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip

Pushing from a repo without cinnabar metadata to a non-empty mercurial repo
with different contents requires pulling first.

  $ git -C def-git cinnabar clear
  $ git -C def-git push --dry-run origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C def-git push origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

Same, even when forced.

  $ git -C def-git push -f --dry-run origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C def-git push -f origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (Cannot push to this remote without pulling/updating first)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

After pulling, we have cinnabar metadata, but we still have an unrelated tree
and can't push, but that's caught by git itself.

  $ git -c fetch.prune=true -C def-git remote update origin
  Fetching origin
  From hg::.*/push.t/repo (re)
   + 62326f3...687e015 branches/default/tip -> origin/branches/default/tip  (forced update)

  $ git -c advice.pushnonffcurrent=true -c advice.pushupdaterejected=true -C def-git push --dry-run origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [rejected]        62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (non-fast-forward)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  hint: Updates were rejected because the tip of your current branch is behind
  hint: its remote counterpart.* (re)
  hint: .*before pushing again. (re)
  hint: See the 'Note about fast-forwards' in 'git push --help' for details.
  [1]
  $ git -c advice.pushnonffcurrent=true -c advice.pushupdaterejected=true -C def-git push origin 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [rejected]        62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (non-fast-forward)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  hint: Updates were rejected because the tip of your current branch is behind
  hint: its remote counterpart.* (re)
  hint: .*before pushing again. (re)
  hint: See the 'Note about fast-forwards' in 'git push --help' for details.
  [1]

This time, forced push is allowed.

  $ git -c advice.pushnonffcurrent=true -c advice.pushupdaterejected=true -C def-git push origin -f --dry-run 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  WARNING Pushing a new root
  To hg::.*/push.t/repo (re)
   + 687e015...62326f3 62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (forced update)
  $ git -c advice.pushnonffcurrent=true -c advice.pushupdaterejected=true -C def-git push origin -f 62326f34fea5b80510f57599da9fd6e5997c0ca4:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  WARNING Pushing a new root
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 3 changesets with 3 changes to 3 files (+1 heads)
  To hg::.*/push.t/repo (re)
   + 687e015...62326f3 62326f34fea5b80510f57599da9fd6e5997c0ca4 -> branches/default/tip (forced update)

Similarly, when pushing from a shallow git repository.

  $ git clone --depth=1 file://$ABC-git abc-shallow
  Cloning into 'abc-shallow'...
  $ rm -rf $REPO/.hg
  $ hg init $REPO
  $ git -C abc-shallow remote set-url origin hg::$REPO
  $ git -C abc-shallow push --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Pushing git shallow clones is not supported)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C abc-shallow push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Pushing git shallow clones is not supported)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C abc-shallow push -f --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Pushing git shallow clones is not supported)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C abc-shallow push -f origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Pushing git shallow clones is not supported)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

After pulling from a different repo, we still recognize we have a shallow clone.

  $ git -C abc-shallow cinnabar fetch hg::$DEF 90f6163d2820561ebe0f6c28e87d766ef619e43c
  From hg::.*/push.t/def (re)
   * branch            hg/revs/90f6163d2820561ebe0f6c28e87d766ef619e43c -> FETCH_HEAD
  $ git -C abc-shallow push -f --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Pushing git shallow clones is not supported)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ git -C abc-shallow push -f origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip (Pushing git shallow clones is not supported)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]

Pulling from a repo that contains the history behind the shallow clone is
supported and makes it unshallowed.

  $ git -C abc-shallow cinnabar fetch hg::$ABC bd623dea939349b06a47d5dce064255e5f1d9ec1
  From hg::.*/push.t/abc (re)
   * branch            hg/revs/bd623dea939349b06a47d5dce064255e5f1d9ec1 -> FETCH_HEAD
  $ git -C abc-shallow push -f --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   * [new branch]      687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip
  $ git -C abc-shallow push -f origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 3 changesets with 3 changes to 3 files
  To hg::.*/push.t/repo (re)
   * [new branch]      687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip

Phase and cinnabar.data tests.

  $ git -C xyz-git fetch ../abc-git 687e015f9f646bb19797d991f2f53087297fbe14
  From ../abc-git
   * branch            687e015f9f646bb19797d991f2f53087297fbe14 -> FETCH_HEAD

  $ git -C xyz-git fetch ../def-git 62326f34fea5b80510f57599da9fd6e5997c0ca4
  From ../def-git
   * branch            62326f34fea5b80510f57599da9fd6e5997c0ca4 -> FETCH_HEAD

  $ git -c cinnabar.data=never -C xyz-git push --dry-run origin 8b86a58578d5270969543e287634e3a2f122a338:refs/heads/branches/default/tip
  To hg::.*/push.t/xyz (re)
   * [new branch]      8b86a58578d5270969543e287634e3a2f122a338 -> branches/default/tip
  $ git -c cinnabar.data=never -C xyz-git push origin 8b86a58578d5270969543e287634e3a2f122a338:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/push.t/xyz (re)
   * [new branch]      8b86a58578d5270969543e287634e3a2f122a338 -> branches/default/tip

  $ git -C xyz-git cinnabar rollback --candidates

  $ git -c fetch.prune=true -C xyz-git remote update origin
  Fetching origin
  $ git -C xyz-git cinnabar rollback --candidates
  2836e453f32b1ecccd3acca412f75b07c88176bf (current)

  $ git -c cinnabar.data=phase -C xyz-git push --dry-run origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  To hg::.*/push.t/xyz (re)
     8b86a58..d04f6df  d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip
  $ git -c cinnabar.data=phase -C xyz-git push origin d04f6df4abe2870ceb759263ee6aaa9241c4f93c:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/push.t/xyz (re)
     8b86a58..d04f6df  d04f6df4abe2870ceb759263ee6aaa9241c4f93c -> branches/default/tip

Server is publishing, so metadata was stored.

  $ git -C xyz-git cinnabar rollback --candidates
  8b8194eefb69ec89edc35dafb965311fe48c49d0 (current)
  2836e453f32b1ecccd3acca412f75b07c88176bf

  $ cat >> $XYZ/.hg/hgrc <<EOF
  > [phases]
  > publish = False
  > EOF

  $ git -c cinnabar.data=phase -C xyz-git push --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/xyz (re)
     d04f6df..687e015  687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip
  $ git -c cinnabar.data=phase -C xyz-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/push.t/xyz (re)
     d04f6df..687e015  687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip

Server is now non-publishing, so metadata is unchanged.

  $ git -C xyz-git cinnabar rollback --candidates
  8b8194eefb69ec89edc35dafb965311fe48c49d0 (current)
  2836e453f32b1ecccd3acca412f75b07c88176bf

  $ git -c fetch.prune=true -C xyz-git remote update origin
  Fetching origin
  $ git -C xyz-git cinnabar rollback --candidates
  a2341d430e5acddf9481eabcad901fda12d023d3 (current)
  8b8194eefb69ec89edc35dafb965311fe48c49d0
  2836e453f32b1ecccd3acca412f75b07c88176bf

  $ git -c cinnabar.data=always -C xyz-git push -f --dry-run origin 7ca6a3c32ec0dbcbcd155b2be6e2f4505012c273:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  WARNING Pushing a new root
  To hg::.*/push.t/xyz (re)
   + 687e015...7ca6a3c 7ca6a3c32ec0dbcbcd155b2be6e2f4505012c273 -> branches/default/tip (forced update)

Whatever happens, --dry-run doesn't store metadata

  $ git -C xyz-git cinnabar rollback --candidates
  a2341d430e5acddf9481eabcad901fda12d023d3 (current)
  8b8194eefb69ec89edc35dafb965311fe48c49d0
  2836e453f32b1ecccd3acca412f75b07c88176bf

There is an extra mode for cinnabar.data that forces --dry-run to store metadata

  $ git -c cinnabar.data=force -C xyz-git push -f --dry-run origin 7ca6a3c32ec0dbcbcd155b2be6e2f4505012c273:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  WARNING Pushing a new root
  To hg::.*/push.t/xyz (re)
   + 687e015...7ca6a3c 7ca6a3c32ec0dbcbcd155b2be6e2f4505012c273 -> branches/default/tip (forced update)
  $ git -C xyz-git cinnabar rollback --candidates
  4305cef3fa610b3370f64ce10d2b50693a904278 (current)
  a2341d430e5acddf9481eabcad901fda12d023d3
  8b8194eefb69ec89edc35dafb965311fe48c49d0
  2836e453f32b1ecccd3acca412f75b07c88176bf
  $ git -C xyz-git cinnabar rollback
  $ git -C xyz-git cinnabar rollback --candidates
  a2341d430e5acddf9481eabcad901fda12d023d3 (current)
  8b8194eefb69ec89edc35dafb965311fe48c49d0
  2836e453f32b1ecccd3acca412f75b07c88176bf

  $ git -c cinnabar.data=always -C xyz-git push -f origin 7ca6a3c32ec0dbcbcd155b2be6e2f4505012c273:refs/heads/branches/default/tip
  \r (no-eol) (esc)
  WARNING Pushing a new root
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files (+1 heads)
  To hg::.*/push.t/xyz (re)
   + 687e015...7ca6a3c 7ca6a3c32ec0dbcbcd155b2be6e2f4505012c273 -> branches/default/tip (forced update)

Server is still non-publishing, but we opted in to store the metadata.

  $ git -C xyz-git cinnabar rollback --candidates
  4305cef3fa610b3370f64ce10d2b50693a904278 (current)
  a2341d430e5acddf9481eabcad901fda12d023d3
  8b8194eefb69ec89edc35dafb965311fe48c49d0
  2836e453f32b1ecccd3acca412f75b07c88176bf

Pushing a root to a new non-publishing repo should work.

  $ cat >> $UVW/.hg/hgrc <<EOF
  > [phases]
  > publish = False
  > EOF

  $ git -C uvw-git fetch ../xyz-git 687e015f9f646bb19797d991f2f53087297fbe14
  From ../xyz-git
   * branch            687e015f9f646bb19797d991f2f53087297fbe14 -> FETCH_HEAD

  $ git -c cinnabar.data=phase -C uvw-git push --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/uvw (re)
   * [new branch]      687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip
  $ git -c cinnabar.data=phase -C uvw-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 3 changesets with 3 changes to 3 files
  To hg::.*/push.t/uvw (re)
   * [new branch]      687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip

Server is non-publishing, metadata should not be stored.

  $ git -C uvw-git cinnabar rollback --candidates

  $ hg -R $UVW phase --public f92470d7f6966a39dfbced6a525fe81ebf5c37b9
  $ hg -R $UVW phase -r 'all()'
  0: public
  1: draft
  2: draft

We won't be able to push without first pulling something, so fetch the first commit.

  $ git -C uvw-git cinnabar fetch hg::$UVW f92470d7f6966a39dfbced6a525fe81ebf5c37b9
  From hg::.*/push.t/uvw (re)
   * branch            hg/revs/f92470d7f6966a39dfbced6a525fe81ebf5c37b9 -> FETCH_HEAD

  $ git -C uvw-git cinnabar rollback --candidates
  2836e453f32b1ecccd3acca412f75b07c88176bf (current)

  $ hg -R $UVW phase --public 636e60525868096cbdc961870493510558f41d2f
  $ hg -R $UVW phase -r 'all()'
  0: public
  1: public
  2: draft
  $ hg --config extensions.strip= -R $UVW strip -r 2 --no-backup

  $ git -c cinnabar.data=phase -C uvw-git push --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  To hg::.*/push.t/uvw (re)
   * [new branch]      687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip
  $ git -c cinnabar.data=phase -C uvw-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 2 files
  To hg::.*/push.t/uvw (re)
   * [new branch]      687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip

We pushed what happens to be one existing public commit and one draft commit.
In that corner case, we don't store metadata.

  $ git -C uvw-git cinnabar rollback --candidates
  2836e453f32b1ecccd3acca412f75b07c88176bf (current)

Test the git_commit experimental feature.

  $ rm -rf $REPO/.hg
  $ hg init $REPO
  $ git -C abc-git cinnabar clear
  $ git -C abc-git push --dry-run origin 8b86a58578d5270969543e287634e3a2f122a338:refs/heads/branches/default/tip
  To hg::.*/push.t/repo (re)
   * [new branch]      8b86a58578d5270969543e287634e3a2f122a338 -> branches/default/tip
  $ git -C abc-git push origin 8b86a58578d5270969543e287634e3a2f122a338:refs/heads/branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/push.t/repo (re)
   * [new branch]      8b86a58578d5270969543e287634e3a2f122a338 -> branches/default/tip

  $ git -c cinnabar.experiments=git_commit -C abc-git push --dry-run origin 687e015f9f646bb19797d991f2f53087297fbe14:branches/default/tip
  To hg::.*/push.t/repo (re)
     8b86a58..687e015  687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip
  $ git -c cinnabar.experiments=git_commit -C abc-git push origin 687e015f9f646bb19797d991f2f53087297fbe14:branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 2 changesets with 2 changes to 2 files
  To hg::.*/push.t/repo (re)
     8b86a58..687e015  687e015f9f646bb19797d991f2f53087297fbe14 -> branches/default/tip

  $ hg -R $REPO log -G --template '{node} {branch} {desc} {extras.git_commit}'
  o  c70941aaa15aa6e5feae28164438f13dc3cd7b8e default c 687e015f9f646bb19797d991f2f53087297fbe14
  |
  o  29872b591f8d41c613bbfad38722824ab0457f17 default b d04f6df4abe2870ceb759263ee6aaa9241c4f93c
  |
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  

Round-trips back to the same commits, despite the Mercurial changesets being
different than without the feature enabled.

  $ git -c fetch.prune=true clone -q hg::$REPO $REPO-git
  $ git -C $REPO-git log --graph --remotes --oneline --no-abbrev-commit
  * 687e015f9f646bb19797d991f2f53087297fbe14 c
  * d04f6df4abe2870ceb759263ee6aaa9241c4f93c b
  * 8b86a58578d5270969543e287634e3a2f122a338 a

Create a new commit in a divergent Mercurial clone.

  $ ABX=$(pwd)/abx
  $ hg clone -q -u 636e60525868096cbdc961870493510558f41d2f abc abx
  $ cd abx
  $ create x
  $ cd ..
  $ hg -R $ABX log -G --template '{node} {branch} {desc}'
  @  2b10b3a49ff6e308c904c2c626d7e449480b6403 default x
  |
  | o  bd623dea939349b06a47d5dce064255e5f1d9ec1 default c
  |/
  o  636e60525868096cbdc961870493510558f41d2f default b
  |
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
Grab the divergent commit in git:

  $ git -C abc-git -c fetch.prune=true fetch -q hg::$ABX
  $ git -C abc-git log --graph --oneline --no-abbrev-commit FETCH_HEAD
  * 846552c6f25c1b46e784f59d8249fb31afac2996 x
  * bc90f2819ad12e294b313097b8763d26ca0c08ae b
  * 8b86a58578d5270969543e287634e3a2f122a338 a

Verify that pushes to the divergent hg clone are rejected by a
reject_new_heads hook:

  $ cat > $REPO/.hg/hgrc <<EOF
  > [hooks]
  > pretxnclose.reject_new_heads = python:$TESTDIR/../CI/reject_new_heads.py:hook
  > [ui]
  > quiet = true
  > EOF
  $ git -C abc-git push -f origin 846552c6f25c1b46e784f59d8249fb31afac2996:branches/default/tip
  remote: error: pretxnclose.reject_new_heads hook failed: Changes on branch 'default' resulted in multiple heads
  remote: transaction abort!
  remote: rollback completed
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 846552c6f25c1b46e784f59d8249fb31afac2996 -> branches/default/tip (Changes on branch 'default' resulted in multiple heads)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ rm $REPO/.hg/hgrc
  $ git -C abc-git log --graph --remotes --oneline --no-abbrev-commit
  * 687e015f9f646bb19797d991f2f53087297fbe14 c
  * d04f6df4abe2870ceb759263ee6aaa9241c4f93c b
  * 8b86a58578d5270969543e287634e3a2f122a338 a
  $ hg -R $REPO log -G --template '{node} {branch} {desc}'
  o  c70941aaa15aa6e5feae28164438f13dc3cd7b8e default c
  |
  o  29872b591f8d41c613bbfad38722824ab0457f17 default b
  |
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  

Verify that pushes to the divergent clone are rejected by a broken
hook:

  $ cat > $REPO/.hg/hgrc <<EOF
  > [hooks]
  > pretxnclose = python:/nonexistent:fail
  > [ui]
  > quiet = true
  > EOF
  $ git -C abc-git push -f origin 846552c6f25c1b46e784f59d8249fb31afac2996:branches/default/tip
  remote: loading pretxnclose hook failed:
  remote: transaction abort!
  remote: rollback completed
  remote: abort: No such file or directory: '/nonexistent'
  To hg::.*/push.t/repo (re)
   ! [remote rejected] 846552c6f25c1b46e784f59d8249fb31afac2996 -> branches/default/tip (failed to fill whole buffer)
  error: failed to push some refs to 'hg::.*/push.t/repo' (re)
  [1]
  $ rm $REPO/.hg/hgrc
  $ git -C abc-git log --graph --remotes --oneline --no-abbrev-commit
  * 687e015f9f646bb19797d991f2f53087297fbe14 c
  * d04f6df4abe2870ceb759263ee6aaa9241c4f93c b
  * 8b86a58578d5270969543e287634e3a2f122a338 a
  $ hg -R $REPO log -G --template '{node} {branch} {desc}'
  o  c70941aaa15aa6e5feae28164438f13dc3cd7b8e default c
  |
  o  29872b591f8d41c613bbfad38722824ab0457f17 default b
  |
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
