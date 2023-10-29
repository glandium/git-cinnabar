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
  

Create a git clone of the above repository, piece by piece to have some
metadata history.

  $ git init -q repo-git
  $ git -C repot-git cinnabar fetch f92470d7f6966a39dfbced6a525fe81ebf5c37b9
  fatal: cannot change to 'repot-git': No such file or directory
  [128]
  $ git -C repo-git cinnabar fetch hg::$REPO 636e60525868096cbdc961870493510558f41d2f
  From hg::.*/rollback.t/repo (re)
   * branch            hg/revs/636e60525868096cbdc961870493510558f41d2f -> FETCH_HEAD
  $ git -C repo-git cinnabar fetch hg::$REPO ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307
  From hg::.*/rollback.t/repo (re)
   * branch            hg/revs/ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 -> FETCH_HEAD

  $ git -C repo-git cinnabar fsck 2> /dev/null

  $ git -C repo-git cinnabar fetch hg::$REPO 7937e1a594596ae25c637d317503d775767671b5
  From hg::.*/rollback.t/repo (re)
   * branch            hg/revs/7937e1a594596ae25c637d317503d775767671b5 -> FETCH_HEAD
  $ git -C repo-git cinnabar fetch hg::$REPO 872d4a0c72d8c2b915a4d85b4f31ca4a12c882eb
  From hg::.*/rollback.t/repo (re)
   * branch            hg/revs/872d4a0c72d8c2b915a4d85b4f31ca4a12c882eb -> FETCH_HEAD
  $ git -C repo-git cinnabar fetch hg::$REPO 312a5a9c675e3ce302a33bd4605205a6be36d561
  From hg::.*/rollback.t/repo (re)
   * branch            hg/revs/312a5a9c675e3ce302a33bd4605205a6be36d561 -> FETCH_HEAD

  $ git -C repo-git cinnabar rollback --candidates
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 (current)
  1533f7bbc5d7bd3e420cd927b890097cf660531e
  544f4ec28c4b9e3b2f5ac01fe2e50a8a67a12909
  ee1547daada51509736d29942d8ad9cdd53e5500 (checked)
  9134dcc9628afe079a8a61e06f1e49a36a983cc4

  $ git -C repo-git for-each-ref refs/cinnabar/ refs/notes/
  ee1547daada51509736d29942d8ad9cdd53e5500 commit	refs/cinnabar/checked
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/metadata
  0d790d01720127d15c119268277eda391270b588 commit	refs/notes/cinnabar

Fake fsck breakage

  $ git -C repo-git update-ref refs/cinnabar/broken refs/cinnabar/metadata

  $ git -C repo-git cinnabar rollback --candidates
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 (current, broken)
  1533f7bbc5d7bd3e420cd927b890097cf660531e
  544f4ec28c4b9e3b2f5ac01fe2e50a8a67a12909
  ee1547daada51509736d29942d8ad9cdd53e5500 (checked)
  9134dcc9628afe079a8a61e06f1e49a36a983cc4

  $ git -C repo-git for-each-ref refs/cinnabar/ refs/notes/
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/broken
  ee1547daada51509736d29942d8ad9cdd53e5500 commit	refs/cinnabar/checked
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/metadata
  0d790d01720127d15c119268277eda391270b588 commit	refs/notes/cinnabar

Rollback to the previous metadata. Its status is not broken but unknown.

  $ git -C repo-git cinnabar rollback

  $ git -C repo-git cinnabar rollback --candidates
  1533f7bbc5d7bd3e420cd927b890097cf660531e (current)
  544f4ec28c4b9e3b2f5ac01fe2e50a8a67a12909
  ee1547daada51509736d29942d8ad9cdd53e5500 (checked)
  9134dcc9628afe079a8a61e06f1e49a36a983cc4

  $ git -C repo-git for-each-ref refs/cinnabar/ refs/notes/
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/broken
  ee1547daada51509736d29942d8ad9cdd53e5500 commit	refs/cinnabar/checked
  1533f7bbc5d7bd3e420cd927b890097cf660531e commit	refs/cinnabar/metadata
  78ae75b918bc679865b2b566d64c81864d8ce7e4 commit	refs/notes/cinnabar

Rollback to the last known good

  $ git -C repo-git cinnabar rollback --fsck

  $ git -C repo-git cinnabar rollback --candidates
  ee1547daada51509736d29942d8ad9cdd53e5500 (current, checked)
  9134dcc9628afe079a8a61e06f1e49a36a983cc4

  $ git -C repo-git for-each-ref refs/cinnabar/ refs/notes/
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/broken
  ee1547daada51509736d29942d8ad9cdd53e5500 commit	refs/cinnabar/checked
  ee1547daada51509736d29942d8ad9cdd53e5500 commit	refs/cinnabar/metadata
  abbd4d8876d12871c52111ef763728cc70b60c20 commit	refs/notes/cinnabar

Rollback to the previous metadata, since it precedes a checked one, it is
considered checked.

  $ git -C repo-git cinnabar rollback

  $ git -C repo-git cinnabar rollback --candidates
  9134dcc9628afe079a8a61e06f1e49a36a983cc4 (current, checked)

  $ git -C repo-git for-each-ref refs/cinnabar/ refs/notes/
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/broken
  9134dcc9628afe079a8a61e06f1e49a36a983cc4 commit	refs/cinnabar/checked
  9134dcc9628afe079a8a61e06f1e49a36a983cc4 commit	refs/cinnabar/metadata
  522a8fcad148fe794046af5769734cdd44f3ebc4 commit	refs/notes/cinnabar

Restore the state where it used to be, except we rightfully lost the checked
state of ee1547d.

  $ git -C repo-git cinnabar rollback fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08
  \r (no-eol) (esc)
  ERROR Cannot rollback to fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08, it is not in the ancestry of current metadata.
  [1]
  $ git -C repo-git cinnabar rollback --force fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08

  $ git -C repo-git cinnabar rollback --candidates
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 (current, broken)
  1533f7bbc5d7bd3e420cd927b890097cf660531e
  544f4ec28c4b9e3b2f5ac01fe2e50a8a67a12909
  ee1547daada51509736d29942d8ad9cdd53e5500
  9134dcc9628afe079a8a61e06f1e49a36a983cc4 (checked)

  $ git -C repo-git for-each-ref refs/cinnabar/ refs/notes/
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/broken
  9134dcc9628afe079a8a61e06f1e49a36a983cc4 commit	refs/cinnabar/checked
  fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08 commit	refs/cinnabar/metadata
  0d790d01720127d15c119268277eda391270b588 commit	refs/notes/cinnabar

Clear metadata

  $ git -C repo-git cinnabar rollback 0000000000000000000000000000000000000000

  $ git -C repo-git cinnabar rollback --candidates

  $ git -C repo-git for-each-ref refs/cinnabar/

Corner cases

  $ git -C repo-git update-ref refs/heads/main FETCH_HEAD
  $ git -C repo-git gc --prune=all 2> /dev/null

  $ git -C repo-git cinnabar rollback
  \r (no-eol) (esc)
  ERROR Nothing to rollback.
  [1]
  $ git -C repo-git cinnabar rollback fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08
  \r (no-eol) (esc)
  ERROR Invalid revision: fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08
  [1]
  $ git -C repo-git cinnabar rollback --force fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08
  \r (no-eol) (esc)
  ERROR Invalid revision: fdc5127c26b6de6ec365bc18e9a4ae2ef2f35c08
  [1]
  $ git -C repo-git cinnabar rollback foo
  \r (no-eol) (esc)
  ERROR Invalid revision: foo
  [1]
  $ git -C repo-git cinnabar rollback --force foo
  \r (no-eol) (esc)
  ERROR Invalid revision: foo
  [1]
  $ git -C repo-git cinnabar rollback --fsck
  \r (no-eol) (esc)
  ERROR No successful fsck has been recorded. Cannot rollback.
  [1]
  $ git -C repo-git cinnabar rollback 0000000000000000000000000000000000000000
  $ git -C repo-git cinnabar rollback main
  \r (no-eol) (esc)
  ERROR Cannot rollback to 23bcc26b9fea7e37426260465bed35eac54af5e1, it is not in the ancestry of current metadata.
  [1]
  $ git -C repo-git cinnabar rollback --force main
  \r (no-eol) (esc)
  ERROR Invalid cinnabar metadata: 23bcc26b9fea7e37426260465bed35eac54af5e1
  [1]
