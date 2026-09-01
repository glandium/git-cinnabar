#!/usr/bin/env cram

  $ PATH=$TESTDIR/..:$PATH

  $ n=0
  $ create_hg() {
  >   echo $1 > $1
  >   hg add $1
  >   [ "$2" = "--no-commit" ] || hg commit -q -m ${2:-$1} -u nobody -d "$n 0"
  >   n=$(expr $n + 1)
  > }

  $ ng=0
  $ create_git() {
  >   echo $1 > $1
  >   git add $1
  >   GIT_COMMITTER_DATE="@$ng +0000" GIT_AUTHOR_DATE="@$ng +0000" git commit -q -m ${2:-$1}
  >   ng=$(expr $ng + 1)
  > }

  $ export GIT_COMMITTER_NAME=nobody
  $ export GIT_COMMITTER_EMAIL=
  $ export GIT_AUTHOR_NAME=nobody
  $ export GIT_AUTHOR_EMAIL=

Create a mercurial repository.

  $ hg init hgrepo
  $ HGREPO=$(pwd)/hgrepo
  $ cd hgrepo
  $ for f in a b c; do create_hg $f --no-commit; done
  $ for f in d e f; do create_hg $f; done
  $ hg up -q -r 1
  $ create_hg g
  $ hg merge -q
  $ create_hg g merge 2>/dev/null

Corner case: some repos may contain very similar commits as parents
of a merge.

  $ create_hg h
  $ hg up -q -r 4
  $ hg branch foo > /dev/null

Rewind to have the same timestamp

  $ n=$(expr $n - 1)
  $ create_hg h
  $ hg up -q -r default
  $ hg merge -q -r foo
  $ create_hg g merge2 2>/dev/null

  $ hg log -G --template '{node} {branch} {desc}'
  @    b251f5b61a34a71c5736e9a746fbe18e830e7692 default merge2
  |\
  | o  68695712246fb6549a41db72c70ba76709742dfc foo h
  | |
  o |  00f515a92d5b35c58f66352a846699f1f9d38939 default h
  |/
  o    bc15c20fd6a3a1fdd70f67f278b4374c6d5e3ed2 default merge
  |\
  | o  299c5a9b90df6fdd0dc2b3716a114545a6536394 default g
  | |
  o |  aa7250354ccc66f3c4b8d068fc00e5c1b0d8a838 default f
  |/
  o  695eafa9c5b95e82f2ebc39f9fb63fd2470862e8 default e
  |
  o  3d1f6f97e0be2f7faab7c8e2b3fe7dd139f492a2 default d
  
  $ cd ..

  $ git init -q -b main gitrepo
  $ cd gitrepo
  $ for f in a b c d e f; do create_git $f; done
  $ git checkout -q HEAD~
  $ create_git g
  $ git merge -q main --no-commit 2>/dev/null
  $ create_git g merge
  $ git checkout -q main
  $ git merge -q HEAD@{1}
  $ create_git h
  $ git checkout -q HEAD~

Rewind to have the same timestamp

  $ ng=$(expr $ng - 1)
  $ create_git h "h-"
  $ git merge -q main --no-commit 2>/dev/null
  $ create_git h merge2
  $ git checkout -q main
  $ git merge -q HEAD@{1}

  $ git log --oneline --graph
  *   9c2fa0d merge2
  |\  
  | * 62a25a3 h
  * | b07c195 h-
  |/  
  *   4b7ce9d merge
  |\  
  | * d06f423 f
  * | 778db95 g
  |/  
  * 0a4d857 e
  * 5ba3548 d
  * a4b51d3 c
  * 13020e5 b
  * 78bbecb a

  $ git -c cinnabar.graft=true fetch -q hg::$HGREPO
  $ git log --oneline --graph --notes=cinnabar
  *   9c2fa0d merge2
  |\  Notes (cinnabar):
  | |     changeset b251f5b61a34a71c5736e9a746fbe18e830e7692
  | |     manifest 164b2f0736d9b0ecd5d3a9cd07c23dc37cf0a875
  | |     patch 59,60,
  | | 
  | * 62a25a3 h
  | | Notes (cinnabar):
  | |     changeset 00f515a92d5b35c58f66352a846699f1f9d38939
  | |     manifest 164b2f0736d9b0ecd5d3a9cd07c23dc37cf0a875
  | |     files h
  | |     patch 56,57,
  | | 
  * | b07c195 h-
  |/  Notes (cinnabar):
  |       changeset 68695712246fb6549a41db72c70ba76709742dfc
  |       manifest 164b2f0736d9b0ecd5d3a9cd07c23dc37cf0a875
  |       extra branch:foo
  |       files h
  |       patch 67,69,
  |   
  *   4b7ce9d merge
  |\  Notes (cinnabar):
  | |     changeset bc15c20fd6a3a1fdd70f67f278b4374c6d5e3ed2
  | |     manifest cd78cfd51d7278235f744c257dd402f6a118bc9b
  | |     patch 58,59,
  | | 
  | * d06f423 f
  | | Notes (cinnabar):
  | |     changeset aa7250354ccc66f3c4b8d068fc00e5c1b0d8a838
  | |     manifest 488092b4bec54565c630cdf953d5945e1a4993a0
  | |     files f
  | |     patch 56,57,
  | | 
  * | 778db95 g
  |/  Notes (cinnabar):
  |       changeset 299c5a9b90df6fdd0dc2b3716a114545a6536394
  |       manifest 3fb79d9a3901d9812a56e2fdfe3049d0b6c2f83a
  |       files g
  |       patch 56,57,
  |   
  * 0a4d857 e
  | Notes (cinnabar):
  |     changeset 695eafa9c5b95e82f2ebc39f9fb63fd2470862e8
  |     manifest 251ee6379d69fc281a21ff9890c4d4cb46c30336
  |     files e
  |     patch 56,57,
  | 
  * 5ba3548 d
  * a4b51d3 c
  * 13020e5 b
  * 78bbecb a

  $ git for-each-ref refs/cinnabar/replace
  c580451755f958f4ee1468e21633521d089710ac commit\trefs/cinnabar/replace/5ba3548eb05496c9f53b043260476fe94bd25172 (esc)
  $ git log --oneline --graph --notes=cinnabar c580451755f958f4ee1468e21633521d089710ac
  * c580451 d
    Notes (cinnabar):
        changeset 3d1f6f97e0be2f7faab7c8e2b3fe7dd139f492a2
        manifest 9c601042bb6720fc7b4364539cae4716791e5fda
        files a
        b
        c
        d
    
Try again with what looks more like what git-cinnabar itself would have
produced, by removing newlines from the end of commit messages.

  $ git cinnabar clear
  $ git filter-branch --msg-filter "awk 'NR > 1 { printf \"\\n\" } { printf \"%s\", \$0 }'" >/dev/null 2>&1

  $ git log --oneline --graph
  *   b1241ac merge2
  |\  
  | * a47b1bf h
  * | 44e4e8b h-
  |/  
  *   30a8507 merge
  |\  
  | * 686539f f
  * | aa9c8bb g
  |/  
  * 2c8e128 e
  * f0a1cba d
  * 687e015 c
  * d04f6df b
  * 8b86a58 a

  $ git -c cinnabar.graft=true fetch -q hg::$HGREPO
  $ git log --oneline --graph --notes=cinnabar
  *   b1241ac merge2
  |\  Notes (cinnabar):
  | |     changeset b251f5b61a34a71c5736e9a746fbe18e830e7692
  | |     manifest 164b2f0736d9b0ecd5d3a9cd07c23dc37cf0a875
  | | 
  | * a47b1bf h
  | | Notes (cinnabar):
  | |     changeset 00f515a92d5b35c58f66352a846699f1f9d38939
  | |     manifest 164b2f0736d9b0ecd5d3a9cd07c23dc37cf0a875
  | |     files h
  | | 
  * | 44e4e8b h-
  |/  Notes (cinnabar):
  |       changeset 68695712246fb6549a41db72c70ba76709742dfc
  |       manifest 164b2f0736d9b0ecd5d3a9cd07c23dc37cf0a875
  |       extra branch:foo
  |       files h
  |       patch 67,68,
  |   
  *   30a8507 merge
  |\  Notes (cinnabar):
  | |     changeset bc15c20fd6a3a1fdd70f67f278b4374c6d5e3ed2
  | |     manifest cd78cfd51d7278235f744c257dd402f6a118bc9b
  | | 
  | * 686539f f
  | | Notes (cinnabar):
  | |     changeset aa7250354ccc66f3c4b8d068fc00e5c1b0d8a838
  | |     manifest 488092b4bec54565c630cdf953d5945e1a4993a0
  | |     files f
  | | 
  * | aa9c8bb g
  |/  Notes (cinnabar):
  |       changeset 299c5a9b90df6fdd0dc2b3716a114545a6536394
  |       manifest 3fb79d9a3901d9812a56e2fdfe3049d0b6c2f83a
  |       files g
  |   
  * 2c8e128 e
  | Notes (cinnabar):
  |     changeset 695eafa9c5b95e82f2ebc39f9fb63fd2470862e8
  |     manifest 251ee6379d69fc281a21ff9890c4d4cb46c30336
  |     files e
  | 
  * f0a1cba d
  * 687e015 c
  * d04f6df b
  * 8b86a58 a


  $ git for-each-ref refs/cinnabar/replace
  c580451755f958f4ee1468e21633521d089710ac commit\trefs/cinnabar/replace/f0a1cba4d5a6919f6ba44b775278734fb5e30f78 (esc)
  $ git log --oneline --graph --notes=cinnabar c580451755f958f4ee1468e21633521d089710ac
  * c580451 d
    Notes (cinnabar):
        changeset 3d1f6f97e0be2f7faab7c8e2b3fe7dd139f492a2
        manifest 9c601042bb6720fc7b4364539cae4716791e5fda
        files a
        b
        c
        d
    

Create metadata for a fresh commit on the git side.

  $ create_git i
  $ git -c cinnabar.data=force push --dry-run hg::$HGREPO main:branches/default/tip
  To hg::.*/grafts.t/hgrepo (re)
     b1241ac..60acdeb  main -> branches/default/tip

Pushing that after metadata was created should not fail.

  $ git -c cinnabar.data=force push hg::$HGREPO main:branches/default/tip
  remote: adding changesets
  remote: adding manifests
  remote: adding file changes
  remote: added 1 changesets with 1 changes to 1 files
  To hg::.*/grafts.t/hgrepo (re)
     b1241ac..60acdeb  main -> branches/default/tip
