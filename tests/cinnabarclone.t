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
  $ create c
  $ cd ..

  $ hg -R $REPO log -G --template '{node} {branch} {desc}'
  @  ae078ae353a9b004afbd6fd6e5e7a5a0a48a4307 default c
  |
  | o  636e60525868096cbdc961870493510558f41d2f default b
  |/
  o  f92470d7f6966a39dfbced6a525fe81ebf5c37b9 default a
  
Create a cinnabar clone of the partial repository

  $ git -c fetch.prune=true clone -n -q hg::$REPO cinnabarclone-incr
  $ git -C cinnabarclone-incr bundle create ../cinnabarclone-incr.git refs/cinnabar/metadata

  $ cd repo
  $ create d
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
  
Create a cinnabar clone of the full repository.

  $ git -c fetch.prune=true clone -n -q hg::$REPO cinnabarclone-full
  $ git -C cinnabarclone-full bundle create ../cinnabarclone-full.git refs/cinnabar/metadata

Ensure the repository looks like what we assume further below.

  $ cat > expected_clone <<EOF
  > 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	HEAD
  > d04f6df4abe2870ceb759263ee6aaa9241c4f93c	refs/heads/branches/default/636e60525868096cbdc961870493510558f41d2f
  > 5c5b259d3c128f3d7b50ce3bd5c9eaafd8d17611	refs/heads/branches/default/tip
  > 23bcc26b9fea7e37426260465bed35eac54af5e1	refs/heads/branches/foo/tip
  > EOF

  $ check_clone() {
  >   git -C $1 ls-remote hg::$REPO | diff -u - expected_clone
  > }

  $ check_clone cinnabarclone-full

Incremental cinnabarclone with git http smart protocol

  $ cat > $REPO/.hg/hgrc <<EOF
  > [extensions]
  > x = $TESTDIR/../CI/hg-serve-exec.py
  > cinnabarclone = $TESTDIR/../mercurial/cinnabarclone.py
  > [web]
  > accesslog = $CRAMTMP/accesslog
  > errorlog = /dev/null
  > [serve]
  > other =
  > EOF

  $ echo http://localhost:8080/ > $REPO/.hg/cinnabar.manifest

Testing error conditions:

- Server does not listen.

  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/
  \r (no-eol) (esc)
  ERROR [Errno 111] Connection refused
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- Server listens but does not serve a repository or bundle
TODO: git errors are repeating and lack newlines.

  $ sed -i '/other/s/=.*/= git/' $REPO/.hg/hgrc
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/
  Not a git repository: '.*/cinnabarclone.t'Not a git repository: '.*/cinnabarclone.t'Request not supported: '.*/cinnabarclone.t/'.* (re)
  ERROR Could not find cinnabar metadata
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- cinnabarclone points to a non-existing server.

  $ echo http://this.cannot.possibly.exist.invalid-tld/ > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://this.cannot.possibly.exist.invalid-tld/
  \r (no-eol) (esc)
  ERROR [Errno -2] Name or service not known
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- cinnabarclone points to an url with unsupported protocol.

  $ echo ftp://this.cannot.possibly.exist.invalid-tld/ > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  \r (no-eol) (esc)
  WARNING Server advertizes cinnabarclone but provided a non http/https git repository. Skipping.
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- cinnabarclone points to a file path

  $ echo /this/cannot/possibly/exist/invalid-dir/ > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  \r (no-eol) (esc)
  WARNING Server advertizes cinnabarclone but provided a non http/https git repository. Skipping.
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- Server listens, but serves a non-cinnabar repository.

  $ git init -q non-cinnabar
  $ git -C non-cinnabar fetch -q ../cinnabarclone-incr refs/remotes/origin/*:refs/remotes/origin/*
  $ echo http://localhost:8080/non-cinnabar > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/non-cinnabar
  \r (no-eol) (esc)
  ERROR Could not find cinnabar metadata
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- Server listens, but serves a 404.

  $ sed -i '/other/s/=.*/= http/' $REPO/.hg/hgrc
  $ echo http://localhost:8080/non-existing.git > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/non-existing.git
  \r (no-eol) (esc)
  ERROR File not found
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- Server listens, but serves a non-bundle file.

  $ echo foo > not-bundle.git
  $ echo http://localhost:8080/not-bundle.git > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/not-bundle.git
  \r (no-eol) (esc)
  ERROR Could not find cinnabar metadata
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

- Server listens, but serves a truncated bundle file.

  $ dd if=cinnabarclone-full.git of=truncated.git bs=1024 count=1 status=none
  $ echo http://localhost:8080/truncated.git > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/truncated.git
  fatal: early EOF
  \r (no-eol) (esc)
  ERROR Failed to fetch cinnabar metadata.
  \r (no-eol) (esc)
  WARNING Falling back to normal clone.

  $ check_clone repo-git
  $ rm -rf repo-git

TODO: old (unsupported) cinnabar metadata
TODO: cinnabar metadata from a different repo

Now test working setups.

First, a full clone.

  $ > $CRAMTMP/accesslog

  $ echo http://localhost:8080/cinnabarclone-full.git > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/cinnabarclone-full.git

  $ grep -q cmd=getbundle $CRAMTMP/accesslog
  [1]

  $ check_clone repo-git
  $ rm -rf repo-git

Then, a partial clone.

  $ > $CRAMTMP/accesslog

  $ echo http://localhost:8080/cinnabarclone-incr.git > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/cinnabarclone-incr.git

  $ grep -q cmd=getbundle $CRAMTMP/accesslog

  $ check_clone repo-git
  $ rm -rf repo-git

Same thing, with git repositories rather than bundles.

  $ sed -i '/other/s/=.*/= git/' $REPO/.hg/hgrc

First, a full clone.

  $ > $CRAMTMP/accesslog

  $ echo http://localhost:8080/cinnabarclone-full > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/cinnabarclone-full

  $ grep -q cmd=getbundle $CRAMTMP/accesslog
  [1]

  $ check_clone repo-git
  $ rm -rf repo-git

Then, a partial clone.

  $ > $CRAMTMP/accesslog

  $ echo http://localhost:8080/cinnabarclone-incr > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/cinnabarclone-incr

  $ grep -q cmd=getbundle $CRAMTMP/accesslog

  $ check_clone repo-git
  $ rm -rf repo-git

Same thing again, with a git daemon.

  $ sed -i '/other/s/=.*/=/' $REPO/.hg/hgrc

First, a full clone.
TODO: this currently does not work (presumably, support for bundles broke it)
TODO: needs a git daemon setup.

  $ > $CRAMTMP/accesslog

  $ echo git://localhost/cinnabarclone-full > $REPO/.hg/cinnabar.manifest
#  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
#  Cloning into 'repo-git'...
#  Fetching cinnabar metadata from git://localhost/cinnabarclone-full

#  $ grep -q cmd=getbundle $CRAMTMP/accesslog
#  [1]

#  $ check_clone repo-git
#  $ rm -rf repo-git

Then, a partial clone.

  $ > $CRAMTMP/accesslog

  $ echo git://localhost/cinnabarclone-incr > $REPO/.hg/cinnabar.manifest
#  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
#  Cloning into 'repo-git'...
#  Fetching cinnabar metadata from git://localhost/cinnabarclone-incr

#  $ grep -q cmd=getbundle $CRAMTMP/accesslog

#  $ check_clone repo-git
#  $ rm -rf repo-git

Git config takes precedence over whatever the mercurial server might say

  $ > $CRAMTMP/accesslog

  $ sed -i '/other/s/=.*/= http/' $REPO/.hg/hgrc
  $ echo http://this.cannot.possibly.exist.invalid-tld/ > $REPO/.hg/cinnabar.manifest
  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.clone=http://localhost:8080/cinnabarclone-full.git -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
  Cloning into 'repo-git'...
  Fetching cinnabar metadata from http://localhost:8080/cinnabarclone-full.git

  $ grep -q cmd=getbundle $CRAMTMP/accesslog
  [1]

  $ check_clone repo-git
  $ rm -rf repo-git

TODO: Can disable via git config

#  $ hg -R $REPO serve-and-exec -- git -c fetch.prune=true -c cinnabar.clone= -c cinnabar.experiments=git-clone clone -n hg::http://localhost:8000/ repo-git
#  Cloning into 'repo-git'...

#  $ grep -q cmd=getbundle $CRAMTMP/accesslog

#  $ check_clone repo-git
#  $ rm -rf repo-git
