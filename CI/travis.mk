include $(addsuffix /,$(dir $(firstword $(MAKEFILE_LIST))))../helper/GIT-VERSION.mk

export PATH := $(CURDIR):$(HOME)/Library/Python/2.7/bin:$(PATH)
export PYTHONPATH := $(HOME)/Library/Python/2.7/lib/python/site-packages
export PYTHONDONTWRITEBYTECODE := 1
REPO ?= https://hg.mozilla.org/users/mh_glandium.org/jqplot

DOWNLOAD_FLAGS = --dev $(VARIANT) $(addprefix --machine ,$(MACHINE))

HELPER_PATH = $(subst https://s3.amazonaws.com/git-cinnabar/,,$(shell $(CURDIR)/git-cinnabar download --url $(DOWNLOAD_FLAGS)))

helper_hash:
	@echo $(word 2,$(subst /, ,$(HELPER_PATH))) > $@

.PHONY: helper_hash

# On Travis-CI, an old pip is installed with easy_install, which means its
# egg ends up before our $PYTHONPATH in sys.path, such that upgrading pip with
# --user and using $PYTHONPATH for subsequent pip calls doesn't work.
PIP = python -c 'import os, sys; sys.path[:0] = os.environ.get("PYTHONPATH", "").split(os.pathsep); from pip._internal import main; sys.exit(main())'
PIP_INSTALL = $(PIP) install --user --upgrade --force-reinstall $1

before_install::
	curl -O -s https://bootstrap.pypa.io/get-pip.py
	python get-pip.py --user

	$(call PIP_INSTALL,mercurial)

# Somehow, OSX's make doesn't want to pick hg from $PATH on its own after it's
# installed above...
HG = $$(which hg)

GIT=git -c core.packedGitWindowSize=8k

before_script::
	$(GIT) --version

HELPER := git-cinnabar-helper
GIT_CINNABAR_HELPER=$(CURDIR)/$(HELPER)
export GIT_CINNABAR_CHECK=all
export GIT_CINNABAR_LOG=process:3

ifndef BUILD_HELPER
$(GIT_CINNABAR_HELPER):
ifdef ARTIFACTS_BUCKET
	$(call PIP_INSTALL,requests)
	-$(GIT) cinnabar download -o $@ --no-config $(DOWNLOAD_FLAGS)
endif
	MACOSX_DEPLOYMENT_TARGET=10.6 $(MAKE) -f $(firstword $(MAKEFILE_LIST)) $@ BUILD_HELPER=1

else

ifeq ($(VARIANT),asan)
EXTRA_MAKE_FLAGS += CFLAGS="-O2 -g -fsanitize=address"
endif

ifneq ($(origin CC),default)
EXTRA_MAKE_FLAGS += CC=$(CC)
endif

$(GIT_CINNABAR_HELPER):
	$(MAKE) --jobs=2 $(@F) prefix=/usr $(EXTRA_MAKE_FLAGS)
	cp git-core/$(@F) $@
	mkdir -p $(dir $(HELPER_PATH))
	cp $@ $(HELPER_PATH)

endif

before_script::
	case "$(shell $(CURDIR)/git-cinnabar --version=cinnabar)" in \
	*a$(addprefix |,$(shell git describe --tags --abbrev=0 HEAD 2> /dev/null))) ;; \
	*) false ;; \
	esac
	case "$(shell $(CURDIR)/git-cinnabar --version=module)" in \
	$(shell git ls-tree HEAD cinnabar | awk '{print $$3}')) ;; \
	*) false ;; \
	esac
	case "$(shell $(CURDIR)/git-cinnabar --version=helper 2> /dev/null | awk -F/ '{print $$NF}')" in \
	$(shell git ls-tree HEAD helper | awk '{print $$3}')) ;; \
	*) false ;; \
	esac

before_script:: $(GIT_CINNABAR_HELPER)
	rm -rf hg.old.git
	$(GIT) -c fetch.prune=true clone -n hg::$(REPO) hg.old.git

script::
	$(GIT) -C hg.old.git cinnabar upgrade || [ "$$?" = 2 ]
	$(GIT) -C hg.old.git cinnabar fsck || [ "$$?" = 2 ]

PATH_URL = file://$(if $(filter /%,$(CURDIR)),,/)$(CURDIR)

COMPARE_COMMANDS = bash -c "diff -u <($1) <($2)"

GET_REF_SHA1 = git -C $1 log --format=%H --reverse --date-order --remotes=origin --no-walk$(if $2, | $2) | awk '{print} END { if (NR == 0) { print \"$1\", NR } }'

COMPARE_REFS = $(call COMPARE_COMMANDS,$(call GET_REF_SHA1,$1,$(if $3, $(call $3,$1))),\
                                       $(call GET_REF_SHA1,$2,$(if $3, $(call $3,$2))))

HG_INIT = $(HG) init $1
ifdef NO_BUNDLE2
HG_INIT += ; (echo "[experimental]"; echo "bundle2-advertise = false") >> $1/.hg/hgrc
endif

script::
	rm -rf hg.hg hg.empty.git hg.git hg.bundle hg.unbundle.git
	$(call HG_INIT, hg.hg)
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/hg.hg hg.empty.git
	$(GIT) -C hg.empty.git push --all hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push hg::$(PATH_URL)/hg.hg 'refs/remotes/origin/*:refs/heads/*'
	$(HG) -R hg.hg verify
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/hg.hg hg.git
	$(call COMPARE_REFS, hg.old.git, hg.git)
	$(GIT) -C hg.git cinnabar fsck

	$(GIT) -C hg.git cinnabar bundle $(CURDIR)/hg.bundle -- --remotes
	$(GIT) -c fetch.prune=true clone -n hg::$(CURDIR)/hg.bundle hg.unbundle.git
	$(call COMPARE_REFS, hg.git, hg.unbundle.git)
	$(GIT) -C hg.unbundle.git cinnabar fsck

script::
	rm -rf hg.incr.hg hg.incr.git
	$(HG) init hg.incr.hg
	# /!\ this only really works for an unchanged $(REPO)
	$(HG) -R hg.incr.hg pull $(CURDIR)/hg.hg -r c262fcbf0656 -r 46585998e744
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/hg.incr.hg hg.incr.git
	$(HG) -R hg.incr.hg pull $(CURDIR)/hg.hg
	$(GIT) -C hg.incr.git remote update
	$(GIT) -C hg.incr.git cinnabar fsck

script::
	rm -rf hg.clonebundles.hg hg.clonebundles.git
	$(HG) clone -U hg.hg hg.clonebundles.hg
	$(HG) -R hg.clonebundles.hg bundle -a -r c262fcbf0656 -r 46585998e744 repo.bundle
	echo $(PATH_URL)/repo.bundle > hg.clonebundles.hg/.hg/clonebundles.manifest
	$(HG) -R hg.clonebundles.hg --config extensions.clonebundles= --config extensions.x=CI/hg-serve-exec.py serve-and-exec -- $(GIT) clone -n hg://localhost:8000.http/ hg.clonebundles.git
	$(call COMPARE_REFS, hg.git, hg.clonebundles.git)

script::
	rm -rf hg.clonebundles-full.hg hg.clonebundles-full.git
	$(HG) clone -U hg.hg hg.clonebundles-full.hg
	$(HG) -R hg.clonebundles-full.hg bundle -a repo.bundle
	echo $(PATH_URL)/repo.bundle > hg.clonebundles-full.hg/.hg/clonebundles.manifest
	$(HG) -R hg.clonebundles-full.hg --config extensions.clonebundles= --config extensions.x=CI/hg-serve-exec.py serve-and-exec -- $(GIT) clone -n hg://localhost:8000.http/ hg.clonebundles-full.git
	$(call COMPARE_REFS, hg.git, hg.clonebundles.git)

script::
	rm -rf hg.push.hg hg.pure.git
	$(call HG_INIT, hg.push.hg)
	# || exit 1 forces mingw32-make to wrap the command through a shell, which works
	# around https://github.com/Alexpux/MSYS2-packages/issues/829.
	$(GIT) clone -n hg.git hg.pure.git || exit 1
	# Push everything, including merges
	$(GIT) -c cinnabar.experiments=merge -C hg.pure.git push hg::$(PATH_URL)/hg.push.hg --all

script::
	rm -rf hg.http.hg gitcredentials
	$(call HG_INIT, hg.http.hg)
	(echo protocol=http; echo host=localhost:8000; echo username=foo; echo password=bar) | $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' credential approve
	$(GIT) -C hg.git remote add hg-http hg::http://localhost:8000/
	$(HG) -R hg.http.hg --config extensions.x=CI/hg-serve-exec.py serve-and-exec -- $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' -C hg.git push hg-http refs/remotes/origin/*:refs/heads/*

script::
	rm -rf hg.cinnabarclone.git
	$(GIT) init hg.cinnabarclone.git
	$(GIT) -C hg.cinnabarclone.git fetch ../hg.incr.git refs/heads/*:refs/heads/* refs/remotes/*:refs/remotes/*
	$(GIT) -C hg.cinnabarclone.git fetch ../hg.incr.git refs/cinnabar/metadata:refs/cinnabar/metadata
	$(GIT) -C hg.cinnabarclone.git cinnabar fsck
