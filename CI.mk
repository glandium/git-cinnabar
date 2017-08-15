OS_NAME = $(TRAVIS_OS_NAME)$(MSYSTEM)
include $(addsuffix /,$(dir $(firstword $(MAKEFILE_LIST))))helper/GIT-VERSION.mk

ifeq (a,$(firstword a$(subst /, ,$(abspath .))))
PATHSEP = :
else
PATHSEP = ;
endif

ifeq ($(OS_NAME),osx)
export PATH := $(HOME)/Library/Python/2.7/bin$(PATHSEP)$(PATH)
export PYTHONPATH := $(HOME)/Library/Python/2.7/lib/python/site-packages
else
export PATH := $(HOME)/.local/bin$(PATHSEP)$(PATH)
export PYTHONPATH := $(HOME)/.local/lib/python2.7/site-packages
endif
export PATH := $(CURDIR)$(PATHSEP)$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
REPO ?= https://hg.mozilla.org/users/mh_glandium.org/jqplot

-include CI-data.mk

DOWNLOAD_FLAGS = --dev $(VARIANT) $(addprefix --machine ,$(MACHINE))

HELPER_PATH = $(subst https://s3.amazonaws.com/git-cinnabar/,,$(shell $(CURDIR)/git-cinnabar download --url $(DOWNLOAD_FLAGS)))

helper_hash:
	@echo $(word 2,$(subst /, ,$(HELPER_PATH))) > $@

.PHONY: helper_hash

# On Travis-CI, an old pip is installed with easy_install, which means its
# egg ends up before our $PYTHONPATH in sys.path, such that upgrading pip with
# --user and using $PYTHONPATH for subsequent pip calls doesn't work.
PIP = $(if $(PYTHON_CHECKS),pip,python -c 'import os, sys; sys.path[:0] = os.environ.get("PYTHONPATH", "").split(os.pathsep); from pip import main; sys.exit(main())')
PIP_INSTALL = $(PIP) install $(if $(or $(PYTHON_CHECKS),$(filter MINGW%,$(OS_NAME))),,--user )--upgrade --force-reinstall $1

before_install::
ifeq ($(OS_NAME),osx)
	curl -O -s https://bootstrap.pypa.io/get-pip.py
	python get-pip.py --user
else
	$(call PIP_INSTALL,pip)
endif

MERCURIAL_VERSION ?= 4.2.2

ifneq ($(MERCURIAL_VERSION),installed)
before_install::
	$(call PIP_INSTALL,mercurial$(addprefix ==,$(MERCURIAL_VERSION)))$(if $(MERCURIAL_VERSION), || $(call PIP_INSTALL,https://www.mercurial-scm.org/release/mercurial-$(MERCURIAL_VERSION).tar.gz))
endif

# Somehow, OSX's make doesn't want to pick hg from $PATH on its own after it's
# installed above...
HG = $$(which hg)

ifeq ($(VARIANT),coverage)
export PATH := $(CURDIR)/coverage$(PATHSEP)$(PATH)
export COVERAGE_FILE := $(CURDIR)/.coverage
BUILD_HELPER = 1

before_install::
	$(call PIP_INSTALL,codecov)

endif

ifdef PYTHON_CHECKS

before_install::
	$(call PIP_INSTALL,flake8)

before_script::

script::
ifndef NO_BUNDLE2
	nosetests --all-modules $(if $(filter coverage,$(VARIANT)),--with-coverage --cover-tests )tests
	flake8 --ignore E402 $$(git ls-files \*\*.py git-cinnabar git-remote-hg)
endif

else

ifneq (file,$(origin GIT_VERSION))
# TODO: cache as artifacts.
GIT=$(CURDIR)/git.git/bin-wrappers/git

before_script::
	rm -rf git.git
	git submodule update --init
	git clone -n git-core git.git
	git -C git.git checkout $(GIT_VERSION)
	$(MAKE) -C git.git --jobs=2 NO_GETTEXT=1 NO_CURL=1 NO_OPENSSL=1

else
GIT=git
endif

before_script::
	$(GIT) --version

ifndef GIT_CINNABAR_OLD_HELPER
GIT += -c core.packedGitWindowSize=8k
endif

ifeq (undefined,$(origin GIT_CINNABAR_HELPER))
ifneq (,$(filter MINGW%,$(OS_NAME)))
HELPER := git-cinnabar-helper.exe
else
HELPER := git-cinnabar-helper
endif
GIT_CINNABAR_HELPER=$(CURDIR)/$(HELPER)
endif
COMMA=,
export GIT_CINNABAR_CHECK=all$(if $(HELPER),,$(COMMA)-helper)
export GIT_CINNABAR_LOG=process:3

define PREPARE_OLD_CINNABAR
rm -rf old-cinnabar
git fetch --unshallow || true
git fetch --all --tags || true
git init old-cinnabar
git push $(CURDIR)/old-cinnabar $1:refs/heads/old
git -C old-cinnabar checkout old
endef

ifndef BUILD_HELPER
$(GIT_CINNABAR_HELPER):
ifdef GIT_CINNABAR_OLD_HELPER
	$(call PREPARE_OLD_CINNABAR,"$$(git log --format=%H -S '#define CMD_VERSION $(shell python -c 'from cinnabar.helper import *; print GitHgHelper.VERSION')00$$' --pickaxe-regex HEAD | tail -1)")
	$(MAKE) -C old-cinnabar -f CI.mk $(HELPER) GIT_CINNABAR_HELPER=$(HELPER) GIT_CINNABAR_OLD_HELPER=
	mv old-cinnabar/$(HELPER) $@
	rm -rf old-cinnabar
else
ifdef ARTIFACTS_BUCKET
	$(call PIP_INSTALL,requests)
	-$(GIT) cinnabar download -o $@ --no-config $(DOWNLOAD_FLAGS)
endif
	MACOSX_DEPLOYMENT_TARGET=10.6 $(MAKE) -f $(firstword $(MAKEFILE_LIST)) $@ BUILD_HELPER=1
endif

else

ifeq ($(VARIANT),asan)
EXTRA_MAKE_FLAGS += CFLAGS="-O2 -g -fsanitize=address"
endif

ifeq ($(VARIANT),coverage)
# Would normally use -coverage, but ccache on Travis-CI doesn't support it
EXTRA_MAKE_FLAGS += CFLAGS="-fprofile-arcs -ftest-coverage"
endif

ifneq ($(origin CC),default)
EXTRA_MAKE_FLAGS += CC=$(CC)
endif

$(GIT_CINNABAR_HELPER):
	$(MAKE) --jobs=2 $(@F) $(EXTRA_MAKE_FLAGS)
	cp git-core/$(@F) $@
	mkdir -p $(dir $(HELPER_PATH))
	cp $@ $(HELPER_PATH)

endif

ifdef UPGRADE_FROM
export PATH := $(CURDIR)/old-cinnabar$(PATHSEP)$(PATH)

before_script:: $(GIT_CINNABAR_HELPER)
	$(call PREPARE_OLD_CINNABAR,$(UPGRADE_FROM))
ifeq (,$(filter 0.3.%,$(UPGRADE_FROM)))
	old-cinnabar/git-cinnabar download --no-config $(addprefix --machine ,$(MACHINE))
endif
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

ifdef UPGRADE_FROM
script::
	rm -rf old-cinnabar
	$(GIT) -C hg.old.git remote update && echo "Should have been asked to upgrade" && exit 1 || true
endif

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

ifndef GRAFT

script::
	rm -rf hg.hg hg.empty.git hg.git hg.bundle hg.unbundle.git
	$(call HG_INIT, hg.hg)
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/hg.hg hg.empty.git
	$(GIT) -C hg.empty.git push --all hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push hg::$(PATH_URL)/hg.hg refs/remotes/origin/*:refs/heads/*
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
	$(HG) -R hg.clonebundles.hg --config extensions.clonebundles= --config extensions.x=CI-hg-serve-exec.py serve-and-exec -- $(GIT) clone -n hg://localhost:8000.http/ hg.clonebundles.git
	$(call COMPARE_REFS, hg.git, hg.clonebundles.git)

script::
	rm -rf hg.clonebundles-full.hg hg.clonebundles-full.git
	$(HG) clone -U hg.hg hg.clonebundles-full.hg
	$(HG) -R hg.clonebundles-full.hg bundle -a repo.bundle
	echo $(PATH_URL)/repo.bundle > hg.clonebundles-full.hg/.hg/clonebundles.manifest
	$(HG) -R hg.clonebundles-full.hg --config extensions.clonebundles= --config extensions.x=CI-hg-serve-exec.py serve-and-exec -- $(GIT) clone -n hg://localhost:8000.http/ hg.clonebundles-full.git
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
	$(HG) -R hg.http.hg --config extensions.x=CI-hg-serve-exec.py serve-and-exec -- $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' -C hg.git push hg-http refs/remotes/origin/*:refs/heads/*
else # GRAFT

GET_ROOTS = $(GIT) -C $1 rev-list $2 --max-parents=0
XARGS_GIT2HG = xargs $(GIT) -C $1 cinnabar git2hg

ifndef NO_BUNDLE2

script::
	rm -rf hg.hg
	$(HG) clone -U $(REPO) hg.hg

script::
	rm -rf hg.graft.git hg.graft2.git
	$(GIT) init hg.graft.git
	$(GIT) -C hg.graft.git remote add origin hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push $(CURDIR)/hg.graft.git refs/remotes/*:refs/remotes/*
	$(GIT) -C hg.graft.git checkout $$($(GIT) -C hg.old.git rev-parse HEAD)

	$(GIT) init hg.graft2.git
	$(GIT) -C hg.graft2.git remote add origin hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push $(CURDIR)/hg.graft2.git refs/remotes/*:refs/remotes/*
	$(GIT) -C hg.graft2.git checkout $$($(GIT) -C hg.old.git rev-parse HEAD)

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git filter-branch --msg-filter 'cat ; echo' --original original -- --all
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, hg.old.git, hg.graft.git, XARGS_GIT2HG)
	$(GIT) -C hg.graft.git cinnabar fsck

	$(GIT) -C hg.graft.git push $(CURDIR)/hg.graft2.git refs/remotes/origin/*:refs/remotes/new/*
	$(GIT) -C hg.graft2.git remote set-url origin hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.graft2.git -c cinnabar.graft=true cinnabar reclone
	$(call COMPARE_REFS, hg.graft.git, hg.graft2.git)
	$(GIT) -C hg.graft2.git cinnabar fsck

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git filter-branch --index-filter 'test $$GIT_COMMIT = '$$($(call GET_ROOTS,hg.graft.git,--remotes))' && git rm -r --cached -- \* || true' --original original -- --all
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, hg.old.git, hg.graft.git, XARGS_GIT2HG)
	$(call COMPARE_COMMANDS,$(call GET_ROOTS,hg.old.git,--remotes),$(call GET_ROOTS,hg.graft.git,--glob=refs/cinnabar/replace))
	$(GIT) -C hg.graft.git cinnabar fsck

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git for-each-ref --format='%(refname)' | grep -v refs/remotes/origin/HEAD | sed 's/^/delete /' | $(GIT) -C hg.graft.git update-ref --stdin
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update

script::
	rm -f hg.graft.new.bundle
	$(GIT) -C hg.graft2.git checkout refs/remotes/new/HEAD
	$(GIT) -C hg.graft2.git -c user.email=git@cinnabar -c user.name=cinnabar commit --allow-empty -m 'New commit'
	$(GIT) -C hg.graft2.git -c cinnabar.graft=true cinnabar bundle $(CURDIR)/hg.graft.new.bundle HEAD^!
	$(GIT) -C hg.graft2.git -c cinnabar.graft=true fetch hg::$(PATH_URL)/hg.graft.new.bundle
	test "$$($(GIT) -C hg.graft2.git cinnabar data -c $$($(GIT) -C hg.graft2.git cinnabar git2hg FETCH_HEAD) | tail -c 1)" = t

endif

endif # GRAFT

endif # PYTHON_CHECKS

ifeq ($(MAKECMDGOALS),package)
PACKAGE_FLAGS = $(addprefix --system ,$(SYSTEM)) $(addprefix --machine ,$(MACHINE))
PACKAGE = $(notdir $(shell $(CURDIR)/git-cinnabar download --url $1 $(PACKAGE_FLAGS)))

$(PACKAGE):
	@mkdir -p tmp
	@rm -rf tmp/git-cinnabar
	git archive --format=tar --prefix=git-cinnabar/ HEAD | tar -C tmp -x
	@$(CURDIR)/git-cinnabar download --no-config --dev -o tmp/git-cinnabar/$(call PACKAGE,--dev) $(PACKAGE_FLAGS)
ifneq (,$(filter %.tar.xz,$(PACKAGE)))
	tar --owner cinnabar:1000 --group cinnabar:1000 -C tmp --remove-files --sort=name -Jcvf $@ git-cinnabar
else
	@rm -f $@
	cd tmp && find git-cinnabar | sort | zip --move $(CURDIR)/$@ -@
endif
	rm -rf tmp

.PHONY: $(PACKAGE)

package: $(PACKAGE)
endif

define CR


endef

packages:
	$(foreach c,$(shell $(CURDIR)/git-cinnabar download --list),$(MAKE) -f $(firstword $(MAKEFILE_LIST)) package SYSTEM=$(firstword $(subst /, ,$(c))) MACHINE=$(word 2,$(subst /, ,$(c)))$(CR))
