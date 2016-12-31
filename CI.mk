OS_NAME = $(TRAVIS_OS_NAME)$(MSYSTEM)
include $(addsuffix /,$(dir $(firstword $(MAKEFILE_LIST))))GIT-VERSION.mk

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
export PATH := $(CURDIR)/old-cinnabar$(PATHSEP)$(CURDIR)$(PATHSEP)$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
REPO ?= https://bitbucket.org/cleonello/jqplot

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

ifneq ($(MERCURIAL_VERSION),installed)
before_install::
	$(call PIP_INSTALL,mercurial$(addprefix ==,$(MERCURIAL_VERSION)))$(if $(MERCURIAL_VERSION), || $(call PIP_INSTALL,https://www.mercurial-scm.org/release/mercurial-$(MERCURIAL_VERSION).tar.gz))
endif

# Somehow, OSX's make doesn't want to pick hg from $PATH on its own after it's
# installed above...
HG = $$(which hg)

ifdef PYTHON_CHECKS

before_install::
	$(call PIP_INSTALL,flake8)

before_script::

script::
ifndef NO_BUNDLE2
	nosetests --all-modules
	flake8 --ignore E402 $$(git ls-files \*\*.py git-cinnabar git-remote-hg)
endif

else

ifneq (file,$(origin GIT_VERSION))
# When building and using a separate git version, disable the helper. It's
# being tested in many different setups, and hides the interactions with git.
GIT_CINNABAR_HELPER=

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
export GIT_CINNABAR_HELPER
COMMA=,
export GIT_CINNABAR_CHECK=all$(if $(HELPER),,$(COMMA)-helper)

ifndef BUILD_HELPER
$(GIT_CINNABAR_HELPER):
ifdef GIT_CINNABAR_OLD_HELPER
	rm -rf old-cinnabar
	git fetch --unshallow || true
	git clone -n . old-cinnabar
	git -C old-cinnabar checkout $$(git log --format=%H -S '#define CMD_VERSION $(shell python -c 'from cinnabar.helper import *; print GitHgHelper.VERSION')$$' --pickaxe-regex HEAD | tail -1)
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
before_script:: $(GIT_CINNABAR_HELPER)
	rm -rf old-cinnabar
	git fetch --unshallow || true
	git clone -n . old-cinnabar
	git -C old-cinnabar checkout $(UPGRADE_FROM)
endif

before_script::
	test "$(shell $(CURDIR)/git-cinnabar --version 2>&1)" = "$(shell git describe --tags --abbrev=0 HEAD)"

before_script:: $(GIT_CINNABAR_HELPER)
	rm -rf hg.old.git
	$(GIT) -c fetch.prune=true clone hg::$(REPO) hg.old.git

ifneq (,$(filter 0.1.% 0.2.%,$(UPGRADE_FROM)))
script::
	rm -rf old-cinnabar
	git -C hg.old.git cinnabar fsck && echo "fsck should have failed" && exit 1 || true
	git clone -n . old-cinnabar
	git -C old-cinnabar checkout 0.3.2
endif

script::
	$(GIT) -C hg.old.git cinnabar fsck || [ "$$?" = 2 ]

ifdef UPGRADE_FROM
script::
	rm -rf old-cinnabar
endif

PATH_URL = file://$(if $(filter /%,$(CURDIR)),,/)$(CURDIR)

COMPARE_COMMANDS = bash -c "diff -u <($1) <($2)"

GET_REF_SHA1 = git -C $1 log --format=%H --reverse --date-order --remotes=origin --no-walk$(if $2, | $2) | awk '{print} END { if (NR == 0) { print \"$1\", NR } }'

COMPARE_REFS = $(call COMPARE_COMMANDS,$(call GET_REF_SHA1,$1,$3),$(call GET_REF_SHA1,$2,$3))

HG_INIT = $(HG) init $1
ifdef NO_BUNDLE2
HG_INIT += ; (echo "[experimental]"; echo "bundle2-advertise = false") >> $1/.hg/hgrc
endif

ifndef GRAFT

script::
	rm -rf hg.hg hg.empty.git hg.git hg.bundle hg.unbundle.git
	$(call HG_INIT, hg.hg)
	$(GIT) -c fetch.prune=true clone hg::$(PATH_URL)/hg.hg hg.empty.git
	$(GIT) -C hg.empty.git push --all hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push hg::$(PATH_URL)/hg.hg refs/remotes/origin/*:refs/heads/*
	$(HG) -R hg.hg verify
	$(GIT) -c fetch.prune=true clone hg::$(PATH_URL)/hg.hg hg.git
	$(call COMPARE_REFS, hg.old.git, hg.git)

	$(GIT) -C hg.git cinnabar bundle $(CURDIR)/hg.bundle -- --remotes
	$(GIT) -c fetch.prune=true clone hg::$(CURDIR)/hg.bundle hg.unbundle.git
	$(call COMPARE_REFS, hg.git, hg.unbundle.git)

script::
	rm -rf hg.push.hg hg.pure.git
	$(call HG_INIT, hg.push.hg)
	$(GIT) clone hg.git hg.pure.git
	# Push both parents of a merge
	$(GIT) -C hg.pure.git push hg::$(PATH_URL)/hg.push.hg 0ca827ab1a83da08c604bf3dc016894dea6d8460^:refs/tips/default
	$(GIT) -C hg.pure.git push hg::$(PATH_URL)/hg.push.hg 0ca827ab1a83da08c604bf3dc016894dea6d8460^2:refs/tips/default
	# Push merge
	$(GIT) -c cinnabar.experiments=merge -C hg.pure.git push hg::$(PATH_URL)/hg.push.hg 0ca827ab1a83da08c604bf3dc016894dea6d8460:refs/tips/default

script::
	rm -rf hg.http.hg gitcredentials
	$(call HG_INIT, hg.http.hg)
	(echo protocol=http; echo host=localhost:8000; echo username=foo; echo password=bar) | $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' credential approve
	$(GIT) -C hg.git remote add hg-http hg::http://localhost:8000/
	$(HG) -R hg.http.hg --config extensions.x=CI-hg-serve-exec.py serve-and-exec -- $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' -C hg.git push hg-http refs/remotes/origin/*:refs/heads/*
else # GRAFT

GET_ROOTS = $(GIT) -C $1 rev-list $2 --max-parents=0

ifndef NO_BUNDLE2

script::
	rm -rf hg.graft.git hg.graft2.git
	$(GIT) init hg.graft.git
	$(GIT) -C hg.graft.git remote add origin hg::$(REPO)
	$(GIT) -C hg.old.git push --mirror $(CURDIR)/hg.graft.git
	$(GIT) -C hg.graft.git checkout HEAD

	$(GIT) init hg.graft2.git
	$(GIT) -C hg.graft2.git remote add origin hg::$(REPO)
	$(GIT) -C hg.old.git push --mirror $(CURDIR)/hg.graft2.git
	$(GIT) -C hg.graft2.git checkout HEAD

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git filter-branch --msg-filter 'cat ; echo' --original original -- --all
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, hg.old.git, hg.graft.git, xargs $(GIT) cinnabar git2hg)

	$(GIT) -C hg.graft.git push $(CURDIR)/hg.graft2.git refs/remotes/origin/*:refs/remotes/new/*
	$(GIT) -C hg.graft2.git remote set-url origin hg::$(REPO)
	$(GIT) -C hg.graft2.git -c cinnabar.graft=true cinnabar reclone
	$(call COMPARE_REFS, hg.graft.git, hg.graft2.git)

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git filter-branch --index-filter 'test $$GIT_COMMIT = '$$($(call GET_ROOTS,hg.graft.git,--remotes))' && git rm -r --cached -- \* || true' --original original -- --all
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, hg.old.git, hg.graft.git, xargs $(GIT) cinnabar git2hg)
	$(call COMPARE_COMMANDS,$(call GET_ROOTS,hg.old.git,--remotes),$(call GET_ROOTS,hg.graft.git,--glob=refs/cinnabar/replace))

script::
	rm -f hg.graft.new.bundle
	$(GIT) -C hg.graft2.git checkout refs/remotes/new/HEAD
	$(GIT) -C hg.graft2.git -c user.email git@cinnabar -c user.name cinnabar commit --allow-empty -m 'New commit'
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
	@$(CURDIR)/git-cinnabar download --dev -o tmp/git-cinnabar/$(call PACKAGE,--dev) $(PACKAGE_FLAGS)
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
