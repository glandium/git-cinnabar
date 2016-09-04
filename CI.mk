OS_NAME = $(TRAVIS_OS_NAME)$(MSYSTEM)
WINDOWS_GIT_VERSION = v2.10.0.windows.1

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

HELPER_HASH := $(shell git ls-tree -r HEAD | grep '\(\.[ch]\|\sgit-core\)$$' | awk '{print $$3}' | shasum | awk '{print $$1}')
HELPER_PATH := artifacts/$(HELPER_HASH)/$(OS_NAME)$(addprefix -,$(VARIANT))

helper_hash:
	@echo $(HELPER_HASH) > $@

# On Travis-CI, an old pip is installed with easy_install, which means its
# egg ends up before our $PYTHONPATH in sys.path, such that upgrading pip with
# --user and using $PYTHONPATH for subsequent pip calls doesn't work.
PIP = $(if $(PYTHON_CHECKS),pip,python -c 'import os, sys; sys.path[:0] = os.environ.get("PYTHONPATH", "").split(os.pathsep); from pip import main; sys.exit(main())')
PIP_INSTALL = $(PIP) install $(if $(or $(PYTHON_CHECKS),$(filter MINGW%,$(OS_NAME))),,--user )--upgrade --force-reinstall $1

before_install::
ifeq ($(OS_NAME)_$(VARIANT),osx_asan)
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

ifdef GIT_VERSION
# When building and using a separate git version, disable the helper. It's
# being tested in many different setups, and hides the interactions with git.
GIT_CINNABAR_HELPER=

# TODO: cache as artifacts.
GIT=$(CURDIR)/git.git/bin-wrappers/git

before_script::
	git submodule update --init
	git clone -n git-core git.git
	git -C git.git checkout v$(GIT_VERSION)
	$(MAKE) -C git.git --jobs=2 NO_GETTEXT=1 NO_CURL=1 NO_OPENSSL=1

else
GIT=git
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

TOPLEVEL := .

ifndef BUILD_HELPER
$(GIT_CINNABAR_HELPER):
ifdef ARTIFACTS_BUCKET
	-curl -f -o $@ --retry 5 https://s3.amazonaws.com/$(ARTIFACTS_BUCKET)/$(HELPER_PATH)/$(@F) && chmod +x $@
endif
	MACOSX_DEPLOYMENT_TARGET=10.6 $(MAKE) -f $(firstword $(MAKEFILE_LIST)) $@ BUILD_HELPER=1

else

ifeq ($(OS_NAME),osx)
EXTRA_MAKE_FLAGS += NO_GETTEXT=1
endif

ifeq ($(VARIANT),asan)
EXTRA_MAKE_FLAGS += CFLAGS="-O2 -g -fsanitize=address"
endif

ifneq ($(origin CC),default)
EXTRA_MAKE_FLAGS += CC=$(CC)
endif

$(GIT_CINNABAR_HELPER):
	git submodule update --init
ifneq (,$(filter MINGW%,$(OS_NAME)))
	git -C git-core remote add git4win https://github.com/git-for-windows/git
	git -C git-core remote update git4win
	git -C git-core merge-base --is-ancestor HEAD $(WINDOWS_GIT_VERSION)
	git -C git-core checkout $(WINDOWS_GIT_VERSION)
endif
	$(MAKE) --jobs=2 $(@F) $(EXTRA_MAKE_FLAGS)
	cp git-core/$(@F) $@
	mkdir -p $(TOPLEVEL)/$(HELPER_PATH)
	cp $@ $(TOPLEVEL)/$(HELPER_PATH)/$(@F)

endif

ifdef UPGRADE_FROM
before_script:: $(GIT_CINNABAR_HELPER)
	git fetch --unshallow || true
	git clone -n . old-cinnabar
	git -C old-cinnabar checkout $(UPGRADE_FROM)
endif

before_script:: $(GIT_CINNABAR_HELPER)
	$(GIT) -c fetch.prune=true clone hg::$(REPO) hg.old.git

ifneq (,$(filter 0.1.% 0.2.%,$(UPGRADE_FROM)))
script::
	rm -rf old-cinnabar
	git -C hg.old.git cinnabar fsck && echo "fsck should have failed" && exit 1 || true
	git clone -n . old-cinnabar
	git -C old-cinnabar checkout 0.3.2
ifdef HELPER
	$(MAKE) -C old-cinnabar -f $(CURDIR)/CI.mk $(HELPER) TOPLEVEL=.. GIT_CINNABAR_HELPER=$(HELPER)
endif
endif

script::
	$(GIT) -C hg.old.git cinnabar fsck || [ "$$?" = 2 ]

ifdef UPGRADE_FROM
script::
	rm -rf old-cinnabar
endif

PATH_URL = file://$(if $(filter /%,$(CURDIR)),,/)$(CURDIR)

COMPARE_REFS = bash -c "diff -u <(git -C $1 log --format=%H --reverse --date-order --branches=refs/remotes/origin/branches) <(git -C $2 log --format=%H --reverse --date-order --branches=refs/remotes/origin/branches)"

HG_INIT = $(HG) init $1
ifdef NO_BUNDLE2
HG_INIT += ; (echo "[experimental]"; echo "bundle2-advertise = false") >> $1/.hg/hgrc
endif

script::
	rm -rf hg.hg hg.empty.git hg.git hg.bundle hg.unbundle.git
	$(call HG_INIT, hg.hg)
	$(GIT) -c fetch.prune=true clone hg::$(PATH_URL)/hg.hg hg.empty.git
	$(GIT) -C hg.empty.git push --all hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push --all hg::$(PATH_URL)/hg.hg
	$(HG) -R hg.hg verify
	$(GIT) -c fetch.prune=true clone hg::$(PATH_URL)/hg.hg hg.git
	$(call COMPARE_REFS, hg.old.git, hg.git)

	$(GIT) -C hg.git cinnabar bundle $(CURDIR)/hg.bundle -- --remotes
	$(GIT) -c fetch.prune=true clone hg::$(CURDIR)/hg.bundle hg.unbundle.git
	$(call COMPARE_REFS, hg.git, hg.unbundle.git)

script::
	rm -rf hg.http.hg gitcredentials
	$(call HG_INIT, hg.http.hg)
	(echo protocol=http; echo host=localhost:8000; echo username=foo; echo password=bar) | $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' credential approve
	$(GIT) -C hg.git remote add hg-http hg::http://localhost:8000/
	$(HG) -R hg.http.hg --config extensions.x=CI-hg-serve-exec.py serve-and-exec -- $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' -C hg.git push --all hg-http

endif # PYTHON_CHECKS
