OS_NAME = $(TRAVIS_OS_NAME)$(MSYSTEM)
COMMIT = $(TRAVIS_COMMIT)$(APPVEYOR_REPO_COMMIT)
WINDOWS_GIT_VERSION = v2.8.2.windows.1

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
REPO ?= https://bitbucket.org/cleonello/jqplot

-include CI-data.mk

HELPER_HASH := $(shell git ls-tree -r HEAD | grep '\(\.[ch]\|\sgit-core\)$$' | awk '{print $$3}' | shasum | awk '{print $$1}')
HELPER_PATH := artifacts/$(HELPER_HASH)/$(OS_NAME)$(addprefix -,$(VARIANT))

helper_path:
	@echo $(HELPER_PATH)

ifeq ($(OS_NAME)_$(VARIANT),osx_asan)
before_install::
	curl -O -s https://bootstrap.pypa.io/get-pip.py
	python get-pip.py --user
endif

before_install::
	@# Somehow, OSX's make doesn't want to pick pip from $PATH on its own
	@# after it's installed above...
	$$(which pip) install --user --upgrade --force-reinstall mercurial$(addprefix ==,$(MERCURIAL_VERSION))

# Same happens for the hg binary...
HG = $$(which hg)

ifdef GIT_VERSION
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

ifneq (,$(filter MINGW%,$(OS_NAME)))
HELPER := git-cinnabar-helper.exe
else
HELPER := git-cinnabar-helper
endif
export GIT_CINNABAR_HELPER=$(CURDIR)/$(HELPER)
export GIT_CINNABAR_CHECK=all

ifndef BUILD_HELPER
$(HELPER):
ifdef ARTIFACTS_BUCKET
	-curl -f -O --retry 5 https://s3.amazonaws.com/$(ARTIFACTS_BUCKET)/$(HELPER_PATH)/$@ && chmod +x $@
endif
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) $@ BUILD_HELPER=1

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

$(HELPER):
	git submodule update --init
ifneq (,$(filter MINGW%,$(OS_NAME)))
	git -C git-core remote add git4win https://github.com/git-for-windows/git
	git -C git-core remote update git4win
	git -C git-core merge-base --is-ancestor HEAD $(WINDOWS_GIT_VERSION)
	git -C git-core checkout $(WINDOWS_GIT_VERSION)
endif
	$(MAKE) --jobs=2 $(@F) $(EXTRA_MAKE_FLAGS)
	cp git-core/$(HELPER) $@
	mkdir -p $(HELPER_PATH)
	cp $@ $(HELPER_PATH)/$(HELPER)

endif

ifdef UPGRADE_FROM
before_script:: $(HELPER)
	git fetch --unshallow
	git checkout $(UPGRADE_FROM)
endif

before_script:: $(HELPER)
	$(GIT) -c fetch.prune=true clone hg::$(REPO) hg.old.git

ifdef UPGRADE_FROM
before_script:: $(HELPER)
	git checkout $(COMMIT)
endif

ifneq (,$(filter 0.1.% 0.2.%,$(UPGRADE_FROM)))
script::
	git -C hg.old.git cinnabar fsck && echo "fsck should have failed" && exit 1 || true
	git checkout 0.3.2
endif

script::
	$(GIT) -C hg.old.git cinnabar fsck || ["$$?" = 2 ]

ifneq (,$(filter 0.1.% 0.2.%,$(UPGRADE_FROM)))
script::
	git checkout $(COMMIT)
endif

PATH_URL = file://$(if $(filter /%,$(CURDIR)),,/)$(CURDIR)

script::
	$(HG) init hg.hg
	$(GIT) -c fetch.prune=true clone hg::$(PATH_URL)/hg.hg hg.empty.git
	$(GIT) -C hg.empty.git push --all hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push --all hg::$(PATH_URL)/hg.hg
	$(HG) -R hg.hg verify
	$(GIT) -c fetch.prune=true clone hg::$(PATH_URL)/hg.hg hg.git
	bash -c "diff -u <(git -C hg.old.git log --format=%H --reverse --date-order --branches=refs/remotes/origin/branches) <(git -C hg.git log --format=%H --reverse --date-order --branches=refs/remotes/origin/branches)"