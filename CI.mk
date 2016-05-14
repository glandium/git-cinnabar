ifeq (a,$(firstword a$(subst /, ,$(abspath .))))
PATHSEP = :
else
PATHSEP = ;
endif

export PATH := $(CURDIR)$(PATHSEP)$(CURDIR)/venv/bin$(PATHSEP)$(CURDIR)/venv/Scripts$(PATHSEP)$(PATH)
export PYTHONPATH := $(CURDIR)/venv/lib/python2.7/site-packages
export PYTHONDONTWRITEBYTECODE := 1
REPO ?= https://bitbucket.org/cleonello/jqplot

-include CI-data.mk

.PHONY: FORCE
CI-data: FORCE
	@git ls-tree -r HEAD | grep '\(\.[ch]\|\sgit-core\)$$' > $@.tmp
	@[ -f $@ ] && diff $@ $@.tmp > /dev/null && rm -f $@.tmp || mv -f $@.tmp $@

CI-data.mk: CI-data
	@echo $<: $$(awk '$$4 != "git-core" {print $$4}' $<) > $@
	@echo HELPER_HASH := $$(awk '{print $$3}' $< | shasum | awk '{print $$1}') >> $@

ifeq ($(TRAVIS_OS_NAME)_$(VARIANT),osx_asan)
LOCAL_PYTHON_PREFIX = $(HOME)/Library/Python/2.7/bin/
before_install::
	curl -O -s https://bootstrap.pypa.io/get-pip.py
	python get-pip.py --user
	$(LOCAL_PYTHON_PREFIX)pip install --user virtualenv
endif

before_install::
	$(LOCAL_PYTHON_PREFIX)virtualenv venv
	@# Somehow, OSX's make doesn't want to pick pip from venv/bin on its
	@# own...
	$$(which pip) install mercurial$(addprefix ==,$(MERCURIAL_VERSION))

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

HELPER_PATH := $(HELPER_HASH)/$(TRAVIS_OS_NAME)$(addprefix -,$(VARIANT))
HELPER := git-cinnabar-helper
export GIT_CINNABAR_HELPER=$(CURDIR)/$(HELPER)
export GIT_CINNABAR_CHECK=all

ifndef BUILD_HELPER
$(HELPER):
ifdef ARTIFACTS_BUCKET
	-curl -f -O --retry 5 https://s3.amazonaws.com/$(ARTIFACTS_BUCKET)/$(HELPER_PATH)/$@ && chmod +x $@
endif
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) $@ BUILD_HELPER=1

else

ifeq ($(TRAVIS_OS_NAME),osx)
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
	$(MAKE) --jobs=2 $(@F) $(EXTRA_MAKE_FLAGS)
	cp git-core/$(HELPER) $@
	mkdir -p artifacts/$(HELPER_PATH)
	cp $@ artifacts/$(HELPER_PATH)/$(HELPER)

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
	git checkout $(TRAVIS_COMMIT)
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
	git checkout $(TRAVIS_COMMIT)
endif

script::
	hg init hg.hg
	$(GIT) -c fetch.prune=true clone hg::$(CURDIR)/hg.hg hg.empty.git
	$(GIT) -C hg.empty.git push --all hg::$(CURDIR)/hg.hg
	$(GIT) -C hg.old.git push --all hg::$(CURDIR)/hg.hg
	hg -R hg.hg verify
	$(GIT) -c fetch.prune=true clone hg::$(CURDIR)/hg.hg hg.git
	bash -c "diff -u <(git -C hg.old.git log --format=%H --reverse --date-order --branches=refs/remotes/origin/branches) <(git -C hg.git log --format=%H --reverse --date-order --branches=refs/remotes/origin/branches)"
