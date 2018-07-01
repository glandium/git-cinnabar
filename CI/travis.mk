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
