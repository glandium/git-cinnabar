CARGO ?= cargo
CARGO_BUILD_FLAGS ?= --release

SYSTEM = $(shell python2.7 -c 'import platform; print platform.system()')
include helper/GIT-VERSION.mk
ifeq ($(SYSTEM),Windows)
GIT_REPO = https://github.com/git-for-windows/git
GIT_VERSION := $(WINDOWS_GIT_VERSION)
else
GIT_REPO = $(shell sed -n 's/.*url = //p' .gitmodules)
endif
SUBMODULE_STATUS := $(shell git submodule status git-core 2> /dev/null || echo no)

define exec
$$(shell echo $1 >&2)
ifeq (fail,$$(shell $1 >&2 || echo fail))
$$(error failed)
endif
endef

ifeq ($(SUBMODULE_STATUS),no)
$(eval $(call exec,git clone -n $(GIT_REPO) git-core))
$(eval $(call exec,git -C git-core checkout $(GIT_VERSION)))
else
ifneq ($(shell git -C git-core rev-parse HEAD),$(shell git -C git-core rev-parse --revs-only $(GIT_VERSION)^{commit}))
$(eval $(call exec,git submodule update --init))
ifeq ($(SYSTEM),Windows)
$(eval $(call exec,git -C git-core remote add git4win $(GIT_REPO)))
$(eval $(call exec,git -C git-core fetch git4win --tags))
$(eval $(call exec,git -C git-core checkout $(GIT_VERSION)))
endif
endif
endif
ifneq ($(shell git -C git-core rev-parse HEAD),$(shell git -C git-core rev-parse --revs-only $(GIT_VERSION)^{commit}))
$(error git-core is not checked out at $(GIT_VERSION))
endif

.PHONY: helper
helper:

.SUFFIXES:

TARGET=$@
git: TARGET=all
git-install: TARGET=install

%:
	$(MAKE) -C $(CURDIR)/git-core -f $(CURDIR)/helper/helper.mk $(TARGET)

install:
	$(error Not a supported target)

include git-core/config.mak.uname

.PHONY: FORCE

git-cinnabar-helper$X git git-install: FORCE

helper: git-cinnabar-helper$X

export CINNABAR_MAKE_FLAGS

git-cinnabar-helper$X: CINNABAR_MAKE_FLAGS := $(filter %,$(foreach v,$(.VARIABLES),$(if $(filter command line,$(origin $(v))),$(v)='$(if $(findstring ',$($(v))),$(error $(v) contains a single quote))$($(v))')))
git-cinnabar-helper$X:
	+cd $(CURDIR)/helper && $(CARGO) build -vv $(addprefix --target=,$(CARGO_TARGET)) $(CARGO_BUILD_FLAGS)
	cp $(CURDIR)/helper/target/$(if $(CARGO_TARGET),$(CARGO_TARGET)/)$(if $(filter --release,$(CARGO_BUILD_FLAGS)),release,debug)/$@ $@
