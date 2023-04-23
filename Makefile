# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

.PHONY: all
all:

.SUFFIXES:

install:
	$(error Not a supported target)

-include git-core/config.mak.uname

git-core/config.mak.uname:
	git submodule sync
	git submodule update --init

all: git-cinnabar$X git-remote-hg$X

CARGO ?= cargo
CARGO_BUILD_FLAGS ?= --release
CARGO_FEATURES ?=

PROFILE = $(if $(filter --release,$(CARGO_BUILD_FLAGS)),release,debug)
ifneq (,$(filter --target%,$(CARGO_BUILD_FLAGS)))
$(error Please use CARGO_TARGET to set the target)
endif

export CINNABAR_MAKE_FLAGS

GIT_CINNABAR = target$(addprefix /,$(CARGO_TARGET))/$(PROFILE)/git-cinnabar$X

git-cinnabar$X git-remote-hg$X: $(GIT_CINNABAR) FORCE
	ln -sf $< $@

$(GIT_CINNABAR): CINNABAR_MAKE_FLAGS := $(filter %,$(foreach v,$(.VARIABLES),$(if $(filter command line,$(origin $(v))),$(v)='$(if $(findstring ',$($(v))),$(error $(v) contains a single quote))$($(v))')))
$(GIT_CINNABAR): FORCE
	$(CARGO) build -vv $(addprefix --target=,$(CARGO_TARGET))$(if $(CARGO_FEATURES), --features "$(CARGO_FEATURES)") $(CARGO_BUILD_FLAGS)

.PHONY: FORCE
