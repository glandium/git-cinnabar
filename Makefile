define exec
$$(shell echo $1 >&2)
ifeq (fail,$$(shell $1 >&2 || echo fail))
$$(error failed)
endif
endef

$(eval $(call exec,git submodule sync))
$(eval $(call exec,git submodule update --init))

.PHONY: helper
helper:

.SUFFIXES:

install:
	$(error Not a supported target)

include git-core/config.mak.uname

helper: git-cinnabar-helper$X

CARGO ?= cargo
CARGO_BUILD_FLAGS ?= --release
CARGO_FEATURES ?=

export CINNABAR_MAKE_FLAGS

git-cinnabar-helper$X: CINNABAR_MAKE_FLAGS := $(filter %,$(foreach v,$(.VARIABLES),$(if $(filter command line,$(origin $(v))),$(v)='$(if $(findstring ',$($(v))),$(error $(v) contains a single quote))$($(v))')))
git-cinnabar-helper$X: FORCE
	$(CARGO) build -vv $(addprefix --target=,$(CARGO_TARGET))$(if $(CARGO_FEATURES), --features "$(CARGO_FEATURES)") $(CARGO_BUILD_FLAGS)
	cp target/$(if $(CARGO_TARGET),$(CARGO_TARGET)/)$(if $(filter --release,$(CARGO_BUILD_FLAGS)),release,debug)/$@ $@

.PHONY: FORCE
