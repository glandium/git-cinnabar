SUBMODULE_STATUS := $(shell git submodule status git-core 2> /dev/null || echo no)

define exec
$$(shell echo $1 >&2)
ifeq (fail,$$(shell $1 >&2 || echo fail))
$$(error failed)
endif
endef

ifeq ($(SUBMODULE_STATUS),no)
GIT_REPO = $(shell sed -n 's/.*url = //p' .gitmodules)
$(eval $(call exec,git clone -n $(GIT_REPO) git-core))
$(eval $(call exec,git -C git-core checkout $(GIT_VERSION)))
else
$(eval $(call exec,git submodule sync))
$(eval $(call exec,git submodule update --init))
endif

.PHONY: helper
helper:

.SUFFIXES:

%:
	$(MAKE) -C $(CURDIR)/git-core -f $(CURDIR)/src/helper.mk $@

install:
	$(error Not a supported target)

include git-core/config.mak.uname

.PHONY: FORCE

git-cinnabar-helper$X: FORCE

helper: git-cinnabar-helper$X
	mv git-core/$^ $^
