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

%:
	$(MAKE) -C $(CURDIR)/git-core -f $(CURDIR)/src/build.mk $@

install:
	$(error Not a supported target)

include git-core/config.mak.uname

.PHONY: FORCE

git-cinnabar-helper$X: FORCE

helper: git-cinnabar-helper$X
	mv git-core/$^ $^
