TOPDIR = $(abspath $(or $(dir $(firstword $(MAKEFILE_LIST))),$(CURDIR))/..)

include $(TOPDIR)/helper/GIT-VERSION.mk

ifeq (a,$(firstword a$(subst /, ,$(abspath .))))
PATHSEP = :
else
PATHSEP = ;
endif

export PATH := $(TOPDIR)$(PATHSEP)$(PATH)
export PYTHONDONTWRITEBYTECODE := 1

ifeq ($(MAKECMDGOALS),package)
PACKAGE_FLAGS = $(addprefix --system ,$(SYSTEM)) $(addprefix --machine ,$(MACHINE))
PACKAGE = $(notdir $(shell $(TOPDIR)/download.py --url $(PACKAGE_FLAGS)))

$(PACKAGE):
	@mkdir -p tmp
	@rm -rf tmp/git-cinnabar
	git archive --format=tar --prefix=git-cinnabar/ HEAD | tar -C tmp -x
	@$(TOPDIR)/download.py --no-config -o tmp/git-cinnabar/$(PACKAGE) $(PACKAGE_FLAGS)
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
	$(foreach c,$(shell $(TOPDIR)/download.py --list),$(MAKE) -f $(firstword $(MAKEFILE_LIST)) package SYSTEM=$(firstword $(subst /, ,$(c))) MACHINE=$(word 2,$(subst /, ,$(c)))$(CR))
