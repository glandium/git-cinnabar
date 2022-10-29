TOPDIR = $(abspath $(or $(dir $(firstword $(MAKEFILE_LIST))),$(CURDIR))/..)

ifeq (a,$(firstword a$(subst /, ,$(abspath .))))
PATHSEP = :
else
PATHSEP = ;
endif

export PATH := $(TOPDIR)$(PATHSEP)$(PATH)
export PYTHONDONTWRITEBYTECODE := 1

ifeq ($(MAKECMDGOALS),package)
LOWER = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

system := $(call LOWER,$(SYSTEM))
machine := $(call LOWER,$(MACHINE))
PACKAGE_FLAGS = $(addprefix --system ,$(SYSTEM)) $(addprefix --machine ,$(MACHINE))
PACKAGE_EXT = $(if $(filter windows,$(system)),zip,tar.xz)
PACKAGE = git-cinnabar.$(system).$(machine).$(PACKAGE_EXT)
EXT = $(if $(filter windows,$(system)),.exe)

export XZ_OPT=-9
export GZIP=-9

$(PACKAGE):
	@mkdir -p tmp
	@rm -rf tmp/git-cinnabar
	@mkdir -p tmp/git-cinnabar
	@$(TOPDIR)/download.py -o tmp/git-cinnabar/git-cinnabar$(EXT) $(PACKAGE_FLAGS)
ifeq (,$(filter zip,$(PACKAGE_EXT)))
	tar --owner cinnabar:1000 --group cinnabar:1000 -C tmp --remove-files --sort=name -acvf $@ git-cinnabar
else
	@rm -f $@
	cd tmp && find git-cinnabar | sort | zip -9 $(if $(filter windows,$(system)),,--symlinks )--move $(CURDIR)/$@ -@
endif
	rm -rf tmp

.PHONY: $(PACKAGE)

package: $(PACKAGE)
endif

define CR


endef

packages:
	$(foreach c,$(shell $(TOPDIR)/download.py --list),$(MAKE) -f $(firstword $(MAKEFILE_LIST)) package SYSTEM=$(firstword $(subst /, ,$(c))) MACHINE=$(word 2,$(subst /, ,$(c)))$(CR))
