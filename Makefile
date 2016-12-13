PYTHON_SCRIPTS := \
	git-remote-hg.py \
	git-cinnabar.py \

PYTHON_LIBS := \
	cinnabar/__init__.py \
	cinnabar/githg.py \
	cinnabar/bdiff.py \
	cinnabar/dag.py \
	cinnabar/helper.py \
	cinnabar/remote_helper.py \
	cinnabar/git.py \
	cinnabar/hg/__init__.py \
	cinnabar/hg/bundle.py \
	cinnabar/hg/changegroup.py \
	cinnabar/util.py

NO_GETTEXT ?= 1
NO_OPENSSL ?= 1

ifndef CINNABAR_RECURSE

ifeq (,$(wildcard $(CURDIR)/git-core/Makefile))
SYSTEM = $(shell python2.7 -c 'import platform; print platform.system()')
include GIT-VERSION.mk
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
$(eval $(call exec,git submodule update --init))
ifeq ($(SYSTEM),Windows)
$(eval $(call exec,git -C git-core remote add git4win $(GIT_REPO)))
$(eval $(call exec,git -C git-core remote update git4win))
$(eval $(call exec,git -C git-core checkout $(GIT_VERSION)))
endif
endif
ifneq ($(shell git -C git-core rev-parse HEAD),$(shell git -C git-core rev-parse $(GIT_VERSION)^{commit}))
$(error git-core is not checked out at $(GIT_VERSION))
endif
endif

all:

.SUFFIXES:

%:
	$(MAKE) -C $(CURDIR)/git-core -f $(CURDIR)/Makefile $@ SCRIPT_PYTHON="git-p4.py $(PYTHON_SCRIPTS)" CINNABAR_RECURSE=1

include git-core/config.mak.uname

.PHONY: FORCE

git-cinnabar-helper$X: FORCE

helper: git-cinnabar-helper$X
	mv git-core/$^ $^

else

include $(CURDIR)/Makefile

vpath cinnabar/% ..
vpath %.c ..

all:: $(addprefix pythonlib/,$(PYTHON_LIBS))

$(addprefix pythonlib/,$(PYTHON_LIBS)): pythonlib/%: %
	$(INSTALL) -d ${@D}
	$(INSTALL) -m 644 $^ $@

install: install-pythonlib
clean: clean-pythonlib clean-pythonscripts clean-patched

clean-pythonscripts:
	$(RM) $(PYTHON_SCRIPTS)

PYTHON_LIBS_DIRS := $(sort $(dir $(PYTHON_LIBS)))

$(PYTHON_SCRIPTS): %.py:
	ln -s ../$* $@

define _
$1

endef

.PHONY: install-pythonlib clean-pythonlib
install-pythonlib:
	$(foreach dir,$(PYTHON_LIBS_DIRS),$(call _,$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$(gitexec_instdir_SQ)/pythonlib/$(dir)'))
	$(foreach dir,$(PYTHON_LIBS_DIRS),$(call _,$(INSTALL) -m 644 $(addprefix pythonlib/,$(foreach lib,$(PYTHON_LIBS),$(if $(filter $(dir)$(notdir $(lib)),$(lib)),$(lib)))) '$(DESTDIR_SQ)$(gitexec_instdir_SQ)/pythonlib/$(dir)'))

clean-pythonlib:
	$(RM) -r pythonlib

ALL_PROGRAMS += git-cinnabar-helper$X

all:: git-cinnabar-helper$X

CINNABAR_OBJECTS += cinnabar-helper.o
CINNABAR_OBJECTS += cinnabar-fast-import.o
CINNABAR_OBJECTS += hg-bundle.o
CINNABAR_OBJECTS += hg-connect.o
ifndef NO_CURL
CINNABAR_OBJECTS += hg-connect-http.o
endif
CINNABAR_OBJECTS += hg-connect-stdio.o

PATCHES = $(notdir $(wildcard ../*.patch))

$(addprefix ../,$(PATCHES:%.c.patch=%.patched.c)): ../%.patched.c: ../%.c.patch %.c
# Funny thing... GNU patch doesn't like -o ../file, and BSD patch doesn't like sending
# the output to stdout.
	cd .. && patch -p1 -F0 -o $(notdir $@) $(CURDIR)/$(notdir $(lastword $^)) < $(notdir $<)

clean-patched:
	$(RM) $(addprefix ../,$(PATCHES:%.c.patch=%.patched.c))

CINNABAR_OBJECTS += $(PATCHES:%.c.patch=%.patched.o)

ifdef USE_COMPUTED_HEADER_DEPENDENCIES
dep_files := $(foreach f,$(CINNABAR_OBJECTS),$(dir $f).depend/$(notdir $f).d)
dep_files_present := $(wildcard $(dep_files))
ifneq ($(dep_files_present),)
include $(dep_files_present)
endif
else
$(CINNABAR_OBJECTS): $(LIB_H)
endif

ifndef NO_CURL
git-cinnabar-helper$X: http.o
endif
git-cinnabar-helper$X: $(CINNABAR_OBJECTS) GIT-LDFLAGS $(GITLIBS)
	$(QUIET_LINK)$(CC) $(ALL_CFLAGS) -o $@ $(ALL_LDFLAGS) $(filter %.o,$^) \
		$(CURL_LIBCURL) $(LIBS)

$(CINNABAR_OBJECTS): %.o: %.c GIT-CFLAGS $(missing_dep_dirs)
	$(QUIET_CC)$(CC) -o $@ -c $(dep_args) $(ALL_CFLAGS) $(EXTRA_CPPFLAGS) $<

endif
