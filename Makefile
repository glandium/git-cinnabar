SHELL_SCRIPTS := \
	git-remote-hg \
	git-cinnabar \

PYTHON_LIBS := \
	cinnabar/__init__.py \
	cinnabar/githg.py \
	cinnabar/bdiff.py \
	cinnabar/dag.py \
	cinnabar/exceptions.py \
	cinnabar/helper.py \
	cinnabar/remote_helper.py \
	cinnabar/git.py \
	cinnabar/hg/__init__.py \
	cinnabar/hg/bundle.py \
	cinnabar/hg/changegroup.py \
	cinnabar/hg/objects.py \
	cinnabar/hg/repo.py \
	cinnabar/cmd/__init__.py \
	cinnabar/cmd/bundle.py \
	cinnabar/cmd/convert.py \
	cinnabar/cmd/data.py \
	cinnabar/cmd/download.py \
	cinnabar/cmd/fetch.py \
	cinnabar/cmd/fsck.py \
	cinnabar/cmd/python.py \
	cinnabar/cmd/reclone.py \
	cinnabar/cmd/rollback.py \
	cinnabar/cmd/upgrade.py \
	cinnabar/cmd/util.py \
	cinnabar/util.py

NO_GETTEXT ?= 1
NO_OPENSSL ?= 1

ifndef CINNABAR_RECURSE

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
	$(MAKE) -C $(CURDIR)/git-core -f $(CURDIR)/Makefile $(TARGET) CINNABAR_RECURSE=1

install:
	$(error Not a supported target)

include git-core/config.mak.uname

.PHONY: FORCE

git-cinnabar-helper$X git git-install: FORCE

helper: git-cinnabar-helper$X
	mv git-core/$^ $^

else

include $(CURDIR)/Makefile

SOURCE_DIR := $(dir $(CURDIR))

vpath cinnabar/% $(SOURCE_DIR)

all:: $(addprefix pythonlib/,$(PYTHON_LIBS)) $(SHELL_SCRIPTS)

$(addprefix pythonlib/,$(PYTHON_LIBS)): pythonlib/%: %
	$(INSTALL) -d ${@D}
	$(INSTALL) -m 644 $^ $@

install: install-pythonlib install-cinnabarscripts
clean: clean-pythonlib clean-cinnabarscripts clean-patched

PYTHON_LIBS_DIRS := $(sort $(dir $(PYTHON_LIBS)))

$(SHELL_SCRIPTS):
	ln -s ../$@ $@

clean-cinnabarscripts:
	rm $(SHELL_SCRIPTS)

install-cinnabarscripts:
	$(INSTALL) $(SHELL_SCRIPTS) '$(DESTDIR_SQ)$(gitexec_instdir_SQ)'

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

CINNABAR_OBJECTS += cinnabar-fast-import.o
CINNABAR_OBJECTS += cinnabar-helper.o
CINNABAR_OBJECTS += cinnabar-notes.o
CINNABAR_OBJECTS += cinnabar-util.o
CINNABAR_OBJECTS += hg-bundle.o
CINNABAR_OBJECTS += hg-connect.o
ifndef NO_CURL
CINNABAR_OBJECTS += hg-connect-http.o
endif
CINNABAR_OBJECTS += hg-connect-stdio.o
CINNABAR_OBJECTS += hg-data.o
CINNABAR_OBJECTS += which.o

PATCHES = $(notdir $(wildcard $(SOURCE_DIR)helper/*.patch))

$(addprefix $(SOURCE_DIR)helper/,$(PATCHES:%.c.patch=%.patched.c)): $(SOURCE_DIR)helper/%.patched.c: $(SOURCE_DIR)helper/%.c.patch %.c
	patch -p1 -F0 -o $@ $(CURDIR)/$(notdir $(lastword $^)) < $<

clean-patched:
	$(RM) $(addprefix $(SOURCE_DIR)helper/,$(PATCHES:%.c.patch=%.patched.c))

$(addprefix $(SOURCE_DIR)helper/,$(PATCHES) $(CINNABAR_OBJECTS:%.o=%.c)):

CINNABAR_OBJECTS += $(filter-out fast-import.patched.o,$(PATCHES:%.c.patch=%.patched.o))

cinnabar-fast-import.o: $(SOURCE_DIR)helper/fast-import.patched.c

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
ifeq (,$(filter http.c.patch,$(PATCHES)))
libcinnabar.a: http.o
endif
endif
libcinnabar.a: $(CINNABAR_OBJECTS) $(filter-out $(PATCHES:%.c.patch=%.o) run-command.o compat/mingw.o,$(LIB_OBJS)) $(XDIFF_OBJS)
	$(QUIET_AR)$(RM) $@ && $(AR) $(ARFLAGS) $@ $^

git-cinnabar-helper$X: libcinnabar.a GIT-LDFLAGS
	$(QUIET_LINK)$(CC) $(ALL_CFLAGS) -o $@ $(ALL_LDFLAGS) libcinnabar.a \
		$(CURL_LIBCURL) $(EXTLIBS)

cinnabar-helper.o: EXTRA_CPPFLAGS=-DHELPER_HASH=$(shell python $(SOURCE_DIR)git-cinnabar --version=helper 2> /dev/null | awk -F/ '{print $$NF}')
cinnabar-helper.o: $(addprefix $(SOURCE_DIR)helper/,$(PATCHES) $(CINNABAR_OBJECTS:%.o=%.c))

$(CINNABAR_OBJECTS): %.o: $(SOURCE_DIR)helper/%.c GIT-CFLAGS $(missing_dep_dirs)
	$(QUIET_CC)$(CC) -o $@ -c $(dep_args) $(ALL_CFLAGS) $(EXTRA_CPPFLAGS) $<

ifdef CURL_COMPAT
git-cinnabar-helper$X: CURL_LIBCURL=$(CURDIR)/libcurl.so
git-cinnabar-helper$X: libcurl.so

libcurl.so: $(SOURCE_DIR)helper/curl-compat.c
	$(CC) -shared -Wl,-soname,libcurl.so.4 -o $@ $<
endif

config.patched.sp config.patched.s config.patched.o: GIT-PREFIX
config.patched.sp config.patched.s config.patched.o: EXTRA_CPPFLAGS = \
	-DETC_GITCONFIG='"$(ETC_GITCONFIG_SQ)"'
endif
