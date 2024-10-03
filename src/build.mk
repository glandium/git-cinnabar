# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

ifdef NO_CURL
$(error Cannot build without curl)
endif

NO_GETTEXT ?= 1
NO_OPENSSL ?= 1
NO_UNIX_SOCKETS ?= 1

SOURCE_DIR = $(subst \,/,$(CARGO_MANIFEST_DIR))

vpath %.c $(SOURCE_DIR)/git-core

$(SOURCE_DIR)/git-core/Makefile:
	git -C $(SOURCE_DIR) submodule sync
	git -C $(SOURCE_DIR) submodule update --init

gitweb/Makefile:
	mkdir -p ${@D}
	touch $@

config.mak.dev: detect-compiler

config.mak.uname config.mak.dev:
	echo "ifndef FAKE_INCLUDE" > $@
	echo "include $(SOURCE_DIR)/git-core/$@" >> $@
	echo "endif" >> $@

FAKE_INCLUDE := 1
-include config.mak.uname
-include config.mak.dev
FAKE_INCLUDE :=
include $(SOURCE_DIR)/git-core/Makefile

GIT-VERSION-FILE: GIT-VERSION-GEN
GIT-VERSION-GEN detect-compiler:
	echo "#!/bin/sh" > $@
	echo ". $(SOURCE_DIR)/git-core/$@" >> $@
	chmod +x $@

shared.mak:
	echo "include $(SOURCE_DIR)/git-core/shared.mak" > $@

ALL_PROGRAMS += git-cinnabar$X
ALL_CFLAGS := $(subst -I. ,-I$(SOURCE_DIR)/git-core -I. ,$(ALL_CFLAGS))
ALL_CFLAGS := $(subst -Icompat,-I$(SOURCE_DIR)/git-core/compat,$(ALL_CFLAGS))
ALL_CFLAGS := $(filter-out -DPRECOMPOSE_UNICODE,$(ALL_CFLAGS))
ifdef MINGW_WRAPPERS
ALL_CFLAGS += -I$(SOURCE_DIR)/src/mingw
endif
ifndef DEVELOPER
ALL_CFLAGS += -Werror=implicit-function-declaration
endif

all:: git-cinnabar$X

CINNABAR_OBJECTS += cinnabar-fast-import.o
CINNABAR_OBJECTS += cinnabar-helper.o
CINNABAR_OBJECTS += cinnabar-notes.o
CINNABAR_OBJECTS += hg-connect-stdio.o
CINNABAR_OBJECTS += hg-data.o
CINNABAR_OBJECTS += mingw.o
CINNABAR_OBJECTS += regex.o

PATCHES = $(notdir $(wildcard $(SOURCE_DIR)/src/*.patch))

define patch
$1.patched.c: $$(SOURCE_DIR)/src/$1.c.patch $$(firstword $$(wildcard $$(SOURCE_DIR)/git-core/$1.c $$(SOURCE_DIR)/git-core/builtin/$1.c $$(SOURCE_DIR)/git-core/compat/win32/$1.c))
	patch -p1 -F0 -o $$@ $$(lastword $$^) < $$<
endef

$(foreach p,$(PATCHES),$(eval $(call patch,$(p:%.c.patch=%))))

$(addprefix $(SOURCE_DIR)/src/,$(PATCHES) $(CINNABAR_OBJECTS:%.o=%.c)):

ifdef USE_COMPUTED_HEADER_DEPENDENCIES
dep_files := $(foreach f,$(ALL_CINNABAR_OBJECTS),$(dir $f).depend/$(notdir $f).d)
dep_files_present := $(wildcard $(dep_files))
ifneq ($(dep_files_present),)
include $(dep_files_present)
endif
else
$(ALL_CINNABAR_OBJECTS): $(LIB_H)

# When not using computed header dependencies, the directories for objects
# aren't going to be created.
obj_dirs := $(sort $(dir $(ALL_CINNABAR_OBJECTS) $(LIB_OBJS) $(REFTABLE_OBJS) $(XDIFF_OBJS)))

$(obj_dirs):
	@mkdir -p $@

missing_obj_dirs := $(filter-out $(wildcard $(obj_dirs)),$(obj_dirs))

$(ALL_CINNABAR_OBJECTS) $(LIB_OBJS) $(REFTABLE_OBJS) $(XDIFF_OBJS): $(missing_obj_dirs)
endif

PATCHED_GIT_OBJECTS := $(filter-out fast-import.patched.o,$(PATCHES:%.c.patch=%.patched.o))
ifeq (,$(filter compat/win32/fscache.o,$(LIB_OBJS)))
PATCHED_GIT_OBJECTS := $(filter-out fscache.patched.o,$(PATCHED_GIT_OBJECTS))
endif
ALL_CINNABAR_OBJECTS = $(CINNABAR_OBJECTS) $(PATCHED_GIT_OBJECTS)

ifeq (,$(filter http.c.patch,$(PATCHES)))
libcinnabar.a: http.o
endif
EXCLUDE_OBJS = $(PATCHES:%.c.patch=%.o)
EXCLUDE_OBJS += add-interactive.o
EXCLUDE_OBJS += add-patch.o
EXCLUDE_OBJS += archive.o
EXCLUDE_OBJS += archive-tar.o
EXCLUDE_OBJS += archive-zip.o
EXCLUDE_OBJS += bitmap.o
EXCLUDE_OBJS += blame.o
EXCLUDE_OBJS += checkout.o
EXCLUDE_OBJS += compat/mingw.o
EXCLUDE_OBJS += compat/precompose_utf8.o
EXCLUDE_OBJS += compat/regex/regex.o
EXCLUDE_OBJS += compat/win32/fscache.o
EXCLUDE_OBJS += connect.o
EXCLUDE_OBJS += default.o
EXCLUDE_OBJS += diagnose.o
EXCLUDE_OBJS += help.o
EXCLUDE_OBJS += iterator.o
EXCLUDE_OBJS += reachable.o
EXCLUDE_OBJS += serve.o
libcinnabar.a: $(ALL_CINNABAR_OBJECTS) $(filter-out $(EXCLUDE_OBJS),$(LIB_OBJS)) $(REFTABLE_OBJS) $(XDIFF_OBJS)
	$(QUIET_AR)$(RM) $@ && $(AR) $(ARFLAGS) $@ $^

linker-flags: GIT-LDFLAGS FORCE
	@echo $(ALL_LDFLAGS) -L$(CURDIR) $(filter-out -lz,$(EXTLIBS))

$(CINNABAR_OBJECTS): %.o: $(SOURCE_DIR)/src/%.c
$(PATCHED_GIT_OBJECTS): %.o: %.c
cinnabar-fast-import.o: fast-import.patched.c
$(ALL_CINNABAR_OBJECTS): GIT-CFLAGS $(missing_dep_dirs)

$(ALL_CINNABAR_OBJECTS):
	$(QUIET_CC)$(CC) -o $@ -c $(dep_args) $(compdb_args) $(ALL_CFLAGS) $(EXTRA_CPPFLAGS) $<

compile_commands.json: $(ALL_CINNABAR_OBJECTS)

config.patched.sp config.patched.s config.patched.o: GIT-PREFIX
config.patched.sp config.patched.s config.patched.o: EXTRA_CPPFLAGS = \
	-DETC_GITCONFIG='"$(ETC_GITCONFIG_SQ)"'

.PHONY: FORCE

# Allow for a smoother transition from helper/ to src/
$(SOURCE_DIR)/helper/%.c: FORCE ;

# hook.o pulls hook-list.h, which requires these two files (although hook-list.h
# is not actually used)
vpath Documentation/githooks.txt $(SOURCE_DIR)/git-core

generate-hooklist.sh: $(SOURCE_DIR)/git-core/generate-hooklist.sh
	echo "$<" > $@
