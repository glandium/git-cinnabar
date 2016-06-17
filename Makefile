PYTHON_SCRIPTS := \
	git-remote-hg.py \
	git-cinnabar.py \

PYTHON_LIBS := \
	cinnabar/__init__.py \
	cinnabar/githg.py \
	cinnabar/bdiff.py \
	cinnabar/bundle.py \
	cinnabar/dag.py \
	cinnabar/helper.py \
	cinnabar/remote_helper.py \
	cinnabar/git.py \
	cinnabar/hg/__init__.py \
	cinnabar/util.py

ifneq (,$(wildcard $(CURDIR)/git-core/Makefile))
all:

.SUFFIXES:

%:
	$(MAKE) -C $(CURDIR)/git-core -f $(CURDIR)/Makefile $@ SCRIPT_PYTHON="git-p4.py $(PYTHON_SCRIPTS)"

else

include $(CURDIR)/Makefile

VPATH += ..

all:: $(addprefix pythonlib/,$(PYTHON_LIBS))

$(addprefix pythonlib/,$(PYTHON_LIBS)): pythonlib/%: %
	$(INSTALL) -d ${@D}
	$(INSTALL) -m 644 $^ $@

install: install-pythonlib
clean: clean-pythonlib clean-pythonscripts

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
	$(foreach dir,$(PYTHON_LIBS_DIRS),$(call _,$(INSTALL) -m 644 $(addprefix pythonlib/,$(filter $(dir)%,$(PYTHON_LIBS))) '$(DESTDIR_SQ)$(gitexec_instdir_SQ)/pythonlib/$(dir)'))

clean-pythonlib:
	$(RM) -r pythonlib

ALL_PROGRAMS += git-cinnabar-helper$X

all:: git-cinnabar-helper$X

CINNABAR_OBJECTS += cinnabar-helper.o
CINNABAR_OBJECTS += cinnabar-fast-import.o
CINNABAR_OBJECTS += hg-bundle.o
CINNABAR_OBJECTS += hg-connect.o
CINNABAR_OBJECTS += hg-connect-http.o
CINNABAR_OBJECTS += hg-connect-stdio.o

ifdef USE_COMPUTED_HEADER_DEPENDENCIES
dep_files := $(foreach f,$(CINNABAR_OBJECTS),$(dir $f).depend/$(notdir $f).d)
dep_files_present := $(wildcard $(dep_files))
ifneq ($(dep_files_present),)
include $(dep_files_present)
endif
else
$(CINNABAR_OBJECTS): $(LIB_H)
endif

git-cinnabar-helper$X: $(CINNABAR_OBJECTS) http.o GIT-LDFLAGS $(GITLIBS)
	$(QUIET_LINK)$(CC) $(ALL_CFLAGS) -o $@ $(ALL_LDFLAGS) $(filter %.o,$^) \
		$(CURL_LIBCURL) $(LIBS)

$(CINNABAR_OBJECTS): %.o: %.c GIT-CFLAGS $(missing_dep_dirs)
	$(QUIET_CC)$(CC) -o $@ -c $(dep_args) $(ALL_CFLAGS) $(EXTRA_CPPFLAGS) $<

endif
