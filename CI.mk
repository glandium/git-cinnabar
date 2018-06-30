include $(addsuffix /,$(dir $(firstword $(MAKEFILE_LIST))))helper/GIT-VERSION.mk

ifeq (a,$(firstword a$(subst /, ,$(abspath .))))
PATHSEP = :
else
PATHSEP = ;
endif

export PATH := $(CURDIR)$(PATHSEP)$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
REPO ?= https://hg.mozilla.org/users/mh_glandium.org/jqplot

HG = hg

ifeq ($(VARIANT),coverage)
export PATH := $(CURDIR)/coverage$(PATHSEP)$(PATH)
export COVERAGE_FILE := $(CURDIR)/.coverage
endif

ifdef PYTHON_CHECKS

script::
ifndef NO_BUNDLE2
	nosetests --all-modules $(if $(filter coverage,$(VARIANT)),--with-coverage --cover-tests )tests
	flake8 --ignore E402 $$(git ls-files \*\*.py git-cinnabar git-remote-hg)
endif

else

GIT=git

ifndef GIT_CINNABAR_OLD_HELPER
GIT += -c core.packedGitWindowSize=8k
endif

ifeq (undefined,$(origin GIT_CINNABAR_HELPER))
ifdef MSYSTEM
HELPER := git-cinnabar-helper.exe
else
HELPER := git-cinnabar-helper
endif
GIT_CINNABAR_HELPER=$(CURDIR)/$(HELPER)
endif
COMMA=,
export GIT_CINNABAR_CHECK=all$(if $(HELPER),,$(COMMA)-helper)
export GIT_CINNABAR_LOG=process:3

ifdef UPGRADE_FROM
script::
	$(GIT) -C hg.old.git remote update && echo "Should have been asked to upgrade" && exit 1 || true
endif

script::
	$(GIT) -C hg.old.git cinnabar upgrade || [ "$$?" = 2 ]
	$(GIT) -C hg.old.git cinnabar fsck || [ "$$?" = 2 ]

PATH_URL = file://$(if $(filter /%,$(CURDIR)),,/)$(CURDIR)

COMPARE_COMMANDS = bash -c "diff -u <($1) <($2)"

GET_REF_SHA1 = git -C $1 log --format=%H --reverse --date-order --remotes=origin --no-walk$(if $2, | $2) | awk '{print} END { if (NR == 0) { print \"$1\", NR } }'

COMPARE_REFS = $(call COMPARE_COMMANDS,$(call GET_REF_SHA1,$1,$(if $3, $(call $3,$1))),\
                                       $(call GET_REF_SHA1,$2,$(if $3, $(call $3,$2))))

HG_INIT = $(HG) init $1
ifdef NO_BUNDLE2
HG_INIT += ; (echo "[experimental]"; echo "bundle2-advertise = false") >> $1/.hg/hgrc
endif

ifndef GRAFT

script::
	rm -rf hg.hg hg.empty.git hg.git hg.bundle hg.unbundle.git
	$(call HG_INIT, hg.hg)
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/hg.hg hg.empty.git
	$(GIT) -C hg.empty.git push --all hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push hg::$(PATH_URL)/hg.hg 'refs/remotes/origin/*:refs/heads/*'
	$(HG) -R hg.hg verify
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/hg.hg hg.git
	$(call COMPARE_REFS, hg.old.git, hg.git)
	$(GIT) -C hg.git cinnabar fsck

	$(GIT) -C hg.git cinnabar bundle $(CURDIR)/hg.bundle -- --remotes
	$(GIT) -c fetch.prune=true clone -n hg::$(CURDIR)/hg.bundle hg.unbundle.git
	$(call COMPARE_REFS, hg.git, hg.unbundle.git)
	$(GIT) -C hg.unbundle.git cinnabar fsck

script::
	rm -rf hg.incr.hg hg.incr.git
	$(HG) init hg.incr.hg
	# /!\ this only really works for an unchanged $(REPO)
	$(HG) -R hg.incr.hg pull $(CURDIR)/hg.hg -r c262fcbf0656 -r 46585998e744
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/hg.incr.hg hg.incr.git
	$(HG) -R hg.incr.hg pull $(CURDIR)/hg.hg
	$(GIT) -C hg.incr.git remote update
	$(GIT) -C hg.incr.git cinnabar fsck

script::
	rm -rf hg.clonebundles.hg hg.clonebundles.git
	$(HG) clone -U hg.hg hg.clonebundles.hg
	$(HG) -R hg.clonebundles.hg bundle -a -r c262fcbf0656 -r 46585998e744 repo.bundle
	echo $(PATH_URL)/repo.bundle > hg.clonebundles.hg/.hg/clonebundles.manifest
	$(HG) -R hg.clonebundles.hg --config extensions.clonebundles= --config extensions.x=CI/hg-serve-exec.py serve-and-exec -- $(GIT) clone -n hg://localhost:8000.http/ hg.clonebundles.git
	$(call COMPARE_REFS, hg.git, hg.clonebundles.git)

script::
	rm -rf hg.clonebundles-full.hg hg.clonebundles-full.git
	$(HG) clone -U hg.hg hg.clonebundles-full.hg
	$(HG) -R hg.clonebundles-full.hg bundle -a repo.bundle
	echo $(PATH_URL)/repo.bundle > hg.clonebundles-full.hg/.hg/clonebundles.manifest
	$(HG) -R hg.clonebundles-full.hg --config extensions.clonebundles= --config extensions.x=CI/hg-serve-exec.py serve-and-exec -- $(GIT) clone -n hg://localhost:8000.http/ hg.clonebundles-full.git
	$(call COMPARE_REFS, hg.git, hg.clonebundles.git)

script::
	rm -rf hg.push.hg hg.pure.git
	$(call HG_INIT, hg.push.hg)
	# || exit 1 forces mingw32-make to wrap the command through a shell, which works
	# around https://github.com/Alexpux/MSYS2-packages/issues/829.
	$(GIT) clone -n hg.git hg.pure.git || exit 1
	# Push everything, including merges
	$(GIT) -c cinnabar.experiments=merge -C hg.pure.git push hg::$(PATH_URL)/hg.push.hg --all

script::
	rm -rf hg.http.hg gitcredentials
	$(call HG_INIT, hg.http.hg)
	(echo protocol=http; echo host=localhost:8000; echo username=foo; echo password=bar) | $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' credential approve
	$(GIT) -C hg.git remote add hg-http hg::http://localhost:8000/
	$(HG) -R hg.http.hg --config extensions.x=CI/hg-serve-exec.py serve-and-exec -- $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' -C hg.git push hg-http refs/remotes/origin/*:refs/heads/*

script::
	rm -rf hg.cinnabarclone.git
	$(GIT) init hg.cinnabarclone.git
	$(GIT) -C hg.cinnabarclone.git fetch ../hg.incr.git refs/heads/*:refs/heads/* refs/remotes/*:refs/remotes/*
	$(GIT) -C hg.cinnabarclone.git fetch ../hg.incr.git refs/cinnabar/metadata:refs/cinnabar/metadata
	$(GIT) -C hg.cinnabarclone.git cinnabar fsck
else # GRAFT

GET_ROOTS = $(GIT) -C $1 rev-list $2 --max-parents=0
XARGS_GIT2HG = xargs $(GIT) -C $1 cinnabar git2hg

ifndef NO_BUNDLE2

script::
	rm -rf hg.hg
	$(HG) clone -U $(REPO) hg.hg

script::
	rm -rf hg.graft.git hg.graft2.git
	$(GIT) init hg.graft.git
	$(GIT) -C hg.graft.git remote add origin hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push $(CURDIR)/hg.graft.git refs/remotes/*:refs/remotes/*
	$(GIT) -C hg.graft.git checkout $$($(GIT) -C hg.old.git rev-parse HEAD)

	$(GIT) init hg.graft2.git
	$(GIT) -C hg.graft2.git remote add origin hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.old.git push $(CURDIR)/hg.graft2.git refs/remotes/*:refs/remotes/*
	$(GIT) -C hg.graft2.git checkout $$($(GIT) -C hg.old.git rev-parse HEAD)

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git filter-branch --msg-filter 'cat ; echo' --original original -- --all
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, hg.old.git, hg.graft.git, XARGS_GIT2HG)
	$(GIT) -C hg.graft.git cinnabar fsck

	$(GIT) -C hg.graft.git push $(CURDIR)/hg.graft2.git refs/remotes/origin/*:refs/remotes/new/*
	$(GIT) -C hg.graft2.git remote set-url origin hg::$(PATH_URL)/hg.hg
	$(GIT) -C hg.graft2.git -c cinnabar.graft=true cinnabar reclone
	$(call COMPARE_REFS, hg.graft.git, hg.graft2.git)
	$(GIT) -C hg.graft2.git cinnabar fsck

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git filter-branch --index-filter 'test $$GIT_COMMIT = '$$($(call GET_ROOTS,hg.graft.git,--remotes))' && git rm -r --cached -- \* || true' --original original -- --all
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, hg.old.git, hg.graft.git, XARGS_GIT2HG)
	$(call COMPARE_COMMANDS,$(call GET_ROOTS,hg.old.git,--remotes),$(call GET_ROOTS,hg.graft.git,--glob=refs/cinnabar/replace))
	$(GIT) -C hg.graft.git cinnabar fsck

	$(GIT) -C hg.graft.git cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C hg.graft.git for-each-ref --format='%(refname)' | grep -v refs/remotes/origin/HEAD | sed 's/^/delete /' | $(GIT) -C hg.graft.git update-ref --stdin
	$(GIT) -C hg.graft.git -c cinnabar.graft=true remote update

script::
	rm -f hg.graft.new.bundle
	$(GIT) -C hg.graft2.git checkout refs/remotes/new/HEAD
	$(GIT) -C hg.graft2.git -c user.email=git@cinnabar -c user.name=cinnabar commit --allow-empty -m 'New commit'
	$(GIT) -C hg.graft2.git -c cinnabar.graft=true cinnabar bundle $(CURDIR)/hg.graft.new.bundle HEAD^!
	$(GIT) -C hg.graft2.git -c cinnabar.graft=true fetch hg::$(PATH_URL)/hg.graft.new.bundle
	test "$$($(GIT) -C hg.graft2.git cinnabar data -c $$($(GIT) -C hg.graft2.git cinnabar git2hg FETCH_HEAD) | tail -c 1)" = t

endif

endif # GRAFT

endif # PYTHON_CHECKS

ifeq ($(MAKECMDGOALS),package)
PACKAGE_FLAGS = $(addprefix --system ,$(SYSTEM)) $(addprefix --machine ,$(MACHINE))
PACKAGE = $(notdir $(shell $(CURDIR)/git-cinnabar download --url $1 $(PACKAGE_FLAGS)))

$(PACKAGE):
	@mkdir -p tmp
	@rm -rf tmp/git-cinnabar
	git archive --format=tar --prefix=git-cinnabar/ HEAD | tar -C tmp -x
	@$(CURDIR)/git-cinnabar download --no-config --dev -o tmp/git-cinnabar/$(call PACKAGE,--dev) $(PACKAGE_FLAGS)
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
	$(foreach c,$(shell $(CURDIR)/git-cinnabar download --list),$(MAKE) -f $(firstword $(MAKEFILE_LIST)) package SYSTEM=$(firstword $(subst /, ,$(c))) MACHINE=$(word 2,$(subst /, ,$(c)))$(CR))
