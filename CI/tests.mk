TOPDIR = $(abspath $(or $(dir $(firstword $(MAKEFILE_LIST))),$(CURDIR))/..)

include $(TOPDIR)/helper/GIT-VERSION.mk

ifeq (a,$(firstword a$(subst /, ,$(abspath .))))
PATHSEP = :
else
PATHSEP = ;
endif

ifdef GRAFT
all: check-graft
else
all: check
endif

export PATH := $(TOPDIR)$(PATHSEP)$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
REPO ?= https://hg.mozilla.org/users/mh_glandium.org/jqplot

HG = hg

ifeq ($(VARIANT),coverage)
export PATH := $(TOPDIR)/coverage$(PATHSEP)$(PATH)
export COVERAGE_FILE := $(TOPDIR)/.coverage
endif

GIT = git

ifndef GIT_CINNABAR_OLD_HELPER
GIT += -c core.packedGitWindowSize=8k
endif

COMMA=,
export GIT_CINNABAR_CHECK:=all,traceback,cinnabarclone,clonebundles$(addprefix $(COMMA),$(GIT_CINNABAR_CHECK))
export GIT_CINNABAR_LOG=process:3

hg.pure.hg:
	$(HG) clone -U $(REPO) $@

hg.old.git:
	$(GIT) -c fetch.prune=true clone -n hg::$(REPO) $@

ifdef UPGRADE_FROM
check: check-upgrade-error
check-upgrade-error: hg.old.git
	cp -r $< $@
	$(GIT) -C $@ remote update && echo "Should have been asked to upgrade" && exit 1 || true
endif

hg.upgraded.git: hg.old.git
	cp -r $< $@
	$(GIT) -C $@ cinnabar upgrade || [ "$$?" = 2 ]
	$(GIT) -C $@ cinnabar fsck --manifest --files || [ "$$?" = 2 ]

PATH_URL = file://$(CURDIR)

COMPARE_COMMANDS = bash -c "diff -u <($1) <($2)"

GET_REF_SHA1 = git -C $1 log --format=%H --reverse --date-order --remotes=origin --no-walk$(if $2, | $2) | awk '{print} END { if (NR == 0) { print \"$1\", NR } }'

COMPARE_REFS = $(call COMPARE_COMMANDS,$(call GET_REF_SHA1,$1,$(if $3, $(call $3,$1))),\
                                       $(call GET_REF_SHA1,$2,$(if $3, $(call $3,$2))))

HG_INIT = $(HG) init $1
%.nobundle2: HG_INIT += ; (echo "[experimental]"; echo "bundle2-advertise = false") >> $1/.hg/hgrc

print-version:
	$(GIT) cinnabar --version

check: print-version
check: hg.empty.git
check: hg.git hg.git.nobundle2
check: hg.unbundle.git
check: hg.incr.git hg.incr.hg.nobundle2
ifndef NO_CLONEBUNDLES
check: hg.clonebundles.git
check: hg.clonebundles-full.git
endif
check: hg.push.hg hg.push.hg.nobundle2
check: hg.http.hg hg.http.hg.nobundle2
check: hg.cinnabarclone.git
check: hg.cinnabarclone-full.git
check: hg.cinnabarclone-bundle.git
check: hg.cinnabarclone-bundle-full.git

check-graft: hg.graft.git
check-graft: hg.graft2.git
check-graft: hg.graft.replace.git
check-graft: hg.cant.graft.git
check-graft: hg.graft.new.bundle
check-graft: hg.cinnabarclone-graft.git
check-graft: hg.cinnabarclone-graft-replace.git

hg.hg hg.hg.nobundle2: hg.upgraded.git
	$(call HG_INIT, $@)
	$(GIT) -C $< push hg::$(PATH_URL)/$@ 'refs/remotes/origin/*:refs/heads/*'
	$(HG) -R $@ verify

hg.empty.hg:
	$(call HG_INIT, $@)

hg.empty.git: hg.empty.hg
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/$< $@

hg.empty.push.hg: hg.empty.git
	$(call HG_INIT, $@)
	$(GIT) -C $< push --all hg::$(PATH_URL)/$@

hg.bundle: hg.git
	$(GIT) -C $< cinnabar bundle $(CURDIR)/$@ -- --remotes

hg.git hg.git.nobundle2: hg.git%: hg.hg% hg.upgraded.git
hg.unbundle.git: hg.bundle hg.git
hg.unbundle.git hg.git hg.git.nobundle2:
	$(GIT) -c fetch.prune=true clone -n hg::$(CURDIR)/$< $@
	$(call COMPARE_REFS, $(word 2,$^), $@)
	$(GIT) -C $@ cinnabar fsck --manifest --files
	$(GIT) -C $@ remote add hg-http hg::http://localhost:8000/

hg.incr.hg hg.incr.hg.nobundle2: hg.incr.hg%: hg.hg%
	$(call HG_INIT, $@)
	# /!\ this only really works for an unchanged $(REPO)
	$(HG) -R $@ pull $(CURDIR)/$< -r c262fcbf0656 -r 46585998e744

hg.incr.git hg.incr.git.nobundle2: hg.incr.git%: hg.incr.hg% hg.hg% hg.git%
	$(HG) clone -U $< $@.hg
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/$@.hg $@
	$(HG) -R $@.hg pull $(CURDIR)/$(word 2,$^)
	$(GIT) -C $@ remote update
	$(call COMPARE_REFS, $(word 3,$^), $@)
	$(GIT) -C $@ cinnabar fsck --manifest --files

BUNDLESPEC = gzip-v2

hg.incr.bundle: hg.incr.hg
hg.full.bundle: hg.hg
hg.incr.bundle hg.full.bundle:
	$(HG) -R $< bundle -t $(BUNDLESPEC) -a $@

hg.clonebundles.hg: hg.hg hg.incr.bundle
hg.clonebundles-full.hg: hg.hg hg.full.bundle
hg.clonebundles.hg hg.clonebundles-full.hg:
	$(HG) clone -U $< $@
	echo http://localhost:8080/$(word 2,$^) BUNDLESPEC=$(BUNDLESPEC) > $@/.hg/clonebundles.manifest

hg.clonebundles.git: hg.clonebundles.hg hg.git
hg.clonebundles-full.git: hg.clonebundles-full.hg hg.git
hg.clonebundles.git hg.clonebundles-full.git:
	OTHER_SERVER=http $(HG) -R $< --config extensions.clonebundles= --config extensions.x=$(TOPDIR)/CI/hg-serve-exec.py serve-and-exec -- $(GIT) clone -n hg://localhost:8000.http/ $@
	$(call COMPARE_REFS, $(word 2,$^), $@)

hg.pure.git: hg.git
	# || exit 1 forces mingw32-make to wrap the command through a shell, which works
	# around https://github.com/Alexpux/MSYS2-packages/issues/829.
	$(GIT) clone -n $< $@ || exit 1

hg.push.hg hg.push.hg.nobundle2: hg.pure.git
	$(call HG_INIT, $@)
	# Push everything, including merges
	$(GIT) -c cinnabar.experiments=merge -C $< push hg::$(PATH_URL)/$@ --all

gitcredentials:
	(echo protocol=http; echo host=localhost:8000; echo username=foo; echo password=bar) | $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' credential approve

hg.http.hg hg.http.hg.nobundle2: gitcredentials hg.git
	$(call HG_INIT, $@)
	$(HG) -R $@ --config extensions.x=$(TOPDIR)/CI/hg-serve-exec.py serve-and-exec -- $(GIT) -c credential.helper='store --file=$(CURDIR)/gitcredentials' -C $(word 2,$^) push hg-http refs/remotes/origin/*:refs/heads/*

hg.incr.base.git: hg.incr.hg
	$(HG) clone -U $< $@.hg
	$(GIT) -c fetch.prune=true clone -n hg::$(PATH_URL)/$@.hg $@

hg.incr.bundle.git: hg.incr.base.git
hg.bundle.git: hg.git
hg.incr.bundle.git hg.bundle.git:
	$(GIT) -C $^ bundle create $(CURDIR)/$@ refs/cinnabar/metadata

HG_CINNABARCLONE_EXT=$(or $(wildcard $(TOPDIR)/mercurial/cinnabarclone.py),$(TOPDIR)/hg/cinnabarclone.py)

hg.cinnabarclone.git: hg.incr.base.git hg.git
hg.cinnabarclone-full.git: hg.git
hg.cinnabarclone-bundle.git: hg.incr.bundle.git hg.git
hg.cinnabarclone-bundle-full.git: hg.bundle.git hg.git
hg.cinnabarclone-graft.git: hg.graft.git
hg.cinnabarclone-graft-replace.git: hg.graft.replace.git
hg.cinnabarclone.git hg.cinnabarclone-full.git hg.cinnabarclone-graft.git hg.cinnabarclone-graft-replace.git: OTHER_SERVER=git
hg.cinnabarclone-bundle.git hg.cinnabarclone-bundle-full.git: OTHER_SERVER=http
hg.cinnabarclone.git hg.cinnabarclone-full.git hg.cinnabarclone-bundle.git hg.cinnabarclone-bundle-full.git hg.cinnabarclone-graft.git hg.cinnabarclone-graft-replace.git: hg.pure.hg
	$(HG) clone -U $< $@.hg
	echo http://localhost:8080/$(word 2,$^) > $@.hg/.hg/cinnabar.manifest
	OTHER_SERVER=$(OTHER_SERVER) $(HG) -R $@.hg --config extensions.x=$(TOPDIR)/CI/hg-serve-exec.py --config extensions.cinnabarclone=$(HG_CINNABARCLONE_EXT) serve-and-exec -- $(GIT) -c cinnabar.experiments=git-clone clone hg://localhost:8000.http/ $@
	$(call COMPARE_REFS, $(or $(word 3,$^),$(word 2,$^)), $@)
	$(GIT) -C $@ cinnabar fsck --manifest --files

GET_ROOTS = $(GIT) -C $1 rev-list $2 --max-parents=0
XARGS_GIT2HG = xargs $(GIT) -C $1 cinnabar git2hg

hg.graft.base.git hg.graft2.base.git: hg.upgraded.git hg.pure.hg
	$(GIT) init $@
	$(GIT) -C $@ remote add origin hg::$(PATH_URL)/$(word 2,$^)
	$(GIT) -C $< push $(CURDIR)/$@ refs/remotes/*:refs/remotes/*
	$(GIT) -C $@ checkout $$($(GIT) -C $< rev-parse HEAD)

hg.graft.git: hg.graft.base.git hg.upgraded.git
	cp -r $< $@
	$(GIT) -C $@ cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C $@ filter-branch --msg-filter 'cat ; echo' --original original -- --all
	$(GIT) -C $@ -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, $(word 2,$^), $@, XARGS_GIT2HG)
	$(GIT) -C $@ cinnabar fsck --manifest --files

hg.graft2.git: hg.graft.git hg.pure.hg hg.graft2.base.git
	cp -r $(word 3,$^) $@
	$(GIT) -C $< push $(CURDIR)/$@ refs/remotes/origin/*:refs/remotes/new/*
	$(GIT) -C $@ remote set-url origin hg::$(PATH_URL)/$(word 2,$^)
	$(GIT) -C $@ -c cinnabar.graft=true cinnabar reclone
	$(call COMPARE_REFS, $<, $@)
	$(GIT) -C $@ cinnabar fsck --manifest --files

hg.graft.replace.git: hg.graft.git hg.upgraded.git
	cp -r $< $@
	$(GIT) -C $@ cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C $@ filter-branch --index-filter 'test $$GIT_COMMIT = '$$($(call GET_ROOTS,$@,--remotes))' && git rm -r --cached -- \* || true' --original original -- --all
	$(GIT) -C $@ -c cinnabar.graft=true remote update
	$(call COMPARE_REFS, $(word 2,$^), $@, XARGS_GIT2HG)
	$(call COMPARE_COMMANDS,$(call GET_ROOTS,$(word 2,$^),--remotes),$(call GET_ROOTS,$@,--glob=refs/cinnabar/replace))
	$(GIT) -C $@ cinnabar fsck --manifest --files

hg.cant.graft.git: hg.graft.replace.git
	cp -r $< $@
	$(GIT) -C $@ cinnabar rollback 0000000000000000000000000000000000000000
	$(GIT) -C $@ for-each-ref --format='%(refname)' | grep -v refs/remotes/origin/HEAD | sed 's/^/delete /' | $(GIT) -C $@ update-ref --stdin
	$(GIT) -C $@ -c cinnabar.graft=true remote update

hg.graft.new.bundle: hg.graft2.git
	cp -r $< $@.git
	$(GIT) -C $@.git checkout refs/remotes/new/HEAD
	$(GIT) -C $@.git -c user.email=git@cinnabar -c user.name=cinnabar commit --allow-empty -m 'New commit'
	$(GIT) -C $@.git -c cinnabar.graft=true cinnabar bundle $(CURDIR)/$@ HEAD^!
	$(GIT) -C $@.git -c cinnabar.graft=true fetch hg::$(PATH_URL)/$@
	test "$$($(GIT) -C $@.git cinnabar data -c $$($(GIT) -C $@.git cinnabar git2hg FETCH_HEAD) | tail -c 1)" = t
