/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "git-compat-util.h"
#include "attr.h"
#include "blob.h"
#include "commit.h"
#include "config.h"
#include "diff.h"
#include "diffcore.h"
#include "environment.h"
#include "exec-cmd.h"
#include "hashmap.h"
#include "log-tree.h"
#include "shallow.h"
#include "strslice.h"
#include "strbuf.h"
#include "string-list.h"
#include "streaming.h"
#include "object.h"
#include "oidset.h"
#include "path.h"
#include "quote.h"
#include "refs.h"
#include "remote.h"
#include "replace-object.h"
#include "revision.h"
#include "run-command.h"
#include "setup.h"
#include "tree.h"
#include "tree-walk.h"
#include "worktree.h"
#include "hg-data.h"
#include "cinnabar-helper.h"
#include "cinnabar-fast-import.h"
#include "cinnabar-notes.h"

struct object_id *commit_oid(struct commit *c) {
	return &c->object.oid;
}

struct rev_info *rev_list_new(int argc, const char **argv) {
	struct rev_info *revs = xmalloc(sizeof(*revs));

	repo_init_revisions(the_repository, revs, NULL);
	// Note: we do a pass through, but don't make much effort to actually
	// support all the options properly.
	setup_revisions(argc, argv, revs, NULL);

	if (prepare_revision_walk(revs))
		die("revision walk setup failed");

	return revs;
}

void rev_list_finish(struct rev_info *revs) {
	// More extensive than reset_revision_walk(). Otherwise --boundary
	// and pathspecs don't work properly.
	clear_object_flags(ALL_REV_FLAGS | TOPO_WALK_EXPLORED | TOPO_WALK_INDEGREE);
	release_revisions(revs);
	free(revs);
}

int maybe_boundary(struct rev_info *revs, struct commit *commit) {
	struct commit_list *parent;
	struct commit_graft *graft;

	if (commit->object.flags & BOUNDARY)
		return 1;

	parent = commit->parents;
	if (revs->boundary && !parent &&
		is_repository_shallow(the_repository) &&
		(graft = lookup_commit_graft(
			the_repository, &commit->object.oid)) != NULL &&
		graft->nr_parent < 0) {
		return 2;
	}
	return 0;
}

const struct commit *commit_list_item(const struct commit_list *list) {
	return list->item;
}

const struct commit_list *commit_list_next(const struct commit_list *list) {
	return list->next;
}

struct diff_tree_file {
	struct object_id *oid;
	char *path;
	unsigned short mode;
};

struct diff_tree_item {
	struct diff_tree_file a;
	struct diff_tree_file b;
	unsigned short int score;
	char status;
};

struct diff_tree_ctx {
	void (*cb)(void *, struct diff_tree_item *);
	void *context;
};

static void diff_tree_cb(struct diff_queue_struct *q,
                         struct diff_options *opt, void *data)
{
	struct diff_tree_ctx *ctx = data;
	int i;

	for (i = 0; i < q->nr; i++) {
		struct diff_filepair *p = q->queue[i];
		if (p->status == 0)
			die("internal diff status error");
		if (p->status != DIFF_STATUS_UNKNOWN) {
			struct diff_tree_item item = {
				{ &p->one->oid, p->one->path, p->one->mode },
				{ &p->two->oid, p->two->path, p->two->mode },
				p->score,
				p->status,
			};
			ctx->cb(ctx->context, &item);
		}
	}
}

void diff_tree_(int argc, const char **argv, void (*cb)(void *, struct diff_tree_item *), void *context)
{
	struct diff_tree_ctx ctx = { cb, context };
	struct rev_info revs;

	repo_init_revisions(the_repository, &revs, NULL);
	revs.diff = 1;
	// Note: we do a pass through, but don't make much effort to actually
	// support all the options properly.
	setup_revisions(argc, argv, &revs, NULL);
	revs.diffopt.output_format = DIFF_FORMAT_CALLBACK;
	revs.diffopt.format_callback = diff_tree_cb;
	revs.diffopt.format_callback_data = &ctx;
	revs.diffopt.flags.recursive = 1;

	if (revs.pending.nr != 2)
		die("diff-tree needs two revs");

	diff_tree_oid(&revs.pending.objects[0].item->oid,
	              &revs.pending.objects[1].item->oid,
	              "", &revs.diffopt);
	log_tree_diff_flush(&revs);
	release_revisions(&revs);
}

const struct object_id *repo_lookup_replace_object(
	struct repository *r, const struct object_id *oid)
{
	return lookup_replace_object(r, oid);
}

void init_replace_map(void)
{
	the_repository->objects->replace_map =
		xmalloc(sizeof(*the_repository->objects->replace_map));
	oidmap_init(the_repository->objects->replace_map, 0);
	the_repository->objects->replace_map_initialized = 1;
}

void reset_replace_map(void)
{
	oidmap_free(the_repository->objects->replace_map, 1);
	FREE_AND_NULL(the_repository->objects->replace_map);
	the_repository->objects->replace_map_initialized = 0;
}

unsigned int replace_map_size(void)
{
	return hashmap_get_size(&the_repository->objects->replace_map->map);
}

unsigned int replace_map_tablesize(void)
{
	return the_repository->objects->replace_map->map.tablesize;
}

static void init_git_config(void)
{
	struct child_process proc = CHILD_PROCESS_INIT;
	struct strbuf path = STRBUF_INIT;
	const char *env = getenv(EXEC_PATH_ENVIRONMENT);
	/* As the helper is not necessarily built with the same build options
	 * as git (because it's built separately), the way its libgit.a is
	 * going to find the system gitconfig may not match git's, and there
	 * might be important configuration items there (like http.sslcainfo
	 * on git for windows).
	 * Trick git into giving us the path to it system gitconfig. */
	if (env && *env) {
		setup_path();
	}
	strvec_pushl(&proc.args, "git", "config", "--system", "-e", NULL);
	strvec_push(&proc.env, "GIT_EDITOR=echo");
	proc.no_stdin = 1;
	proc.no_stderr = 1;
	/* We don't really care about the capture_command return value. If
	 * the path we get is empty we'll know it failed. */
	capture_command(&proc, &path, 0);
	strbuf_trim_trailing_newline(&path);

	/* If we couldn't get a path, then so be it. We may just not have
	 * a complete configuration. */
	if (path.len)
		setenv("GIT_CONFIG_SYSTEM", path.buf, 1);

	strbuf_release(&path);
}

static void cleanup_git_config(int nongit)
{
	const char *value;
	if (!git_config_get_value("cinnabar.fsck", &value)) {
		// We used to set cinnabar.fsck globally, then locally.
		// Remove both.
		char *user_config, *xdg_config;
		git_global_config_paths(&user_config, &xdg_config);
		if (user_config) {
			if (access_or_warn(user_config, R_OK, 0) &&
				xdg_config &&
				!access_or_warn(xdg_config, R_OK, 0))
			{
				git_config_set_in_file_gently(
					xdg_config, "cinnabar.fsck", NULL,
					NULL);
			} else {
				git_config_set_in_file_gently(
					user_config, "cinnabar.fsck", NULL,
					NULL);
			}
		}
		free(user_config);
		free(xdg_config);
		if (!nongit) {
			user_config = git_pathdup("config");
			if (user_config) {
				git_config_set_in_file_gently(
					user_config, "cinnabar.fsck", NULL,
					NULL);
			}
			free(user_config);
		}
	}
}

static void restore_sigpipe_to_default(void)
{
	sigset_t unblock;

	sigemptyset(&unblock);
	sigaddset(&unblock, SIGPIPE);
	sigprocmask(SIG_UNBLOCK, &unblock, NULL);
	signal(SIGPIPE, SIG_DFL);
}

const char *remote_get_name(const struct remote *remote)
{
	return remote->name;
}

void remote_get_url(const struct remote *remote, const char * const **url,
                    int* url_nr)
{
	*url = remote->url;
	*url_nr = remote->url_nr;
}

int remote_skip_default_update(const struct remote *remote)
{
	return remote->skip_default_update;
}

void add_ref(struct ref ***tail, char *name, const struct object_id *oid)
{
	struct ref *ref = alloc_ref(name);
	if (oid) {
		oidcpy(&ref->old_oid, oid);
	}
	**tail = ref;
        *tail = &ref->next;
}

void add_symref(struct ref ***tail, const char *name, const char *sym)
{
	struct ref *ref = alloc_ref(name);
	ref->symref = xstrdup(sym);
	**tail = ref;
        *tail = &ref->next;
}

struct ref *get_ref_map(const struct remote *remote,
                        const struct ref *remote_refs)
{
	struct ref *ref_map = NULL;
	struct ref **tail = &ref_map;
	int i;

	for (i = 0; i < remote->fetch.nr; i++) {
		get_fetch_map(remote_refs, &remote->fetch.items[i], &tail, 0);
	}
	apply_negative_refspecs(ref_map, (struct refspec *)&remote->fetch);
	ref_map = ref_remove_duplicates(ref_map);
	return ref_map;
}

struct ref *get_stale_refs(const struct remote *remote,
                           const struct ref *ref_map)
{
	return get_stale_heads((struct refspec *)&remote->fetch,
	                       (struct ref *)ref_map);
}

const struct ref *get_next_ref(const struct ref *ref)
{
	return ref->next;
}

const char *get_ref_name(const struct ref *ref)
{
	return ref->name;
}

const struct ref *get_ref_peer_ref(const struct ref *ref)
{
	return ref->peer_ref;
}

const char *get_worktree_path(const struct worktree *wr)
{
	return wr->path;
}

int get_worktree_is_current(const struct worktree *wr)
{
	return wr->is_current;
}

int get_worktree_is_detached(const struct worktree *wr)
{
	return wr->is_detached;
}

const struct object_id *get_worktree_head_oid(const struct worktree *wr)
{
	return &wr->head_oid;
}

extern NORETURN void do_panic(const char *err, size_t len);

static NORETURN void die_panic(const char *err, va_list params)
{
	char msg[4096];
	int len = vsnprintf(msg, sizeof(msg), err, params);
	do_panic(msg, (size_t)(len < 0) ? 0 : len);
}

int init_cinnabar(const char *argv0)
{
	int nongit = 0;

	set_die_routine(die_panic);

	// Initialization from common-main.c.
	sanitize_stdfds();
	restore_sigpipe_to_default();

	git_resolve_executable_dir(argv0);

	git_setup_gettext();

	initialize_the_repository();

	attr_start();

	init_git_config();
	setup_git_directory_gently(&nongit);
	git_config(git_diff_basic_config, NULL);
	cleanup_git_config(nongit);
	save_commit_buffer = 0;
	warn_on_object_refname_ambiguity = 0;

	// In git 2.44, git clone doesn't create a repository that
	// setup_git_directory_gently will recognize as a git directory.
	// The first indicator that we might be in a git clone is that
	// GIT_DIR is set.
	if (getenv("GIT_DIR") != NULL) {
		if (nongit) {
			// If GIT_DIR is set and setup_git_directory_gently
			// says we're not in a git directory, assume we're in
			// that weird git 2.44 case.
			struct strbuf err = STRBUF_INIT;
			check_repository_format(NULL);
			if (refs_init_db(get_main_ref_store(the_repository),
			                 0, &err))
				die("failed to set up refs db: %s", err.buf);
			nongit = 0;
		} else {
			// To make things even gnarlier, git 2.45 hits a case
			// where it will print an irrelevant hint because of the
			// HEAD it created itself. Removing that HEAD works
			// around the problem, so try to detect it.
			// See http://public-inbox.org/git/20240503020432.2fxwuhjsvumy7i7z@glandium.org/
			struct strbuf head = STRBUF_INIT;
			struct strbuf buf = STRBUF_INIT;
			git_path_buf(&head, "HEAD");
			if (strbuf_read_file(&buf, head.buf, 0) > 0) {
				const char invalid_head_s[] =
					"ref: refs/heads/.invalid\n";
				struct strbuf invalid_head = {
					.buf = (char*)invalid_head_s,
					.len = sizeof(invalid_head_s) - 1,
					.alloc = 0
				};
				if (strbuf_cmp(&invalid_head, &buf) == 0) {
					unlink(head.buf);
				}
			}
			strbuf_release(&head);
			strbuf_release(&buf);
		}
	}
	return !nongit;
}

int common_exit(const char *file, int line, int code)
{
	return code;
}
