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

/* The git storage for a mercurial manifest used to be a commit with two
 * directories at its root:
 * - a git directory, matching the git tree in the git commit corresponding to
 *   the mercurial changeset using the manifest.
 * - a hg directory, containing the same file paths, but where all pointed
 *   objects are commits (mode 160000 in the git tree) whose sha1 is actually
 *   the mercurial sha1 for the corresponding mercurial file.
 * Reconstructing the mercurial manifest required file paths, mercurial sha1
 * for each file, and the corresponding attribute ("l" for symlinks, "x" for
 * executables"). The hg directory alone was not enough for that, because it
 * lacked the attribute information.
 */
static void track_tree(struct tree *tree, struct object_list **tree_list)
{
	if (tree_list) {
		object_list_insert(&tree->object, tree_list);
		tree->object.flags |= SEEN;
	}
}

struct manifest_tree_state {
	struct tree *tree;
	struct tree_desc desc;
};

static int manifest_tree_state_init(const struct object_id *tree_id,
                                    struct manifest_tree_state *result,
                                    struct object_list **tree_list)
{
	result->tree = parse_tree_indirect(tree_id);
	if (!result->tree)
		return -1;
	track_tree(result->tree, tree_list);

	init_tree_desc(&result->desc, result->tree->buffer,
	               result->tree->size);
	return 0;
}

struct merge_manifest_tree_state {
	struct manifest_tree_state state_a, state_b;
	struct name_entry entry_a, entry_b;
	struct strslice entry_a_path, entry_b_path;
	int cmp;
};

struct merge_name_entry {
	struct name_entry *entry_a, *entry_b;
	struct strslice path;
};

static int merge_manifest_tree_state_init(const struct object_id *tree_id_a,
                                          const struct object_id *tree_id_b,
                                          struct merge_manifest_tree_state *result,
                                          struct object_list **tree_list)
{
	int ret;
	memset(result, 0, sizeof(*result));
	result->cmp = 0;

	if (tree_id_a) {
		ret = manifest_tree_state_init(tree_id_a, &result->state_a, tree_list);
		if (ret)
			return ret;
	} else {
		result->entry_a_path = empty_strslice();
		result->cmp = 1;
	}
	if (tree_id_b) {
		return manifest_tree_state_init(tree_id_b, &result->state_b, tree_list);
	} else if (result->cmp == 0) {
		result->entry_b_path = empty_strslice();
		result->cmp = -1;
		return 0;
	}
	return 1;
}

static int merge_tree_entry(struct merge_manifest_tree_state *state,
                            struct merge_name_entry *entries)
{
	if (state->cmp <= 0) {
		if (tree_entry(&state->state_a.desc, &state->entry_a)) {
			state->entry_a_path = strslice_from_str(state->entry_a.path);
		} else {
			state->entry_a_path = empty_strslice();
		}
	}
	if (state->cmp >= 0) {
		if (tree_entry(&state->state_b.desc, &state->entry_b)) {
			state->entry_b_path = strslice_from_str(state->entry_b.path);
		} else {
			state->entry_b_path = empty_strslice();
		}
	}
	if (!state->entry_a_path.len) {
		if (!state->entry_b_path.len)
			return 0;
		state->cmp = 1;
	} else if (!state->entry_b_path.len) {
		state->cmp = -1;
	} else {
		state->cmp = base_name_compare(
			state->entry_a_path.buf, state->entry_a_path.len, state->entry_a.mode,
			state->entry_b_path.buf, state->entry_b_path.len, state->entry_b.mode);
	}
	if (state->cmp <= 0) {
		entries->entry_a = &state->entry_a;
		entries->path = state->entry_a_path;
	} else {
		entries->entry_a = NULL;
	}
	if (state->cmp >= 0) {
		entries->entry_b = &state->entry_b;
		entries->path = state->entry_b_path;
	} else {
		entries->entry_b = NULL;
	}
	return 1;
}

static struct name_entry *
lazy_tree_entry_by_name(struct manifest_tree_state *state,
                        const struct object_id *tree_id,
                        const char *path)
{
	int cmp;

	if (!tree_id)
		return NULL;

	if (!state->tree) {
		if (manifest_tree_state_init(tree_id, state, NULL))
			return NULL;
	}

	while (state->desc.size &&
	       (cmp = strcmp(state->desc.entry.path, path)) < 0)
		update_tree_entry(&state->desc);

	if (state->desc.size && cmp == 0)
		return &state->desc.entry;

	return NULL;
}

struct oid_map_entry {
	struct hashmap_entry ent;
	struct object_id old_oid;
	struct object_id new_oid;
};

static int oid_map_entry_cmp(const void *cmpdata, const struct hashmap_entry *e1,
                             const struct hashmap_entry *e2, const void *keydata)
{
	const struct oid_map_entry *entry1 =
		container_of(e1, const struct oid_map_entry, ent);
	const struct oid_map_entry *entry2 =
		container_of(e2, const struct oid_map_entry, ent);

	return oidcmp(&entry1->old_oid, &entry2->old_oid);
}

static void recurse_create_git_tree(const struct object_id *tree_id,
                                    const struct object_id *reference,
                                    const struct object_id *merge_tree_id,
                                    struct object_id *result,
				    struct hashmap *cache)
{
	struct oid_map_entry k, *cache_entry = NULL;

	if (!merge_tree_id) {
		hashmap_entry_init(&k.ent, oidhash(tree_id));
		oidcpy(&k.old_oid, tree_id);
		cache_entry = hashmap_get_entry(cache, &k, ent, NULL);
	}
	if (!cache_entry) {
		struct merge_manifest_tree_state state;
		struct manifest_tree_state ref_state = { NULL, };
		struct merge_name_entry entries;
		struct strbuf tree_buf = STRBUF_INIT;

		if (merge_manifest_tree_state_init(tree_id, merge_tree_id, &state, NULL))
			goto corrupted;

		while (merge_tree_entry(&state, &entries)) {
			struct object_id oid;
			struct name_entry *entry = entries.entry_a ? entries.entry_a : entries.entry_b;
			unsigned mode = entry->mode;
			struct strslice entry_path;
			struct strslice underscore = { 1, "_" };
			if (!strslice_startswith(entries.path, underscore))
				goto corrupted;
			entry_path = strslice_slice(entries.path, 1, SIZE_MAX);
			// In some edge cases, presumably all related to the use of
			// `hg convert` before Mercurial 2.0.1, manifest trees have
			// double slashes, which end up as "_" directories in the
			// corresponding git cinnabar metadata.
			// With further changes in the subsequent Mercurial manifests,
			// those entries with double slashes are superseded with entries
			// with single slash, while still being there. So to create
			// the corresponding git commit, we need to merge both in some
			// manner.
			// Mercurial doesn't actually guarantee which of the paths would
			// actually be checked out when checking out such manifests,
			// but we always choose the single slash path. Most of the time,
			// though, both will have the same contents. At least for files.
			// Sub-directories may differ in what paths they contain, but
			// again, the files they contain are usually identical.
			if (entry_path.len == 0) {
				if (!S_ISDIR(mode))
					goto corrupted;
				if (merge_tree_id)
					continue;
				recurse_create_git_tree(
					tree_id, reference, &entry->oid, result, cache);
				goto cleanup;
			} else if (S_ISDIR(mode)) {
				struct name_entry *ref_entry;
				ref_entry = lazy_tree_entry_by_name(
					&ref_state, reference, entry_path.buf);
				recurse_create_git_tree(
					&entry->oid,
					ref_entry ? &ref_entry->oid : NULL,
					(entries.entry_b && S_ISDIR(entries.entry_b->mode))
						? &entries.entry_b->oid : NULL,
					&oid, cache);
			} else {
				const struct object_id *file_oid;
				struct hg_object_id hg_oid;
				oidcpy2hg(&hg_oid, &entry->oid);
				if (is_empty_hg_file(&hg_oid))
					file_oid = ensure_empty_blob();
				else
					file_oid = resolve_hg2git(&hg_oid);
				if (!file_oid)
					goto corrupted;
				oidcpy(&oid, file_oid);
				mode &= 0777;
				if (!mode)
					mode = S_IFLNK;
				else
					mode = S_IFREG | mode;
			}
			strbuf_addf(&tree_buf, "%o ", canon_mode(mode));
			strbuf_addslice(&tree_buf, entry_path);
			strbuf_addch(&tree_buf, '\0');
			strbuf_add(&tree_buf, oid.hash, 20);
		}

		if (!merge_tree_id) {
			cache_entry = xmalloc(sizeof(k));
			cache_entry->ent = k.ent;
			cache_entry->old_oid = k.old_oid;
		}
		store_git_tree(&tree_buf, reference, cache_entry ? &cache_entry->new_oid : result);
		strbuf_release(&tree_buf);
		if (!merge_tree_id) {
			hashmap_add(cache, &cache_entry->ent);
		}

cleanup:
		if (state.state_a.tree)
			free_tree_buffer(state.state_a.tree);
		if (state.state_b.tree)
			free_tree_buffer(state.state_b.tree);
		if (ref_state.tree)
			free_tree_buffer(ref_state.tree);
	}
	if (result && cache_entry)
		oidcpy(result, &cache_entry->new_oid);
	return;

corrupted:
	die("Corrupt mercurial metadata");
}

static struct hashmap git_tree_cache;

void create_git_tree(const struct object_id *tree_id,
                     const struct object_id *ref_tree,
                     struct object_id *result)
{
	recurse_create_git_tree(tree_id, ref_tree, NULL, result, &git_tree_cache);
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

extern void init_metadata(struct commit *c);

extern void reset_changeset_heads(void);
extern void reset_manifest_heads(void);

void do_reload(struct object_id *oid)
{
	struct commit *c = NULL;

	done_cinnabar();
	hashmap_init(&git_tree_cache, oid_map_entry_cmp, NULL, 0);

	reset_replace_map();
	if (oid) {
		if (!is_null_oid(oid)) {
			c = lookup_commit_reference(the_repository, oid);
		}
	} else {
		c = lookup_commit_reference_by_name(METADATA_REF);
	}
	init_metadata(c);
	reset_changeset_heads();
	reset_manifest_heads();
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

static void cleanup_git_config(void)
{
	const char *value;
	if (!git_config_get_value("cinnabar.fsck", &value)) {
		// We used to set cinnabar.fsck globally, then locally.
		// Remove both.
		char *user_config, *xdg_config;
		git_global_config(&user_config, &xdg_config);
		if (user_config) {
			if (access_or_warn(user_config, R_OK, 0) &&
				xdg_config &&
				!access_or_warn(xdg_config, R_OK, 0))
			{
				git_config_set_in_file_gently(
					xdg_config, "cinnabar.fsck", NULL);
			} else {
				git_config_set_in_file_gently(
					user_config, "cinnabar.fsck", NULL);
			}
		}
		free(user_config);
		free(xdg_config);
		user_config = git_pathdup("config");
		if (user_config) {
			git_config_set_in_file_gently(
				user_config, "cinnabar.fsck", NULL);
		}
		free(user_config);
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

static int nongit = 0;

extern NORETURN void do_panic(const char *err, size_t len);

static NORETURN void die_panic(const char *err, va_list params)
{
	char msg[4096];
	int len = vsnprintf(msg, sizeof(msg), err, params);
	do_panic(msg, (size_t)(len < 0) ? 0 : len);
}

void init_cinnabar(const char *argv0)
{
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
	cleanup_git_config();
	save_commit_buffer = 0;
	warn_on_object_refname_ambiguity = 0;
}

int init_cinnabar_2(void)
{
	struct commit *c;
	if (nongit) {
		return 0;
	}
	c = lookup_commit_reference_by_name(METADATA_REF);
	init_metadata(c);
	hashmap_init(&git_tree_cache, oid_map_entry_cmp, NULL, 0);
	return 1;
}

extern void done_metadata(void);

void done_cinnabar(void)
{
	done_metadata();
	hashmap_clear_and_free(&git_tree_cache, struct oid_map_entry, ent);
}

int common_exit(const char *file, int line, int code)
{
	return code;
}
