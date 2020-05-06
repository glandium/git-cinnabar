/* Helper program for git-cinnabar
 *
 * It receives commands on stdin and outputs results on stdout.
 * The following commands are supported:
 * - git2hg <committish>
 *     Returns the contents of the git note containing git->hg metadata
 *     for the given commit in a `cat-file --batch`-like format.
 * - hg2git <hg_sha1>
 *     Returns the sha1 of the git object corresponding to the given
 *     mercurial sha1.
 * - manifest <hg_sha1>
 *     Returns the contents of the mercurial manifest with the given
 *     mercurial sha1, preceded by its length in text form, and followed
 *     by a carriage return.
 * - check-manifest <hg_sha1>
 *     Returns 'ok' when the sha1 of the contents of the mercurial manifest
 *     matches the manifest sha1, otherwise returns 'error'.
 * - cat-file <object>
 *     Returns the contents of the given git object, in a `cat-file
 *     --batch`-like format.
 *  - connect <url>
 *     Connects to the mercurial repository at the given url. The helper then
 *     expects one of the following commands:
 *     - state
 *       This prints out three blocks of data, being the result of the
 *       following commands on the repository: branchmap, heads, bookmarks.
 *     - known <node>+
 *       Calls the "known" command on the repository and returns the
 *       corresponding result.
 *     - listkeys <namespace>
 *     	 Calls the "listkeys" command on the repository and returns the
 *     	 corresponding result.
 *     - getbundle <heads> <common> <bundle2caps>
 *       Calls the "getbundle" command on the repository and streams a
 *       changegroup in result. `heads` and `common` are comma separated
 *       lists of changesets.
 *     - unbundle <head>+
 *       Calls the "unbundle command on the repository.
 *     - pushkey <namespace> <key> <old> <new>
 *     	 Calls the "pushkey" command on the repository and returns the
 *     	 corresponding result.
 *     - lookup <key>
 *       Calls the "lookup" command on the repository and returns the
 *     	 corresponding result.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "attr.h"
#include "blob.h"
#include "commit.h"
#include "config.h"
#include "diff.h"
#include "diffcore.h"
#include "exec-cmd.h"
#include "hashmap.h"
#include "log-tree.h"
#include "strslice.h"
#include "strbuf.h"
#include "string-list.h"
#include "streaming.h"
#include "object.h"
#include "oidset.h"
#include "progress.h"
#include "quote.h"
#include "replace-object.h"
#include "revision.h"
#include "tree.h"
#include "tree-walk.h"
#include "hg-connect.h"
#include "hg-data.h"
#include "cinnabar-helper.h"
#include "cinnabar-fast-import.h"
#include "cinnabar-notes.h"
#include "which.h"

#define _STRINGIFY(s) # s
#define STRINGIFY(s) _STRINGIFY(s)

#define CMD_VERSION 3006
#define MIN_CMD_VERSION 3003

static const char NULL_NODE[] = "0000000000000000000000000000000000000000";

#define MODE_IMPORT 0x01
#define MODE_WIRE 0x02

static int mode = 0xff; // Enable everything by default

struct notes_tree git2hg, hg2git, files_meta;

// XXX: Should use a hg-specific oidset type.
struct oidset hg2git_seen = OIDSET_INIT;

int metadata_flags = 0;
int cinnabar_check = 0;
int cinnabar_experiments = 0;

FILE* get_stdin() {
	return stdin;
}

static int config(const char *name, struct strbuf *result)
{
	struct strbuf key = STRBUF_INIT;
	char *p, *end;
	const char *val;

	strbuf_addstr(&key, "GIT_CINNABAR_");
	strbuf_addstr(&key, name);
	for (p = key.buf + sizeof("git_cinnabar"), end = key.buf + key.len;
	     p < end; p++)
		*p = toupper(*p);
	val = getenv(key.buf);
	if (!val) {
		strbuf_release(&key);
		strbuf_addstr(&key, "cinnabar.");
		strbuf_addstr(&key, name);
		if (git_config_get_value(key.buf, &val)) {
			strbuf_release(&key);
			return 1;
		}
	}
	strbuf_addstr(result, val);
	strbuf_release(&key);
	return 0;
}

static int cleanup_object_array_entry(struct object_array_entry *entry, void *data)
{
	if (entry->item->type == OBJ_TREE)
		free_tree_buffer((struct tree *)entry->item);
	return 1;
}

static void rev_info_release(struct rev_info *revs)
{
	int i;

	object_array_filter(&revs->pending, cleanup_object_array_entry, NULL);
	object_array_clear(&revs->pending);
	object_array_clear(&revs->boundary_commits);
	for (i = 0; i < revs->cmdline.nr; i++)
		free((void *)revs->cmdline.rev[i].name);
	free(revs->cmdline.rev);
	clear_pathspec(&revs->prune_data);
	clear_pathspec(&revs->pruning.pathspec);
	clear_pathspec(&revs->diffopt.pathspec);
	revs->cmdline.rev = NULL;
	for (i = 0; i < revs->treesame.size; i++)
		if (revs->treesame.entries[i].base)
			free(revs->treesame.entries[i].decoration);
	free(revs->treesame.entries);
}

static void split_command(char *line, const char **command,
			  struct string_list *args)
{
	struct string_list split_line = STRING_LIST_INIT_NODUP;
	string_list_split_in_place(&split_line, line, ' ', 1);
	*command = split_line.items[0].string;
	if (split_line.nr > 1)
		string_list_split_in_place(
			args, split_line.items[1].string, ' ', -1);
	string_list_clear(&split_line, 0);
}

extern void send_buffer(struct strbuf *buf);

/* Send git object info and content to stdout, like cat-file --batch does. */
static void send_object(const struct object_id *oid)
{
	struct strbuf header = STRBUF_INIT;
	enum object_type type;
	unsigned long sz;
	struct git_istream *st;

	st = open_istream(the_repository, oid, &type, &sz, NULL);

	if (!st)
		die("open_istream failed for %s", oid_to_hex(oid));

	strbuf_addf(&header, "%s %s %lu\n", oid_to_hex(oid), type_name(type),
	            sz);

	write_or_die(1, header.buf, header.len);

	strbuf_release(&header);

	for (;;) {
		char buf[1024 * 16];
		ssize_t wrote;
		ssize_t readlen = read_istream(st, buf, sizeof(buf));

		if (readlen <= 0)
			break;

		wrote = write_in_full(1, buf, readlen);
		if (wrote < readlen)
			break;

		sz -= wrote;
	}

	if (sz != 0)
		die("Failed to write object");

	write_or_die(1, "\n", 1);

	close_istream(st);
}

static void do_cat_file(struct string_list *args)
{
	struct object_id oid;

	if (args->nr != 1)
		goto not_found;

	if (get_oid(args->items[0].string, &oid))
		goto not_found;

	send_object(&oid);
	return;

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

struct ls_tree_context {
	struct strbuf buf;
	struct object_list *list;
	int recursive;
};

static int fill_ls_tree(const struct object_id *oid, struct strbuf *base,
			const char *pathname, unsigned mode, int stage,
			void *context)
{
	struct ls_tree_context *ctx = context;
	struct strbuf *buf = &ctx->buf;
	const char *type = blob_type;

	if (S_ISGITLINK(mode)) {
		type = commit_type;
	} else if (S_ISDIR(mode)) {
		object_list_insert((struct object *)lookup_tree(the_repository, oid),
		                   &ctx->list);
		if (ctx->recursive)
			return READ_TREE_RECURSIVE;
		type = tree_type;
	}

	strbuf_addf(buf, "%06o %s %s\t", mode, type, oid_to_hex(oid));
	strbuf_addbuf(buf, base);
	strbuf_addstr(buf, pathname);
	strbuf_addch(buf, '\0');
	return 0;
}

static void do_ls_tree(struct string_list *args)
{
	struct object_id oid;
	struct tree *tree = NULL;
	struct ls_tree_context ctx = { STRBUF_INIT, NULL, 0 };
	struct pathspec match_all;

	if (args->nr == 2) {
		if (strcmp(args->items[1].string, "-r"))
			goto not_found;
		ctx.recursive = 1;
	} else if (args->nr != 1)
		goto not_found;

	if (get_oid(args->items[0].string, &oid))
		goto not_found;

	tree = parse_tree_indirect(&oid);
	if (!tree)
		goto not_found;

	memset(&match_all, 0, sizeof(match_all));
	read_tree_recursive(the_repository, tree, "", 0, 0, &match_all,
	                    fill_ls_tree, &ctx);
	send_buffer(&ctx.buf);
	strbuf_release(&ctx.buf);

	while (ctx.list) {
		struct object *obj = ctx.list->item;
		struct object_list *elem = ctx.list;
		ctx.list = elem->next;
		free(elem);
		free_tree_buffer((struct tree *)obj);
	}
	return;
not_found:
	write_or_die(1, "0\n\n", 3);
}

static const char **string_list_to_argv(struct string_list *args)
{
	const char **argv = malloc(sizeof(char *) * (args->nr + 2));
	int i;

	argv[0] = "";
	for (i = 0; i < args->nr; i++) {
		argv[i + 1] = args->items[i].string;
	}
	argv[args->nr + 1] = NULL;

	return argv;
}

static void do_rev_list(struct string_list *args)
{
	struct rev_info revs;
	struct commit *commit;
	struct strbuf buf = STRBUF_INIT;
	const char **argv = string_list_to_argv(args);

	init_revisions(&revs, NULL);
	// Note: we do a pass through, but don't make much effort to actually
	// support all the options properly.
	setup_revisions(args->nr + 1, argv, &revs, NULL);
	free(argv);

	// Hack to force simplify_commit to save parents. full_diff is only
	// checked for there or in setup_revisions so there is no other side
	// effect.
	revs.full_diff = 1;

	if (prepare_revision_walk(&revs))
		die("revision walk setup failed");

	while ((commit = get_revision(&revs)) != NULL) {
		struct commit_list *parent;
		if (commit->object.flags & BOUNDARY)
			strbuf_addch(&buf, '-');
		strbuf_addstr(&buf, oid_to_hex(&commit->object.oid));
		strbuf_addch(&buf, ' ');
		strbuf_addstr(&buf, oid_to_hex(get_commit_tree_oid(commit)));
		parent = commit->parents;
		while (parent) {
			strbuf_addch(&buf, ' ');
			strbuf_addstr(&buf, oid_to_hex(
				&parent->item->object.oid));
			parent = parent->next;
		}
		strbuf_addch(&buf, '\n');

		// If parents were altered by simplify_commit, we want to
		// restore them for any subsequent operation on the commit.
		//
		// get_saved_parents returning NULL means there is no saved
		// parents for the commit. If there was a saved value of null,
		// it would mean the commit was a root in the first place, but
		// then why would it have been saved?
		parent = get_saved_parents(&revs, commit);
		if (parent && parent != commit->parents) {
			free_commit_list(commit->parents);
			commit->parents = copy_commit_list(parent);
		}
	}

	// More extensive than reset_revision_walk(). Otherwise --boundary
	// and pathspecs don't work properly.
	clear_object_flags(ALL_REV_FLAGS | TOPO_WALK_EXPLORED | TOPO_WALK_INDEGREE);
	send_buffer(&buf);
	strbuf_release(&buf);
	rev_info_release(&revs);
}

static void strbuf_diff_tree(struct diff_queue_struct *q,
                             struct diff_options *opt, void *data)
{
	struct strbuf *buf = data;
	int i;

	for (i = 0; i < q->nr; i++) {
		struct diff_filepair *p = q->queue[i];
		if (p->status == 0)
			die("internal diff status error");
		if (p->status == DIFF_STATUS_UNKNOWN)
			continue;
		strbuf_addf(buf, "%06o %06o %s %s %c",
		            p->one->mode,
		            p->two->mode,
		            oid_to_hex(&p->one->oid),
		            oid_to_hex(&p->two->oid),
		            p->status);
		if (p->score)
			strbuf_addf(buf, "%03d",
			            (int)(p->score * 100 / MAX_SCORE));
		strbuf_addch(buf, '\t');
		if (p->status == DIFF_STATUS_COPIED ||
		    p->status == DIFF_STATUS_RENAMED) {
			strbuf_addstr(buf, p->one->path);
			strbuf_addch(buf, '\0');
			strbuf_addstr(buf, p->two->path);
		} else {
			strbuf_addstr(buf, p->one->mode ? p->one->path
			                                : p->two->path);
		}
		strbuf_addch(buf, '\0');
	}
}

static void do_diff_tree(struct string_list *args)
{
	struct rev_info revs;
	struct strbuf buf = STRBUF_INIT;
	const char **argv = string_list_to_argv(args);

	init_revisions(&revs, NULL);
	revs.diff = 1;
	// Note: we do a pass through, but don't make much effort to actually
	// support all the options properly.
	setup_revisions(args->nr + 1, argv, &revs, NULL);
	revs.diffopt.output_format = DIFF_FORMAT_CALLBACK;
	revs.diffopt.format_callback = strbuf_diff_tree;
	revs.diffopt.format_callback_data = &buf;
	revs.diffopt.flags.recursive = 1;
	free(argv);

	if (revs.pending.nr != 2)
		die("diff-tree needs two revs");

	diff_tree_oid(&revs.pending.objects[0].item->oid,
	              &revs.pending.objects[1].item->oid,
	              "", &revs.diffopt);
	log_tree_diff_flush(&revs);
	send_buffer(&buf);
	strbuf_release(&buf);
	rev_info_release(&revs);
}

void ensure_notes(struct notes_tree *notes)
{
	if (!notes_initialized(notes)) {
		const char *ref;
		int flags = 0;
		if (notes == &git2hg)
			ref = NOTES_REF;
		else if (notes == &hg2git)
			ref = HG2GIT_REF;
		else if (notes == &files_meta) {
			ref = FILES_META_REF;
			if (!(metadata_flags & FILES_META))
				flags = NOTES_INIT_EMPTY;
		} else
			die("Unknown notes tree");
		init_notes(notes, ref, combine_notes_ignore, flags);
	}
}

const struct object_id *repo_lookup_replace_object(
	struct repository *r, const struct object_id *oid)
{
	return lookup_replace_object(r, oid);
}

static void do_get_note(struct notes_tree *t, struct string_list *args)
{
	struct object_id oid;
	const struct object_id *note;

	if (args->nr != 1)
		goto not_found;

	ensure_notes(t);

	if (get_oid_committish(args->items[0].string, &oid))
		goto not_found;

	note = get_note(t, lookup_replace_object(the_repository, &oid));
	if (!note)
		goto not_found;

	send_object(note);
	return;

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

static size_t get_abbrev_sha1_hex(const char *hex, unsigned char *sha1)
{
	const char *hex_start = hex;
	unsigned char *end = sha1 + 20;
	while (sha1 < end) {
		unsigned int val;
		if (!hex[0])
			val = 0xff;
		else if (!hex[1])
			val = (hexval(hex[0]) << 4) | 0xf;
		else
			val = (hexval(hex[0]) << 4) | hexval(hex[1]);
		if (val & ~0xff)
			return 0;
		*sha1++ = val;
		if (!hex[0] || !hex[1])
			break;
		hex += 2;
	}
	while (sha1 < end) {
		*sha1++ = 0xff;
	}
	return hex - hex_start + !!hex[0];
}

const struct object_id *resolve_hg(
	struct notes_tree* tree, const struct hg_object_id *oid, size_t len)
{
	struct object_id git_oid;
	const struct object_id *note;

	ensure_notes(tree);

	note = get_note_hg(tree, oid);
	if (len == 40)
		return note;

	hg_oidcpy2git(&git_oid, oid);
	return get_abbrev_note(tree, &git_oid, len);
}

const struct object_id *resolve_hg2git(const struct hg_object_id *oid,
                                       size_t len)
{
	return resolve_hg(&hg2git, oid, len);
}

static void do_hg2git(struct string_list *args)
{
        struct hg_object_id oid;
	const struct object_id *note;
	size_t sha1_len;

	if (args->nr != 1)
		goto not_found;

	sha1_len =  get_abbrev_sha1_hex(args->items[0].string, oid.hash);
	if (!sha1_len)
		goto not_found;

	note = resolve_hg2git(&oid, sha1_len);
	if (note) {
		write_or_die(1, oid_to_hex(note), 40);
		write_or_die(1, "\n", 1);
		return;
	}

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

/* The git storage for a mercurial manifest uses not-entirely valid file modes
 * to keep the mercurial manifest data as git trees.
 * While mercurial manifests are flat, the corresponding git tree uses
 * sub-directories. The file sha1s are stored as git links (since they're not
 * valid git sha1s), and the file modes are stored as extra bits in the git
 * link file mode, that git normally ignores.
 * - Symlinks are set to have a file mode of 0160000 (standard git link).
 * - Executables are set to have a file mode of 0160755.
 * - Regular files are set to have a file mode of 0160644.
 */

/* Return the mercurial manifest character corresponding to the given
 * git file mode. */
static const char *hgattr(unsigned int mode)
{
	if (S_ISGITLINK(mode)) {
		if ((mode & 0755) == 0755)
			return "x";
		else if ((mode & 0644) == 0644)
			return "";
		else if ((mode & 0777) == 0)
			return "l";
	}
	die("Unsupported mode %06o", mode);
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

/* Return whether two entries have matching sha1s and modes */
static int manifest_entry_equal(const struct name_entry *e1,
                                const struct name_entry *e2)
{
	return (e1->mode == e2->mode) && (oidcmp(&e1->oid, &e2->oid) == 0);
}

/* Return whether base + name matches path */
static int path_match(struct strslice base, struct strslice name,
                      struct strslice path)
{
	struct strslice slice;

	if (!strslice_startswith(path, base) ||
	    !strslice_startswith(strslice_slice(path, base.len, SIZE_MAX),
	                         name))
		return 0;

	slice = strslice_slice(path, name.len + base.len, 1);
	return slice.len == 1 && (slice.buf[0] == '\0' || slice.buf[0] == '/');
}

static void recurse_manifest(const struct object_id *ref_tree_id,
                             struct strslice ref_manifest,
                             const struct object_id *tree_id,
                             struct strbuf *manifest, struct strslice base,
                             struct object_list **tree_list)
{
	struct merge_manifest_tree_state state;
	struct merge_name_entry entries;
	struct strslice cursor;
	struct strslice underscore = { 1, "_" };
	struct strbuf dir = STRBUF_INIT;

	if (merge_manifest_tree_state_init(ref_tree_id, tree_id, &state, tree_list))
		goto corrupted;

	while (merge_tree_entry(&state, &entries)) {
		if (!strslice_startswith(entries.path, underscore))
			goto corrupted;
		cursor = ref_manifest;
		if (entries.entry_a) {
			size_t len = base.len + entries.path.len + 40;
			do {
				strslice_split_once(&ref_manifest, '\n');
			} while (S_ISDIR(entries.entry_a->mode) &&
			         (ref_manifest.len > len) &&
			         path_match(base, strslice_slice(
					entries.path, 1, SIZE_MAX), ref_manifest));
		}
		/* File/directory was removed, nothing to do */
		if (!entries.entry_b)
			continue;
		/* File/directory didn't change, copy from the reference
		 * manifest. */
		if (entries.entry_a && entries.entry_b &&
		    manifest_entry_equal(entries.entry_a, entries.entry_b)) {
			strbuf_add(manifest, cursor.buf,
			           cursor.len - ref_manifest.len);
			continue;
		}
		if (entries.entry_b && !S_ISDIR(entries.entry_b->mode)) {
			strbuf_addslice(manifest, base);
			strbuf_addslice(manifest, strslice_slice(
				entries.path, 1, SIZE_MAX));
			strbuf_addf(manifest, "%c%s%s\n", '\0',
			            oid_to_hex(&entries.entry_b->oid),
			            hgattr(entries.entry_b->mode));
			continue;
		}

		strbuf_addslice(&dir, base);
		strbuf_addslice(&dir, strslice_slice(
			entries.path, 1, SIZE_MAX));
		strbuf_addch(&dir, '/');
		if (entries.entry_a && entries.entry_b &&
                    S_ISDIR(entries.entry_a->mode)) {
			recurse_manifest(&entries.entry_a->oid, cursor,
				         &entries.entry_b->oid, manifest,
			                 strbuf_as_slice(&dir), tree_list);
		} else
			recurse_manifest(NULL, empty_strslice(),
			                 &entries.entry_b->oid, manifest,
			                 strbuf_as_slice(&dir), tree_list);
		strbuf_release(&dir);
	}

	return;
corrupted:
	die("Corrupted metadata");
}

struct manifest {
	struct object_id tree_id;
	struct strbuf content;
	struct object_list *tree_list;
};

#define MANIFEST_INIT { { { 0, } }, STRBUF_INIT, NULL }

/* For repositories with a lot of files, generating a manifest is a slow
 * operation.
 * In most cases, there are way less changes between changesets than there
 * are files in the repository, so it is much faster to generate a manifest
 * from a previously generated manifest, by applying the differences between
 * the corresponding trees.
 * Therefore, we always keep the last generated manifest.
 */
static struct manifest generated_manifest = MANIFEST_INIT;

/* The returned strbuf must not be released and/or freed. */
struct strbuf *generate_manifest(const struct object_id *oid)
{
	struct strbuf content = STRBUF_INIT;
	struct object_list *tree_list = NULL;

	/* We keep a list of all the trees we've seen while generating the
	 * previous manifest. Each tree is marked as SEEN at that time.
	 * Then, on the next manifest generation, we unmark them as SEEN,
	 * and the generation that follows will re-mark them if they are
	 * re-used. Trees that are not marked SEEN are subsequently freed.
	 */
	struct object_list *previous_list = generated_manifest.tree_list;
	while (previous_list) {
		previous_list->item->flags &= ~SEEN;
		previous_list = previous_list->next;
	}

	if (oidcmp(&generated_manifest.tree_id, oid) == 0) {
		return &generated_manifest.content;
	}

	if (generated_manifest.content.len) {
		struct strslice gm;
		gm = strbuf_slice(&generated_manifest.content, 0, SIZE_MAX);
		strbuf_grow(&content, generated_manifest.content.alloc - 1);
		recurse_manifest(&generated_manifest.tree_id, gm,
		                 oid, &content, empty_strslice(), &tree_list);
	} else {
		recurse_manifest(NULL, empty_strslice(), oid, &content,
		                 empty_strslice(), &tree_list);
	}

	oidcpy(&generated_manifest.tree_id, oid);
	strbuf_swap(&content, &generated_manifest.content);
	strbuf_release(&content);

	previous_list = generated_manifest.tree_list;
	generated_manifest.tree_list = tree_list;

	while (previous_list) {
		struct object *obj = previous_list->item;
		struct object_list *elem = previous_list;
		previous_list = elem->next;
		free(elem);
		if (!(obj->flags & SEEN))
			free_tree_buffer((struct tree *)obj);
	}
	return &generated_manifest.content;
}

static void do_manifest(struct string_list *args)
{
	struct hg_object_id hg_oid;
	struct object_id oid;
	const struct object_id *manifest_oid;
	struct strbuf *manifest = NULL;
	size_t sha1_len;

	if (args->nr != 1)
		goto not_found;

	if (!strncmp(args->items[0].string, "git:", 4)) {
		if (get_oid_hex(args->items[0].string + 4, &oid))
			goto not_found;
		manifest_oid = &oid;
	} else {
		sha1_len = get_abbrev_sha1_hex(args->items[0].string, hg_oid.hash);
		if (!sha1_len)
			goto not_found;

		manifest_oid = resolve_hg2git(&hg_oid, sha1_len);
		if (!manifest_oid)
			goto not_found;
	}

	manifest = generate_manifest(manifest_oid);
	if (!manifest)
		goto not_found;

	send_buffer(manifest);
	return;

not_found:
	write_or_die(1, "0\n\n", 3);
}

static void get_manifest_oid(const struct commit *commit, struct hg_object_id *oid)
{
	const char *msg;
	const char *hex_sha1;

	msg = get_commit_buffer(commit, NULL);

	hex_sha1 = strstr(msg, "\n\n") + 2;

	if (get_sha1_hex(hex_sha1, oid->hash))
		hg_oidclr(oid);

	unuse_commit_buffer(commit, msg);
}

static void hg_sha1(struct strbuf *data, const struct hg_object_id *parent1,
                    const struct hg_object_id *parent2, struct hg_object_id *result)
{
	git_SHA_CTX ctx;

	if (!parent1)
		parent1 = &hg_null_oid;
	if (!parent2)
		parent2 = &hg_null_oid;

	git_SHA1_Init(&ctx);

	if (hg_oidcmp(parent1, parent2) < 0) {
		git_SHA1_Update(&ctx, parent1, 20);
		git_SHA1_Update(&ctx, parent2, 20);
	} else {
		git_SHA1_Update(&ctx, parent2, 20);
		git_SHA1_Update(&ctx, parent1, 20);
	}

	git_SHA1_Update(&ctx, data->buf, data->len);

	git_SHA1_Final(result->hash, &ctx);
}

int check_manifest(const struct object_id *oid,
                   struct hg_object_id *hg_oid)
{
	struct hg_object_id parent1, parent2, stored, computed;
	const struct commit *manifest_commit;
	struct strbuf *manifest;

	manifest = generate_manifest(oid);
	if (!manifest)
		return 0;

	manifest_commit = lookup_commit(the_repository, oid);
	if (!manifest_commit)
		return 0;

	if (manifest_commit->parents) {
		get_manifest_oid(manifest_commit->parents->item, &parent1);
		if (manifest_commit->parents->next) {
			get_manifest_oid(manifest_commit->parents->next->item,
			                 &parent2);
		} else
			hg_oidclr(&parent2);
	} else {
		hg_oidclr(&parent1);
		hg_oidclr(&parent2);
	}

	if (!hg_oid)
		hg_oid = &computed;

	hg_sha1(manifest, &parent1, &parent2, hg_oid);

	get_manifest_oid(manifest_commit, &stored);

	return hg_oideq(&stored, hg_oid);
}

static void do_check_manifest(struct string_list *args)
{
	struct hg_object_id hg_oid, stored;
	struct object_id oid;
	const struct object_id *manifest_oid;

	if (args->nr != 1)
		goto error;

	if (!strncmp(args->items[0].string, "git:", 4)) {
		if (get_oid_hex(args->items[0].string + 4, &oid))
			goto error;
		manifest_oid = &oid;
	} else {
		if (get_sha1_hex(args->items[0].string, hg_oid.hash))
			goto error;

		manifest_oid = resolve_hg2git(&hg_oid, 40);
		if (!manifest_oid)
			goto error;
	}

	if (!check_manifest(manifest_oid, &stored))
		goto error;

	if (manifest_oid != &oid && !hg_oideq(&stored, &hg_oid))
		goto error;

	write_or_die(1, "ok\n", 3);
	return;
error:
	write_or_die(1, "error\n", 6);
}

static void do_check_file(struct string_list *args)
{
	struct hg_file file;
	struct hg_object_id oid, parent1, parent2, result;

	hg_file_init(&file);

	if (args->nr < 1 || args->nr > 3)
		goto error;

	if (get_sha1_hex(args->items[0].string, oid.hash))
		goto error;

	if (args->nr > 1) {
		if (get_sha1_hex(args->items[1].string, parent1.hash))
			goto error;
	} else
		hg_oidclr(&parent1);

	if (args->nr > 2) {
		if (get_sha1_hex(args->items[2].string, parent2.hash))
			goto error;
	} else
		hg_oidclr(&parent2);

	hg_file_load(&file, &oid);

	/* We do the quick and dirty thing here, for now.
	 * See details in cinnabar.githg.FileFindParents._set_parents_fallback
	 */
	hg_sha1(&file.file, &parent1, &parent2, &result);
	if (hg_oideq(&oid, &result))
		goto ok;

	hg_sha1(&file.file, &parent1, NULL, &result);
	if (hg_oideq(&oid, &result))
		goto ok;

	hg_sha1(&file.file, &parent2, NULL, &result);
	if (hg_oideq(&oid, &result))
		goto ok;

	hg_sha1(&file.file, &parent1, &parent1, &result);
	if (hg_oideq(&oid, &result))
		goto ok;

	hg_sha1(&file.file, NULL, NULL, &result);
	if (!hg_oideq(&oid, &result))
		goto error;

ok:
	write_or_die(1, "ok\n", 3);
	hg_file_release(&file);
	return;

error:
	write_or_die(1, "error\n", 6);
	hg_file_release(&file);
}

extern void get_helper_hash(struct strbuf *buf);

static void do_version(struct string_list *args)
{
	long int version;
	struct strbuf version_s = STRBUF_INIT;

	if (args->nr != 1)
		exit(1);

	version = strtol(args->items[0].string, NULL, 10);
	if (version < 100)
		version *= 100;

	if (!version || version < MIN_CMD_VERSION || version > CMD_VERSION)
		exit(128);

	get_helper_hash(&version_s);
	if (version >= 3000)
		strbuf_addf(&version_s, " " STRINGIFY(CMD_VERSION));
	strbuf_addch(&version_s, '\n');
	write_or_die(1, version_s.buf, version_s.len);
	strbuf_release(&version_s);
}

static void do_helpercaps(struct string_list *args)
{
	struct strbuf caps = STRBUF_INIT;

	if (args->nr != 0)
		die("helpercaps takes no arguments");

	if (mode & MODE_WIRE) {
		strbuf_addstr(&caps, "compression=UN,GZ,BZ,ZS");
	}

	if (cinnabar_experiments & EXPERIMENT_STORE) {
		if (caps.len)
			strbuf_addch(&caps, '\n');
		strbuf_addstr(&caps, "store=new");
	}

	send_buffer(&caps);
	strbuf_release(&caps);
}

static void string_list_as_oid_array(struct string_list *list,
				     struct oid_array *array)
{
	struct string_list_item *item;
	for_each_string_list_item(item, list) {
		struct object_id oid;
		if (!get_oid_hex(item->string, &oid))
			oid_array_append(array, &oid);
	}
}

extern void do_known(struct hg_connection *conn, struct string_list *args);

static void do_listkeys(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	if (args->nr != 1)
		exit(1);

	hg_listkeys(conn, &result, args->items[0].string);
	send_buffer(&result);
	strbuf_release(&result);
}

extern void do_getbundle(struct hg_connection *conn, struct string_list *args);

extern void do_unbundle(struct hg_connection *conn, struct string_list *args);

static void do_pushkey(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;

	if (args->nr != 4)
		exit(1);

	hg_pushkey(conn, &result, args->items[0].string, args->items[1].string,
		   args->items[2].string, args->items[3].string);
	send_buffer(&result);
	strbuf_release(&result);
}

static void do_capable(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	const char *result_str;

	if (args->nr != 1)
		exit(1);

	result_str = hg_get_capability(conn, args->items[0].string);
	if (result_str) {
		strbuf_addstr(&result, result_str);
		send_buffer(&result);
	} else {
		send_buffer(NULL);
	}
	strbuf_release(&result);
}

static void do_state(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf branchmap = STRBUF_INIT;
	struct strbuf heads = STRBUF_INIT;
	struct strbuf bookmarks = STRBUF_INIT;

	if (args->nr != 0)
		exit(1);

	hg_get_repo_state(conn, &branchmap, &heads, &bookmarks);
	send_buffer(&branchmap);
	send_buffer(&heads);
	send_buffer(&bookmarks);
	strbuf_release(&branchmap);
	strbuf_release(&heads);
	strbuf_release(&bookmarks);
}

static void do_lookup(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	if (args->nr != 1)
		exit(1);

	hg_lookup(conn, &result, args->items[0].string);
	send_buffer(&result);
	strbuf_release(&result);
}

static void do_clonebundles(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	if (args->nr != 0)
		exit(1);

	hg_clonebundles(conn, &result);
	send_buffer(&result);
	strbuf_release(&result);
}

static void do_cinnabarclone(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	if (args->nr != 0)
		exit(1);

	hg_cinnabarclone(conn, &result);
	send_buffer(&result);
	strbuf_release(&result);
}

static void connected_loop(struct hg_connection *conn)
{
	struct strbuf buf = STRBUF_INIT;

	while (strbuf_getline(&buf, stdin) != EOF) {
		struct string_list args = STRING_LIST_INIT_NODUP;
		const char *command;
		record_command(&buf);
		split_command(buf.buf, &command, &args);

		if (!*command) {
			string_list_clear(&args, 0);
			break;
		}
		if (!strcmp("known", command))
			do_known(conn, &args);
		else if (!strcmp("listkeys", command))
			do_listkeys(conn, &args);
		else if (!strcmp("getbundle", command))
			do_getbundle(conn, &args);
		else if (!strcmp("unbundle", command))
			do_unbundle(conn, &args);
		else if (!strcmp("pushkey", command))
			do_pushkey(conn, &args);
		else if (!strcmp("capable", command))
			do_capable(conn, &args);
		else if (!strcmp("state", command))
			do_state(conn, &args);
		else if (!strcmp("lookup", command))
			do_lookup(conn, &args);
		else if (!strcmp("clonebundles", command))
			do_clonebundles(conn, &args);
		else if (!strcmp("cinnabarclone", command))
			do_cinnabarclone(conn, &args);
		else
			die("Unknown command: \"%s\"", command);

		string_list_clear(&args, 0);
	}

	strbuf_release(&buf);
}

static void do_connect(struct string_list *args)
{
	const char *url;
	struct hg_connection *conn;

	if (args->nr != 1)
		return;

	url = args->items[0].string;

	conn = hg_connect(url, 0);

	// hg_connect either dies in case of connection failure,
	// or returns NULL, in which case it has sent out a stream
	// to stdout.
	if (conn) {
		write_or_die(1, "ok\n", 3);
		connected_loop(conn);

		hg_finish_connect(conn);
	}
}

static int add_each_head(const struct object_id *oid, void *data)
{
	struct strbuf *buf = data;

	strbuf_addstr(buf, oid_to_hex(oid));
	strbuf_addch(buf, '\n');
	return 0;
}

static void do_heads(struct string_list *args)
{
	//XXX: Should use hg specific oid array.
        struct oid_array *heads = NULL;
        struct strbuf heads_buf = STRBUF_INIT;

        if (args->nr != 1)
                die("heads needs 1 argument");

        if (!strcmp(args->items[0].string, "manifests")) {
                heads = &manifest_heads;
        } else
                die("Unknown kind: %s", args->items[0].string);

	ensure_heads(heads);
	oid_array_for_each_unique(heads, add_each_head, &heads_buf);
	send_buffer(&heads_buf);
	strbuf_release(&heads_buf);
}

static void reset_heads(struct oid_array *heads)
{
	oid_array_clear(heads);
	// We don't want subsequent ensure_heads to refill the array,
	// so mark it as sorted, which means it's initialized.
	heads->sorted = 1;
}

static void do_reset_heads(struct string_list *args)
{
        struct oid_array *heads = NULL;

        if (args->nr != 1)
                die("reset-heads needs 1 argument");

        if (!strcmp(args->items[0].string, "manifests")) {
                heads = &manifest_heads;
        } else
                die("Unknown kind: %s", args->items[0].string);

	ensure_heads(heads);
	reset_heads(heads);
}

struct track_upgrade {
	struct oidset set;
	struct progress *progress;
};

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

struct track_manifests_upgrade {
	struct progress *progress;
	struct oidset manifests;
	struct hashmap tree_cache;
	struct hashmap commit_cache;
};

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

static void do_upgrade(struct string_list *args)
{
        if (args->nr != 0)
                die("upgrade takes no arguments");

	if (!(metadata_flags & (FILES_META | UNIFIED_MANIFESTS_v2))) {
		die("Unsupported upgrade");
	}

	write_or_die(1, "ok\n", 3);
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
					file_oid = resolve_hg2git(&hg_oid, 40);
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

static void do_create_git_tree(struct string_list *args)
{
	struct hg_object_id hg_oid;
	struct object_id oid;
	const struct object_id *manifest_oid;
	struct commit *commit;
	struct object_id *ref_tree = NULL;

	if (args->nr == 0 || args->nr > 2)
		die("create-git-tree takes 1 or 2 arguments");

	if (!strncmp(args->items[0].string, "git:", 4)) {
		if (get_oid_hex(args->items[0].string + 4, &oid))
			goto not_found;
		manifest_oid = &oid;
	} else {
		if (get_sha1_hex(args->items[0].string, hg_oid.hash))
			goto not_found;

		manifest_oid = resolve_hg2git(&hg_oid, 40);
		if (!manifest_oid)
			goto not_found;
	}

	commit = lookup_commit(the_repository, manifest_oid);
	if (parse_commit(commit))
		goto not_found;

	if (args->nr == 2) {
		struct hg_object_id ref_oid;
		const struct object_id *ref_commit_oid;
		struct commit *ref_commit;
		if (get_sha1_hex(args->items[1].string, ref_oid.hash))
			die("invalid argument");
		ref_commit_oid = resolve_hg2git(&ref_oid, 40);
		if (!ref_commit_oid)
			die("invalid argument");
		ref_commit = lookup_commit(the_repository, ref_commit_oid);
		parse_commit_or_die(ref_commit);
		ref_tree = get_commit_tree_oid(ref_commit);
	}

	recurse_create_git_tree(get_commit_tree_oid(commit), ref_tree, NULL,
	                        &oid, &git_tree_cache);

	write_or_die(1, oid_to_hex(&oid), 40);
	write_or_die(1, "\n", 1);
	return;

not_found:
	die("Couldn't find manifest %s", args->items[0].string);
}

// 12th bit is only used by builtin/blame.c, so it should be safe to use.
#define FSCK_SEEN (1 << 12)

static void do_seen(struct string_list *args)
{
	struct object_id oid;
	int seen = 0;

	if (args->nr != 2)
		die("seen takes two argument");

	if (get_oid_hex(args->items[1].string, &oid))
		die("Invalid sha1");

	if (!strcmp(args->items[0].string, "hg2git"))
		seen = oidset_insert(&hg2git_seen, &oid);
	else if (!strcmp(args->items[0].string, "git2hg")) {
		struct commit *c = lookup_commit(the_repository, &oid);
		if (!c)
			die("Unknown commit");
		seen = c->object.flags & FSCK_SEEN;
		c->object.flags |= FSCK_SEEN;
	}

	if (seen)
		write_or_die(1, "yes\n", 4);
	else
		write_or_die(1, "no\n", 3);
}

struct dangling_data {
	struct notes_tree *notes;
	struct strbuf *buf;
	int exclude_blobs;
};

static int dangling_note(const struct object_id *object_oid,
                         const struct object_id *note_oid, char *note_path,
                         void *cb_data)
{
	struct dangling_data *data = cb_data;
	struct object_id oid;
	int is_dangling = 0;

	oidcpy(&oid, object_oid);
	if (data->notes == &hg2git) {
		if (!data->exclude_blobs ||
		    (oid_object_info(the_repository, note_oid, NULL) != OBJ_BLOB))
			is_dangling = !oidset_contains(&hg2git_seen, &oid);
	} else if (data->notes == &git2hg) {
		struct commit *c = lookup_commit(the_repository, &oid);
		is_dangling = !c || !(c->object.flags & FSCK_SEEN);
	}

	if (is_dangling) {
		strbuf_add(data->buf, oid_to_hex(&oid), 40);
		strbuf_addch(data->buf, '\n');
	}

	return 0;
}

static void do_dangling(struct string_list *args)
{
	struct strbuf buf = STRBUF_INIT;
	struct dangling_data data = { NULL, &buf, 0 };

        if (args->nr != 1)
                die("dangling takes one argument");

	if (!strcmp(args->items[0].string, "hg2git-no-blobs")) {
		data.notes = &hg2git;
		data.exclude_blobs = 1;
	} else if (!strcmp(args->items[0].string, "hg2git")) {
		data.notes = &hg2git;
	} else if (!strcmp(args->items[0].string, "git2hg")) {
		data.notes = &git2hg;
	} else {
		die("Unknown argument");
	}

	ensure_notes(data.notes);
	for_each_note(data.notes, 0, dangling_note, &data);

	send_buffer(&buf);
	strbuf_release(&buf);
}

static void init_config()
{
	struct strbuf conf = STRBUF_INIT;
	if (!config("check", &conf)) {
		struct strbuf **check = strbuf_split(&conf, ',');
		struct strbuf **c;
		for (c = check; *c; c++) {
			// strbuf_split leaves the `,`.
			if ((*c)->buf[(*c) -> len - 1] == ',')
				strbuf_setlen(*c, (*c)->len - 1);
			if (!strcmp((*c)->buf, "true") ||
			    !strcmp((*c)->buf, "all"))
				cinnabar_check = -1;
			else if (!strcmp((*c)->buf, "helper"))
				cinnabar_check |= CHECK_HELPER;
			else if (!strcmp((*c)->buf, "manifests"))
				cinnabar_check |= CHECK_MANIFESTS;
		}
		strbuf_list_free(check);
	}
	strbuf_release(&conf);

	if (!config("experiments", &conf)) {
		struct strbuf **check = strbuf_split(&conf, ',');
		struct strbuf **c;
		for (c = check; *c; c++) {
			// strbuf_split leaves the `,`.
			if ((*c)->buf[(*c) -> len - 1] == ',')
				strbuf_setlen(*c, (*c)->len - 1);
			if (!strcmp((*c)->buf, "true") ||
			    !strcmp((*c)->buf, "all"))
				cinnabar_experiments = -1;
			else if (!strcmp((*c)->buf, "store"))
				cinnabar_experiments |= EXPERIMENT_STORE;
		}
		strbuf_list_free(check);
	}
	strbuf_release(&conf);
}

static void reset_replace_map()
{
	oidmap_free(the_repository->objects->replace_map, 1);
	FREE_AND_NULL(the_repository->objects->replace_map);
	the_repository->objects->replace_map_initialized = 0;
}

static void init_metadata()
{
	struct commit *c;
	const char *msg, *body;
	struct strbuf **flags, **f;
	struct tree *tree;
	struct tree_desc desc;
	struct name_entry entry;
	struct replace_object *replace;

	c = lookup_commit_reference_by_name(METADATA_REF);
	if (!c)
		return;
	msg = get_commit_buffer(c, NULL);
	body = strstr(msg, "\n\n") + 2;
	unuse_commit_buffer(c, msg);
	flags = strbuf_split_str(body, ' ', -1);
	for (f = flags; *f; f++) {
		strbuf_trim(*f);
		if (!strcmp("files-meta", (*f)->buf))
			metadata_flags |= FILES_META;
		else if (!strcmp("unified-manifests", (*f)->buf))
			metadata_flags |= UNIFIED_MANIFESTS;
		else if (!strcmp("unified-manifests-v2", (*f)->buf))
			metadata_flags |= UNIFIED_MANIFESTS_v2;
	}
	strbuf_list_free(flags);

	reset_replace_map();
	the_repository->objects->replace_map =
		xmalloc(sizeof(*the_repository->objects->replace_map));
	oidmap_init(the_repository->objects->replace_map, 0);
	the_repository->objects->replace_map_initialized = 1;

	tree = get_commit_tree(c);
	parse_tree(tree);
	init_tree_desc(&desc, tree->buffer, tree->size);
	while (tree_entry(&desc, &entry)) {
		struct object_id original_oid;
		if (entry.pathlen != 40 ||
		    get_oid_hex(entry.path, &original_oid)) {
			struct strbuf buf = STRBUF_INIT;
			strbuf_add(&buf, entry.path, entry.pathlen);
			warning(_("bad replace name: %s"), buf.buf);
			strbuf_release(&buf);
			continue;
		}
		if (oideq(&entry.oid, &original_oid)) {
			warning(_("self-referencing graft: %s"),
				oid_to_hex(&original_oid));
			continue;
		}
		replace = xmalloc(sizeof(*replace));
		oidcpy(&replace->original.oid, &original_oid);
		oidcpy(&replace->replacement, &entry.oid);
		if (oidmap_put(the_repository->objects->replace_map, replace))
			die(_("duplicate replace: %s"),
			    oid_to_hex(&replace->original.oid));
	}
}

void dump_branches(void);

static void do_reload(struct string_list *args)
{
        if (args->nr != 0)
                die("reload takes no arguments");

	if (notes_initialized(&git2hg))
		free_notes(&git2hg);

	if (notes_initialized(&hg2git))
		free_notes(&hg2git);

	if (notes_initialized(&files_meta))
		free_notes(&files_meta);

	oidset_clear(&hg2git_seen);

	hashmap_free_entries(&git_tree_cache, struct oid_map_entry, ent);
	hashmap_init(&git_tree_cache, oid_map_entry_cmp, NULL, 0);

	oid_array_clear(&manifest_heads);
	oid_array_clear(&changeset_heads);

	dump_branches();

	metadata_flags = 0;
	reset_replace_map();
	init_metadata();
}

int configset_add_value(struct config_set *, const char*, const char *);

static int config_set_callback(const char *key, const char *value, void *data)
{
	struct config_set *config = data;
	configset_add_value(config, key, value);
	return 0;
}

static void init_git_config()
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
	const char *argv[] = {
		"git", "config", "--system", "-e", NULL
	};
	if (env && *env) {
		setup_path();
	}
	proc.argv = argv;
	argv_array_push(&proc.env_array, "GIT_EDITOR=echo");
	proc.no_stdin = 1;
	proc.no_stderr = 1;
	/* We don't really care about the capture_command return value. If
	 * the path we get is empty we'll know it failed. */
	capture_command(&proc, &path, 0);
	strbuf_trim_trailing_newline(&path);
	/* If we couldn't get a path, then so be it. We may just not have
	 * a complete configuration. */
	if (!path.len)
		goto cleanup;

	if (!git_config_system() || access_or_die(path.buf, R_OK, 0))
		goto cleanup;

	if (the_repository->config)
		// This shouldn't happen, but just in case...
		git_configset_clear(the_repository->config);
	else
		the_repository->config = xcalloc(1, sizeof(struct config_set));

	git_configset_init(the_repository->config);
	git_configset_add_file(the_repository->config, path.buf);
	// Avoid read_early_config reading the config we just read (or the
	// wrong system gitconfig).
	putenv("GIT_CONFIG_NOSYSTEM=1");
	read_early_config(config_set_callback, the_repository->config);

cleanup:
	strbuf_release(&path);
}

static void restore_sigpipe_to_default(void)
{
	sigset_t unblock;

	sigemptyset(&unblock);
	sigaddset(&unblock, SIGPIPE);
	sigprocmask(SIG_UNBLOCK, &unblock, NULL);
	signal(SIGPIPE, SIG_DFL);
}

void init_cinnabar(const char *argv0)
{
	// Initialization from common-main.c.
	sanitize_stdfds();
	restore_sigpipe_to_default();

	git_resolve_executable_dir(argv0);

	git_setup_gettext();

	initialize_the_repository();

	attr_start();

	init_git_config();
	git_config(git_default_config, NULL);
	init_config();
	ignore_case = 0;
	save_commit_buffer = 0;
	warn_on_object_refname_ambiguity = 0;
}

void init_cinnabar_2()
{
	setup_git_directory();
	git_config(git_diff_basic_config, NULL);
	ignore_case = 0;
	init_metadata();
	hashmap_init(&git_tree_cache, oid_map_entry_cmp, NULL, 0);
}

void done_cinnabar()
{
	if (notes_initialized(&git2hg))
		free_notes(&git2hg);

	if (notes_initialized(&hg2git))
		free_notes(&hg2git);

	if (notes_initialized(&files_meta))
		free_notes(&files_meta);

	oidset_clear(&hg2git_seen);

	hashmap_free_entries(&git_tree_cache, struct oid_map_entry, ent);
}

int helper_main(int argc, const char *argv[])
{
	int initialized = 0;
	struct strbuf buf = STRBUF_INIT;

	init_cinnabar(argv[0]);

	if (argc > 1) {
		if (argc > 2)
			die("Too many arguments");
		if (!strcmp(argv[1], "--wire")) {
			mode = MODE_WIRE;
		} else if (!strcmp(argv[1], "--import")) {
			mode = MODE_IMPORT;
		}
	}

	while (strbuf_getline(&buf, stdin) != EOF) {
		struct string_list args = STRING_LIST_INIT_NODUP;
		const char *command;
		record_command(&buf);
		split_command(buf.buf, &command, &args);
		if (!strcmp("version", command)) {
			do_version(&args);
			string_list_clear(&args, 0);
			continue;
		} else if (!strcmp("helpercaps", command)) {
			do_helpercaps(&args);
			string_list_clear(&args, 0);
			continue;
		} else if ((mode & MODE_WIRE) && !strcmp("connect", command)) {
			do_connect(&args);
			string_list_clear(&args, 0);
			break;
		}
		if (!(mode & MODE_IMPORT))
			die("Unknown command: \"%s\"", command);
		if (!initialized) {
			init_cinnabar_2();
			initialized = 1;
		}
		if (!strcmp("git2hg", command))
			do_get_note(&git2hg, &args);
		else if (!strcmp("file-meta", command))
			// XXX: Should use a different function that reads a hg oid.
			do_get_note(&files_meta, &args);
		else if (!strcmp("hg2git", command))
			do_hg2git(&args);
		else if (!strcmp("manifest", command))
			do_manifest(&args);
		else if (!strcmp("check-manifest", command))
			do_check_manifest(&args);
		else if (!strcmp("check-file", command))
			do_check_file(&args);
		else if (!strcmp("cat-file", command))
			do_cat_file(&args);
		else if (!strcmp("ls-tree", command))
			do_ls_tree(&args);
		else if (!strcmp("rev-list", command))
			do_rev_list(&args);
		else if (!strcmp("diff-tree", command))
			do_diff_tree(&args);
		else if (!strcmp("heads", command))
			do_heads(&args);
		else if (!strcmp("reset-heads", command))
			do_reset_heads(&args);
		else if (!strcmp("upgrade", command))
			do_upgrade(&args);
		else if (!strcmp("create-git-tree", command))
			do_create_git_tree(&args);
		else if (!strcmp("seen", command))
			do_seen(&args);
		else if (!strcmp("dangling", command))
			do_dangling(&args);
		else if (!strcmp("reload", command))
			do_reload(&args);
		else if (!maybe_handle_command(command, &args))
			die("Unknown command: \"%s\"", command);

		string_list_clear(&args, 0);
	}

	strbuf_release(&buf);

	done_cinnabar();
	return 0;
}
