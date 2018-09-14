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

#define STRINGIFY(s) _STRINGIFY(s)
#define _STRINGIFY(s) # s

#ifndef HELPER_HASH
#define HELPER_HASH unknown
#endif

#define CMD_VERSION 3000
#define MIN_CMD_VERSION 3000

static const char NULL_NODE[] = "0000000000000000000000000000000000000000";

struct notes_tree git2hg, hg2git, files_meta;

struct oidset hg2git_seen = OIDSET_INIT;

int metadata_flags = 0;
int cinnabar_check = 0;

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
	revs->cmdline.rev = NULL;
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

static void send_buffer(struct strbuf *buf)
{
	if (buf) {
		struct strbuf header = STRBUF_INIT;

		strbuf_addf(&header, "%lu\n", buf->len);
		write_or_die(1, header.buf, header.len);
		strbuf_release(&header);

		write_or_die(1, buf->buf, buf->len);
		write_or_die(1, "\n", 1);
	} else {
		write_or_die(1, "-1\n\n", 4);
	}
}

/* Send git object info and content to stdout, like cat-file --batch does. */
static void send_object(const struct object_id *oid)
{
	struct strbuf header = STRBUF_INIT;
	enum object_type type;
	unsigned long sz;
	struct git_istream *st;

	st = open_istream(oid, &type, &sz, NULL);

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
	struct ls_tree_context *ctx = (struct ls_tree_context *) context;
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
	read_tree_recursive(tree, "", 0, 0, &match_all, fill_ls_tree, &ctx);
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
	}

	// More extensive than reset_revision_walk(). Otherwise --boundary
	// and pathspecs don't work properly.
	clear_object_flags(ALL_REV_FLAGS);
	send_buffer(&buf);
	strbuf_release(&buf);
	rev_info_release(&revs);
}

static void strbuf_diff_tree(struct diff_queue_struct *q,
                             struct diff_options *opt, void *data)
{
	struct strbuf *buf = (struct strbuf *) data;
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

static const struct object_id *resolve_hg2git(const struct object_id *oid,
                                              size_t len)
{
	const struct object_id *note;

	ensure_notes(&hg2git);

	note = get_note(&hg2git, oid);
	if (len == 40)
		return note;

	return get_abbrev_note(&hg2git, oid, len);
}

static void do_hg2git(struct string_list *args)
{
        struct object_id oid;
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

static void recurse_manifest(const struct object_id *tree_id,
                             struct strbuf *manifest, struct strslice base,
                             struct object_list **tree_list)
{
	struct manifest_tree_state state;
	struct name_entry entry;

	if (manifest_tree_state_init(tree_id, &state, tree_list))
		goto corrupted;

	while (tree_entry(&state.desc, &entry)) {
		struct strslice entry_path;
		struct strslice underscore = { 1, "_" };
		entry_path = strslice_from_str(entry.path);
		if (!strslice_startswith(entry_path, underscore))
			goto corrupted;
		entry_path = strslice_slice(entry_path, 1, SIZE_MAX);
		if (S_ISDIR(entry.mode)) {
			struct strbuf dir = STRBUF_INIT;
			strbuf_addslice(&dir, base);
			strbuf_addslice(&dir, entry_path);
			strbuf_addch(&dir, '/');
			recurse_manifest(entry.oid, manifest,
			                 strbuf_as_slice(&dir), tree_list);
			strbuf_release(&dir);
			continue;
		} else if (entry_path.len == 0)
			goto corrupted;
		strbuf_addslice(manifest, base);
		strbuf_addslice(manifest, entry_path);
		strbuf_addf(manifest, "%c%s%s\n", '\0',
		            oid_to_hex(entry.oid), hgattr(entry.mode));
	}

	return;
corrupted:
	die("Corrupted metadata");

}

/* Return whether two entries have matching sha1s and modes */
static int manifest_entry_equal(const struct name_entry *e1,
                                const struct name_entry *e2)
{
	return (e1->mode == e2->mode) && (oidcmp(e1->oid, e2->oid) == 0);
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

static void recurse_manifest2(const struct object_id *ref_tree_id,
                              struct strslice ref_manifest,
                              const struct object_id *tree_id,
                              struct strbuf *manifest, struct strslice base,
                              struct object_list **tree_list)
{
	struct manifest_tree_state ref, cur;
	struct name_entry ref_entry, cur_entry;
	struct strslice ref_entry_path, cur_entry_path;
	struct strslice next = ref_manifest;
	struct strslice underscore = { 1, "_" };
	struct strbuf dir = STRBUF_INIT;
	int cmp = 0;

	if (manifest_tree_state_init(ref_tree_id, &ref, tree_list))
		goto corrupted;

	if (manifest_tree_state_init(tree_id, &cur, tree_list))
		goto corrupted;

	for (;;) {
		if (cmp >= 0) {
			if (tree_entry(&cur.desc, &cur_entry)) {
				cur_entry_path =
					strslice_from_str(cur_entry.path);
				if (!strslice_startswith(cur_entry_path, underscore))
					goto corrupted;
			} else {
				cur_entry_path.len = 0;
			}
		}
		if (cmp <= 0) {
			if (tree_entry(&ref.desc, &ref_entry)) {
				ref_entry_path =
					strslice_from_str(ref_entry.path);
				if (!strslice_startswith(ref_entry_path, underscore))
					goto corrupted;
			} else {
				ref_entry_path.len = 0;
			}
			ref_manifest = next;
			assert(!ref_entry_path.len ||
			       path_match(base, strslice_slice(
					ref_entry_path, 1, SIZE_MAX), next));
		}
		if (!ref_entry_path.len) {
			if (!cur_entry_path.len)
				break;
			cmp = 1;
		} else if (!cur_entry_path.len) {
			cmp = -1;
		} else {
			cmp = name_compare(
				ref_entry_path.buf, ref_entry_path.len,
				cur_entry_path.buf, cur_entry_path.len);
		}
		if (cmp <= 0) {
			size_t len = base.len + ref_entry_path.len + 40;
			do {
				strslice_split_once(&next, '\n');
			} while (S_ISDIR(ref_entry.mode) &&
			         (next.len > len) &&
			         path_match(base, strslice_slice(
					ref_entry_path, 1, SIZE_MAX), next));
		}
		/* File/directory was removed, nothing to do */
		if (cmp < 0)
			continue;
		/* File/directory didn't change, copy from the reference
		 * manifest. */
		if (cmp == 0 && manifest_entry_equal(&ref_entry, &cur_entry)) {
			strbuf_add(manifest, ref_manifest.buf,
			           ref_manifest.len - next.len);
			continue;
		}
		if (!S_ISDIR(cur_entry.mode)) {
			if (cur_entry_path.len == 0)
				goto corrupted;
			strbuf_addslice(manifest, base);
			strbuf_addslice(manifest, strslice_slice(
				cur_entry_path, 1, SIZE_MAX));
			strbuf_addf(manifest, "%c%s%s\n", '\0',
			            oid_to_hex(cur_entry.oid),
			            hgattr(cur_entry.mode));
			continue;
		}

		strbuf_addslice(&dir, base);
		strbuf_addslice(&dir, strslice_slice(
			cur_entry_path, 1, SIZE_MAX));
		strbuf_addch(&dir, '/');
		if (cmp == 0 && S_ISDIR(ref_entry.mode)) {
			recurse_manifest2(ref_entry.oid, ref_manifest,
				          cur_entry.oid, manifest,
			                  strbuf_as_slice(&dir), tree_list);
		} else
			recurse_manifest(cur_entry.oid, manifest,
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
		recurse_manifest2(&generated_manifest.tree_id, gm,
		                  oid, &content, empty_strslice(), &tree_list);
	} else {
		recurse_manifest(oid, &content, empty_strslice(), &tree_list);
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
		sha1_len = get_abbrev_sha1_hex(args->items[0].string, oid.hash);
		if (!sha1_len)
			goto not_found;

		manifest_oid = resolve_hg2git(&oid, sha1_len);
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

static void get_manifest_sha1(const struct commit *commit, unsigned char *sha1)
{
	const char *msg;
	const char *hex_sha1;

	msg = get_commit_buffer(commit, NULL);

	hex_sha1 = strstr(msg, "\n\n") + 2;

	if (get_sha1_hex(hex_sha1, sha1))
		hashclr(sha1);

	unuse_commit_buffer(commit, msg);
}

static void hg_sha1(struct strbuf *data, const unsigned char *parent1,
                    const unsigned char *parent2, unsigned char *result)
{
	git_SHA_CTX ctx;

	if (!parent1)
		parent1 = null_sha1;
	if (!parent2)
		parent2 = null_sha1;

	git_SHA1_Init(&ctx);

	if (hashcmp(parent1, parent2) < 0) {
		git_SHA1_Update(&ctx, parent1, 20);
		git_SHA1_Update(&ctx, parent2, 20);
	} else {
		git_SHA1_Update(&ctx, parent2, 20);
		git_SHA1_Update(&ctx, parent1, 20);
	}

	git_SHA1_Update(&ctx, data->buf, data->len);

	git_SHA1_Final(result, &ctx);
}

static void do_check_manifest(struct string_list *args)
{
	unsigned char parent1[20], parent2[20], result[20];
	struct object_id oid;
	const struct object_id *manifest_oid;
	const struct commit *manifest_commit;
	struct strbuf *manifest = NULL;

	if (args->nr != 1)
		goto error;

	if (!strncmp(args->items[0].string, "git:", 4)) {
		if (get_oid_hex(args->items[0].string + 4, &oid))
			goto error;
		manifest_oid = &oid;
	} else {
		if (get_oid_hex(args->items[0].string, &oid))
			goto error;

		manifest_oid = resolve_hg2git(&oid, 40);
		if (!manifest_oid)
			goto error;
	}

	manifest = generate_manifest(manifest_oid);
	if (!manifest)
		goto error;

	manifest_commit = lookup_commit(the_repository, manifest_oid);
	if (!manifest_commit)
		goto error;

	if (manifest_commit->parents) {
		get_manifest_sha1(manifest_commit->parents->item, parent1);
		if (manifest_commit->parents->next) {
			get_manifest_sha1(manifest_commit->parents->next->item,
			                  parent2);
		} else
			hashclr(parent2);
	} else {
		hashclr(parent1);
		hashclr(parent2);
	}

	hg_sha1(manifest, parent1, parent2, result);

	if (manifest_oid == &oid)
		get_manifest_sha1(manifest_commit, oid.hash);

	if (hashcmp(result, oid.hash) == 0) {
		write_or_die(1, "ok\n", 3);
		return;
	}

error:
	write_or_die(1, "error\n", 6);
}

static void do_check_file(struct string_list *args)
{
	struct hg_file file;
	unsigned char sha1[20], parent1[20], parent2[20], result[20];

	hg_file_init(&file);

	if (args->nr < 1 || args->nr > 3)
		goto error;

	if (get_sha1_hex(args->items[0].string, sha1))
		goto error;

	if (args->nr > 1) {
		if (get_sha1_hex(args->items[1].string, parent1))
			goto error;
	} else
		hashclr(parent1);

	if (args->nr > 2) {
		if (get_sha1_hex(args->items[2].string, parent2))
			goto error;
	} else
		hashclr(parent2);

	hg_file_load(&file, sha1);

	/* We do the quick and dirty thing here, for now.
	 * See details in cinnabar.githg.FileFindParents._set_parents_fallback
	 */
	hg_sha1(&file.file, parent1, parent2, result);
	if (hashcmp(sha1, result) == 0)
		goto ok;

	hg_sha1(&file.file, parent1, NULL, result);
	if (hashcmp(sha1, result) == 0)
		goto ok;

	hg_sha1(&file.file, parent2, NULL, result);
	if (hashcmp(sha1, result) == 0)
		goto ok;

	hg_sha1(&file.file, parent1, parent1, result);
	if (hashcmp(sha1, result) == 0)
		goto ok;

	hg_sha1(&file.file, NULL, NULL, result);
	if (hashcmp(sha1, result))
		goto error;

ok:
	write_or_die(1, "ok\n", 3);
	hg_file_release(&file);
	return;

error:
	write_or_die(1, "error\n", 6);
	hg_file_release(&file);
}

static void do_version(struct string_list *args)
{
	long int version;

	if (args->nr != 1)
		exit(1);

	version = strtol(args->items[0].string, NULL, 10);
	if (version < 100)
		version *= 100;

	if (!version || version < MIN_CMD_VERSION || version > CMD_VERSION)
		exit(128);

	write_or_die(1, STRINGIFY(HELPER_HASH) "\n",
	             sizeof(STRINGIFY(HELPER_HASH)));
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

static void do_known(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	struct oid_array nodes = OID_ARRAY_INIT;
	string_list_as_oid_array(args, &nodes);
	hg_known(conn, &result, &nodes);
	send_buffer(&result);
	oid_array_clear(&nodes);
	strbuf_release(&result);
}

static void do_listkeys(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	if (args->nr != 1)
		exit(1);

	hg_listkeys(conn, &result, args->items[0].string);
	send_buffer(&result);
	strbuf_release(&result);
}

static void arg_as_oid_array(char *nodes, struct oid_array *array)
{
	struct string_list list = STRING_LIST_INIT_NODUP;
	string_list_split_in_place(&list, nodes, ',', -1);
	string_list_as_oid_array(&list, array);
	string_list_clear(&list, 0);
}

static void do_getbundle(struct hg_connection *conn, struct string_list *args)
{
	struct oid_array heads = OID_ARRAY_INIT;
	struct oid_array common = OID_ARRAY_INIT;
	const char *bundle2caps = NULL;

	if (args->nr > 3)
		exit(1);

	if (args->nr > 0)
		arg_as_oid_array(args->items[0].string, &heads);
	if (args->nr > 1)
		arg_as_oid_array(args->items[1].string, &common);
	if (args->nr > 2)
		bundle2caps = args->items[2].string;

	hg_getbundle(conn, stdout, &heads, &common, bundle2caps);

	oid_array_clear(&common);
	oid_array_clear(&heads);
}

static void do_unbundle(struct hg_connection *conn, struct string_list *args)
{
	struct strbuf result = STRBUF_INIT;
	struct oid_array heads = OID_ARRAY_INIT;
	if (args->nr < 1)
		exit(1);
	if (args->nr != 1 || strcmp(args->items[0].string, "force"))
		string_list_as_oid_array(args, &heads);
	hg_unbundle(conn, &result, stdin, &heads);
	send_buffer(&result);
	oid_array_clear(&heads);
	strbuf_release(&result);
}

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
	struct strbuf *buf = (struct strbuf *)data;

	strbuf_addstr(buf, oid_to_hex(oid));
	strbuf_addch(buf, '\n');
	return 0;
}

static void do_heads(struct string_list *args)
{
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

static int oid_map_entry_cmp(const void *cmpdata, const void *e1,
                             const void *e2, const void *keydata)
{
	const struct oid_map_entry *entry1 = e1;
	const struct oid_map_entry *entry2 = e2;

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
                                    struct strbuf *tree_buf,
                                    struct object_id *result,
				    struct hashmap *cache)
{
	struct oid_map_entry k, *cache_entry;

	hashmap_entry_init(&k.ent, sha1hash(tree_id->hash));
	oidcpy(&k.old_oid, tree_id);
	cache_entry = hashmap_get(cache, &k, NULL);
	if (!cache_entry) {
		struct manifest_tree_state state;
		struct manifest_tree_state ref_state = { NULL, };
		struct name_entry entry;
		struct strbuf tree_buf_ = STRBUF_INIT;
		if (!tree_buf)
			tree_buf = &tree_buf_;

		if (manifest_tree_state_init(tree_id, &state, NULL))
			goto corrupted;

		while (tree_entry(&state.desc, &entry)) {
			struct object_id oid;
			unsigned mode = entry.mode;
			struct strslice entry_path;
			struct strslice underscore = { 1, "_" };
			entry_path = strslice_from_str(entry.path);
			if (!strslice_startswith(entry_path, underscore))
				goto corrupted;
			entry_path = strslice_slice(entry_path, 1, SIZE_MAX);
			if (entry_path.len == 0) {
				if (!S_ISDIR(mode))
					goto corrupted;
				recurse_create_git_tree(
					entry.oid, NULL, tree_buf, NULL,
					cache);
				continue;
			} else if (S_ISDIR(mode)) {
				struct name_entry *ref_entry;
				ref_entry = lazy_tree_entry_by_name(
					&ref_state, reference, entry_path.buf);
				recurse_create_git_tree(
					entry.oid,
					ref_entry ? ref_entry->oid : NULL,
					NULL, &oid, cache);
			} else {
				const struct object_id *file_oid;
				if (is_empty_hg_file(entry.oid->hash))
					file_oid = ensure_empty_blob();
				else
					file_oid = resolve_hg2git(entry.oid, 40);
				if (!file_oid)
					goto corrupted;
				oidcpy(&oid, file_oid);
				mode &= 0777;
				if (!mode)
					mode = S_IFLNK;
				else
					mode = S_IFREG | mode;
			}
			strbuf_addf(tree_buf, "%o ", canon_mode(mode));
			strbuf_addslice(tree_buf, entry_path);
			strbuf_addch(tree_buf, '\0');
			strbuf_add(tree_buf, oid.hash, 20);
		}

		if (tree_buf == &tree_buf_) {
			cache_entry = xmalloc(sizeof(k));
			cache_entry->ent = k.ent;
			cache_entry->old_oid = k.old_oid;
			store_git_tree(tree_buf, reference, &cache_entry->new_oid);
			strbuf_release(&tree_buf_);
			hashmap_add(cache, cache_entry);
		}

		if (state.tree)
			free_tree_buffer(state.tree);
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
		if (get_oid_hex(args->items[0].string, &oid))
			goto not_found;

		manifest_oid = resolve_hg2git(&oid, 40);
		if (!manifest_oid)
			goto not_found;
	}

	commit = lookup_commit(the_repository, manifest_oid);
	if (parse_commit(commit))
		goto not_found;

	if (args->nr == 2) {
		struct object_id ref_oid;
		const struct object_id *ref_commit_oid;
		struct commit *ref_commit;
		if (get_oid_hex(args->items[1].string, &ref_oid))
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
	struct dangling_data *data = (struct dangling_data *)cb_data;
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
		for (c = check; *c; c++)
			if (!strcmp((*c)->buf, "true") ||
			    !strcmp((*c)->buf, "all") ||
			    !strcmp((*c)->buf, "helper"))
				cinnabar_check |= CHECK_HELPER;
		strbuf_list_free(check);
	}
	strbuf_release(&conf);
}

static void init_flags()
{
	struct commit *c;
	const char *msg, *body;
	struct strbuf **flags, **f;

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
}

extern void dump_branches(void);

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

	hashmap_free(&git_tree_cache, 1);
	hashmap_init(&git_tree_cache, oid_map_entry_cmp, NULL, 0);

	oid_array_clear(&manifest_heads);
	oid_array_clear(&changeset_heads);

	dump_branches();

	metadata_flags = 0;
	init_flags();
}

int cmd_main(int argc, const char *argv[])
{
	int initialized = 0;
	struct strbuf buf = STRBUF_INIT;

	git_config(git_default_config, NULL);
	ignore_case = 0;
	save_commit_buffer = 0;
	warn_on_object_refname_ambiguity = 0;

	while (strbuf_getline(&buf, stdin) != EOF) {
		struct string_list args = STRING_LIST_INIT_NODUP;
		const char *command;
		split_command(buf.buf, &command, &args);
		if (!strcmp("version", command)) {
			do_version(&args);
			string_list_clear(&args, 0);
			continue;
		} else if (!strcmp("connect", command)) {
			do_connect(&args);
			string_list_clear(&args, 0);
			break;
		}
		if (!initialized) {
			setup_git_directory();
			git_config(git_diff_basic_config, NULL);
			ignore_case = 0;
			init_config();
			init_flags();
			initialized = 1;
			hashmap_init(&git_tree_cache, oid_map_entry_cmp, NULL, 0);
		}
		if (!strcmp("git2hg", command))
			do_get_note(&git2hg, &args);
		else if (!strcmp("file-meta", command))
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

	if (notes_initialized(&git2hg))
		free_notes(&git2hg);

	if (notes_initialized(&hg2git))
		free_notes(&hg2git);

	if (notes_initialized(&files_meta))
		free_notes(&files_meta);

	oidset_clear(&hg2git_seen);

	hashmap_free(&git_tree_cache, 1);

	return 0;
}
