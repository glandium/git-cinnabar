/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "git-compat-util.h"
struct object_id;
static void start_packfile(void);
static void cinnabar_unregister_shallow(const struct object_id *oid);
#include "alloc.h"
#include "dir.h"
#define fspathncmp strncmp
#include "fast-import.patched.c"
#include "cinnabar-fast-import.h"
#include "cinnabar-helper.h"
#include "cinnabar-notes.h"
#include "hg-bundle.h"
#include "hg-data.h"
#include "list.h"
#include "replace-object.h"
#include "shallow.h"
#include "strslice.h"
#include "tree-walk.h"

#define ENSURE_INIT() do { \
	if (!initialized) \
		init(); \
} while (0)

static int initialized = 0;
static int update_shallow = 0;

void cinnabar_unregister_shallow(const struct object_id *oid) {
	if (unregister_shallow(oid) == 0)
		update_shallow = 1;
}

extern void locked_rollback(void);

/* Divert fast-import.c's calls to hashwrite so as to keep a fake pack window
 * on the last written bits, avoiding munmap/mmap cycles from
 * gfi_unpack_entry. */
static struct pack_window *pack_win;
static struct pack_window *prev_win;

void real_hashwrite(struct hashfile *, const void *, unsigned int);

void hashwrite(struct hashfile *f, const void *buf, unsigned int count)
{
	size_t window_size;

	if (f != pack_file) {
		real_hashwrite(f, buf, count);
		return;
	}

	if (!pack_win) {
		pack_win = xcalloc(1, sizeof(*pack_data->windows));
		pack_win->offset = 0;
		pack_win->len = 20;
		pack_win->base = xmalloc(packed_git_window_size + 20);
		pack_win->next = NULL;
	}
	/* pack_data is not set the first time hashwrite is called */
	if (pack_data && !pack_data->windows) {
		pack_data->windows = pack_win;
		pack_data->pack_size = pack_win->len;
	}

	real_hashwrite(f, buf, count);
	pack_win->last_used = -1; /* always last used */
	pack_win->inuse_cnt = -1;
	if (pack_data)
		pack_data->pack_size += count;

	window_size = packed_git_window_size + (pack_win->offset ? 20 : 0);

	if (window_size + 20 - pack_win->len > count) {
		memcpy(pack_win->base + pack_win->len - 20, buf, count);
		pack_win->len += count;
	} else {
		/* Slide our window so that it starts at an offset multiple of
		 * the window size minus 20 (we want 20 bytes of overlap with the
		 * preceding window, so that use_pack() won't create an overlapping
		 * window on its own) */
		off_t offset = pack_win->offset;
		pack_win->offset = ((pack_data->pack_size - 20)
			/ packed_git_window_size) * packed_git_window_size - 20;
		assert(offset != pack_win->offset);
		pack_win->len = pack_data->pack_size - pack_win->offset;

		/* Ensure a pack window on the data preceding that. */
		hashflush(f);
		if (prev_win)
			unuse_pack(&prev_win);
		use_pack(pack_data, &prev_win,
			 pack_win->offset + 20 - packed_git_window_size, NULL);
		assert(prev_win->len == packed_git_window_size);

		/* Copy the overlapping bytes. */
		memcpy(pack_win->base,
		       prev_win->base + packed_git_window_size - 20, 20);

		/* Fill up the new window. */
		memcpy(pack_win->base + 20,
		       (char*)buf + count + 40 - pack_win->len,
		       pack_win->len - 40);
	}
}

off_t real_find_pack_entry_one(const unsigned char *sha1,
                               struct packed_git *p);

off_t find_pack_entry_one(const unsigned char *sha1, struct packed_git *p)
{
	if (p == pack_data) {
		struct object_entry *oe = get_object_entry(sha1);
		if (oe && oe->idx.offset > 1 && oe->pack_id == pack_id)
			return oe->idx.offset;
		return 0;
	}
	return real_find_pack_entry_one(sha1, p);
}

void *get_object_entry(const unsigned char *sha1)
{
	struct object_id oid;
	hashcpy(oid.hash, sha1);
	oid.algo = GIT_HASH_SHA1;
	return find_object(&oid);
}

/* Mostly copied from fast-import.c's cmd_main() */
static void init(void)
{
	int i;

	reset_pack_idx_option(&pack_idx_opts);
	git_pack_config();
	warn_on_object_refname_ambiguity = 0;

	alloc_objects(object_entry_alloc);
	atom_table_sz = 131071;
	atom_table = xcalloc(atom_table_sz, sizeof(struct atom_str*));
	branch_table = xcalloc(branch_table_sz, sizeof(struct branch*));
	avail_tree_table = xcalloc(avail_tree_table_sz, sizeof(struct avail_tree_content*));
	marks = mem_pool_calloc(&fi_mem_pool, 1, sizeof(struct mark_set));

	hashmap_init(&object_table, object_entry_hashcmp, NULL, 0);

	global_argc = 1;

	rc_free = mem_pool_alloc(&fi_mem_pool, cmd_save * sizeof(*rc_free));
	for (i = 0; i < (cmd_save - 1); i++)
		rc_free[i].next = &rc_free[i + 1];
	rc_free[cmd_save - 1].next = NULL;

	start_packfile();

	parse_one_feature("force", 0);
	initialized = 1;
	atexit(locked_rollback);
}

static void cleanup(void)
{
	if (!initialized)
		return;

	if (require_explicit_termination)
		object_count = 0;
	end_packfile();
	reprepare_packed_git(the_repository);

	if (!require_explicit_termination) {
		if (update_shallow) {
			struct shallow_lock shallow_lock;
			const char *alternate_shallow_file;
			setup_alternate_shallow(
				&shallow_lock, &alternate_shallow_file,
				NULL);
			commit_shallow_file(the_repository, &shallow_lock);
		}
	}

	unkeep_all_packs();

	initialized = 0;

	if (cinnabar_check(CHECK_HELPER))
		pack_report();
}

void do_cleanup(int rollback)
{
	if (!rollback)
		require_explicit_termination = 0;
	cleanup();
}

static void start_packfile(void)
{
	real_start_packfile();
	install_packed_git(the_repository, pack_data);
	list_add_tail(&pack_data->mru, &the_repository->objects->packed_git_mru);
}

static void end_packfile(void)
{
	if (prev_win)
		unuse_pack(&prev_win);
	if (pack_data) {
		struct pack_window *win, *prev;
		for (prev = NULL, win = pack_data->windows;
		     win; prev = win, win = win->next) {
			if (win != pack_win)
				continue;
			if (prev)
				prev->next = win->next;
			else
				pack_data->windows = win->next;
			break;
		}
	}
	if (pack_win) {
		free(pack_win->base);
		free(pack_win);
		pack_win = NULL;
	}

	/* uninstall_packed_git(pack_data) */
	if (pack_data) {
		struct packed_git *pack, *prev;
		for (prev = NULL, pack = the_repository->objects->packed_git;
		     pack; prev = pack, pack = pack->next) {
			if (pack != pack_data)
				continue;
			if (prev)
				prev->next = pack->next;
			else
				the_repository->objects->packed_git = pack->next;
			hashmap_remove(&the_repository->objects->pack_map,
			               &pack_data->packmap_ent,
			               pack_data->pack_name);
			break;
		}
		list_del_init(&pack_data->mru);
		close_pack_windows(pack_data);
	}

	real_end_packfile();
}

extern void handle_changeset_conflict(const struct hg_object_id *hg_id,
                                      struct object_id *git_id);

void do_set_replace(const struct object_id *replaced,
                    const struct object_id *replace_with)
{
	struct replace_object *replace;

	if (is_null_oid(replace_with)) {
		oidmap_remove(the_repository->objects->replace_map, replaced);
	} else {
		struct replace_object *old;
		replace = xmalloc(sizeof(*replace));
		oidcpy(&replace->original.oid, replaced);
		oidcpy(&replace->replacement, replace_with);
		old = oidmap_put(the_repository->objects->replace_map, replace);
		if (old)
			free(old);
	}
}

int write_object_file_flags(const void *buf, size_t len, enum object_type type,
                            struct object_id *oid, unsigned flags)
{
	struct strbuf data;
	data.buf = (void *)buf;
	data.len = len;
	data.alloc = len;
	store_object(type, &data, NULL, oid, 0);
	return 0;
}

void hg_file_store(struct hg_file *file, struct hg_file *reference)
{
	struct object_id oid;
	struct last_object last_blob = { STRBUF_INIT, 0, 0, 1 };
	struct object_entry *oe = NULL;

	ENSURE_INIT();

	if (file->metadata.buf) {
		store_object(OBJ_BLOB, &file->metadata, NULL, &oid, 0);
		add_files_meta(&file->oid, &oid);
	}

	if (reference)
		oe = (struct object_entry *) reference->content_oe;

	if (oe && oe->idx.offset > 1 && oe->pack_id == pack_id) {
		last_blob.data.buf = reference->content.buf;
		last_blob.data.len = reference->content.len;
		last_blob.offset = oe->idx.offset;
		last_blob.depth = oe->depth;
	}
	store_object(OBJ_BLOB, &file->content, &last_blob, &oid, 0);
	add_hg2git(&file->oid, &oid);

	file->content_oe = find_object(&oid);
}

void store_file(struct rev_chunk *chunk)
{
	static struct hg_file last_file;
	struct hg_file file;
	struct strbuf data = STRBUF_INIT;
	struct strslice diff;
	struct rev_diff_part part;
	size_t last_end = 0;

	if (is_empty_hg_file(chunk->node))
		return;

	if (!hg_oideq(chunk->delta_node, &last_file.oid)) {
		hg_file_release(&last_file);

		if (!is_null_hg_oid(chunk->delta_node))
			hg_file_load(&last_file, chunk->delta_node);

	}

	rev_diff_start_iter(&diff, chunk);
	while (rev_diff_iter_next(&diff, &part)) {
		if (part.start > last_file.file.len || part.start < last_end)
			die("Malformed file chunk for %s",
			    hg_oid_to_hex(chunk->node));
		strbuf_add(&data, last_file.file.buf + last_end,
		           part.start - last_end);
		strbuf_addslice(&data, part.data);

		last_end = part.end;
	}

	if (last_file.file.len < last_end)
		die("Malformed file chunk for %s", hg_oid_to_hex(chunk->node));

	strbuf_add(&data, last_file.file.buf + last_end,
		   last_file.file.len - last_end);

	hg_file_init(&file);
	hg_file_from_memory(&file, chunk->node, &data);

	hg_file_store(&file, &last_file);
	hg_file_swap(&file, &last_file);
	hg_file_release(&file);
}

struct manifest_line {
       struct strslice path;
       struct hg_object_id oid;
       char attr;
};

static int split_manifest_line(struct strslice *slice,
                               struct manifest_line *result)
{
       // The format of a manifest line is:
       //    <path>\0<sha1><attr>
       // where attr is one of '', 'l', 'x'
       result->path = strslice_split_once(slice, '\0');
       if (result->path.len == 0)
	       return -1;

       if (slice->len < 41)
	       return -1;
       if (get_hash_hex(slice->buf, result->oid.hash))
	       return -1;
       *slice = strslice_slice(*slice, 40, SIZE_MAX);

       result->attr = slice->buf[0];
       if (result->attr == 'l' || result->attr == 'x') {
	       *slice = strslice_slice(*slice, 1, SIZE_MAX);
       } else if (result->attr == '\n')
	       result->attr = '\0';
       else
	       return -1;
       if (slice->len < 1 || slice->buf[0] != '\n')
	       return -1;
       *slice = strslice_slice(*slice, 1, SIZE_MAX);
       return 0;
}

static int add_parent(struct strbuf *data,
                      const struct hg_object_id *last_manifest_oid,
                      const struct branch *last_manifest,
                      const struct hg_object_id *parent_oid)
{
	if (!is_null_hg_oid(parent_oid)) {
		const struct object_id *note;
		if (hg_oideq(parent_oid, last_manifest_oid))
			note = &last_manifest->oid;
		else {
			note = resolve_hg2git(parent_oid);
		}
		if (!note)
			return -1;
		strbuf_addf(data, "parent %s\n", oid_to_hex(note));
	}
	return 0;
}

static void manifest_metadata_path(struct strbuf *out, struct strslice *in)
{
	struct strslice part;
	size_t len = in->len;
	part = strslice_split_once(in, '/');
	while (len != in->len) {
		strbuf_addch(out, '_');
		strbuf_addslice(out, part);
		strbuf_addch(out, '/');
		len = in->len;
		part = strslice_split_once(in, '/');
	}
	strbuf_addch(out, '_');
	strbuf_addslice(out, *in);
}

extern void add_manifest_head(const struct object_id *manifest);

void store_manifest(struct rev_chunk *chunk,
                    const struct strslice last_manifest_content,
                    struct strslice_mut stored_manifest)
{
	static struct hg_object_id last_manifest_oid;
	static struct branch *last_manifest;
	struct strbuf path = STRBUF_INIT;
	struct strbuf data = STRBUF_INIT;
	struct strslice_mut manifest = stored_manifest;
	struct strslice diff;
	struct rev_diff_part part;
	size_t last_end = 0;
	struct strslice slice;
	struct manifest_line line;

	if (!last_manifest) {
		last_manifest = new_branch("refs/cinnabar/manifests");
	}
	if (is_null_hg_oid(chunk->delta_node)) {
		if (last_manifest->branch_tree.tree) {
			release_tree_content_recursive(
				last_manifest->branch_tree.tree);
			last_manifest->branch_tree.tree = NULL;
		}
		oidclr(&last_manifest->branch_tree.versions[0].oid);
		oidclr(&last_manifest->branch_tree.versions[1].oid);
		hg_oidclr(&last_manifest_oid);
		oidclr(&last_manifest->oid);
		assert(last_manifest_content.len == 0);
	} else if (!hg_oideq(chunk->delta_node, &last_manifest_oid)) {
		const struct object_id *note;
		note = resolve_hg2git(chunk->delta_node);
		if (!note)
			die("Cannot find delta node %s for %s",
			    hg_oid_to_hex(chunk->delta_node),
			    hg_oid_to_hex(chunk->node));

		// TODO: this could be smarter, avoiding to throw everything
		// away. But this is what the equivalent fast-import commands
		// would do so for now, this is good enough.
		if (last_manifest->branch_tree.tree) {
			release_tree_content_recursive(
				last_manifest->branch_tree.tree);
			last_manifest->branch_tree.tree = NULL;
		}
		hg_oidcpy(&last_manifest_oid, chunk->delta_node);
		oidcpy(&last_manifest->oid, note);
		parse_from_existing(last_manifest);
		load_tree(&last_manifest->branch_tree);
	}

	rev_diff_start_iter(&diff, chunk);
	while (rev_diff_iter_next(&diff, &part)) {
		size_t len;
		if (part.start > last_manifest_content.len ||
		    part.start < last_end || part.start > part.end)
			goto malformed;
		len = part.start - last_end;
		strslice_copy(
			strslice_slice(last_manifest_content, last_end, len),
			strslice_mut_slice(manifest, 0, part.start - last_end));
		manifest = strslice_mut_slice(manifest, len, SIZE_MAX);
		strslice_copy(part.data,
		              strslice_mut_slice(manifest, 0, part.data.len));
		manifest = strslice_mut_slice(manifest, part.data.len, SIZE_MAX);

		last_end = part.end;

		// We assume manifest diffs are line-based.
		if (part.start > 0 &&
		    last_manifest_content.buf[part.start - 1] != '\n')
			goto malformed;
		if (part.end > 0 &&
		    last_manifest_content.buf[part.end - 1] != '\n')
			goto malformed;

		// TODO: Avoid a remove+add cycle for same-file modifications.

		// Process removed files.
		slice = strslice_slice(last_manifest_content, part.start,
                                       part.end - part.start);
		while (split_manifest_line(&slice, &line) == 0) {
			manifest_metadata_path(&path, &line.path);
			tree_content_remove(&last_manifest->branch_tree,
			                    path.buf, NULL, 1);
			strbuf_reset(&path);
		}

		// Some manifest chunks can have diffs like:
		//   - start: off, end: off, data: string of length len
		//   - start: off, end: off + len, data: ""
		// which is valid, albeit wasteful.
		// (example: 13b23929aeb7d1f1f21458dfcb32b8efe9aad39d in the
		// mercurial mercurial repository, as of writing)
		// What that means, however, is that we can't
		// tree_content_set for additions until the end because a
		// subsequent iteration might be removing what we just
		// added. So we don't do them now, we'll re-iterate the diff
		// later.
	}

	rev_diff_start_iter(&diff, chunk);
	while (rev_diff_iter_next(&diff, &part)) {
		// Process added files.
		slice = part.data;
		while (split_manifest_line(&slice, &line) == 0) {
			uint16_t mode;
			struct object_id file_node;
			hg_oidcpy2git(&file_node, &line.oid);

			if (line.attr == '\0')
				mode = 0160644;
			else if (line.attr == 'x')
				mode = 0160755;
			else if (line.attr == 'l')
				mode = 0160000;
			else
				goto malformed;

			manifest_metadata_path(&path, &line.path);
			tree_content_set(&last_manifest->branch_tree,
			                 path.buf, &file_node, mode, NULL);
			strbuf_reset(&path);
		}
	}

	strbuf_release(&path);

	if (last_manifest_content.len < last_end)
		goto malformed;

	strslice_copy(
		strslice_slice(last_manifest_content, last_end, SIZE_MAX),
		manifest);

	store_tree(&last_manifest->branch_tree);
	oidcpy(&last_manifest->branch_tree.versions[0].oid,
	       &last_manifest->branch_tree.versions[1].oid);

	strbuf_addf(&data, "tree %s\n",
	            oid_to_hex(&last_manifest->branch_tree.versions[1].oid));

	if ((add_parent(&data, &last_manifest_oid, last_manifest,
	                chunk->parent1) == -1) ||
	    (add_parent(&data, &last_manifest_oid, last_manifest,
	                chunk->parent2) == -1))
		goto malformed;

	hg_oidcpy(&last_manifest_oid, chunk->node);
	strbuf_addstr(&data, "author  <cinnabar@git> 0 +0000\n"
	                     "committer  <cinnabar@git> 0 +0000\n"
	                     "\n");
	strbuf_addstr(&data, hg_oid_to_hex(&last_manifest_oid));
	store_object(OBJ_COMMIT, &data, NULL, &last_manifest->oid, 0);
	strbuf_release(&data);
	add_hg2git(&last_manifest_oid, &last_manifest->oid);
	add_manifest_head(&last_manifest->oid);
	if ((cinnabar_check(CHECK_MANIFESTS)) &&
	    !check_manifest(&last_manifest->oid))
		die("sha1 mismatch for node %s", hg_oid_to_hex(chunk->node));
	return;

malformed:
	die("Malformed manifest chunk for %s", hg_oid_to_hex(chunk->node));
}

void ensure_store_init(void)
{
	ENSURE_INIT();
	require_explicit_termination = 1;
}

void store_replace_map(struct object_id *result) {
	struct strbuf buf = STRBUF_INIT;
	struct oidmap_iter iter;
	struct replace_object *replace;

	oidmap_iter_init(the_repository->objects->replace_map, &iter);
	while ((replace = oidmap_iter_next(&iter))) {
		strbuf_addf(&buf, "160000 %s%c",
		            oid_to_hex(&replace->original.oid), '\0');
		strbuf_add(&buf, replace->replacement.hash, the_hash_algo->rawsz);
	}
	store_object(OBJ_TREE, &buf, NULL, result, 0);
	strbuf_release(&buf);
}

void store_git_tree(struct strbuf *tree_buf, const struct object_id *reference,
                    struct object_id *result)
{
	struct last_object ref_tree = { STRBUF_INIT, 0, 0, 1 };
	struct last_object *last_tree = NULL;
	struct object_entry *oe = NULL;
	char *buf = NULL;

	ENSURE_INIT();
	if (reference) {
		oe = find_object((struct object_id *)reference);
	}
	if (oe && oe->idx.offset > 1 && oe->pack_id == pack_id) {
		unsigned long len;
		ref_tree.data.buf = buf = gfi_unpack_entry(oe, &len);
		ref_tree.data.len = len;
		ref_tree.offset = oe->idx.offset;
		ref_tree.depth = oe->depth;
		last_tree = &ref_tree;
	}
	store_object(OBJ_TREE, tree_buf, last_tree, result, 0);
	if (last_tree) {
		// store_object messes with last_tree so free using an old
		// copy of the pointer.
		free(buf);
	}
}

void store_git_blob(struct strbuf *blob_buf, struct object_id *result)
{
	ENSURE_INIT();
	store_object(OBJ_BLOB, blob_buf, NULL, result, 0);
}

void store_git_commit(struct strbuf *commit_buf, struct object_id *result)
{
	ENSURE_INIT();
	store_object(OBJ_COMMIT, commit_buf, NULL, result, 0);
}

const struct object_id empty_blob = { {
	0xe6, 0x9d, 0xe2, 0x9b, 0xb2, 0xd1, 0xd6, 0x43, 0x4b, 0x8b,
	0x29, 0xae, 0x77, 0x5a, 0xd8, 0xc2, 0xe4, 0x8c, 0x53, 0x91,
}, GIT_HASH_SHA1 };

const struct object_id *ensure_empty_blob(void) {
	struct object_entry *oe = find_object((struct object_id *)&empty_blob);
	if (!oe) {
		struct object_id hash;
		struct strbuf buf = STRBUF_INIT;
		store_object(OBJ_BLOB, &buf, NULL, &hash, 0);
		assert(oidcmp(&hash, &empty_blob) == 0);
	}
	return &empty_blob;
}
