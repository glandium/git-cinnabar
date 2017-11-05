#define cmd_main fast_import_main
#define sha1write fast_import_sha1write
#include "fast-import.patched.c"
#undef sha1write
#include "cinnabar-fast-import.h"
#include "cinnabar-helper.h"
#include "hg-bundle.h"
#include "hg-data.h"
#include "mru.h"
#include "notes.h"
#include "sha1-array.h"
#include "tree-walk.h"

#define ENSURE_INIT() do { \
	if (!initialized) \
		init(); \
} while (0)

static int initialized = 0;

static void cleanup();

/* Divert fast-import.c's calls to sha1write so as to keep a fake pack window
 * on the last written bits, avoiding munmap/mmap cycles from
 * gfi_unpack_entry. */
static struct pack_window *pack_win;
static struct pack_window *prev_win;

extern void sha1write(struct sha1file *, const void *, unsigned int);

void fast_import_sha1write(struct sha1file *f, const void *buf,
			   unsigned int count)
{
	size_t window_size;

	if (!pack_win) {
		pack_win = xcalloc(1, sizeof(*pack_data->windows));
		pack_win->offset = 0;
		pack_win->len = 20;
		pack_win->base = xmalloc(packed_git_window_size + 20);
		pack_win->next = NULL;
	}
	/* pack_data is not set the first time sha1write is called */
	if (pack_data && !pack_data->windows) {
		pack_data->windows = pack_win;
		pack_data->pack_size = pack_win->len;
	}

	sha1write(f, buf, count);
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
		sha1flush(f);
		if (prev_win)
			unuse_pack(&prev_win);
		use_pack(pack_data, &prev_win,
			 pack_win->offset + 20 - packed_git_window_size, NULL);
		assert(prev_win->len == packed_git_window_size);

		/* Copy the overlapping bytes. */
		memcpy(pack_win->base,
		       prev_win->base + packed_git_window_size - 20, 20);

		/* Fill up the new window. */
		memcpy(pack_win->base + 20, buf + count + 40 - pack_win->len,
		       pack_win->len - 40);
	}
}

extern off_t real_find_pack_entry_one(const unsigned char *sha1,
				      struct packed_git *p);

off_t find_pack_entry_one(const unsigned char *sha1, struct packed_git *p)
{
	if (p == pack_data) {
		struct object_entry *oe = get_object_entry(sha1);
		if (oe && oe->idx.offset > 1)
			return oe->idx.offset;
		return 0;
	}
	return real_find_pack_entry_one(sha1, p);
}

void *get_object_entry(const unsigned char *sha1)
{
	struct object_id oid;
	hashcpy(oid.hash, sha1);
	return find_object(&oid);
}

/* Mostly copied from fast-import.c's cmd_main() */
static void init()
{
	int i;

	reset_pack_idx_option(&pack_idx_opts);
	git_pack_config();
	ignore_case = 0;
	max_depth = 50;
	warn_on_object_refname_ambiguity = 0;

	alloc_objects(object_entry_alloc);
	strbuf_init(&command_buf, 0);
	atom_table_sz = 131071;
	atom_table = xcalloc(atom_table_sz, sizeof(struct atom_str*));
	branch_table = xcalloc(branch_table_sz, sizeof(struct branch*));
	avail_tree_table = xcalloc(avail_tree_table_sz, sizeof(struct avail_tree_content*));
	marks = pool_calloc(1, sizeof(struct mark_set));

	global_argc = 1;

	rc_free = pool_alloc(cmd_save * sizeof(*rc_free));
	for (i = 0; i < (cmd_save - 1); i++)
		rc_free[i].next = &rc_free[i + 1];
	rc_free[cmd_save - 1].next = NULL;

	prepare_packed_git();
	start_packfile();
	install_packed_git(pack_data);
	mru_append(&packed_git_mru, pack_data);
	set_die_routine(die_nicely);

	parse_one_feature("force", 0);
	initialized = 1;
	atexit(cleanup);
}

static void cleanup()
{
	if (!initialized)
		return;

	if (require_explicit_termination)
		object_count = 0;
	end_packfile();
	reprepare_packed_git();

	if (!require_explicit_termination)
		dump_branches();

	unkeep_all_packs();

	initialized = 0;

	if (cinnabar_check & CHECK_HELPER)
		pack_report();
}

static void end_packfile()
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
	{
		struct packed_git *pack, *prev;
		for (prev = NULL, pack = packed_git; pack;
		     prev = pack, pack = pack->next) {
			if (pack != pack_data)
				continue;
			if (prev)
				prev->next = pack->next;
			else
				packed_git = pack->next;
			break;
		}
	}

	real_end_packfile();
}

const struct object_id empty_tree = { {
	0x4b, 0x82, 0x5d, 0xc6, 0x42, 0xcb, 0x6e, 0xb9, 0xa0, 0x60,
	0xe5, 0x4b, 0xf8, 0xd6, 0x92, 0x88, 0xfb, 0xee, 0x49, 0x04,
} };

/* Override fast-import.c's parse_mark_ref to allow a syntax for
 * mercurial sha1s, resolved through hg2git. Hack: it uses a fixed
 * mark for this: 2.
 * The added syntax is: :h<sha1>[:path]
 * With :path, a tree is returned. */
static uintmax_t parse_mark_ref(const char *p, char **endptr)
{
	struct object_id oid;
	const struct object_id *note;
	struct object_entry *e;

	assert(*p == ':');
	if (p[1] != 'h')
		return real_parse_mark_ref(p, endptr);
	if (get_oid_hex(p + 2, &oid))
		die("Invalid sha1");

	ensure_notes(&hg2git);
	note = get_note(&hg2git, &oid);
	*endptr = (char *)p + 42;
	if (**endptr == ':') {
		char *path_end = strpbrk(++(*endptr), " \n");
		if (path_end) {
			unsigned mode;
			char *path = xstrndup(*endptr, path_end - *endptr);
			if (!get_tree_entry(note->hash, path, oid.hash, &mode))
				note = &oid;
			else
				note = &empty_tree;
			free(path);
			*endptr = path_end;
		}
	}
	e = find_object((struct object_id *)note);
	if (!e) {
		e = insert_object((struct object_id *)note);
		e->type = sha1_object_info(note->hash, NULL);
		e->pack_id = MAX_PACK_ID;
		e->idx.offset = 1;
	}
	insert_mark(2, e);
	return 2;
}

/* Fill fast-import.c's command_buf and recent commands */
static void fill_command_buf(const char *command, struct string_list *args)
{
	struct recent_command *rc;
	struct string_list_item *arg;

	strbuf_detach(&command_buf, NULL);
	strbuf_addstr(&command_buf, command);
	for_each_string_list_item(arg, args) {
		strbuf_addch(&command_buf, ' ');
		strbuf_addstr(&command_buf, arg->string);
	}

	/* Copied from fast-import.c's read_next_command() */
	rc = rc_free;
	if (rc)
		rc_free = rc->next;
	else {
		rc = cmd_hist.next;
		cmd_hist.next = rc->next;
		cmd_hist.next->prev = &cmd_hist;
		free(rc->buf);
	}

	rc->buf = command_buf.buf;
	rc->prev = cmd_tail;
	rc->next = cmd_hist.prev;
	rc->prev->next = rc;
	cmd_tail = rc;
}

void maybe_reset_notes(const char *branch)
{
	struct notes_tree *notes = NULL;

	// The python frontend will use fast-import commands to commit the
	// hg2git and git2hg trees as separate temporary branches, and then
	// remove them. We want to update the notes tree on the temporary
	// branches, and keep them there when they are removed.
	if (!strcmp(branch, "refs/cinnabar/hg2git")) {
		notes = &hg2git;
	} else if (!strcmp(branch, "refs/notes/cinnabar")) {
		notes = &git2hg;
	}
	if (notes) {
		struct branch *b = lookup_branch(branch);
		if (!is_null_oid(&b->oid)) {
			if (notes->initialized)
				free_notes(notes);
			init_notes(notes, oid_to_hex(&b->oid),
				   combine_notes_ignore, 0);
		}
	}
}

struct oid_array changeset_heads = OID_ARRAY_INIT;
struct oid_array manifest_heads = OID_ARRAY_INIT;

static void oid_array_insert(struct oid_array *array, int index,
                             const struct object_id *oid)
{
	ALLOC_GROW(array->oid, array->nr + 1, array->alloc);
	memmove(&array->oid[index+1], &array->oid[index],
	        sizeof(array->oid[0]) * (array->nr++ - index));
	oidcpy(&array->oid[index], oid);
}

static void oid_array_remove(struct oid_array *array, int index)
{
	memmove(&array->oid[index], &array->oid[index+1],
	        sizeof(array->oid[0]) * (array->nr-- - index));
}

void ensure_heads(struct oid_array *heads)
{
	struct commit *c = NULL;
	struct commit_list *parent;
	const char *body = NULL;

	/* We always keep the array sorted, so if it's not sorted, it's
	 * not initialized. */
	if (heads->sorted)
		return;

	heads->sorted = 1;
	if (heads == &changeset_heads)
		c = lookup_commit_reference_by_name(CHANGESETS_REF);
	else if (heads == &manifest_heads)
		c = lookup_commit_reference_by_name(MANIFESTS_REF);
	if (c) {
		const char *msg = get_commit_buffer(c, NULL);
		body = strstr(msg, "\n\n") + 2;
		unuse_commit_buffer(c, msg);
	}
	for (parent = c ? c->parents : NULL; parent;
	     parent = parent->next) {
		const struct object_id *parent_sha1 =
			&parent->item->object.oid;
		/* Skip first parent when "has-flat-manifest-tree" is
		 * there */
		if (heads == &manifest_heads && body && parent == c->parents &&
		    !strcmp(body, "has-flat-manifest-tree"))
			continue;
		if (!heads->nr || oidcmp(&heads->oid[heads->nr-1],
		                         parent_sha1)) {
			oid_array_insert(heads, heads->nr, parent_sha1);
		} else {
			/* This should not happen, but just in case,
			 * instead of failing. */
			add_head(heads, parent_sha1);
		}
	}
}

void add_head(struct oid_array *heads, const struct object_id *oid)
{
	struct commit *c = NULL;
	struct commit_list *parent;
	int pos;

	ensure_heads(heads);
	c = lookup_commit(oid);
	parse_commit_or_die(c);

	for (parent = c->parents; parent; parent = parent->next) {
		pos = oid_array_lookup(heads, &parent->item->object.oid);
		if (pos >= 0)
			oid_array_remove(heads, pos);
	}
	pos = oid_array_lookup(heads, oid);
	if (pos >= 0)
		return;
	oid_array_insert(heads, -pos - 1, oid);
}

static void handle_changeset_conflict(struct object_id *hg_id,
                                      struct object_id *git_id)
{
	/* There are cases where two changesets would map to the same git
	 * commit because their differences are not in information stored in
	 * the git commit (different manifest node, but identical tree ;
	 * different branches ; etc.)
	 * In that case, add invisible characters to the commit message until
	 * we find a commit that doesn't map to another changeset.
	 */
	struct strbuf buf = STRBUF_INIT;
	const struct object_id *note;

	ensure_notes(&git2hg);
	while ((note = get_note(&git2hg, git_id))) {
		struct object_id oid;
		enum object_type type;
		unsigned long len;
		char *content = read_sha1_file_extended(note->hash, &type, &len, 0);
		if (len < 50 || !starts_with(content, "changeset ") ||
		    get_oid_hex(&content[10], &oid))
			die("Invalid git2hg note for %s", oid_to_hex(git_id));

		free(content);

		/* We might just already have the changeset in store */
		if (oidcmp(&oid, hg_id) == 0)
			break;

		if (!buf.len) {
			content = read_sha1_file_extended(git_id->hash, &type,
			                                  &len, 0);
			strbuf_add(&buf, content, len);
			free(content);
		}

		strbuf_addch(&buf, '\0');
		store_object(OBJ_COMMIT, &buf, NULL, git_id, 0);
	}
	strbuf_release(&buf);

}

static void do_set(struct string_list *args)
{
	enum object_type type;
	struct object_id hg_id, git_id;
	struct oid_array *heads = NULL;
	struct notes_tree *notes = &hg2git;
	int is_changeset = 0;

	if (args->nr != 3)
		die("set needs 3 arguments");

	if (!strcmp(args->items[0].string, "file")) {
		type = OBJ_BLOB;
	} else if (!strcmp(args->items[0].string, "manifest") ||
	           !strcmp(args->items[0].string, "changeset")) {
		type = OBJ_COMMIT;
		if (args->items[0].string[0] == 'm')
			heads = &manifest_heads;
		else
			is_changeset = 1;
	} else if (!strcmp(args->items[0].string, "changeset-metadata")) {
		type = OBJ_BLOB;
		notes = &git2hg;
	} else if (!strcmp(args->items[0].string, "file-meta")) {
		type = OBJ_BLOB;
		notes = &files_meta;
	} else {
		die("Unknown kind of object: %s", args->items[0].string);
	}

	if (get_oid_hex(args->items[1].string, &hg_id))
		die("Invalid sha1");

	if (args->items[2].string[0] == ':') {
		uintmax_t mark = parse_mark_ref_eol(args->items[2].string);
		struct object_entry *oe = find_mark(mark);
		oidcpy(&git_id, &oe->idx.oid);
	} else if (get_oid_hex(args->items[2].string, &git_id))
		die("Invalid sha1");

	if (notes == &git2hg) {
		const struct object_id *note;
		ensure_notes(&hg2git);
		note = get_note(&hg2git, &hg_id);
		if (note)
			oidcpy(&hg_id, note);
		else if (!is_null_oid(&git_id))
			die("Invalid sha1");
	}

	ensure_notes(notes);
	if (is_null_oid(&git_id)) {
		remove_note(notes, hg_id.hash);
	} else if (sha1_object_info(git_id.hash, NULL) != type) {
		die("Invalid object");
	} else {
		if (is_changeset)
			handle_changeset_conflict(&hg_id, &git_id);
		add_note(notes, &hg_id, &git_id, NULL);
		if (heads)
			add_head(heads, &git_id);
	}
}

struct store_each_note_data {
	struct tree_entry *tree;
	struct notes_tree *notes;
};

static int store_each_note(const struct object_id *object_oid,
                           const struct object_id *note_oid, char *note_path,
                           void *data)
{
	int mode;
	size_t len;
	struct store_each_note_data *d = (struct store_each_note_data *)data;

	switch (sha1_object_info(note_oid->hash, NULL)) {
	case OBJ_BLOB: {
		if (d->notes == &files_meta) {
			mode = S_IFREG | 0644;
			break;
		}
	}
	case OBJ_COMMIT:
		mode = S_IFGITLINK;
		break;
	case OBJ_TREE:
		mode = S_IFDIR;
		// for_each_note calls with a path ending with a slash, but
		// tree_content_set doesn't like that
		len = strlen(note_path);
		if (note_path[len - 1] == '/')
			note_path[len - 1] = '\0';
		break;
	default:
		die("Unexpected object type in notes tree");
	}
	tree_content_set(d->tree, note_path, note_oid, mode, NULL);
	return 0;
}

static void store_notes(struct notes_tree *notes, struct object_id *result)
{
	hashcpy(result->hash, null_sha1);
	if (notes->dirty) {
		struct store_each_note_data data;
		data.tree = new_tree_entry();
		data.notes = notes;

		require_explicit_termination = 1;
		memset(data.tree, 0, sizeof(*data.tree));
		if (for_each_note(notes, FOR_EACH_NOTE_DONT_UNPACK_SUBTREES |
		                         FOR_EACH_NOTE_YIELD_SUBTREES,
		                  store_each_note, &data))
			die("Failed to store notes");
		store_tree(data.tree);
		oidcpy(result, &data.tree->versions[1].oid);
		release_tree_entry(data.tree);
	}
}

void hg_file_store(struct hg_file *file, struct hg_file *reference)
{
	struct object_id file_oid;
	struct object_id oid;
	struct last_object last_blob = { STRBUF_INIT, 0, 0, 1 };
	struct object_entry *oe = NULL;

	ENSURE_INIT();

        hashcpy(file_oid.hash, file->sha1);

	if (file->metadata.buf) {
		store_object(OBJ_BLOB, &file->metadata, NULL, &oid, 0);
		ensure_notes(&files_meta);
		add_note(&files_meta, &file_oid, &oid, NULL);
	}

	if (reference)
		oe = (struct object_entry *) reference->content_oe;

	if (oe && oe->idx.offset > 1) {
		last_blob.data.buf = reference->content.buf;
		last_blob.data.len = reference->content.len;
		last_blob.offset = oe->idx.offset;
		last_blob.depth = oe->depth;
	}
	store_object(OBJ_BLOB, &file->content, &last_blob, &oid, 0);
	ensure_notes(&hg2git);
	add_note(&hg2git, &file_oid, &oid, NULL);

	file->content_oe = find_object(&oid);
}

static void store_file(struct rev_chunk *chunk)
{
	static struct hg_file last_file;
	struct hg_file file;
	struct strbuf data = STRBUF_INIT;
	struct rev_diff_part diff;
	size_t last_end = 0;

	if (is_empty_hg_file(chunk->node))
		return;

	if (hashcmp(chunk->delta_node, last_file.sha1)) {
		hg_file_release(&last_file);

		if (!is_null_sha1(chunk->delta_node))
			hg_file_load(&last_file, chunk->delta_node);

	}

	rev_diff_start_iter(&diff, chunk);
	while (rev_diff_iter_next(&diff)) {
		strbuf_add(&data, last_file.file.buf + last_end,
		           diff.start - last_end);
		strbuf_addbuf(&data, &diff.data);

		last_end = diff.end;
	}

	strbuf_add(&data, last_file.file.buf + last_end,
		   last_file.file.len - last_end);

	hg_file_init(&file);
	hg_file_from_memory(&file, chunk->node, &data);

	hg_file_store(&file, &last_file);
	hg_file_swap(&file, &last_file);
	hg_file_release(&file);
}

static void do_store(struct string_list *args)
{
	if (args->nr < 2)
		die("store needs at least 3 arguments");

	if (!strcmp(args->items[0].string, "metadata")) {
		if (args->nr != 2)
			die("store metadata needs 3 arguments");
		if (!strcmp(args->items[1].string, "hg2git") ||
		    !strcmp(args->items[1].string, "git2hg") ||
		    !strcmp(args->items[1].string, "files-meta")) {
			struct object_id result;
			struct notes_tree *notes = NULL;
			switch (args->items[1].string[0]) {
			case 'f':
				notes = &files_meta;
				break;
			case 'g':
				notes = &git2hg;
				break;
			case 'h':
				notes = &hg2git;
			}
			store_notes(notes, &result);
			write_or_die(1, oid_to_hex(&result), 40);
			write_or_die(1, "\n", 1);
		} else {
			die("Unknown metadata kind: %s", args->items[1].string);
		}
	} else if (!strcmp(args->items[0].string, "file")) {
		struct strbuf buf = STRBUF_INIT;
		struct rev_chunk chunk;
		size_t length;
		struct object_id oid;
		unsigned char *delta_node;

		if (args->nr != 3)
			die("store file needs 4 arguments");
		if (!strcmp(args->items[1].string, "cg2")) {
			delta_node = NULL;
		} else {
			if (get_oid_hex(args->items[1].string, &oid))
				die("Neither 'cg2' nor a sha1: %s",
				    args->items[1].string);
			delta_node = oid.hash;
		}

		// TODO: Error handling
		length = strtol(args->items[2].string, NULL, 10);
		strbuf_fread(&buf, length, stdin);
		rev_chunk_from_memory(&chunk, &buf, delta_node);
		store_file(&chunk);
		rev_chunk_release(&chunk);
	} else {
		die("Unknown store kind: %s", args->items[0].string);
	}
}

void store_git_tree(struct strbuf *tree_buf, const struct object_id *reference,
                    struct object_id *result)
{
	struct last_object ref_blob = { STRBUF_INIT, 0, 0, 1 };
	struct last_object *last_blob = NULL;
	struct object_entry *oe = NULL;
	char *buf = NULL;

	ENSURE_INIT();
	if (reference) {
		oe = find_object((struct object_id *)reference);
	}
	if (oe && oe->idx.offset > 1) {
		unsigned long len;
		ref_blob.data.buf = buf = gfi_unpack_entry(oe, &len);
		ref_blob.data.len = len;
		ref_blob.offset = oe->idx.offset;
		ref_blob.depth = oe->depth;
		last_blob = &ref_blob;
	}
	store_object(OBJ_TREE, tree_buf, last_blob, result, 0);
	if (last_blob) {
		// store_object messes with last_blob so free using an old
		// copy of the pointer.
		free(buf);
	}
}

void store_git_commit(struct strbuf *commit_buf, struct object_id *result)
{
	ENSURE_INIT();
	store_object(OBJ_COMMIT, commit_buf, NULL, result, 0);
}

const struct object_id empty_blob = { {
	0xe6, 0x9d, 0xe2, 0x9b, 0xb2, 0xd1, 0xd6, 0x43, 0x4b, 0x8b,
	0x29, 0xae, 0x77, 0x5a, 0xd8, 0xc2, 0xe4, 0x8c, 0x53, 0x91,
} };

const struct object_id *ensure_empty_blob() {
	struct object_entry *oe = find_object((struct object_id *)&empty_blob);
	if (!oe) {
		struct object_id hash;
		struct strbuf buf = STRBUF_INIT;
		store_object(OBJ_BLOB, &buf, NULL, &hash, 0);
		assert(oidcmp(&hash, &empty_blob) == 0);
	}
	return &empty_blob;
}

int maybe_handle_command(const char *command, struct string_list *args)
{
#define COMMON_HANDLING() do { \
	ENSURE_INIT(); \
	fill_command_buf(command, args); \
} while (0)

	if (!strcmp(command, "done")) {
		COMMON_HANDLING();
		require_explicit_termination = 0;
		cleanup();
	} else if (!strcmp(command, "feature")) {
		COMMON_HANDLING();
		parse_feature(command_buf.buf + sizeof("feature"));
	} else if (!strcmp(command, "set")) {
		ENSURE_INIT();
		do_set(args);
	} else if (!strcmp(command, "store")) {
		ENSURE_INIT();
		require_explicit_termination = 1;
		do_store(args);
	} else if (!strcmp(command, "blob")) {
		COMMON_HANDLING();
		require_explicit_termination = 1;
		parse_new_blob();
	} else if (!strcmp(command, "commit")) {
		char *arg;
		COMMON_HANDLING();
		require_explicit_termination = 1;
		arg = strdup(command_buf.buf + sizeof("commit"));
		parse_new_commit(command_buf.buf + sizeof("commit"));
		maybe_reset_notes(arg);
		free(arg);
	} else if (!strcmp(command, "reset")) {
		char *arg;
		COMMON_HANDLING();
		arg = strdup(command_buf.buf + sizeof("reset"));
		parse_reset_branch(command_buf.buf + sizeof("reset"));
		maybe_reset_notes(arg);
		free(arg);
	} else if (!strcmp(command, "get-mark")) {
		COMMON_HANDLING();
		parse_get_mark(command_buf.buf + sizeof("get_mark"));
	} else if (!strcmp(command, "cat-blob")) {
		COMMON_HANDLING();
		parse_cat_blob(command_buf.buf + sizeof("cat-blob"));
	} else if (!strcmp(command, "ls")) {
		COMMON_HANDLING();
		parse_ls(command_buf.buf + sizeof("ls"), NULL);
	} else
		return 0;

	return 1;
}
