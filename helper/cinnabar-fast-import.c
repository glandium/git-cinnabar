#undef sha1write
#include "cinnabar-fast-import.h"
#include "cinnabar-helper.h"
#include "mru.h"
#include "notes.h"
#include "sha1-array.h"

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
		pack_win->offset = ((pack_data->pack_size - 20 + 1)
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
		struct object_entry *oe = find_object((unsigned char *)sha1);
		if (oe && oe->idx.offset > 1)
			return oe->idx.offset;
		return 0;
	}
	return real_find_pack_entry_one(sha1, p);
}

/* Mostly copied from fast-import.c's cmd_main() */
static void init()
{
	int i;

	reset_pack_idx_option(&pack_idx_opts);
	git_pack_config();
	ignore_case = 0;
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
	mru_append(packed_git_mru, pack_data);
	set_die_routine(die_nicely);

	parse_one_feature("force", 0);
	initialized = 1;
	atexit(cleanup);
}

static void cleanup()
{
	if (!initialized)
		return;

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

	if (require_explicit_termination)
		object_count = 0;
	end_packfile();
	reprepare_packed_git();

	if (!require_explicit_termination)
		dump_branches();

	unkeep_all_packs();

	initialized = 0;

	pack_report();
}

/* Override fast-import.c's parse_mark_ref to allow a syntax for
 * mercurial sha1s, resolved through hg2git. Hack: it uses a fixed
 * mark for this: 2.
 * The added syntax is: :h<sha1> */
static uintmax_t parse_mark_ref(const char *p, char **endptr)
{
	struct object_id oid;
	const unsigned char *note;
	struct object_entry *e;

	assert(*p == ':');
	if (p[1] != 'h')
		return real_parse_mark_ref(p, endptr);
	if (get_oid_hex(p + 2, &oid))
		die("Invalid sha1");

	ensure_hg2git();
	note = get_note(&hg2git, oid.hash);
	e = find_object((unsigned char *)note);
	if (!e) {
		e = insert_object((unsigned char *)note);
		e->type = sha1_object_info(note, NULL);
		e->pack_id = MAX_PACK_ID;
		e->idx.offset = 1;
	}
	insert_mark(2, e);
	*endptr = (char *)p + 42;
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
		if (!is_null_sha1(b->sha1)) {
			if (notes->initialized)
				free_notes(notes);
			init_notes(notes, sha1_to_hex(b->sha1),
				   combine_notes_overwrite, 0);
		}
	}
}

struct sha1_array manifest_heads = SHA1_ARRAY_INIT;

static void sha1_array_insert(struct sha1_array *array, int index,
                              const unsigned char *sha1)
{
	ALLOC_GROW(array->sha1, array->nr + 1, array->alloc);
	memmove(array->sha1[index+1], array->sha1[index],
	        sizeof(array->sha1[0]) * (array->nr++ - index));
	hashcpy(array->sha1[index], sha1);
}

static void sha1_array_remove(struct sha1_array *array, int index)
{
	memmove(array->sha1[index], array->sha1[index+1],
	        sizeof(array->sha1[0]) * (array->nr-- - index));
}

static void add_head(struct sha1_array *heads, const unsigned char *sha1)
{
	struct commit *c = NULL;
	struct commit_list *parent;
	int pos;

	/* We always keep the array sorted, so if it's not sorted, it's
	 * not initialized. */
	if (!heads->sorted) {
		const char *body = NULL;
		heads->sorted = 1;
		if (heads == &manifest_heads)
			c = lookup_commit_reference_by_name(MANIFESTS_REF);
		if (c)
			body = strstr(get_commit_buffer(c, NULL), "\n\n") + 2;
		for (parent = c ? c->parents : NULL; parent;
		     parent = parent->next) {
			const unsigned char *parent_sha1 =
				parent->item->object.oid.hash;
			/* Skip first parent when "has-flat-manifest-tree" is
			 * there */
			if (body && parent == c->parents &&
			    !strcmp(body, "has-flat-manifest-tree"))
				continue;
			if (!heads->nr || hashcmp(heads->sha1[heads->nr-1],
			                          parent_sha1)) {
				sha1_array_insert(heads, heads->nr, parent_sha1);
			} else {
				/* This should not happen, but just in case,
				 * instead of failing. */
				add_head(heads, parent_sha1);
			}
		}
	}

	c = lookup_commit(sha1);
	parse_commit_or_die(c);

	for (parent = c->parents; parent; parent = parent->next) {
		pos = sha1_array_lookup(heads, parent->item->object.oid.hash);
		if (pos >= 0)
			sha1_array_remove(heads, pos);
	}
	pos = sha1_array_lookup(heads, sha1);
	if (pos >= 0)
		return;
	sha1_array_insert(heads, -pos - 1, sha1);
}

static void do_set(struct string_list *args)
{
	enum object_type type;
	struct object_id hg_id, git_id;
	struct sha1_array *heads = NULL;

	if (args->nr != 3)
		die("set needs 3 arguments");

	if (!strcmp(args->items[0].string, "file")) {
		type = OBJ_BLOB;
	} else if (!strcmp(args->items[0].string, "manifest") ||
	           !strcmp(args->items[0].string, "changeset")) {
		type = OBJ_COMMIT;
		if (args->items[0].string[0] == 'm')
			heads = &manifest_heads;
	} else {
		die("Unknown kind of object: %s", args->items[0].string);
	}

	if (get_oid_hex(args->items[1].string, &hg_id))
		die("Invalid sha1");

	if (args->items[2].string[0] == ':') {
		uintmax_t mark = parse_mark_ref_eol(args->items[2].string);
		struct object_entry *oe = find_mark(mark);
		hashcpy(git_id.hash, oe->idx.sha1);
	} else if (get_oid_hex(args->items[2].string, &git_id))
		die("Invalid sha1");

	ensure_hg2git();
	if (is_null_oid(&git_id)) {
		remove_note(&hg2git, hg_id.hash);
	} else if (sha1_object_info(git_id.hash, NULL) != type) {
		die("Invalid object");
	} else {
		add_note(&hg2git, hg_id.hash, git_id.hash, NULL);
		if (heads)
			add_head(heads, git_id.hash);
	}
}

static int store_each_note(const unsigned char *object_sha1,
                           const unsigned char *note_sha1, char *note_path,
                           void *data)
{
	int mode;
	size_t len;
	struct tree_entry *tree = (struct tree_entry *)data;

	switch (sha1_object_info(note_sha1, NULL)) {
	case OBJ_BLOB:
		mode = S_IFREG | 0644;
		break;
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
	tree_content_set(tree, note_path, note_sha1, mode, NULL);
	return 0;
}

static void store_notes(struct notes_tree *notes, struct object_id *result)
{
	hashcpy(result->hash, null_sha1);
	if (notes->dirty) {
		struct tree_entry *tree = new_tree_entry();

		require_explicit_termination = 1;
		memset(tree, 0, sizeof(*tree));
		if (for_each_note(notes, FOR_EACH_NOTE_DONT_UNPACK_SUBTREES |
		                         FOR_EACH_NOTE_YIELD_SUBTREES,
		                  store_each_note, tree))
			die("Failed to store notes");
		store_tree(tree);
		hashcpy(result->hash, tree->versions[1].sha1);
		release_tree_entry(tree);
	}
}

static void do_store(struct string_list *args)
{
	if (args->nr != 2)
		die("store needs 3 arguments");

	if (!strcmp(args->items[0].string, "metadata")) {
		if (!strcmp(args->items[1].string, "hg2git")) {
			struct object_id result;
			store_notes(&hg2git, &result);
			write_or_die(1, oid_to_hex(&result), 40);
			write_or_die(1, "\n", 1);
		} else {
			die("Unknown metadata kind: %s", args->items[1].string);
		}
	} else {
		die("Unknown store kind: %s", args->items[0].string);
	}
}

int maybe_handle_command(const char *command, struct string_list *args)
{
#define INIT() do { \
	if (!initialized) \
		init(); \
} while (0)

#define COMMON_HANDLING() do { \
	INIT(); \
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
		INIT();
		do_set(args);
	} else if (!strcmp(command, "store")) {
		INIT();
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
