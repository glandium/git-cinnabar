#include "git-compat-util.h"
#if defined(__MINGW32__)
#define cmd_main fast_import_main
#else
#define main fast_import_main
#endif
#define sha1write fast_import_sha1write
#include "fast-import.c"
#undef sha1write

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
	if (!pack_win) {
		pack_win = xcalloc(1, sizeof(*pack_data->windows));
		pack_win->offset = 0;
		pack_win->len = 20;
		pack_win->base = xmalloc(packed_git_window_size);
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

	if (packed_git_window_size - pack_win->len >= count) {
		memcpy(pack_win->base + pack_win->len - 20, buf, count);
		pack_win->len += count;
	} else {
		/* We're closing the window, so we don't actually need
		 * to copy the beginning of the data, only what will
		 * remain in the new window. */
		pack_win->offset += (((off_t) pack_win->len - 20 + count)
			/ packed_git_window_size) * packed_git_window_size;
		pack_win->len = count % packed_git_window_size -
			(packed_git_window_size - pack_win->len);
		memcpy(pack_win->base, buf + count - pack_win->len + 20,
		       pack_win->len - 20);
		/* Ensure a pack window on the data before that, otherwise,
		 * use_pack() may try to create a window that overlaps with
		 * this one, and that won't work because it won't be complete. */
		sha1flush(f);
		if (prev_win)
			unuse_pack(&prev_win);
		use_pack(pack_data, &prev_win,
			 pack_win->offset - packed_git_window_size, NULL);
	}
}

/* Mostly copied from fast-import.c's main() */
static void init()
{
	int i;

	reset_pack_idx_option(&pack_idx_opts);
	git_pack_config();
	if (!pack_compression_seen && core_compression_seen)
		pack_compression_level = core_compression_level;

	alloc_objects(object_entry_alloc);
	strbuf_init(&command_buf, 0);
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
	set_die_routine(die_nicely);

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

	end_packfile();

	if (!require_explicit_termination)
		dump_branches();

	unkeep_all_packs();

	initialized = 0;

	pack_report();
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

int maybe_handle_command(const char *command, struct string_list *args)
{
#define COMMON_HANDLING() { \
	if (!initialized) \
		init(); \
	fill_command_buf(command, args); \
}

	if (!strcmp(command, "done")) {
		COMMON_HANDLING();
		require_explicit_termination = 0;
		cleanup();
	} else if (!strcmp(command, "feature")) {
		COMMON_HANDLING();
		parse_feature(command_buf.buf + sizeof("feature"));
	} else if (!strcmp(command, "blob")) {
		COMMON_HANDLING();
		parse_new_blob();
	} else if (!strcmp(command, "commit")) {
		COMMON_HANDLING();
		parse_new_commit(command_buf.buf + sizeof("commit"));
	} else if (!strcmp(command, "reset")) {
		COMMON_HANDLING();
		parse_reset_branch(command_buf.buf + sizeof("reset"));
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
