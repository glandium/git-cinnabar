#define main fast_import_main
#include "fast-import.c"

static int initialized = 0;

static void cleanup();

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
	if (require_explicit_termination)
		die("stream ends early");

	end_packfile();

	dump_branches();
	unkeep_all_packs();

	initialized = 0;
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
