#include "git-compat-util.h"
#include "cache.h"
#include "hg-connect-internal.h"
#include "hg-bundle.h"
#include "strbuf.h"
#include "tempfile.h"
#include "url.h"

/* Copied from bisect.c */
static char *join_oid_array_hex(struct oid_array *array, char delim)
{
	struct strbuf joined_hexs = STRBUF_INIT;
	int i;

	for (i = 0; i < array->nr; i++) {
		strbuf_addstr(&joined_hexs, oid_to_hex(&array->oid[i]));
		if (i + 1 < array->nr)
			strbuf_addch(&joined_hexs, delim);
	}

	return strbuf_detach(&joined_hexs, NULL);
}

/* Split the list of capabilities a mercurial server returned. Also url-decode
 * the bundle2 value in place.
 * The resulting string_list contains capability names in item->string, and
 * their corresponding value in item->util. */
void split_capabilities(struct string_list *list, const char *buf)
{
	struct string_list_item *item;
	string_list_split(list, buf, ' ', -1);
	for_each_string_list_item(item, list) {
		char *value = strchr(item->string, '=');
		if (value) {
			*(value++) = '\0';
			item->util = value;
			if (!strcmp(item->string, "bundle2")) {
				char *decoded = url_decode(value);
				/* url decoded is always smaller. */
				xsnprintf(value, strlen(value), "%s", decoded);
				free(decoded);
			}
		}
	}
}

const char *hg_get_capability(struct hg_connection *conn, const char *name)
{
	struct string_list_item *item;

	item = unsorted_string_list_lookup(&conn->capabilities, name);
	if (item)
		return item->util ? item->util : "";
	return NULL;
}

/* Generic helpers to handle passing parameters through the mercurial
 * wire protocol. */
static void command_add_asterisk(void *data,
				 command_add_param_t command_add_param,
				 const struct string_list *params)
{
	const struct string_list_item *item;
	union param_value num;
	num.size = params ? params->nr : 0;
	command_add_param(data, "*", num);
	if (params)
		for_each_string_list_item(item, params) {
			const char *name = item->string;
			union param_value value;
			value.value = item->util;
			command_add_param(data, name, value);
		}
}

void prepare_command(void *data, command_add_param_t command_add_param,
		     va_list ap)
{
	const char *name;

	while ((name = va_arg(ap, const char *))) {
		if (strcmp(name, "*")) {
			union param_value value;
			value.value = va_arg(ap, const char *);
			command_add_param(data, name, value);
		} else
			command_add_asterisk(
				data, command_add_param,
				va_arg(ap, const struct string_list *));
	}
}

struct hg_connection *hg_connect(const char *url, int flags)
{
	struct hg_connection *conn;
	const char *required_caps[] = {
		"getbundle",
		"branchmap",
		"known",
		"pushkey",
		//TODO: defer to when pushing.
		"unbundle",
	};
	int i;

#ifndef NO_CURL
	if (!strncmp(url, "http://", sizeof("http://") - 1) ||
	    !strncmp(url, "https://", sizeof("https://") - 1)) {
		conn = hg_connect_http(url, flags);
	} else
#endif
		conn = hg_connect_stdio(url, flags);

	if (!conn)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(required_caps); i++)
		if (!hg_get_capability(conn, required_caps[i]))
			die("Mercurial repository doesn't support the required"
			    " \"%s\" capability.", required_caps[i]);

	return conn;
}

/* Batched output concatenates all responses, separating them with ';'
 * The output also has four characters escaped: '=', ';', ',' and ':',
 * as, resp., ":e", ":s", ":o", and ":c". */
static void split_batched_repo_state(struct strbuf *state,
				     struct strbuf *branchmap,
				     struct strbuf *heads,
				     struct strbuf *bookmarks)
{
	struct strbuf *all[] = { branchmap, heads, bookmarks, NULL };
	struct strbuf **current;
	const char *buf, *state_end;

	state_end = state->buf + state->len;
	buf = state->buf;
	for (current = all; *current; current++) {
		for (; *buf != ';' && buf != state_end; buf++) {
			if (*buf != ':' || buf + 1 == state_end) {
				strbuf_addch(*current, *buf);
				continue;
			}
			if (buf[1] == 'e') {
				strbuf_addstr(*current, "=");
				buf++;
			} else if (buf[1] == 's') {
				strbuf_addstr(*current, ";");
				buf++;
			} else if (buf[1] == 'o') {
				strbuf_addstr(*current, ",");
				buf++;
			} else if (buf[1] == 'c') {
				strbuf_addstr(*current, ":");
				buf++;
			} else
				strbuf_addch(*current, *buf);
		}
		if (*buf == ';')
			buf++;
	}
}

void hg_get_repo_state(struct hg_connection *conn, struct strbuf *branchmap,
		       struct strbuf *heads, struct strbuf *bookmarks)
{
	if (hg_get_capability(conn, "batch")) {
		struct strbuf out = STRBUF_INIT;
		conn->simple_command(
			conn, &out, "batch", "cmds",
			"branchmap ;heads ;listkeys namespace=bookmarks",
			"*", NULL, NULL);
		if (!out.buf)
			return;
		split_batched_repo_state(&out, branchmap, heads, bookmarks);
		strbuf_release(&out);
	} else {
		// TODO: when not batching, check for coherency
		// (see the cinnabar.remote_helper python module)
		conn->simple_command(conn, branchmap, "branchmap", NULL);
		conn->simple_command(conn, heads, "heads", NULL);
		hg_listkeys(conn, bookmarks, "bookmarks");
	}
}

void hg_known(struct hg_connection *conn, struct strbuf *result,
	      struct oid_array *nodes)
{
	char *nodes_str = join_oid_array_hex(nodes, ' ');
	conn->simple_command(conn, result, "known",
			     "nodes", nodes_str,
			     "*", NULL, NULL);
	free(nodes_str);
}

void hg_listkeys(struct hg_connection *conn, struct strbuf *result,
		 const char *namespace)
{
	conn->simple_command(conn, result, "listkeys",
			     "namespace", namespace, NULL);
}

void hg_getbundle(struct hg_connection *conn, FILE *out,
		  struct oid_array *heads, struct oid_array *common,
		  const char *bundle2caps)
{
	struct string_list args = STRING_LIST_INIT_NODUP;
	struct string_list_item *item;

	if (heads && heads->nr) {
		item = string_list_append(&args, "heads");
		item->util = join_oid_array_hex(heads, ' ');
	}
	if (common && common->nr) {
		item = string_list_append(&args, "common");
		item->util = join_oid_array_hex(common, ' ');
	}
	if (bundle2caps && *bundle2caps) {
		item = string_list_append(&args, "bundlecaps");
		item->util = strdup(bundle2caps);
	}
	conn->changegroup_command(conn, out, "getbundle", "*", &args, NULL);
	string_list_clear(&args, 1);

	fflush(out);
}

static int unbundlehash(const struct object_id *oid, void *data)
{
	git_SHA_CTX *ctx = (git_SHA_CTX *) data;

	git_SHA1_Update(ctx, oid->hash, 20);

	return 0;
}

void hg_unbundle(struct hg_connection *conn, struct strbuf *response, FILE *in,
		 struct oid_array *heads)
{
	struct tempfile *tmpfile;
	struct stat st;
	FILE *file;
	/* When the heads list is empty, we send "force", which needs to be
	 * sent as hex. */
	char *heads_str;
	if (heads->nr) {
		if (hg_get_capability(conn, "unbundlehash")) {
			git_SHA_CTX ctx;
			unsigned char sha1[20];

			/* The unbundlehash format is "hashed" as hex,
			 * followed by a whitespace, then the sha1 of all
			 * heads, sorted */
			heads_str = malloc(54);
			memcpy(heads_str, "686173686564 ", 13);
			git_SHA1_Init(&ctx);
			/* oid_array_for_each_unique sorts the sha1 list */
			oid_array_for_each_unique(heads, unbundlehash, &ctx);
			git_SHA1_Final(sha1, &ctx);
			sha1_to_hex_r(&heads_str[13], sha1);
		} else
			heads_str = join_oid_array_hex(heads, ' ');
	} else
		heads_str = "666f726365";

	/* Neither the stdio nor the HTTP protocols can handle a stream for
	 * push commands, so store the data as a temporary file. */
	//TODO: error checking
	tmpfile = mks_tempfile_ts("hg-bundle-XXXXXX.hg", 3);
	file = fdopen_tempfile(tmpfile, "w");
	copy_bundle(in, file);
	close_tempfile_gently(tmpfile);

	file = fopen(tmpfile->filename.buf, "r");
	fstat(fileno(file), &st);
	conn->push_command(conn, response, file, st.st_size, "unbundle",
			   "heads", heads_str, NULL);
	fclose(file);

	delete_tempfile(&tmpfile);
	if (heads->nr)
		free(heads_str);
}

void hg_pushkey(struct hg_connection *conn, struct strbuf *response,
		const char *namespace, const char *key, const char *old,
		const char *new)
{
	//TODO: handle the response being a mix of return code and output
	conn->simple_command(conn, response, "pushkey",
			     "namespace", namespace,
			     "key", key,
			     "old", old,
			     "new", new,
			     NULL);
}

void hg_lookup(struct hg_connection *conn, struct strbuf *result,
	       const char *key)
{
	conn->simple_command(conn, result, "lookup", "key", key, NULL);
}

void hg_clonebundles(struct hg_connection *conn, struct strbuf *result)
{
	conn->simple_command(conn, result, "clonebundles", NULL);
}

void hg_cinnabarclone(struct hg_connection *conn, struct strbuf *result)
{
	conn->simple_command(conn, result, "cinnabarclone", NULL);
}

int hg_finish_connect(struct hg_connection *conn)
{
	int code = conn->finish(conn);
	string_list_clear(&conn->capabilities, 0);
	free(conn);
	return code;
}
