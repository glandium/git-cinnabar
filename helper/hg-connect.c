#include "git-compat-util.h"
#include "cache.h"
#include "hg-connect-internal.h"
#include "hg-bundle.h"
#include "strbuf.h"
#include "tempfile.h"
#include "url.h"

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
extern void command_add_asterisk(void *data,
				 command_add_param_t command_add_param,
				 const void *params);

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
				va_arg(ap, const void *));
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

	if (!strncmp(url, "http://", sizeof("http://") - 1) ||
	    !strncmp(url, "https://", sizeof("https://") - 1)) {
		conn = hg_connect_http(url, flags);
	} else
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

int hg_finish_connect(struct hg_connection *conn)
{
	int code = conn->finish(conn);
	string_list_clear(&conn->capabilities, 0);
	free(conn);
	return code;
}
