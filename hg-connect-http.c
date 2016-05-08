#include "git-compat-util.h"
#include "hg-connect-internal.h"
#include "http.h"
#include "strbuf.h"

/* The Mercurial HTTP protocol uses HTTP requests for each individual command.
 * The command name is passed as "cmd" query parameter.
 * The command arguments can be passed in several different ways, but for now,
 * only the following is supported:
 * - each argument is passed as a query parameter.
 *
 * The command results are simply the corresponding HTTP responses.
 */
static char *query_encode(const char *buf)
{
	struct strbuf encoded = STRBUF_INIT;
	const char *p;

	for (p = buf; *p; ++p) {
		if (isalnum(*p) || *p == '*' || *p == '-' || *p == '.' ||
		    *p == '_')
			strbuf_addch(&encoded, *p);
		else if (*p == ' ')
			strbuf_addch(&encoded, '+');
		else
			strbuf_addf(&encoded, "%%%02x", *p);
	}

	return strbuf_detach(&encoded, NULL);
}

static void http_query_add_param(void *data, const char *name,
				 union param_value value)
{
	struct strbuf *command_url = (struct strbuf *)data;
	char *encoded;
	if (!strcmp(name, "*"))
		return;

	/* Theoretically, name should be encoded, too, but we'll assume it's
         * always going to be alphanumeric characters. */
	encoded = query_encode(value.value);
	strbuf_addf(command_url, "&%s=%s", name, encoded);
	free(encoded);
}

static void http_simple_command(struct hg_connection *conn,
				struct strbuf *response,
				const char *command, ...)
{
	va_list ap;
	struct strbuf command_url = STRBUF_INIT;
	strbuf_addf(&command_url, "%s?cmd=%s", conn->http.url, command);
	va_start(ap, command);
	// TODO: use HTTP headers for parameters when httpheader capability is
	// reported by the server.
	prepare_command(&command_url, http_query_add_param, ap);
	va_end(ap);

	// TODO: handle errors
	http_get_strbuf(command_url.buf, response, NULL);
	strbuf_release(&command_url);
}

static int http_finish(struct hg_connection *conn)
{
	http_cleanup();
	free(conn->http.url);
	return 0;
}

struct hg_connection *hg_connect_http(const char *url, int flags)
{
	struct hg_connection *conn = xmalloc(sizeof(*conn));
	struct strbuf caps = STRBUF_INIT;
	string_list_init(&conn->capabilities, 1);

	conn->http.url = xstrdup(url);

	http_init(NULL, conn->http.url, 0);

	http_simple_command(conn, &caps, "capabilities", NULL);
	split_capabilities(&conn->capabilities, caps.buf);
	strbuf_release(&caps);

	conn->simple_command = http_simple_command;
	conn->finish = http_finish;
	return conn;
}
