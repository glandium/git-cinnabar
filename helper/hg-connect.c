#include "git-compat-util.h"
#include "cache.h"
#include "hg-connect-internal.h"
#include "hg-bundle.h"
#include "strbuf.h"
#include "tempfile.h"
#include "url.h"

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

int hg_finish_connect(struct hg_connection *conn)
{
	int code = conn->finish(conn);
	drop_capabilities(conn);
	free(conn);
	return code;
}
