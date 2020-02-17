#include "git-compat-util.h"
#include "cinnabar-util.h"
#include "hg-connect.h"
#include "hg-bundle.h"
#include "credential.h"
#include "http.h"
#include "strbuf.h"

int http_finish(struct hg_connection_http *conn)
{
	http_cleanup();
	free(conn->url);
	return 0;
}

struct hg_connection_http *hg_connect_http(const char *url, int flags)
{
	struct hg_connection_http *conn = xmalloc(sizeof(*conn));

	conn->url = xstrdup(url);
	conn->initial_request = 1;

	http_init(NULL, conn->url, 0);

	return conn;
}
