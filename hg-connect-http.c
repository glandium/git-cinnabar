#include "git-compat-util.h"
#include "hg-connect-internal.h"
#include "credential.h"
#include "http.h"
#include "strbuf.h"

typedef void (*prepare_request_cb_t)(CURL *curl, struct curl_slist *headers,
				     void *data);

static int http_request(prepare_request_cb_t prepare_request_cb, void *data)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct curl_slist *headers = NULL;
	int ret;

	slot = get_active_slot();
	curl_easy_setopt(slot->curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);

	headers = curl_slist_append(headers,
				    "Accept: application/mercurial-0.1");
	prepare_request_cb(slot->curl, headers, data);

	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, headers);
	/* Strictly speaking, this is not necessary, but bitbucket does
         * user-agent sniffing, and git's user-agent gets 404 on mercurial
         * urls. */
	curl_easy_setopt(slot->curl, CURLOPT_USERAGENT,
			 "mercurial/proto-1.0");

	ret = run_one_slot(slot, &results);
	curl_slist_free_all(headers);

	return ret;
}

static int http_request_reauth(prepare_request_cb_t prepare_request_cb,
			       void *data)
{
	int ret = http_request(prepare_request_cb, data);

	if (ret != HTTP_REAUTH)
		return ret;

	credential_fill(&http_auth);

	return http_request(prepare_request_cb, data);
}

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

static void prepare_simple_request(CURL *curl, struct curl_slist *headers,
				   void *data)
{
	curl_easy_setopt(curl, CURLOPT_FILE, data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
}

static void prepare_pushkey_request(CURL *curl, struct curl_slist *headers,
				    void *data)
{
	prepare_simple_request(curl, headers, data);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);
	headers = curl_slist_append(headers,
				    "Content-Type: application/mercurial-0.1");
	headers = curl_slist_append(headers, "Expect:");
}

struct command_request_data {
	struct hg_connection *conn;
	prepare_request_cb_t prepare_request_cb;
	void *data;
	const char *command;
	struct strbuf args;
};

static void prepare_command_request(CURL *curl, struct curl_slist *headers,
				    void *data)
{
	char *end;
	struct strbuf command_url = STRBUF_INIT;
	struct command_request_data *request_data =
		(struct command_request_data *) data;
	const char *httpheader_str =
		hg_get_capability(request_data->conn, "httpheader");
	size_t httpheader =
		httpheader_str ? strtol(httpheader_str, &end, 10) : 0;

	if (httpheader && end[0] != '\0')
		httpheader = 0;

	request_data->prepare_request_cb(curl, headers, request_data->data);

	strbuf_addf(&command_url, "%s?cmd=%s", request_data->conn->http.url,
		    request_data->command);
	if (httpheader && request_data->args.len) {
		const char *args = request_data->args.buf + 1;
		size_t len = request_data->args.len - 1;
		int num;
		for (num = 1; len; num++) {
			size_t writable_len;
			struct strbuf header = STRBUF_INIT;
			strbuf_addf(&header, "X-HgArg-%d: ", num);
			writable_len = httpheader - header.len;
			writable_len = writable_len > len ? len : writable_len;
			strbuf_add(&header, args, writable_len);
			args += writable_len;
			len -= writable_len;
			headers = curl_slist_append(headers, header.buf);
			strbuf_release(&header);
		}
	} else
		strbuf_addbuf(&command_url, &request_data->args);

	curl_easy_setopt(curl, CURLOPT_URL, command_url.buf);
	strbuf_release(&command_url);
}

static void http_command(struct hg_connection *conn,
			 prepare_request_cb_t prepare_request_cb, void *data,
			 const char *command, va_list ap)
{
	struct command_request_data request_data = {
		conn,
		prepare_request_cb,
		data,
		command,
		STRBUF_INIT,
	};
	prepare_command(&request_data.args, http_query_add_param, ap);
	// TODO: handle errors
	http_request_reauth(prepare_command_request, &request_data);
	strbuf_release(&request_data.args);
}

static void http_simple_command(struct hg_connection *conn,
				struct strbuf *response,
				const char *command, ...)
{
	va_list ap;
	va_start(ap, command);
	if (strcmp(command, "pushkey"))
		http_command(conn, prepare_simple_request, response, command,
		             ap);
	else
		http_command(conn, prepare_pushkey_request, response, command,
		             ap);
	va_end(ap);
}

struct deflater {
	FILE *out;
	git_zstream strm;
};

static size_t deflate_response(char *ptr, size_t size, size_t nmemb, void *data)
{
	char buf[4096];
	struct deflater *deflater = (struct deflater *)data;
	int ret;

	deflater->strm.next_in = (void *)ptr;
	deflater->strm.avail_in = size * nmemb;

	do {
		deflater->strm.next_out = (void *)buf;
		deflater->strm.avail_out = sizeof(buf);
		ret = git_inflate(&deflater->strm, Z_SYNC_FLUSH);
		fwrite(buf, 1, sizeof(buf) - deflater->strm.avail_out,
		       deflater->out);
	} while (deflater->strm.avail_in && ret == Z_OK);

	return size * nmemb;
}

static void prepare_compressed_request(CURL *curl, struct curl_slist *headers,
				       void *data)
{
	curl_easy_setopt(curl, CURLOPT_FILE, data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, deflate_response);
}

/* The changegroup, changegroupsubset and getbundle commands return a raw
 * zlib stream when called over HTTP. */
static void http_changegroup_command(struct hg_connection *conn, FILE *out,
				      const char *command, ...)
{
	va_list ap;
	struct deflater deflater;

	memset(&deflater, 0, sizeof(deflater));
	deflater.out = out;
	va_start(ap, command);
	git_inflate_init(&deflater.strm);
	http_command(conn, prepare_compressed_request, &deflater, command, ap);
	git_inflate_end(&deflater.strm);
	va_end(ap);
}

struct push_request_info {
	struct strbuf *response;
	FILE *in;
	curl_off_t len;
};

static void prepare_push_request(CURL *curl, struct curl_slist *headers,
				 void *data)
{
	struct push_request_info *info = (struct push_request_info *)data;
	prepare_simple_request(curl, headers, info->response);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, info->len);
	/* Ensure we have no state from a previous attempt that failed because
	 * of authentication (401). */
	fseek(info->in, 0L, SEEK_SET);
	strbuf_release(info->response);
	curl_easy_setopt(curl, CURLOPT_INFILE, info->in);

	headers = curl_slist_append(headers,
				    "Content-Type: application/mercurial-0.1");
	headers = curl_slist_append(headers, "Expect:");
}

static void http_push_command(struct hg_connection *conn,
			      struct strbuf *response, FILE *in, off_t len,
			      const char *command, ...)
{
	va_list ap;
	struct push_request_info info;
	struct strbuf http_response = STRBUF_INIT;
	struct string_list list = STRING_LIST_INIT_NODUP;
	va_start(ap, command);
	info.response = &http_response;
	info.in = in;
	info.len = len;
	//TODO: handle errors
	http_command(conn, prepare_push_request, &info, command, ap);
	va_end(ap);

	if (!strncmp(http_response.buf, "HG20", 4)) {
		strbuf_addbuf(response, &http_response);
	} else {
		string_list_split_in_place(&list, http_response.buf, '\n', 1);
		strbuf_addstr(response, list.items[0].string);
		fwrite(list.items[1].string, 1, strlen(list.items[1].string), stderr);
		string_list_clear(&list, 0);
	}
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
	conn->changegroup_command = http_changegroup_command;
	conn->push_command = http_push_command;
	conn->finish = http_finish;
	return conn;
}
