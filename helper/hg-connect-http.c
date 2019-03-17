#include "git-compat-util.h"
#include "cinnabar-util.h"
#include "hg-connect-internal.h"
#include "hg-bundle.h"
#include "credential.h"
#include "http.h"
#include "strbuf.h"

typedef void (*prepare_request_cb_t)(CURL *curl, struct curl_slist *headers,
				     void *data);

struct http_request_info {
	long redirects;
	char *effective_url;
	void *data;
};

struct command_request_data {
	struct hg_connection *conn;
	prepare_request_cb_t prepare_request_cb;
	void *data;
	const char *command;
	struct strbuf args;
};

static int http_request(prepare_request_cb_t prepare_request_cb, void *data)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct curl_slist *headers = NULL;
	struct http_request_info *info = (struct http_request_info *)data;
	int ret;

	slot = get_active_slot();
	curl_easy_setopt(slot->curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);

	headers = curl_slist_append(headers,
				    "Accept: application/mercurial-0.1");
	prepare_request_cb(slot->curl, headers, info->data);

	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, headers);
	/* Strictly speaking, this is not necessary, but bitbucket does
         * user-agent sniffing, and git's user-agent gets 404 on mercurial
         * urls. */
	curl_easy_setopt(slot->curl, CURLOPT_USERAGENT,
			 "mercurial/proto-1.0");

	ret = run_one_slot(slot, &results);
	curl_slist_free_all(headers);

	curl_easy_getinfo(slot->curl, CURLINFO_REDIRECT_COUNT, &info->redirects);
	curl_easy_getinfo(slot->curl, CURLINFO_EFFECTIVE_URL, &info->effective_url);

	return ret;
}

static int http_request_reauth(prepare_request_cb_t prepare_request_cb,
			       void *data)
{
	struct http_request_info info = { 0, NULL, data };
	int ret = http_request(prepare_request_cb, &info);

	if (ret != HTTP_OK && ret != HTTP_REAUTH)
		return ret;

	if (info.redirects) {
		char *query = strstr(info.effective_url, "?cmd=");
		if (query) {
			struct command_request_data *request_data =
				(struct command_request_data *)data;
			free(request_data->conn->http.url);
			request_data->conn->http.url =
				xstrndup(info.effective_url,
				         query - info.effective_url);
			warning("redirecting to %s",
			        request_data->conn->http.url);
		}
	}

	if (ret != HTTP_REAUTH)
		return ret;

	credential_fill(&http_auth);

	return http_request(prepare_request_cb, &info);
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
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
	headers = curl_slist_append(headers,
				    "Content-Type: application/mercurial-0.1");
	headers = curl_slist_append(headers, "Expect:");
}

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

	if (http_follow_config == HTTP_FOLLOW_INITIAL &&
	    request_data->conn->http.initial_request) {
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
		request_data->conn->http.initial_request = 0;
	}

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
	// TODO: better handle errors
	switch (http_request_reauth(prepare_command_request, &request_data)) {
	case HTTP_OK:
		break;
	default:
		die("unable to access '%s': %s", conn->http.url, curl_errorstr);
	}
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

struct inflate_context {
	struct writer out;
	git_zstream strm;
};

static size_t inflate_to(char *ptr, size_t size, size_t nmemb, void *data)
{
	char buf[4096];
	struct inflate_context *context = (struct inflate_context *)data;
	int ret;

	context->strm.next_in = (void *)ptr;
	context->strm.avail_in = size * nmemb;

	do {
		context->strm.next_out = (void *)buf;
		context->strm.avail_out = sizeof(buf);
		ret = git_inflate(&context->strm, Z_SYNC_FLUSH);
		write_to(buf, 1, sizeof(buf) - context->strm.avail_out, &context->out);
	} while (context->strm.avail_in && ret == Z_OK);

	return size * nmemb;
}

static int inflate_flush(void *data)
{
	struct inflate_context *context = (struct inflate_context *)data;
	git_inflate_end(&context->strm);
	return 0;
}

struct changegroup_response_data {
	CURL *curl;
	struct inflate_context inflater;
};

static size_t changegroup_header(char *buffer, size_t size, size_t nmemb, void* data)
{
	struct changegroup_response_data *response_data =
		(struct changegroup_response_data *)data;

	if (strcmp(buffer, "Content-Type: application/hg-error\r\n") == 0) {
		write_to("err\n", 4, 1, &response_data->inflater.out);
		curl_easy_setopt(response_data->curl, CURLOPT_FILE, stderr);
		curl_easy_setopt(response_data->curl, CURLOPT_WRITEFUNCTION, fwrite);
	}
	return size * nmemb;
}

static void prepare_changegroup_request(CURL *curl, struct curl_slist *headers,
				        void *data)
{
	struct changegroup_response_data *response_data =
		(struct changegroup_response_data *)data;

	response_data->curl = curl;

	curl_easy_setopt(curl, CURLOPT_HEADERDATA, data);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, changegroup_header);
	curl_easy_setopt(curl, CURLOPT_FILE, &response_data->inflater);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, inflate_to);
}

/* The changegroup, changegroupsubset and getbundle commands return a raw
 * zlib stream when called over HTTP. */
static void http_changegroup_command(struct hg_connection *conn, FILE *out,
				      const char *command, ...)
{
	va_list ap;
	struct changegroup_response_data response_data;
	struct writer writer;

	memset(&response_data, 0, sizeof(response_data));
	response_data.inflater.out.write = (write_callback)fwrite;
	response_data.inflater.out.flush = (flush_callback)fflush;
	response_data.inflater.out.context = out;
	git_inflate_init(&response_data.inflater.strm);
	writer.write = inflate_to;
	writer.flush = inflate_flush;
	writer.context = &response_data.inflater;

	va_start(ap, command);
	http_command(conn, prepare_changegroup_request, &response_data, command, ap);
	va_end(ap);

	writer_flush(&writer);
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

/* The first request we send is a "capabilities" request. This sends to
 * the repo url with a query string "?cmd=capabilities". If the remote
 * url is not actually a repo, but a bundle, the content will start with
 * 'HG10' or 'HG20', which is not something that would appear as the first
 * four characters for the "capabilities" answer. In that case, we output
 * the stream to stdout.
 * (Note this assumes HTTP servers serving bundles don't care about query
 * strings)
 * Ideally, it would be good to pause the curl request, return a
 * hg_connection, and give control back to the caller, but git's http.c
 * doesn't allow pauses.
 */
static size_t caps_request_write(char *ptr, size_t size, size_t nmemb,
				 void *data)
{
	struct writer *writer = (struct writer *)data;
	size_t len = size * nmemb;
	if (writer->write == fwrite_buffer && ((struct strbuf *)writer->context)->len == 0) {
		if (len > 4 && ptr[0] == 'H' && ptr[1] == 'G' &&
		    (ptr[2] == '1' || ptr[2] == '2') && ptr[3] == '0') {
			writer->write = (write_callback)fwrite;
			writer->context = stdout;
			fwrite("bundle\n", 1, 7, stdout);
		}
	}
	return write_to(ptr, size, nmemb, writer);
}

static void prepare_caps_request(CURL *curl, struct curl_slist *headers,
				 void *data)
{
	curl_easy_setopt(curl, CURLOPT_FILE, data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, caps_request_write);
}

static void http_capabilities_command(struct hg_connection *conn,
				      struct writer *writer, ...)
{
	va_list ap;
	va_start(ap, writer);
	http_command(conn, prepare_caps_request, writer, "capabilities", ap);
	va_end(ap);
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
	struct writer writer;
	string_list_init(&conn->capabilities, 1);

	conn->http.url = xstrdup(url);
	conn->http.initial_request = 1;

	http_init(NULL, conn->http.url, 0);

	writer.write = fwrite_buffer;
	writer.flush = NULL;
	writer.context = &caps;
	http_capabilities_command(conn, &writer, NULL);
	/* Cf. comment above caps_request_write. If the bundle stream was
	 * sent to stdout, the writer was switched to fwrite. */
	if (writer.write == (write_callback)fwrite) {
		writer_flush(&writer);
		free(conn->http.url);
		free(conn);
		return NULL;
	}
	split_capabilities(&conn->capabilities, caps.buf);
	strbuf_release(&caps);

	conn->simple_command = http_simple_command;
	conn->changegroup_command = http_changegroup_command;
	conn->push_command = http_push_command;
	conn->finish = http_finish;
	return conn;
}
