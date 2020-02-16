#include "git-compat-util.h"
#include "cinnabar-util.h"
#include "hg-connect.h"
#include "hg-bundle.h"
#include "credential.h"
#include "http.h"
#include "strbuf.h"

void prepare_simple_request(CURL *curl, struct curl_slist *headers,
			    struct strbuf *data)
{
	curl_easy_setopt(curl, CURLOPT_FILE, data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
}

void prepare_pushkey_request(CURL *curl, struct curl_slist *headers,
			     struct strbuf *data)
{
	prepare_simple_request(curl, headers, data);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
	headers = curl_slist_append(headers,
				    "Content-Type: application/mercurial-0.1");
	headers = curl_slist_append(headers, "Expect:");
}

struct changegroup_response_data {
	CURL *curl;
	struct writer *writer;
};

static size_t changegroup_write(char *buffer, size_t size, size_t nmemb, void* data)
{
	struct changegroup_response_data *response_data =
		(struct changegroup_response_data *)data;

	if (response_data->curl) {
		char *content_type;
		if (!curl_easy_getinfo(response_data->curl, CURLINFO_CONTENT_TYPE,
		                       &content_type) && content_type) {
			if (strcmp(content_type, "application/mercurial-0.1") == 0) {
				inflate_writer(response_data->writer);
			} else if (strcmp(content_type, "application/hg-error") == 0) {
				write_to("err\n", 1, 4, response_data->writer);
				response_data->writer->write = (write_callback)fwrite;
				response_data->writer->close = (close_callback)fflush;
				response_data->writer->context = stderr;
				prefix_writer(response_data->writer, "remote: ");
			}
		}
		bufferize_writer(response_data->writer);
		response_data->curl = NULL;
	}

	return write_to(buffer, size, nmemb, response_data->writer);
}

void prepare_changegroup_request(CURL *curl, struct curl_slist *headers,
			         struct changegroup_response_data *data)
{
	data->curl = curl;

	curl_easy_setopt(curl, CURLOPT_FILE, data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, changegroup_write);
}

struct push_request_info {
	struct strbuf *response;
	FILE *in;
	curl_off_t len;
};

void prepare_push_request(CURL *curl, struct curl_slist *headers,
			  struct push_request_info *info)
{
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
	struct writer *writer = data;
	size_t len = size * nmemb;
	if (writer->write == fwrite_buffer && ((struct strbuf *)writer->context)->len == 0) {
		if (len > 4 && ptr[0] == 'H' && ptr[1] == 'G' &&
		    (ptr[2] == '1' || ptr[2] == '2') && ptr[3] == '0') {
			writer->write = (write_callback)fwrite;
			writer->close = (close_callback)fflush;
			writer->context = stdout;
			fwrite("bundle\n", 1, 7, stdout);
			decompress_bundle_writer(writer);
			bufferize_writer(writer);
		}
	}
	return write_to(ptr, size, nmemb, writer);
}

void prepare_caps_request(CURL *curl, struct curl_slist *headers,
			  struct writer *writer)
{
	curl_easy_setopt(curl, CURLOPT_FILE, writer);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, caps_request_write);
}

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
