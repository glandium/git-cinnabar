#include "git-compat-util.h"
#include "cinnabar-util.h"
#include "hg-connect.h"
#include "hg-bundle.h"
#include "strbuf.h"
#include "quote.h"

#include "connect.c"

/* Similar to sq_quote_buf, but avoid quoting when the string only contains
 * "shell-safe" characters. The list of those characters comes from
 * Mercurial's shell quoting function used for its ssh client. There likely
 * are more that could be added to the list. */
static void maybe_sq_quote_buf(struct strbuf *buf, const char *src)
{
	const char *p;
	for (p = src; *p; ++p) {
		if (!isalnum(*p) && *p != '@' && *p != '%' && *p != '_' &&
		    *p != '+' && *p != '=' && *p != ':' && *p != ',' &&
		    *p != '.' && *p != '/' && *p != '-')
			break;
	}
	if (*p)
		sq_quote_buf(buf, src);
	else
		strbuf_addstr(buf, src);
}

void stdio_write(struct hg_connection_stdio *conn, const uint8_t *buf, size_t len) {
	xwrite(conn->proc->in, buf, len);
}

void stdio_read_response(struct hg_connection_stdio *conn,
			 struct strbuf *response)
{
	struct strbuf length_str = STRBUF_INIT;
	size_t length;

	//TODO: Check for errors, etc.
	strbuf_getline_lf(&length_str, conn->out);
	length = strtol(length_str.buf, NULL, 10);
	strbuf_release(&length_str);

	strbuf_fread(response, length, conn->out);
}

extern void stdio_send_empty_command(struct hg_connection_stdio *conn);

int stdio_finish(struct hg_connection_stdio *conn)
{
	int ret;
	stdio_send_empty_command(conn);
	close(conn->proc->in);
	fclose(conn->out);
	pthread_join(conn->thread, NULL);
	ret = finish_command(conn->proc);
	free(conn->proc);
	return ret;
}

void *prefix_remote_stderr(void *context)
{
	struct hg_connection_stdio *conn = context;
	struct writer writer;

	writer.write = (write_callback)fwrite;
	writer.close = (close_callback)fflush;
	writer.context = stderr;
	prefix_writer(&writer, "remote: ");

	for (;;) {
		char buf[4096];
		ssize_t len = xread(conn->proc->err, buf, 4096);
		if (len <= 0)
			break;
		write_to(buf, 1, len, &writer);
	}
	writer_close(&writer);
	return NULL;
}

struct hg_connection_stdio *hg_connect_stdio(const char *userhost, const char *port,
					     const char *path, int flags)
{
	struct strbuf buf = STRBUF_INIT;
	struct hg_connection_stdio *conn = xmalloc(sizeof(*conn));
	struct child_process *proc = xmalloc(sizeof(*proc));
	conn->proc = proc;

	child_process_init(proc);

	if (looks_like_command_line_option(path))
		die("strange pathname '%s' blocked", path);

	proc->env = local_repo_env;
	proc->use_shell = 1;
	proc->in = proc->out = proc->err = -1;

	if (userhost) {
		proc->trace2_child_class = "transport/ssh";
		fill_ssh_args(proc, userhost, port, protocol_v0, flags);
	}

	strbuf_addstr(&buf, "hg -R ");
	maybe_sq_quote_buf(&buf, path);
	strbuf_addstr(&buf, " serve --stdio");
	argv_array_push(&proc->args, buf.buf);
	strbuf_release(&buf);

	start_command(proc);
	conn->is_remote = userhost != NULL;
	conn->out = xfdopen(proc->out, "r");
	pthread_create(&conn->thread, NULL, prefix_remote_stderr, conn);
	// TODO: return earlier in case the command fails somehow.

	return conn;
}
