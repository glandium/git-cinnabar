#include "git-compat-util.h"
#include "cinnabar-util.h"
#include "hg-connect-internal.h"
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
	xwrite(conn->proc.in, buf, len);
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

extern void stdio_simple_command(struct hg_connection *conn,
				 struct strbuf *response,
				 const char *command, struct args_slice args);

extern void stdio_changegroup_command(struct hg_connection *conn,
                                      struct writer *out,
				      const char *command, struct args_slice args);

extern void stdio_push_command(struct hg_connection *conn,
			       struct strbuf *response, FILE *in, off_t len,
			       const char *command, struct args_slice args);

extern void stdio_send_empty_command(struct hg_connection_stdio *conn);
extern void stdio_send_capabilities_command(struct hg_connection_stdio *conn);
extern void stdio_send_between_command(struct hg_connection_stdio *conn);

static int stdio_finish(struct hg_connection *conn)
{
	stdio_send_empty_command(&conn->stdio);
	close(conn->stdio.proc.in);
	fclose(conn->stdio.out);
	pthread_join(conn->stdio.thread, NULL);
	return finish_command(&conn->stdio.proc);
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
		ssize_t len = xread(conn->proc.err, buf, 4096);
		if (len <= 0)
			break;
		write_to(buf, 1, len, &writer);
	}
	writer_close(&writer);
	return NULL;
}

struct hg_connection *hg_connect_stdio(const char *url, int flags)
{
	char *user, *hostandport, *path;
	const char *remote_path;
	enum protocol protocol;
	struct strbuf buf = STRBUF_INIT;
	struct hg_connection *conn = xmalloc(sizeof(*conn));
	struct child_process *proc = &conn->stdio.proc;
	conn->capabilities = NULL;

	protocol = parse_connect_url(url, &hostandport, &path);

	child_process_init(proc);

	if (looks_like_command_line_option(path))
		die("strange pathname '%s' blocked", path);

	proc->env = local_repo_env;
	proc->use_shell = 1;
	proc->in = proc->out = proc->err = -1;

	remote_path = path;

	if (protocol == PROTO_SSH) {
		char *ssh_host = hostandport;
		const char *port = NULL;
		transport_check_allowed("ssh");
		get_host_and_port(&ssh_host, &port);

		if (!port)
			port = get_port(ssh_host);

		proc->trace2_child_class = "transport/ssh";
		while (*remote_path == '/')
			remote_path++;
		fill_ssh_args(proc, ssh_host, port, protocol_v0, flags);
	} else if (protocol == PROTO_FILE || protocol == PROTO_LOCAL) {
		struct stat st;
		stat(path, &st);
		if (S_ISREG(st.st_mode)) {
			FILE *file;
			struct writer writer;
			free(hostandport);
			child_process_clear(proc);
			free(conn);
			// TODO: Eventually we want to have a hg_connection
			// for bundles, but for now, just send the stream to
			// stdout and return NULL.
			file = fopen(path, "r");
			free(path);
			fwrite("bundle\n", 1, 7, stdout);
			writer.write = (write_callback)fwrite;
			writer.close = (close_callback)fflush;
			writer.context = stdout;
			decompress_bundle_writer(&writer);
			copy_to(file, st.st_size, &writer);
			writer_close(&writer);
			return NULL;
		}
		proc->use_shell = 1;
	} else
		die("I don't handle protocol '%s'", prot_name(protocol));

	strbuf_addstr(&buf, "hg -R ");
	maybe_sq_quote_buf(&buf, remote_path);
	strbuf_addstr(&buf, " serve --stdio");
	argv_array_push(&proc->args, buf.buf);
	strbuf_release(&buf);

	start_command(proc);
	conn->stdio.is_remote = (protocol == PROTO_SSH);
	conn->stdio.out = xfdopen(proc->out, "r");
	pthread_create(&conn->stdio.thread, NULL, prefix_remote_stderr, &conn->stdio);
	// TODO: return earlier in case the command fails somehow.

	free(path);
	free(hostandport);

	/* Very old versions of the mercurial server (< 0.9) would ignore
         * unknown commands, and didn't know the "capabilities" command we want
         * to use to retrieve the server capabilities.
         * So, we also emit a command that is supported by those old versions,
         * and will see if we get a response for one or both commands.
         * Note the "capabilities" command is not supported over the stdio
         * protocol before mercurial 1.7, but we require features from at
         * least mercurial 1.9 anyways. Server versions between 0.9 and 1.7
         * will return an empty result for the "capabilities" command, as
         * opposed to no result at all with older servers. */
	stdio_send_capabilities_command(&conn->stdio);
	stdio_send_between_command(&conn->stdio);

	stdio_read_response(&conn->stdio, &buf);
	if (!(buf.len == 1 && buf.buf[0] == '\n')) {
		split_capabilities(conn, buf.buf);
		/* Now read the response for the "between" command. */
		stdio_read_response(&conn->stdio, &buf);
	}
	strbuf_release(&buf);

	conn->simple_command = stdio_simple_command;
	conn->changegroup_command = stdio_changegroup_command;
	conn->push_command = stdio_push_command;
	conn->finish = stdio_finish;
	return conn;
}
