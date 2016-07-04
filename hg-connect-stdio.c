#include "git-compat-util.h"
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

/* The mercurial "stdio" protocol is used for both local repositories and
 * remote ssh repositories.
 * A mercurial client sends commands in the following form:
 *   <command> LF
 *   (<param> SP <length> LF <value>)*
 *   ('*' SP <num> LF (<param> SP <length> LF <value>){num})
 *
 * <value> is <length> bytes long. The number of parameters depends on the
 * command.
 *
 * The '*' special parameter introduces a variable number of extra parameters.
 * The number following the '*' is the number of extra parameters.
 *
 * The server response, for simple commands, is of the following form:
 *   <length> LF
 *   <content>
 *
 * <content> is <length> bytes long.
 */
static void stdio_command_add_param(void *data, const char *name,
				    union param_value value)
{
	struct strbuf *cmd = (struct strbuf *)data;
	int is_asterisk = !strcmp(name, "*");
	uintmax_t len = is_asterisk ? value.size : strlen(value.value);
	strbuf_addf(cmd, "%s %"PRIuMAX"\n", name, len);
	if (!is_asterisk)
		strbuf_add(cmd, value.value, len);
}

static void stdio_send_command_v(struct hg_connection *conn,
				 const char *command, va_list ap)
{
	struct strbuf cmd = STRBUF_INIT;
	strbuf_addstr(&cmd, command);
	strbuf_addch(&cmd, '\n');
	prepare_command(&cmd, stdio_command_add_param, ap);

	xwrite(conn->stdio.proc.in, cmd.buf, cmd.len);
	strbuf_release(&cmd);
}

static void stdio_send_command(struct hg_connection *conn,
			       const char *command, ...)
{
	va_list ap;
	va_start(ap, command);
	stdio_send_command_v(conn, command, ap);
	va_end(ap);
}

static void stdio_read_response(struct hg_connection *conn,
				struct strbuf *response)
{
	struct strbuf length_str = STRBUF_INIT;
	size_t length;

	//TODO: Check for errors, etc.
	strbuf_getline_lf(&length_str, conn->stdio.out);
	length = strtol(length_str.buf, NULL, 10);
	strbuf_release(&length_str);

	strbuf_fread(response, length, conn->stdio.out);
}

static void stdio_simple_command(struct hg_connection *conn,
				 struct strbuf *response,
				 const char *command, ...)
{
	va_list ap;
	va_start(ap, command);
	stdio_send_command_v(conn, command, ap);
	stdio_read_response(conn, response);
	va_end(ap);
}

static void stdio_changegroup_command(struct hg_connection *conn, FILE *out,
				      const char *command, ...)
{
	va_list ap;
	va_start(ap, command);
	stdio_send_command_v(conn, command, ap);

	/* We're going to receive a stream, but we don't know how big it is
	 * going to be in advance, so we have to read it according to its
	 * format: the changegroup format. For now, only support changegroupv1
	 */
	copy_bundle(conn->stdio.out, out);
	va_end(ap);
}

static void stdio_push_command(struct hg_connection *conn,
			       struct strbuf *response, FILE *in, off_t len,
			       const char *command, ...)
{
	char buf[4096];
	struct strbuf header = STRBUF_INIT;
	va_list ap;
	va_start(ap, command);
	stdio_send_command_v(conn, command, ap);
	/* The server normally sends an empty response before reading the data
	 * it's sent if not, it's an error. */
	//TODO: handle that error.
	stdio_read_response(conn, &header);
	va_end(ap);

	//TODO: chunk in smaller pieces.
	strbuf_addf(&header, "%"PRIuMAX"\n", len);
	xwrite(conn->stdio.proc.in, header.buf, header.len);
	strbuf_release(&header);

	while (len) {
		size_t read = sizeof(buf) > len ? len : sizeof(buf);
		read = fread(buf, 1, read, in);
		len -= read;
		xwrite(conn->stdio.proc.in, buf, read);
	}

	xwrite(conn->stdio.proc.in, "0\n", 2);
	/* There are two responses, one for output, one for actual response. */
	//TODO: actually handle output here
	stdio_read_response(conn, &header);
	strbuf_release(&header);
	stdio_read_response(conn, response);
}

static int stdio_finish(struct hg_connection *conn)
{
	stdio_send_command(conn, "", NULL);
	close(conn->stdio.proc.in);
	fclose(conn->stdio.out);
	return finish_command(&conn->stdio.proc);
}

struct hg_connection *hg_connect_stdio(const char *url, int flags)
{
	char *user, *host, *port, *path;
	const char *remote_path;
	enum protocol protocol;
	struct strbuf buf = STRBUF_INIT;
	struct hg_connection *conn = xmalloc(sizeof(*conn));
	struct child_process *proc = &conn->stdio.proc;
	string_list_init(&conn->capabilities, 1);

	protocol = parse_connect_url(url, &user, &host, &port, &path);

	child_process_init(proc);
	proc->env = local_repo_env;
	proc->in = proc->out = -1;

	remote_path = path;

	if (protocol == PROTO_SSH) {
		if (*remote_path == '/')
			remote_path++;
		proc->use_shell = prepare_ssh_command(
			&proc->args, user, host, port, flags);
	} else if (protocol == PROTO_FILE || protocol == PROTO_LOCAL)
		proc->use_shell = 1;
	else
		die("I don't handle protocol '%s'", prot_name(protocol));

	strbuf_addstr(&buf, "hg -R ");
	maybe_sq_quote_buf(&buf, path);
	strbuf_addstr(&buf, " serve --stdio");
	argv_array_push(&proc->args, buf.buf);
	strbuf_release(&buf);

	start_command(proc);
	conn->stdio.out = xfdopen(proc->out, "r");
	// TODO: return earlier in case the command fails somehow.

	free(path);
	free(port);
	free(host);
	free(user);

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
	stdio_send_command(conn, "capabilities", NULL);
	stdio_send_command(conn, "between", "pairs",
			   "0000000000000000000000000000000000000000-"
			   "0000000000000000000000000000000000000000", NULL);

	stdio_read_response(conn, &buf);
	if (!(buf.len == 1 && buf.buf[0] == '\n')) {
		split_capabilities(&conn->capabilities, buf.buf);
		/* Now read the response for the "between" command. */
		stdio_read_response(conn, &buf);
	}
	strbuf_release(&buf);

	conn->simple_command = stdio_simple_command;
	conn->changegroup_command = stdio_changegroup_command;
	conn->push_command = stdio_push_command;
	conn->finish = stdio_finish;
	return conn;
}
