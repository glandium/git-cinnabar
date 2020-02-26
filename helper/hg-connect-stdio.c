#include "git-compat-util.h"
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

int stdio_finish(struct child_process *proc)
{
	int ret = finish_command(proc);
	free(proc);
	return ret;
}

int proc_in(struct child_process *proc) {
	return proc->in;
}

int proc_out(struct child_process *proc) {
	return proc->out;
}

int proc_err(struct child_process *proc) {
	return proc->err;
}

struct child_process *hg_connect_stdio(
	const char *userhost, const char *port, const char *path, int flags)
{
	struct strbuf buf = STRBUF_INIT;
	struct child_process *proc = xmalloc(sizeof(*proc));

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
	return proc;
}
