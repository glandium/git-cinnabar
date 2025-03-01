/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define DISABLE_SIGN_COMPARE_WARNINGS
#define USE_THE_REPOSITORY_VARIABLE
#include "git-compat-util.h"
#include "hg-connect.h"
#include "hg-bundle.h"
#include "run-command.h"
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

extern const char **prepare_shell_cmd(struct strvec *out, const char **argv);

void hg_connect_prepare_command(
	void *ctx, void (*add_arg)(void *ctx, const char *arg),
	const char *userhost, const char *port, const char *path, int flags)
{
	struct strvec out = STRVEC_INIT;
	struct strbuf buf = STRBUF_INIT;
	struct child_process proc = CHILD_PROCESS_INIT;
	child_process_init(&proc);

	if (looks_like_command_line_option(path))
		die("strange pathname '%s' blocked", path);

	//strvec_pushv(&proc.env, (const char **)local_repo_env);
	proc.use_shell = 1;
	proc.in = proc.out = proc.err = -1;

	if (userhost) {
		proc.trace2_child_class = "transport/ssh";
		fill_ssh_args(&proc, userhost, port, protocol_v0, flags);
	}

	strbuf_addstr(&buf, "hg -R ");
	maybe_sq_quote_buf(&buf, path);
	strbuf_addstr(&buf, " serve --stdio");
	strvec_push(&proc.args, buf.buf);
	strbuf_release(&buf);

	if (proc.use_shell) {
		prepare_shell_cmd(&out, proc.args.v);
	} else {
		strvec_pushv(&out, proc.args.v);
	}

	for (size_t i = 0; i < out.nr; i++) {
		add_arg(ctx, out.v[i]);
	}

	child_process_clear(&proc);
	strvec_clear(&out);
}
