/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

struct child_process;

int stdio_finish(struct child_process *proc);

int proc_in(struct child_process *proc);

int proc_out(struct child_process *proc);

int proc_err(struct child_process *proc);

struct child_process *hg_connect_stdio(
	const char *userhost, const char *port, const char *path, int flags);
