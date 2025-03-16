/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

void hg_connect_prepare_command(
	void *ctx, void (*add_arg)(void *ctx, const char *arg),
	const char *userhost, const char *port, const char *path, int flags);
