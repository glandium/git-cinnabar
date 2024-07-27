/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef _WIN32
static inline void winansi_init(void) {}
#define main cinnabar_main
extern int cinnabar_main(int argc, const char *argv[]);
// Work around the function being declared despite NO_UNIX_SOCKETS.
int mingw_have_unix_sockets(void);
#include "compat/mingw.c"
#else
typedef int make_pedantic_happy;
#endif
