/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef _WIN32
#define winansi_init(...)
#define main cinnabar_main
extern int cinnabar_main(int argc, const char *argv[]);
#include "compat/mingw.c"
#endif
