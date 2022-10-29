/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "git-compat-util.h"
#include "regex.h"

int regcomp (regex_t *__restrict __preg,
             const char *__restrict __pattern,
             int __cflags)
{
	die("regex not supposed to be used");
}

int regexec (const regex_t *__restrict __preg,
             const char *__restrict __cstring, size_t __nmatch,
             regmatch_t __pmatch[__restrict_arr],
             int __eflags)
{
	die("regex not supposed to be used");
}

size_t regerror (int __errcode, const regex_t *__restrict __preg,
                 char *__restrict __errbuf, size_t __errbuf_size)
{
	die("regex not supposed to be used");
}

void regfree (regex_t *__preg) {}
