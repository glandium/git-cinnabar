/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "git-compat-util.h"
#include "http.h"
#include "hg-bundle.h"
#include <stdint.h>

void rev_diff_start_iter(struct rev_diff_part *iterator,
                         struct rev_chunk *chunk)
{
	iterator->start = 0;
	iterator->end = 0;
	iterator->data.len = 0;
	iterator->data.buf = NULL;
	iterator->chunk = chunk;
}

int rev_diff_iter_next(struct rev_diff_part *iterator)
{
	const char *part;
	const char *chunk_end = iterator->chunk->raw.buf +
	                        iterator->chunk->raw.len;

	if (iterator->data.buf == NULL)
		part = (char *) iterator->chunk->diff_data;
	else
		part = iterator->data.buf +
		       iterator->data.len;

	if (part == chunk_end)
		return 0;

	if (part > chunk_end - 12)
		die("Invalid revchunk");

	iterator->start = get_be32(part);
	iterator->end = get_be32(part + 4);
	iterator->data.len = get_be32(part + 8);
	iterator->data.buf = (char *) part + 12;

	if (iterator->data.buf + iterator->data.len > chunk_end ||
	    iterator->start > iterator->end)
		die("Invalid revchunk");

	return 1;
}
