/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BUNDLE_H
#define BUNDLE_H

#include "git-compat-util.h"
#include "strbuf.h"
#include "hg-data.h"
#include <stdio.h>

struct rev_chunk {
	struct strbuf raw;

	const struct hg_object_id *node;
	const struct hg_object_id *parent1;
	const struct hg_object_id *parent2;
	// Only in changegroupv2
	const struct hg_object_id *delta_node;
/*	const struct hg_object_id *changeset; // We actually don't care about this */
	const unsigned char *diff_data;
};

struct rev_diff_part {
	size_t start;
	size_t end;
	struct strbuf data;
	struct rev_chunk *chunk;
};

static inline void rev_chunk_release(struct rev_chunk *chunk)
{
	strbuf_release(&chunk->raw);
	chunk->node = chunk->parent1 = chunk->parent2 = chunk->delta_node = NULL;
	chunk->diff_data = NULL;
}

void rev_diff_start_iter(struct rev_diff_part *iterator,
                         struct rev_chunk *chunk);

int rev_diff_iter_next(struct rev_diff_part *iterator);

#endif
