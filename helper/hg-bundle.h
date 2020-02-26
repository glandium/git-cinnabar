#ifndef BUNDLE_H
#define BUNDLE_H

#include "cache.h"
#include "strbuf.h"
#include "cinnabar-util.h"
#include "hg-data.h"
#include <stdio.h>

void read_chunk(FILE *in, struct strbuf *out);

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

void rev_chunk_from_memory(struct rev_chunk *result,
                           struct strbuf *buf,
                           const struct hg_object_id *delta_node);

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
