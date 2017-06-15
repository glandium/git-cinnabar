#ifndef BUNDLE_H
#define BUNDLE_H

#include "strbuf.h"
#include <stdio.h>

struct bundle_writer {
	union {
		FILE *file;
		struct strbuf *buf;
	} out;
	int type;
};

#define WRITER_FILE 1
#define WRITER_STRBUF 2

extern size_t write_data(const unsigned char *buf, size_t size,
			 struct bundle_writer *out);
extern size_t copy_data(size_t len, FILE *in, struct bundle_writer *out);

extern void copy_bundle(FILE *in, FILE *out);
extern void copy_bundle_to_strbuf(FILE *in, struct strbuf *out);

struct rev_chunk {
	struct strbuf raw;

	const unsigned char *node;
	const unsigned char *parent1;
	const unsigned char *parent2;
	// Only in changegroupv2
	const unsigned char *delta_node;
/*	const unsigned char *changeset; // We actually don't care about this */
	const unsigned char *diff_data;
};

struct rev_diff_part {
	size_t start;
	size_t end;
	struct strbuf data;
	struct rev_chunk *chunk;
};

extern void rev_chunk_from_memory(struct rev_chunk *result,
                                  struct strbuf *buf,
                                  const unsigned char *delta_node);

static inline void rev_chunk_release(struct rev_chunk *chunk)
{
	strbuf_release(&chunk->raw);
	chunk->node = chunk->parent1 = chunk->parent2 = chunk->delta_node =
	chunk->diff_data = NULL;
}

extern void rev_diff_start_iter(struct rev_diff_part *iterator,
                                struct rev_chunk *chunk);

extern int rev_diff_iter_next(struct rev_diff_part *iterator);

#endif
