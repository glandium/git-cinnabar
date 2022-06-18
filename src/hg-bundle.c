#include "git-compat-util.h"
#include "http.h"
#include "hg-bundle.h"
#include <stdint.h>

void rev_chunk_from_memory(struct rev_chunk *result, struct strbuf *buf,
                           const struct hg_object_id *delta_node)
{
	size_t data_offset = 80 + 20 * !!(delta_node == NULL);
	unsigned char *data = (unsigned char *) buf->buf;

	strbuf_swap(&result->raw, buf);
	if (result->raw.len < data_offset)
		die("Invalid revchunk");

	result->node = (const struct hg_object_id *)data;
	result->parent1 = (const struct hg_object_id *)(data + 20);
	result->parent2 = (const struct hg_object_id *)(data + 40);
	result->delta_node = delta_node ? delta_node
	                                : (const struct hg_object_id *)(data + 60);
/*	result->changeset = data + 60 + 20 * !!(delta_node == NULL); */
	result->diff_data = data + data_offset;
}

void rev_diff_start_iter(struct rev_diff_part *iterator,
                         struct rev_chunk *chunk)
{
	iterator->start = 0;
	iterator->end = 0;
	iterator->data.alloc = 0;
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
