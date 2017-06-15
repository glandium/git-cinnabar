#ifndef HG_DATA_H
#define HG_DATA_H

#include "strbuf.h"

extern int is_empty_hg_file(const unsigned char *sha1);

struct hg_file {
	unsigned char sha1[20];

	struct strbuf file;
	struct strbuf metadata;
	struct strbuf content;
	void *content_oe;
};

extern void hg_file_load(struct hg_file *result, const unsigned char *sha1);

extern void hg_file_from_memory(struct hg_file *result,
                                const unsigned char *sha1, struct strbuf *buf);

static inline void hg_file_swap(struct hg_file *a, struct hg_file *b)
{
        SWAP(*a, *b);
}

extern void hg_file_init(struct hg_file *file);

extern void hg_file_release(struct hg_file *file);

extern void hg_file_store(struct hg_file *file, struct hg_file *reference);

#endif
