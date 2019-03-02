#ifndef HG_DATA_H
#define HG_DATA_H

#include "strbuf.h"
#include "cinnabar-notes.h"

struct hg_object_id {
	unsigned char hash[20];
};

extern const struct hg_object_id hg_null_oid;

static inline int hg_oidcmp(const struct hg_object_id *oid1,
                            const struct hg_object_id *oid2)
{
	return memcmp(oid1->hash, oid2->hash, 20);
}

static inline int hg_oideq(const struct hg_object_id *oid1,
                           const struct hg_object_id *oid2)
{
	return !hg_oidcmp(oid1, oid2);
}

static inline void hg_oidclr(struct hg_object_id *oid)
{
	memset(oid->hash, 0, 20);
}

static inline void hg_oidcpy(struct hg_object_id *dst,
                             const struct hg_object_id *src)
{
	memcpy(dst->hash, src->hash, 20);
}

static inline void hg_oidcpy2git(struct object_id *dst,
                                 const struct hg_object_id *src)
{
	memcpy(dst->hash, src->hash, 20);
	memset(dst->hash + 20, 0, the_hash_algo->rawsz - 20);
}

static inline void oidcpy2hg(struct hg_object_id *dst,
                             const struct object_id *src)
{
	memcpy(dst->hash, src->hash, 20);
}

extern int is_null_hg_oid(const struct hg_object_id *oid);

extern int is_empty_hg_file(const struct hg_object_id *oid);

struct hg_file {
	struct hg_object_id oid;

	struct strbuf file;
	struct strbuf metadata;
	struct strbuf content;
	void *content_oe;
};

extern void hg_file_load(struct hg_file *result, const struct hg_object_id *oid);

extern void hg_file_from_memory(struct hg_file *result,
                                const struct hg_object_id *oid, struct strbuf *buf);

static inline void hg_file_swap(struct hg_file *a, struct hg_file *b)
{
        SWAP(*a, *b);
}

extern void hg_file_init(struct hg_file *file);

extern void hg_file_release(struct hg_file *file);

extern void hg_file_store(struct hg_file *file, struct hg_file *reference);

extern int add_note_hg(struct notes_tree *notes,
                       const struct hg_object_id *oid,
                       const struct object_id *note_oid,
                       combine_notes_fn combine_notes);

extern int remove_note_hg(struct notes_tree *notes,
                          const struct hg_object_id *oid);

extern const struct object_id *get_note_hg(struct notes_tree *notes,
                                           const struct hg_object_id *oid);

#endif
