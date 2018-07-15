#ifndef CINNABAR_NOTES_H
#define CINNABAR_NOTES_H

#include "notes.h"

struct cinnabar_notes_tree {
	struct notes_tree current;
	struct notes_tree additions;
	int init_flags;
};

/* The notes API from libgit doesn't distinguish between nodes that
 * have been visited and nodes that have been dirtied, such that
 * on large notes tree, small modifications after large amount of
 * lookups induces a large cost when storing them.
 * So we transparently wrap the API to work around this problem. */
#define notes_tree cinnabar_notes_tree
#define init_notes cinnabar_init_notes
#define free_notes cinnabar_free_notes
#define add_note cinnabar_add_note
#define remove_note cinnabar_remove_note
#define get_note cinnabar_get_note
#define for_each_note cinnabar_for_each_note
#define write_notes_tree cinnabar_write_notes_tree

static inline int notes_initialized(struct notes_tree *notes)
{
	return notes->current.initialized;
}

static inline int notes_dirty(struct notes_tree *notes)
{
	return notes->current.dirty || notes->additions.dirty;
}

extern const struct object_id *get_abbrev_note(
	struct notes_tree *t, const struct object_id *object_oid, size_t len);

extern void init_notes(struct notes_tree *t, const char *notes_ref,
                       combine_notes_fn combine_notes, int flags);

extern void free_notes(struct notes_tree *t);

extern int add_note(
	struct notes_tree *t, const struct object_id *object_oid,
	const struct object_id *note_oid, combine_notes_fn combine_notes);

extern int remove_note(struct notes_tree *t, const unsigned char *object_sha1);

extern const struct object_id *get_note(struct notes_tree *t,
                                        const struct object_id *object_oid);

extern int for_each_note(struct notes_tree *t, int flags, each_note_fn fn,
                         void *cb_data);

extern int write_notes_tree(struct notes_tree *t, struct object_id *result,
                            unsigned int mode);

extern void consolidate_notes(struct notes_tree *t);

#endif
