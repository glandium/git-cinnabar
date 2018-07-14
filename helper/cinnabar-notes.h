#ifndef CINNABAR_NOTES_H
#define CINNABAR_NOTES_H

#include "notes.h"

static inline int notes_initialized(struct notes_tree *notes)
{
	return notes->initialized;
}

extern const struct object_id *get_abbrev_note(
	struct notes_tree *t, const struct object_id *object_oid, size_t len);

#endif
