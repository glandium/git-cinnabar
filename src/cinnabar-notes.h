/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
#define add_note cinnabar_add_note
#define remove_note cinnabar_remove_note
#define get_note cinnabar_get_note
#define for_each_note cinnabar_for_each_note
#define write_notes_tree cinnabar_write_notes_tree

extern const struct object_id *get_abbrev_note(
	struct notes_tree *t, const struct object_id *object_oid, size_t len);

extern int add_note(
	struct notes_tree *t, const struct object_id *object_oid,
	const struct object_id *note_oid);

int remove_note(struct notes_tree *t, const unsigned char *object_sha1);

const struct object_id *get_note(struct notes_tree *t,
                                 const struct object_id *object_oid);

int for_each_note(struct notes_tree *t, int flags, each_note_fn fn,
                  void *cb_data);

int write_notes_tree(struct notes_tree *t, struct object_id *result,
                     unsigned int mode);

void consolidate_notes(struct notes_tree *t);

#endif
