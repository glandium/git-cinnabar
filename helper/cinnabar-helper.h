#ifndef CINNABAR_HELPER_H
#define CINNABAR_HELPER_H

#include "notes.h"

#define METADATA_REF "refs/cinnabar/metadata"
#define MANIFESTS_REF METADATA_REF "^2"
#define HG2GIT_REF METADATA_REF "^3"
#define NOTES_REF METADATA_REF "^4"

extern struct sha1_array manifest_heads;

extern void ensure_heads(struct sha1_array *heads);

extern struct notes_tree git2hg, hg2git;

static inline void ensure_notes(struct notes_tree *notes)
{
	if (!notes->initialized) {
		const char *ref;
		if (notes == &git2hg)
			ref = NOTES_REF;
		else if (notes == &hg2git)
			ref = HG2GIT_REF;
		else
			die("Unknown notes tree");
		init_notes(notes, ref, combine_notes_ignore, 0);
	}
}

#endif
