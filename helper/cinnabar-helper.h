#ifndef CINNABAR_HELPER_H
#define CINNABAR_HELPER_H

#include "notes.h"

#define METADATA_REF "refs/cinnabar/metadata"
#define CHANGESETS_REF METADATA_REF "^1"
#define MANIFESTS_REF METADATA_REF "^2"
#define HG2GIT_REF METADATA_REF "^3"
#define NOTES_REF METADATA_REF "^4"
#define FILES_META_REF METADATA_REF "^5"


#define FILES_META 0x1
#define UNIFIED_MANIFESTS 0x2

extern int metadata_flags;

#define CHECK_HELPER 0x1

extern int cinnabar_check;

extern struct oid_array changeset_heads, manifest_heads;

extern void ensure_heads(struct oid_array *heads);

extern struct notes_tree git2hg, hg2git, files_meta;

static inline void ensure_notes(struct notes_tree *notes)
{
	if (!notes->initialized) {
		const char *ref;
		int flags = 0;
		if (notes == &git2hg)
			ref = NOTES_REF;
		else if (notes == &hg2git)
			ref = HG2GIT_REF;
		else if (notes == &files_meta) {
			ref = FILES_META_REF;
			if (!(metadata_flags & FILES_META))
				flags = NOTES_INIT_EMPTY;
		} else
			die("Unknown notes tree");
		init_notes(notes, ref, combine_notes_ignore, flags);
	}
}

extern struct strbuf *generate_manifest(const struct object_id *oid);

#endif
