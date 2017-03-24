#ifndef CINNABAR_HELPER_H
#define CINNABAR_HELPER_H

#include "notes.h"

#define METADATA_REF "refs/cinnabar/metadata"
#define MANIFESTS_REF METADATA_REF "^2"
#define HG2GIT_REF METADATA_REF "^3"
#define NOTES_REF METADATA_REF "^4"

extern struct notes_tree git2hg, hg2git;

static inline void ensure_git2hg()
{
	if (!git2hg.initialized)
		init_notes(&git2hg, NOTES_REF, combine_notes_overwrite, 0);
}

static inline void ensure_hg2git()
{
	if (!hg2git.initialized)
		init_notes(&hg2git, HG2GIT_REF, combine_notes_overwrite, 0);
}

#endif
