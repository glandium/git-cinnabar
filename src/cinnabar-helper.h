#ifndef CINNABAR_HELPER_H
#define CINNABAR_HELPER_H

#include "hg-data.h"
#include "cinnabar-notes.h"

#define METADATA_REF "refs/cinnabar/metadata"
#define CHANGESETS_REF METADATA_REF "^1"
#define MANIFESTS_REF METADATA_REF "^2"
#define HG2GIT_REF METADATA_REF "^3"
#define NOTES_REF METADATA_REF "^4"
#define FILES_META_REF METADATA_REF "^5"


#define FILES_META 0x1
#define UNIFIED_MANIFESTS_v2 0x2

extern int metadata_flags;

#define CHECK_HELPER 0x1
#define CHECK_MANIFESTS 0x2
#define CHECK_VERSION 0x4

#define EXPERIMENT_STORE 0x1

extern int cinnabar_check;
extern int cinnabar_experiments;

extern struct oid_array changeset_heads, manifest_heads;

void ensure_heads(struct oid_array *heads);

extern struct notes_tree git2hg, hg2git, files_meta;

extern void ensure_notes(struct notes_tree *notes);

struct strbuf *generate_manifest(const struct object_id *oid);

int check_manifest(const struct object_id *oid,
                   struct hg_object_id *hg_oid);

#endif
