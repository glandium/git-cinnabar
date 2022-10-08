/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef CINNABAR_HELPER_H
#define CINNABAR_HELPER_H

#include "hg-data.h"
#include "cinnabar-notes.h"

#define METADATA_REF "refs/cinnabar/metadata"

extern struct object_id metadata_oid, changesets_oid, manifests_oid, git2hg_oid,
                        hg2git_oid, files_meta_oid;

#define FILES_META 0x1
#define UNIFIED_MANIFESTS_v2 0x2

extern int metadata_flags;

#define CHECK_HELPER 0x1
#define CHECK_MANIFESTS 0x2

extern int cinnabar_check(int);

extern struct oid_array manifest_heads;

void ensure_heads(struct oid_array *heads);

extern struct notes_tree git2hg, hg2git, files_meta;

extern void ensure_notes(struct notes_tree *notes);

struct strbuf *generate_manifest(const struct object_id *oid);

int check_manifest(const struct object_id *oid,
                   struct hg_object_id *hg_oid);

struct reader;

extern size_t strbuf_from_reader(struct strbuf *sb, size_t size,
                                 struct reader *reader);

#endif
