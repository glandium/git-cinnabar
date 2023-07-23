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

struct remote;

const char *remote_get_name(const struct remote *remote);
void remote_get_url(const struct remote *remote, const char * const **url,
                    int* url_nr);
int remote_skip_default_update(const struct remote *remote);

void init_cinnabar(const char *argv0);
int init_cinnabar_2(void);
void done_cinnabar(void);

void create_git_tree(const struct object_id *tree_id,
                     const struct object_id *ref_tree,
                     struct object_id *result);

void reset_manifest_heads(void);
void do_reload(void);
unsigned int replace_map_size(void);

const struct object_id *repo_lookup_replace_object(
	struct repository *r, const struct object_id *oid);
const struct object_id *resolve_hg(
	struct notes_tree* tree, const struct hg_object_id *oid, size_t len);
const struct object_id *resolve_hg2git(const struct hg_object_id *oid,
                                       size_t len);

struct commit;

struct object_id *commit_oid(struct commit *c);
struct rev_info *rev_list_new(int argc, const char **argv);
void rev_list_finish(struct rev_info *revs);
int maybe_boundary(struct rev_info *revs, struct commit *commit);

struct diff_tree_item;

void diff_tree_(int argc, const char **argv, void (*cb)(void *, struct diff_tree_item *), void *context);

#endif
