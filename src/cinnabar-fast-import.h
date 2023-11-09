/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef CINNABAR_FAST_IMPORT_H
#define CINNABAR_FAST_IMPORT_H

#include "strslice.h"

struct reader;
struct object_id;
struct hg_object_id;
struct cinnabar_notes_tree;
struct rev_chunk;

int maybe_handle_command(struct reader *helper_input, int helper_output,
                         const char *command, struct string_list *args);

void *get_object_entry(const unsigned char *sha1);

void store_git_tree(struct strbuf *tree_buf,
                    const struct object_id *reference,
                    struct object_id *result);

void store_git_commit(struct strbuf *commit_buf, struct object_id *result);

void store_git_blob(struct strbuf *blob_buf, struct object_id *result);

const struct object_id *ensure_empty_blob(void);

void do_cleanup(int rollback);

void do_set_replace(const struct object_id *replaced,
                    const struct object_id *replace_with);

void do_set_(const char *what, const struct hg_object_id *hg_id,
             const struct object_id *git_id);

void store_file(struct rev_chunk *chunk);
void store_manifest(struct rev_chunk *chunk,
                    const struct strslice last_manifest_content,
                    struct strslice_mut data);
void store_metadata_notes(
	struct cinnabar_notes_tree *notes, const struct object_id *reference,
	struct object_id *result);

void ensure_store_init(void);

void store_replace_map(struct object_id *result);

void do_store_metadata(struct object_id *result);

#endif
