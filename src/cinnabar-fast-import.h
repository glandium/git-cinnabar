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
struct object_entry;
struct Store;

int maybe_handle_command(struct reader *helper_input, int helper_output,
                         const char *command, struct string_list *args);

struct object_entry *get_object_entry(const struct object_id *oid);

void unpack_object_entry(struct object_entry *oe, char **buf,
                         unsigned long *len);

void store_git_tree(struct strslice tree_buf,
                    const struct object_id *reference,
                    struct object_id *result);

void store_git_object(enum object_type type, const struct strslice buf,
                      struct object_id *result, const struct strslice *reference,
                      const struct object_entry *reference_entry);

void do_cleanup(int rollback);

void do_set_replace(const struct object_id *replaced,
                    const struct object_id *replace_with);

void store_manifest(struct Store *store, struct rev_chunk *chunk,
                    const struct strslice last_manifest_content,
                    struct strslice_mut data);

void ensure_store_init(void);

void store_replace_map(struct object_id *result);

#endif
