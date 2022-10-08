/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef CINNABAR_FAST_IMPORT_H
#define CINNABAR_FAST_IMPORT_H

struct reader;

int maybe_handle_command(struct reader *helper_input, int helper_output,
                         const char *command, struct string_list *args);

void *get_object_entry(const unsigned char *sha1);

void store_git_tree(struct strbuf *tree_buf,
                    const struct object_id *reference,
                    struct object_id *result);

void store_git_commit(struct strbuf *commit_buf, struct object_id *result);

void add_head(struct oid_array *heads, const struct object_id *oid);

const struct object_id *ensure_empty_blob();

#endif
