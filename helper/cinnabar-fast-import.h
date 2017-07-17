#ifndef CINNABAR_FAST_IMPORT_H
#define CINNABAR_FAST_IMPORT_H

extern int maybe_handle_command(const char *command, struct string_list *args);

extern void *get_object_entry(const unsigned char *sha1);

extern void store_git_tree(struct strbuf *tree_buf,
                           const struct object_id *reference,
                           struct object_id *result);

extern void store_git_commit(struct strbuf *commit_buf, struct object_id *result);

extern void add_head(struct oid_array *heads, const struct object_id *oid);

extern const unsigned char *ensure_empty_blob();

#endif
