#include "cache.h"
#include "cinnabar-notes.h"

#undef notes_tree
#undef init_notes
#undef free_notes
#undef add_note
#undef remove_note
#undef get_note
#undef for_each_note

static int abbrev_sha1_cmp(const unsigned char *ref_sha1,
                           const unsigned char *abbrev_sha1, size_t len)
{
        int i;

        for (i = 0; i < len / 2; i++, ref_sha1++, abbrev_sha1++) {
                if (*ref_sha1 != *abbrev_sha1)
                        return *ref_sha1 - *abbrev_sha1;
        }

	if (len % 2) {
		unsigned char ref_bits = *ref_sha1 & 0xf0;
		unsigned char abbrev_bits = *abbrev_sha1 & 0xf0;
		if (ref_bits != abbrev_bits)
			return ref_bits - abbrev_bits;
	}

        return 0;

}

/* Definitions from git's notes.c. See there for more details */
struct int_node {
	void *a[16];
};

struct leaf_node {
	struct object_id key_oid;
	struct object_id val_oid;
};

#define PTR_TYPE_NULL     0
#define PTR_TYPE_INTERNAL 1
#define PTR_TYPE_NOTE     2
#define PTR_TYPE_SUBTREE  3

#define GET_PTR_TYPE(ptr)       ((uintptr_t) (ptr) & 3)
#define CLR_PTR_TYPE(ptr)       ((void *) ((uintptr_t) (ptr) & ~3))

#define GET_NIBBLE(n, sha1) (((sha1[(n) >> 1]) >> ((~(n) & 0x01) << 2)) & 0x0f)

/* This function assumes the note tree has been populated for the given key,
 * which means get_note must have been called before */
static struct leaf_node *note_tree_abbrev_find(struct notes_tree *t,
		struct int_node *tree, unsigned char n,
		const unsigned char *key_sha1, size_t len)
{
	unsigned char i, j;
	void *p;

	if (n > len) {
		for (i = 17, j = 0; j < 16; j++) {
			if (tree->a[j])
				i = (i < 17) ? 16 : j;
		}
		if (i >= 16)
			return NULL;
	} else {
		i = GET_NIBBLE(n, key_sha1);
	}

	p = tree->a[i];

	switch (GET_PTR_TYPE(p)) {
	case PTR_TYPE_INTERNAL:
		tree = CLR_PTR_TYPE(p);
		return note_tree_abbrev_find(t, tree, ++n, key_sha1, len);
	case PTR_TYPE_SUBTREE:
		return NULL;
	default:
		{
			struct leaf_node *node = CLR_PTR_TYPE(p);
			if (node && !abbrev_sha1_cmp(node->key_oid.hash,
			                             key_sha1, len))
				return node;
			return NULL;
		}
	}
}

const struct object_id *get_abbrev_note(struct cinnabar_notes_tree *t,
		const struct object_id *object_oid, size_t len)
{
	struct leaf_node *found;

	assert(t);
	assert(notes_initialized(t));
	found = note_tree_abbrev_find(&t->current, t->current.root, 0,
	                              object_oid->hash, len);
	if (!found)
		found = note_tree_abbrev_find(
			&t->additions, t->additions.root, 0,
			object_oid->hash, len);
	return found ? &found->val_oid : NULL;
}

void cinnabar_init_notes(struct cinnabar_notes_tree *t, const char *notes_ref,
                         combine_notes_fn combine_notes, int flags)
{
	t->init_flags = flags;
	init_notes(&t->current, notes_ref, combine_notes, flags);
	init_notes(&t->additions, notes_ref, combine_notes_ignore,
	           NOTES_INIT_EMPTY);
}

void cinnabar_free_notes(struct cinnabar_notes_tree *t)
{
	free_notes(&t->current);
	free_notes(&t->additions);
}

int cinnabar_add_note(
	struct cinnabar_notes_tree *t, const struct object_id *object_oid,
	const struct object_id *note_oid, combine_notes_fn combine_notes)
{
	if (!combine_notes)
		combine_notes = t->current.combine_notes;
	if (combine_notes == combine_notes_ignore) {
		if (get_note(&t->current, object_oid))
			return 0;
	} else if (combine_notes != combine_notes_overwrite) {
		die("Unsupported combine_notes");
	}

	return add_note(&t->additions, object_oid, note_oid, NULL);
}

int cinnabar_remove_note(struct cinnabar_notes_tree *t,
                         const unsigned char *object_sha1)
{
	int result = remove_note(&t->current, object_sha1);
	int result2 = remove_note(&t->additions, object_sha1);
	if (!result) {
		struct object_id oid;
		hashcpy(oid.hash, object_sha1);
		add_note(&t->additions, &oid, &null_oid, NULL);
	}
	return result && result2;
}

const struct object_id *cinnabar_get_note(struct cinnabar_notes_tree *t,
                                          const struct object_id *object_oid)
{
	const struct object_id *note = get_note(&t->current, object_oid);
	if (!note) {
		note = get_note(&t->additions, object_oid);
		if (note && is_null_oid(note))
			note = NULL;
	}
	return note;
}

static int merge_note(const struct object_id *object_oid,
                      const struct object_id *note_oid, char *note_path,
                      void *data)
{
	struct notes_tree *notes = (struct notes_tree *)data;
	if (is_null_oid(note_oid))
		remove_note(notes, object_oid->hash);
	else
		add_note(notes, object_oid, note_oid, combine_notes_overwrite);

	return 0;
}

int cinnabar_for_each_note(struct cinnabar_notes_tree *t, int flags,
                           each_note_fn fn, void *cb_data)
{
	struct int_node empty_node = { 0, };
	char *notes_ref = xstrdup_or_null(t->current.ref);
	if (memcmp(&t->current.root, &empty_node, sizeof(empty_node)) == 0) {
		// If current is empty, we just copy the additions to it.
		free_notes(&t->current);
		memcpy(&t->current, &t->additions, sizeof(struct notes_tree));
		init_notes(&t->additions, notes_ref, combine_notes_ignore,
		           NOTES_INIT_EMPTY);
	} else {
		/* Reinitialize current */
		combine_notes_fn combine_notes = t->current.combine_notes;
		free_notes(&t->current);
		init_notes(&t->current, notes_ref, combine_notes, t->init_flags);
		/* Merge additions */
		for_each_note(&t->additions, FOR_EACH_NOTE_DONT_UNPACK_SUBTREES,
		              merge_note, &t->current);
		/* Reinitialize additions */
		free_notes(&t->additions);
		init_notes(&t->additions, notes_ref, combine_notes_ignore,
		           NOTES_INIT_EMPTY);
	}
	free(notes_ref);

	/* Now we can iterate the updated current */
	return for_each_note(&t->current, flags, fn, cb_data);
}
