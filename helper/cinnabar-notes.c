#include "cache.h"
#include "cinnabar-notes.h"

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

const struct object_id *get_abbrev_note(struct notes_tree *t,
		const struct object_id *object_oid, size_t len)
{
	struct leaf_node *found;

	if (!t)
		t = &default_notes_tree;
	assert(notes_initialized(t));
	found = note_tree_abbrev_find(t, t->root, 0, object_oid->hash, len);
	return found ? &found->val_oid : NULL;
}
