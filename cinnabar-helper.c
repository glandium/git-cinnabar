/* Helper program for git-cinnabar
 *
 * It receives commands on stdin and outputs results on stdout.
 * The following commands are supported:
 * - git2hg <committish>
 *     Returns the contents of the git note containing git->hg metadata
 *     for the given commit in a `cat-file --batch`-like format.
 * - hg2git <hg_sha1>
 *     Returns the sha1 of the git object corresponding to the given
 *     mercurial sha1.
 * - manifest <hg_sha1>
 *     Returns the contents of the mercurial manifest with the given
 *     mercurial sha1, preceded by its length in text form, and followed
 *     by a carriage return.
 * - check-manifest <hg_sha1>
 *     Returns 'ok' when the sha1 of the contents of the mercurial manifest
 *     matches the manifest sha1, otherwise returns 'error'.
 * - cat-file <object>
 *     Returns the contents of the given git object, in a `cat-file
 *     --batch`-like format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "commit.h"
#include "strbuf.h"
#include "string-list.h"
#include "notes.h"
#include "streaming.h"
#include "object.h"
#include "revision.h"
#include "tree.h"
#include "tree-walk.h"

#define CMD_VERSION 2

#define REFS_PREFIX "refs/cinnabar/"
#define NOTES_REF "refs/notes/cinnabar"

static const char NULL_NODE[] = "0000000000000000000000000000000000000000";
static const unsigned char NULL_NODE_SHA1[20] = { 0, };

static struct notes_tree git2hg, hg2git;

static void split_command(char *line, const char **command,
			  struct string_list *args)
{
	struct string_list split_line = STRING_LIST_INIT_NODUP;
	string_list_split_in_place(&split_line, line, ' ', 1);
	*command = split_line.items[0].string;
	if (split_line.nr > 1)
		string_list_split_in_place(
			args, split_line.items[1].string, ' ', -1);
}

static void send_buffer(struct strbuf *buf)
{
	struct strbuf header = STRBUF_INIT;

	strbuf_addf(&header, "%lu\n", buf->len);
	write_or_die(1, header.buf, header.len);
	strbuf_release(&header);

	write_or_die(1, buf->buf, buf->len);
	write_or_die(1, "\n", 1);
	return;
}

/* Send git object info and content to stdout, like cat-file --batch does. */
static void send_object(unsigned const char *sha1)
{
	struct strbuf header = STRBUF_INIT;
	enum object_type type;
	unsigned long sz;
	struct git_istream *st;

	st = open_istream(sha1, &type, &sz, NULL);

	strbuf_addf(&header, "%s %s %lu\n", sha1_to_hex(sha1), typename(type),
	            sz);

	write_or_die(1, header.buf, header.len);

	strbuf_release(&header);

	for (;;) {
		char buf[1024 * 16];
		ssize_t wrote;
		ssize_t readlen = read_istream(st, buf, sizeof(buf));

		if (readlen <= 0)
			break;

		wrote = write_in_full(1, buf, readlen);
		if (wrote < readlen)
			break;

		sz -= wrote;
	}

	if (sz != 0)
		die("Failed to write object");

	write_or_die(1, "\n", 1);

	close_istream(st);
}

static void do_cat_file(struct string_list *args)
{
	unsigned char sha1[20];

	if (args->nr != 1)
		goto not_found;

	if (get_sha1(args->items[0].string, sha1))
		goto not_found;

	send_object(sha1);
	return;

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

static void do_git2hg(struct string_list *args)
{
	unsigned char sha1[20];
	const unsigned char *note;

	if (args->nr != 1)
		goto not_found;

	if (!git2hg.initialized)
		init_notes(&git2hg, NOTES_REF, combine_notes_overwrite, 0);

	if (get_sha1_committish(args->items[0].string, sha1))
		goto not_found;

	note = get_note(&git2hg, lookup_replace_object(sha1));
	if (!note)
		goto not_found;

	send_object(note);
	return;

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

static size_t get_abbrev_sha1_hex(const char *hex, unsigned char *sha1)
{
	unsigned char *start = sha1;
	unsigned char *end = sha1 + 20;
	size_t len;
	while (sha1 < end) {
		unsigned int val;
		if (!hex[0])
			val = 0xff;
		else if (!hex[1])
			val = (hexval(hex[0]) << 4) | 0xf;
		else
			val = (hexval(hex[0]) << 4) | hexval(hex[1]);
		if (val & ~0xff)
			return 0;
		*sha1++ = val;
		if (!hex[0] || !hex[1])
			break;
		hex += 2;
	}
	len = (sha1 - start) * 2 + !!hex[0];
	while (sha1 < end) {
		*sha1++ = 0xff;
	}
	return len;
}

/* Definitions from git's notes.c. See there for more details */
struct int_node {
	void *a[16];
};

struct leaf_node {
	unsigned char key_sha1[20];
	unsigned char val_sha1[20];
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
		return (struct leaf_node *) CLR_PTR_TYPE(p);
	}
}

const unsigned char *get_abbrev_note(struct notes_tree *t,
		const unsigned char *object_sha1, size_t len)
{
	struct leaf_node *found;

	if (!t)
		t = &default_notes_tree;
	assert(t->initialized);
	found = note_tree_abbrev_find(t, t->root, 0, object_sha1, len);
	return found ? found->val_sha1 : NULL;
}


static const unsigned char *resolve_hg2git(const unsigned char *sha1,
                                           size_t len)
{
	const unsigned char *note;

	if (!hg2git.initialized)
		init_notes(&hg2git, REFS_PREFIX "hg2git",
		           combine_notes_overwrite, 0);

	note = get_note(&hg2git, sha1);
	if (len == 40)
		return note;

	return get_abbrev_note(&hg2git, sha1, len);
}

static void do_hg2git(struct string_list *args)
{
	unsigned char sha1[20];
	const unsigned char *note;
	size_t sha1_len;

	if (args->nr != 1)
		goto not_found;

	sha1_len =  get_abbrev_sha1_hex(args->items[0].string, sha1);
	if (!sha1_len)
		goto not_found;

	note = resolve_hg2git(sha1, sha1_len);
	if (note) {
		write_or_die(1, sha1_to_hex(note), 40);
		write_or_die(1, "\n", 1);
		return;
	}

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

/* Return the mercurial manifest character corresponding to the given
 * git file mode. */
static const char *hgattr(unsigned int mode)
{
	if (S_ISLNK(mode))
		return "l";
	if (S_ISREG(mode)) {
		if ((mode & 0755) == 0755)
			return "x";
		else if ((mode & 0644) == 0644)
			return "";
	}
	die("Unsupported mode %06o", mode);
}

/* The git storage for a mercurial manifest is a commit with two directories
 * at its root:
 * - a git directory, matching the git tree in the git commit corresponding to
 *   the mercurial changeset using the manifest.
 * - a hg directory, containing the same file paths, but where all pointed
 *   objects are commits (mode 160000 in the git tree) whose sha1 is actually
 *   the mercurial sha1 for the corresponding mercurial file.
 * Reconstructing the mercurial manifest requires file paths, mercurial sha1
 * for each file, and the corresponding attribute ("l" for symlinks, "x" for
 * executables"). The hg directory alone is not enough for that, because it
 * lacks the attribute information. So, both directories are recursed in
 * parallel to generate the original manifest data.
 */
struct manifest_tree {
	unsigned char git[20];
	unsigned char hg[20];
};

static void track_tree(struct tree *tree, struct object_list **tree_list)
{
	object_list_insert(&tree->object, tree_list);
	tree->object.flags |= SEEN;
}

/* Fills a manifest_tree with the tree sha1s for the git/ and hg/
 * subdirectories of the given (git) manifest tree. */
static int get_manifest_tree(const unsigned char *git_sha1,
                             struct manifest_tree *result,
                             struct object_list **tree_list)
{
	struct tree *tree = NULL;
	struct tree_desc desc;
	struct name_entry entry;

	tree = parse_tree_indirect(git_sha1);
	if (!tree)
		return -1;

	track_tree(tree, tree_list);

	/* If the tree is empty, return an empty tree for both git
	 * and hg. */
	if (!tree->size) {
		hashcpy(result->git, tree->object.oid.hash);
		hashcpy(result->hg, tree->object.oid.hash);
		return 0;
	}

	init_tree_desc(&desc, tree->buffer, tree->size);
	/* The first entry in the manifest tree is the git subtree. */
	if (!tree_entry(&desc, &entry))
		goto not_found;
	if (strcmp(entry.path, "git"))
		goto not_found;
	hashcpy(result->git, entry.sha1);

	/* The second entry in the manifest tree is the hg subtree. */
	if (!tree_entry(&desc, &entry))
		goto not_found;
	if (strcmp(entry.path, "hg"))
		goto not_found;
	hashcpy(result->hg, entry.sha1);

	/* There shouldn't be any other entry. */
	if (tree_entry(&desc, &entry))
		goto not_found;

	return 0;

not_found:
	return -1;
}

struct manifest_tree_state {
	struct tree *tree_git, *tree_hg;
	struct tree_desc desc_git, desc_hg;
};

static int manifest_tree_state_init(const struct manifest_tree *tree,
                                    struct manifest_tree_state *result,
                                    struct object_list **tree_list)
{
	result->tree_git = parse_tree_indirect(tree->git);
	if (!result->tree_git)
		return -1;
	track_tree(result->tree_git, tree_list);

	result->tree_hg = parse_tree_indirect(tree->hg);
	if (!result->tree_hg)
		return -1;
	track_tree(result->tree_hg, tree_list);

	init_tree_desc(&result->desc_git, result->tree_git->buffer,
	               result->tree_git->size);
	init_tree_desc(&result->desc_hg, result->tree_hg->buffer,
	               result->tree_hg->size);
	return 0;
}

struct manifest_entry {
	const unsigned char *sha1;
	/* Used for trees only. */
	const unsigned char *other_sha1;
	const char *path;
	unsigned int mode;
};

/* Like tree_entry, returns true for success. */
static int manifest_tree_entry(struct manifest_tree_state *state,
                               struct manifest_entry *result)
{
	struct name_entry entry_git, entry_hg;
	int has_git_entry = tree_entry(&state->desc_git, &entry_git);
	int has_hg_entry = tree_entry(&state->desc_hg, &entry_hg);
	if (has_git_entry != has_hg_entry)
		goto corrupted;
	if (!has_git_entry) {
		result->path = NULL;
		return 0;
	}

	result->sha1 = entry_hg.sha1;
	result->path = entry_hg.path;
	result->mode = entry_git.mode;
	if (strcmp(entry_hg.path, entry_git.path))
		goto corrupted;
	if (S_ISDIR(entry_git.mode)) {
		if (entry_git.mode != entry_hg.mode)
			goto corrupted;
		result->other_sha1 = entry_git.sha1;
	}
	return 1;
corrupted:
	die("Corrupted metadata");
}

static void recurse_manifest(const struct manifest_tree *tree,
                             struct strbuf *manifest, char *base,
                             struct object_list **tree_list)
{
	struct manifest_tree_state state;
	struct manifest_entry entry;
	size_t base_len = strlen(base);

	if (manifest_tree_state_init(tree, &state, tree_list))
		goto corrupted;

	while (manifest_tree_entry(&state, &entry)) {
		if (S_ISDIR(entry.mode)) {
			struct strbuf dir = STRBUF_INIT;
			struct manifest_tree subtree;
			if (base_len)
				strbuf_add(&dir, base, base_len);
			strbuf_addstr(&dir, entry.path);
			strbuf_addch(&dir, '/');
			hashcpy(subtree.git, entry.other_sha1);
			hashcpy(subtree.hg, entry.sha1);
			recurse_manifest(&subtree, manifest, dir.buf, tree_list);
			strbuf_release(&dir);
			continue;
		}
		strbuf_addf(manifest, "%s%s%c%s%s\n", base, entry.path,
		            '\0', sha1_to_hex(entry.sha1), hgattr(entry.mode));
	}

	return;
corrupted:
	die("Corrupted metadata");

}

struct strslice {
	size_t len;
	const char *buf;
};

/* Return whether two entries have matching sha1s and modes */
static int manifest_entry_equal(const struct manifest_entry *e1,
                                const struct manifest_entry *e2)
{
	if (e1->mode != e2->mode)
		return 0;
	if (hashcmp(e1->sha1, e2->sha1))
		return 0;
	if (!S_ISDIR(e1->mode))
		return 1;
	/* For trees, both sha1 need to match */
	return hashcmp(e1->other_sha1, e2->other_sha1) == 0;
}

/* Return whether base + name matches path */
static int path_match(const char *base, size_t base_len,
                      const char *name, size_t name_len, const char *path)
{
	return memcmp(base, path, base_len) == 0 &&
	       memcmp(name, path + base_len, name_len) == 0 &&
	       (path[base_len + name_len] == '\0' ||
	        path[base_len + name_len] == '/');
}

static void recurse_manifest2(const struct manifest_tree *ref_tree,
                              struct strslice *ref_manifest,
                              const struct manifest_tree *tree,
                              struct strbuf *manifest, char *base,
                              struct object_list **tree_list)
{
	struct manifest_tree_state ref, cur;
	struct manifest_entry ref_entry, cur_entry;
	struct manifest_tree ref_subtree, cur_subtree;
	const char *next = ref_manifest->buf;
	struct strbuf dir = STRBUF_INIT;
	size_t base_len = strlen(base);
	size_t ref_entry_len = 0;
	int cmp = 0;

	if (manifest_tree_state_init(ref_tree, &ref, tree_list))
		goto corrupted;

	if (manifest_tree_state_init(tree, &cur, tree_list))
		goto corrupted;

	for (;;) {
		if (cmp >= 0)
			manifest_tree_entry(&cur, &cur_entry);
		if (cmp <= 0) {
			manifest_tree_entry(&ref, &ref_entry);
			assert(ref_manifest->buf + ref_manifest->len >= next);
			ref_manifest->len -= next - ref_manifest->buf;
			ref_manifest->buf = next;
			ref_entry_len = ref_entry.path ?
				strlen(ref_entry.path) : 0;
			assert(!ref_entry.path ||
			       path_match(base, base_len, ref_entry.path,
			                  ref_entry_len, next));
		}
		if (!ref_entry.path) {
			if (!cur_entry.path)
				break;
			cmp = 1;
		} else if (!cur_entry.path) {
			cmp = -1;
		} else {
			cmp = name_compare(
				ref_entry.path, ref_entry_len,
				cur_entry.path, strlen(cur_entry.path));
		}
		if (cmp <= 0) {
			const char *tail = next + ref_manifest->len;
			size_t len = base_len + ref_entry_len + 41;
			do {
				next = memchr(next + len, '\n', tail - next)
				       + 1;
			} while (S_ISDIR(ref_entry.mode) &&
			         (tail - next > len) &&
			         path_match(base, base_len, ref_entry.path,
			                    ref_entry_len, next));
		}
		/* File/directory was removed, nothing to do */
		if (cmp < 0)
			continue;
		/* File/directory didn't change, copy from the reference
		 * manifest. */
		if (cmp == 0 && manifest_entry_equal(&ref_entry, &cur_entry)) {
			strbuf_add(manifest, ref_manifest->buf,
			           next - ref_manifest->buf);
			continue;
		}
		if (!S_ISDIR(cur_entry.mode)) {
			strbuf_addf(manifest, "%s%s%c%s%s\n", base,
			            cur_entry.path, '\0',
			            sha1_to_hex(cur_entry.sha1),
			            hgattr(cur_entry.mode));
			continue;
		}

		if (base_len)
			strbuf_add(&dir, base, base_len);
		strbuf_addstr(&dir, cur_entry.path);
		strbuf_addch(&dir, '/');
		hashcpy(cur_subtree.git, cur_entry.other_sha1);
		hashcpy(cur_subtree.hg, cur_entry.sha1);
		if (cmp == 0 && S_ISDIR(ref_entry.mode)) {
			hashcpy(ref_subtree.git, ref_entry.other_sha1);
			hashcpy(ref_subtree.hg, ref_entry.sha1);
			recurse_manifest2(&ref_subtree, ref_manifest,
				          &cur_subtree, manifest, dir.buf,
			                  tree_list);
		} else
			recurse_manifest(&cur_subtree, manifest, dir.buf,
			                 tree_list);
		strbuf_release(&dir);
	}

	return;
corrupted:
	die("Corrupted metadata");
}

struct manifest {
	struct manifest_tree tree;
	struct strbuf content;
	struct object_list *tree_list;
};

#define MANIFEST_INIT { { { 0, }, { 0, } }, STRBUF_INIT, NULL }

/* For repositories with a lot of files, generating a manifest is a slow
 * operation.
 * In most cases, there are way less changes between changesets than there
 * are files in the repository, so it is much faster to generate a manifest
 * from a previously generated manifest, by applying the differences between
 * the corresponding trees.
 * Therefore, we always keep the last generated manifest.
 */
static struct manifest generated_manifest = MANIFEST_INIT;

/* The returned strbuf must not be released and/or freed. */
static struct strbuf *generate_manifest(const unsigned char *git_sha1)
{
	struct manifest_tree manifest_tree;
	struct strbuf content = STRBUF_INIT;
	struct object_list *tree_list = NULL;

	/* We keep a list of all the trees we've seen while generating the
	 * previous manifest. Each tree is marked as SEEN at that time.
	 * Then, on the next manifest generation, we unmark them as SEEN,
	 * and the generation that follows will re-mark them if they are
	 * re-used. Trees that are not marked SEEN are subsequently freed.
	 */
	struct object_list *previous_list = generated_manifest.tree_list;
	while (previous_list) {
		previous_list->item->flags &= ~SEEN;
		previous_list = previous_list->next;
	}

	if (get_manifest_tree(git_sha1, &manifest_tree, &tree_list))
		goto not_found;

	if (generated_manifest.content.len) {
		struct strslice gm = {
			generated_manifest.content.len,
			generated_manifest.content.buf
		};
		strbuf_grow(&content, generated_manifest.content.len);
		recurse_manifest2(&generated_manifest.tree, &gm,
		                  &manifest_tree, &content, "", &tree_list);
	} else {
		recurse_manifest(&manifest_tree, &content, "", &tree_list);
	}

	hashcpy(generated_manifest.tree.git, manifest_tree.git);
	hashcpy(generated_manifest.tree.hg, manifest_tree.hg);
	strbuf_swap(&content, &generated_manifest.content);
	strbuf_release(&content);

	previous_list = generated_manifest.tree_list;
	generated_manifest.tree_list = tree_list;

	while (previous_list) {
		struct object *obj = previous_list->item;
		struct object_list *elem = previous_list;
		previous_list = elem->next;
		free(elem);
		if (!obj->flags & SEEN)
			free_tree_buffer((struct tree *)obj);
	}
	return &generated_manifest.content;

not_found:
	return NULL;
}

static void do_manifest(struct string_list *args)
{
	unsigned char sha1[20];
	const unsigned char *manifest_sha1;
	struct strbuf *manifest = NULL;
	size_t sha1_len;

	if (args->nr != 1)
		goto not_found;

	sha1_len = get_abbrev_sha1_hex(args->items[0].string, sha1);
	if (!sha1_len)
		goto not_found;

	manifest_sha1 = resolve_hg2git(sha1, sha1_len);
	if (!manifest_sha1)
		goto not_found;

	manifest = generate_manifest(manifest_sha1);
	if (!manifest)
		goto not_found;

	send_buffer(manifest);
	return;

not_found:
	write_or_die(1, "0\n\n", 3);
}

static void get_manifest_sha1(const struct commit *commit, unsigned char *sha1)
{
	const char *msg;
	const char *hex_sha1;

	msg = get_commit_buffer(commit, NULL);

	hex_sha1 = strstr(msg, "\n\n") + 2;

	if (get_sha1_hex(hex_sha1, sha1))
		hashclr(sha1);

	unuse_commit_buffer(commit, msg);
}

static void do_check_manifest(struct string_list *args)
{
	unsigned char sha1[20], parent1[20], parent2[20], result[20];
	const unsigned char *manifest_sha1;
	const struct commit *manifest_commit;
	struct strbuf *manifest = NULL;
	git_SHA_CTX ctx;

	if (args->nr != 1)
		goto error;

	if (get_sha1_hex(args->items[0].string, sha1))
		goto error;

	manifest_sha1 = resolve_hg2git(sha1, 40);
	if (!manifest_sha1)
		goto error;

	manifest = generate_manifest(manifest_sha1);
	if (!manifest)
		goto error;

	manifest_commit = lookup_commit(manifest_sha1);
	if (!manifest_commit)
		goto error;

	if (manifest_commit->parents) {
		get_manifest_sha1(manifest_commit->parents->item, parent1);
		if (manifest_commit->parents->next) {
			get_manifest_sha1(manifest_commit->parents->next->item,
			                  parent2);
		} else
			hashclr(parent2);
	} else {
		hashclr(parent1);
		hashclr(parent2);
	}

	git_SHA1_Init(&ctx);

	if (hashcmp(parent1, parent2) < 0) {
		git_SHA1_Update(&ctx, parent1, sizeof(parent1));
		git_SHA1_Update(&ctx, parent2, sizeof(parent2));
	} else {
		git_SHA1_Update(&ctx, parent2, sizeof(parent2));
		git_SHA1_Update(&ctx, parent1, sizeof(parent1));
	}

	git_SHA1_Update(&ctx, manifest->buf, manifest->len);

	git_SHA1_Final(result, &ctx);

	if (hashcmp(result, sha1) == 0) {
		write(1, "ok\n", 3);
		return;
	}

error:
	write_or_die(1, "error\n", 6);
}

static void do_version(struct string_list *args)
{
	long int version;

	if (args->nr != 1)
		exit(1);

	version = strtol(args->items[0].string, NULL, 10);

	if (!version || version != CMD_VERSION)
		exit(1);

	write_or_die(1, "ok\n", 3);
}

int main(int argc, const char *argv[])
{
	struct strbuf buf = STRBUF_INIT;

	setup_git_directory();
	git_config(git_default_config, NULL);

	while (strbuf_getline(&buf, stdin) != EOF) {
		struct string_list args = STRING_LIST_INIT_NODUP;
		const char *command;
		split_command(buf.buf, &command, &args);
		if (!strcmp("git2hg", command))
			do_git2hg(&args);
		else if (!strcmp("hg2git", command))
			do_hg2git(&args);
		else if (!strcmp("manifest", command))
			do_manifest(&args);
		else if (!strcmp("check-manifest", command))
			do_check_manifest(&args);
		else if (!strcmp("cat-file", command))
			do_cat_file(&args);
		else if (!strcmp("version", command))
			do_version(&args);
		else
			die("Unknown command: \"%s\"", command);

		string_list_clear(&args, 0);
	}

	strbuf_release(&buf);

	if (git2hg.initialized)
		free_notes(&git2hg);

	if (hg2git.initialized)
		free_notes(&hg2git);

	return 0;
}
