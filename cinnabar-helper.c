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
 * - cat-file <object>
 *     Returns the contents of the given git object, in a `cat-file
 *     --batch`-like format.
 */

#include <stdio.h>
#include <string.h>

#include "cache.h"
#include "strbuf.h"
#include "string-list.h"
#include "notes.h"
#include "streaming.h"
#include "object.h"
#include "tree.h"
#include "tree-walk.h"

#define REFS_PREFIX "refs/cinnabar/"
#define NOTES_REF "refs/notes/cinnabar"

static const char NULL_NODE[] = "0000000000000000000000000000000000000000";
static const unsigned char NULL_NODE_SHA1[20] = { 0, };

static struct notes_tree git2hg, hg2git;

/* Send git object info and content to stdout, like cat-file --batch does. */
static void send_object(unsigned const char *sha1) {
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

static void do_cat_file(struct string_list *command) {
	unsigned char sha1[20];

	if (command->nr != 2)
		goto not_found;

	if (get_sha1(command->items[1].string, sha1))
		goto not_found;

	send_object(sha1);
	return;

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

static void do_git2hg(struct string_list *command) {
	unsigned char sha1[20];
	const unsigned char *note;

	if (command->nr != 2)
		goto not_found;

	if (!git2hg.initialized)
		init_notes(&git2hg, NOTES_REF, combine_notes_overwrite, 0);

	if (get_sha1_committish(command->items[1].string, sha1))
		goto not_found;

	note = get_note(&git2hg, sha1);
	if (!note)
		goto not_found;

	send_object(note);
	return;

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
}

static const unsigned char *resolve_hg2git(const unsigned char *sha1) {
	if (!hg2git.initialized)
		init_notes(&hg2git, REFS_PREFIX "hg2git",
		           combine_notes_overwrite, 0);

	return get_note(&hg2git, sha1);
}

static void do_hg2git(struct string_list *command) {
	unsigned char sha1[20];
	const unsigned char *note;

	if (command->nr != 2)
		goto not_found;

	if (get_sha1_hex(command->items[1].string, sha1))
		goto not_found;

	note = resolve_hg2git(sha1);
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
static const char *hgattr(unsigned int mode) {
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
 * - a git directory, matching the git tree in git commit * corresponding to
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
static void recurse_manifest(const unsigned char *sha1_git,
                             const unsigned char *sha1_hg,
                             struct strbuf *manifest, char *base) {
	struct tree *tree_git = NULL, *tree_hg = NULL;
	struct tree_desc desc_git, desc_hg;
	struct name_entry entry_git, entry_hg;

	tree_git = parse_tree_indirect(sha1_git);
	if (!tree_git)
		goto corrupted;
	tree_hg = parse_tree_indirect(sha1_hg);
	if (!tree_hg)
		goto corrupted;
	init_tree_desc(&desc_git, tree_git->buffer, tree_git->size);
	init_tree_desc(&desc_hg, tree_hg->buffer, tree_hg->size);

	while (tree_entry(&desc_git, &entry_git)) {
		if (!tree_entry(&desc_hg, &entry_hg))
			goto corrupted;

		if (S_ISDIR(entry_git.mode)) {
			struct strbuf dir = STRBUF_INIT;
			if (!S_ISDIR(entry_hg.mode))
				goto corrupted;
			strbuf_addstr(&dir, base);
			strbuf_addstr(&dir, entry_git.path);
			strbuf_addch(&dir, '/');
			recurse_manifest(entry_git.sha1, entry_hg.sha1,
			                 manifest, dir.buf);
			strbuf_release(&dir);
			continue;
		}
		strbuf_addf(manifest, "%s%s%c%s%s\n", base, entry_git.path,
		            '\0', sha1_to_hex(entry_hg.sha1),
		            hgattr(entry_git.mode));
	}
	if (tree_entry(&desc_hg, &entry_hg))
		goto corrupted;

	free_tree_buffer(tree_hg);
	free_tree_buffer(tree_git);
	return;
corrupted:
	die("Corrupted metadata");
}

static void do_manifest(struct string_list *command) {
	unsigned char sha1[20];
	const unsigned char *tree_sha1;
	unsigned char sha1_git[20], sha1_hg[20];
	struct tree_desc desc;
	struct name_entry entry;
	struct tree *manifest_tree = NULL;
	struct strbuf manifest = STRBUF_INIT;
	struct strbuf header = STRBUF_INIT;

	if (command->nr != 2)
		goto not_found;

	if (get_sha1_hex(command->items[1].string, sha1))
		goto not_found;

	tree_sha1 = resolve_hg2git(sha1);
	if (!tree_sha1)
		goto not_found;

	manifest_tree = parse_tree_indirect(tree_sha1);
	if (!manifest_tree)
		goto not_found;

	init_tree_desc(&desc, manifest_tree->buffer, manifest_tree->size);
	/* The first entry in the manifest tree is the git subtree. */
	if (!tree_entry(&desc, &entry))
		goto not_found;
	if (strcmp(entry.path, "git"))
		goto not_found;
	memcpy(sha1_git, entry.sha1, 20);

	/* The second entry in the manifest tree is the hg subtree. */
	if (!tree_entry(&desc, &entry))
		goto not_found;
	if (strcmp(entry.path, "hg"))
		goto not_found;
	memcpy(sha1_hg, entry.sha1, 20);

	/* There shouldn't be any other entry. */
	if (tree_entry(&desc, &entry))
		goto not_found;

	recurse_manifest(sha1_git, sha1_hg, &manifest, "");

not_found:
	if (manifest_tree)
		free_tree_buffer(manifest_tree);

	strbuf_addf(&header, "%lu\n", manifest.len);

	write_or_die(1, header.buf, header.len);

	strbuf_release(&header);

	write_or_die(1, manifest.buf, manifest.len);
	write_or_die(1, "\n", 1);

	strbuf_release(&manifest);
}

int main(int argc, const char *argv[]) {
	struct strbuf buf = STRBUF_INIT;

	while (strbuf_getline(&buf, stdin, '\n') != EOF) {
		struct string_list command = STRING_LIST_INIT_NODUP;
		string_list_split_in_place(&command, buf.buf, ' ', -1);
		if (!strcmp("git2hg", command.items[0].string))
			do_git2hg(&command);
		else if (!strcmp("hg2git", command.items[0].string))
			do_hg2git(&command);
		else if (!strcmp("manifest", command.items[0].string))
			do_manifest(&command);
		else if (!strcmp("cat-file", command.items[0].string))
			do_cat_file(&command);
		else
			die("Unknown command: \"%s\"", command.items[0].string);

		string_list_clear(&command, 0);
	}

	strbuf_release(&buf);

	if (git2hg.initialized)
		free_notes(&git2hg);

	if (hg2git.initialized)
		free_notes(&hg2git);

	return 0;
}
