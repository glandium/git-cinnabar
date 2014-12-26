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
 */

#include <stdio.h>
#include <string.h>

#include "cache.h"
#include "strbuf.h"
#include "string-list.h"
#include "notes.h"
#include "streaming.h"
#include "object.h"

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

static void do_hg2git(struct string_list *command) {
	unsigned char sha1[20];
	const unsigned char *note;

	if (command->nr != 2)
		goto not_found;

	if (!hg2git.initialized)
		init_notes(&hg2git, REFS_PREFIX "hg2git",
			combine_notes_overwrite, 0);

	if (get_sha1_hex(command->items[1].string, sha1))
		goto not_found;

	note = get_note(&hg2git, sha1);
	if (note) {
		write_or_die(1, sha1_to_hex(note), 40);
		write_or_die(1, "\n", 1);
		return;
	}

not_found:
	write_or_die(1, NULL_NODE, 40);
	write_or_die(1, "\n", 1);
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
