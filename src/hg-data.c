/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "git-compat-util.h"
#include "object-store.h"
#include "cinnabar-helper.h"
#include "cinnabar-notes.h"
#include "cinnabar-fast-import.h"
#include "hg-data.h"

static const struct hg_object_id empty_hg_file = {{
	0xb8, 0x0d, 0xe5, 0xd1, 0x38, 0x75, 0x85, 0x41, 0xc5, 0xf0,
	0x52, 0x65, 0xad, 0x14, 0x4a, 0xb9, 0xfa, 0x86, 0xd1, 0xdb,
}};

const struct hg_object_id hg_null_oid = {{ 0, }};

int is_null_hg_oid(const struct hg_object_id *oid)
{
	return hg_oideq(&hg_null_oid, oid);
}

int is_empty_hg_file(const struct hg_object_id *oid)
{
	return hg_oideq(&empty_hg_file, oid);
}

static void _hg_file_split(struct hg_file *result, size_t metadata_len)
{
	result->metadata.buf = metadata_len ? result->file.buf + 2 : NULL;
	result->metadata.len = metadata_len - 4;
	result->content.buf = result->file.buf + metadata_len;
	result->content.len = result->file.len - metadata_len;
}

void hg_file_load(struct hg_file *result, const struct hg_object_id *oid)
{
	const struct object_id *note;
	struct object_info oi = OBJECT_INFO_INIT;
	char *content;
	enum object_type type;
	unsigned long len;
	size_t metadata_len;

	oi.typep = &type;
	oi.sizep = &len;
	oi.contentp = (void **) &content;

	strbuf_release(&result->file);
	hg_oidcpy(&result->oid, oid);

	if (is_empty_hg_file(oid))
		return;

	ensure_notes(&files_meta);
	note = get_note_hg(&files_meta, oid);
	if (note) {
		if (oid_object_info_extended(
				the_repository, note, &oi,
				OBJECT_INFO_DIE_IF_CORRUPT) != 0)
			die("Missing data");
		strbuf_add(&result->file, "\1\n", 2);
		strbuf_add(&result->file, content, len);
		strbuf_add(&result->file, "\1\n", 2);
		free(content);
	}

	metadata_len = result->file.len;

	note = resolve_hg2git(oid);
	if (!note)
		die("Missing data");

	if (oid_object_info_extended(
			the_repository, note, &oi,
			OBJECT_INFO_DIE_IF_CORRUPT) != 0)
		die("Missing data");

	strbuf_add(&result->file, content, len);
	free(content);

	// Note this duplicates work read_object_file already did.
	result->content_oe = get_object_entry(note->hash);

	_hg_file_split(result, metadata_len);
}

void hg_file_from_memory(struct hg_file *result,
                         const struct hg_object_id *oid, struct strbuf *buf)
{
	size_t metadata_len = 0;

	strbuf_swap(&result->file, buf);
	hg_oidcpy(&result->oid, oid);
	result->content_oe = NULL;

	if (result->file.len > 4 && memcmp(result->file.buf, "\1\n", 2) == 0) {
		char *metadata_end = strstr(result->file.buf + 2, "\1\n");
		if (metadata_end)
			metadata_len = metadata_end + 2 - result->file.buf;
	}

	_hg_file_split(result, metadata_len);
}

void hg_file_init(struct hg_file *file)
{
	hg_oidclr(&file->oid);
	strbuf_init(&file->file, 0);
	file->metadata.buf = NULL;
	file->metadata.len = 0;
	strbuf_init(&file->content, 0);
	file->content_oe = NULL;
}

void hg_file_release(struct hg_file *file)
{
	strbuf_release(&file->file);
	hg_file_init(file);
}

int remove_note_hg(struct notes_tree *notes,
                   const struct hg_object_id *oid)
{
	struct object_id git_oid;
	hg_oidcpy2git(&git_oid, oid);
	return cinnabar_remove_note(notes, git_oid.hash);
}
