#include "git-compat-util.h"
#include "cache.h"
#include "cinnabar-helper.h"
#include "cinnabar-fast-import.h"
#include "hg-data.h"

static const unsigned char empty_hg_file[20] = {
	0xb8, 0x0d, 0xe5, 0xd1, 0x38, 0x75, 0x85, 0x41, 0xc5, 0xf0,
	0x52, 0x65, 0xad, 0x14, 0x4a, 0xb9, 0xfa, 0x86, 0xd1, 0xdb,
};

int is_empty_hg_file(const unsigned char *sha1)
{
	return hashcmp(empty_hg_file, sha1) == 0;
}

void _hg_file_split(struct hg_file *result, size_t metadata_len)
{
	result->metadata.buf = metadata_len ? result->file.buf + 2 : NULL;
	result->metadata.len = metadata_len - 4;
	result->content.buf = result->file.buf + metadata_len;
	result->content.len = result->file.len - metadata_len;
}

void hg_file_load(struct hg_file *result, const unsigned char *sha1)
{
	const unsigned char *note;
	char *content;
	enum object_type type;
	unsigned long len;
	size_t metadata_len;

	strbuf_release(&result->file);
	hashcpy(result->sha1, sha1);

	if (is_empty_hg_file(sha1))
		return;

	ensure_notes(&files_meta);
	note = get_note(&files_meta, sha1);
	if (note) {
		content = read_sha1_file_extended(note, &type, &len, 0);
		strbuf_add(&result->file, "\1\n", 2);
		strbuf_add(&result->file, content, len);
		strbuf_add(&result->file, "\1\n", 2);
		free(content);
	}

	metadata_len = result->file.len;

	ensure_notes(&hg2git);
	note = get_note(&hg2git, sha1);
	if (!note)
		die("Missing data");

	content = read_sha1_file_extended(note, &type, &len, 0);
	strbuf_add(&result->file, content, len);
	free(content);

	// Note this duplicates work read_sha1_file already did.
	result->content_oe = get_object_entry((unsigned char*) note);

	_hg_file_split(result, metadata_len);
}

void hg_file_from_memory(struct hg_file *result,
                         const unsigned char *sha1, struct strbuf *buf)
{
	size_t metadata_len = 0;

	strbuf_swap(&result->file, buf);
	hashcpy(result->sha1, sha1);
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
	hashcpy(file->sha1, null_sha1);
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
