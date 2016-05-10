#include "git-compat-util.h"
#include "hg-bundle.h"
#include <stdint.h>

static size_t copy_changegroup_chunk(FILE *in, FILE *out)
{
	unsigned char buf[4096];
	const unsigned char *p = buf;
	uint32_t len;
	size_t ret = 0;
	//TODO: Check for errors, etc.
	fread(buf, 1, 4, in);
	fwrite(buf, 1, 4, out);
	len = get_be32(p);
	if (len <= 4)
		//TODO: len != 0 is actually invalid
		return 0;
	ret = len -= 4;
	while (len) {
		uint32_t sz = len > sizeof(buf) ? sizeof(buf) : len;
		fread(buf, 1, sz, in);
		fwrite(buf, 1, sz, out);
		len -= sz;
	}
	return ret;
}

void copy_changegroup(FILE *in, FILE *out)
{
	/* changesets */
	while (copy_changegroup_chunk(in, out)) {}
	/* manifests */
	while (copy_changegroup_chunk(in, out)) {}
	/* files */
	while (copy_changegroup_chunk(in, out)) {
		while (copy_changegroup_chunk(in, out)) {}
	}
}
