#include "git-compat-util.h"
#include "hg-bundle.h"
#include <stdint.h>

static size_t copy_data(uint32_t len, FILE *in, FILE *out)
{
	unsigned char buf[4096];
	size_t ret = len;
	while (len) {
		uint32_t sz = len > sizeof(buf) ? sizeof(buf) : len;
		fread(buf, 1, sz, in);
		fwrite(buf, 1, sz, out);
		len -= sz;
	}
	return ret;
}

static size_t copy_chunk(int adjust, FILE *in, FILE *out)
{
	unsigned char buf[4];
	const unsigned char *p = buf;
	uint32_t len;
	size_t ret = 0;
	//TODO: Check for errors, etc.
	fread(buf, 1, 4, in);
	fwrite(buf, 1, 4, out);
	len = get_be32(p);
	if (len <= adjust)
		//TODO: len != 0 is actually invalid
		return 0;
	ret = len -= adjust;
	copy_data(len, in, out);
	return ret;
}

static size_t copy_changegroup_chunk(FILE *in, FILE *out)
{
	return copy_chunk(4, in, out);
}

static void copy_changegroup(FILE *in, FILE *out)
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

static size_t copy_bundle2_chunk(FILE *in, FILE *out)
{
	return copy_chunk(0, in, out);
}

void copy_bundle(FILE *in, FILE *out)
{
	unsigned char buf[4];
	const unsigned char *p = buf;
	//TODO: Check for errors, etc.
	fread(buf, 1, 4, in);
	fwrite(buf, 1, 4, out);
	if (memcmp(buf, "HG20", 4)) {
		copy_data(get_be32(p) - 4, in, out);
		copy_changegroup(in, out);
		return;
	}
	// bundle2 parameters
	copy_bundle2_chunk(in, out);
	// bundle2 parts
	while (copy_bundle2_chunk(in, out)) {
		while (copy_bundle2_chunk(in, out)) {}
	}
}
