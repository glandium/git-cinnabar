#include "cache.h"
#include "cinnabar-util.h"

size_t write_to_strbuf(char *buf, size_t size, size_t nmemb, void *context)
{
	struct strbuf *out = (struct strbuf *) context;
	size_t len = size * nmemb;
	strbuf_add(out, buf, len);
	return len;
}

size_t write_to_file(char *buf, size_t size, size_t nmemb, void *context)
{
	FILE *out = (FILE *) context;
	return fwrite(buf, size, nmemb, out);
}

size_t copy_to(FILE *in, size_t len, struct writer *writer)
{
	char buf[4096];
	size_t ret = len;
	while (len) {
		uint32_t sz = len > sizeof(buf) ? sizeof(buf) : len;
		fread(buf, 1, sz, in);
		len -= write_to(buf, 1, sz, writer);
	}
	return ret;
}
