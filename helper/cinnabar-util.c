#include "cache.h"
#include "cinnabar-util.h"

#ifdef NO_CURL
size_t fwrite_buffer(char *ptr, size_t eltsize, size_t nmemb, void *buffer_)
{
	size_t size = eltsize * nmemb;
	struct strbuf *buffer = buffer_;

	strbuf_add(buffer, ptr, size);
	return size;
}
#endif

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
