#include "cache.h"
#include "run-command.h"
#include "strslice.h"
#include "thread-utils.h"
#include "http.h"
#include "cinnabar-util.h"

FILE *get_stderr() {
	return stderr;
}

size_t write_to(char *buf, size_t size, size_t nmemb, struct writer *writer)
{
	return writer->write(buf, size, nmemb, writer->context);
}

int writer_close(struct writer* writer)
{
	if (writer->close)
		return writer->close(writer->context);
	return 0;
}

size_t copy_to(FILE *in, size_t len, struct writer *writer)
{
	char buf[4096];
	size_t ret = len;
	while (len) {
		size_t sz = len > sizeof(buf) ? sizeof(buf) : len;
		size_t sz_read = fread(buf, 1, sz, in);
		if (sz_read < sz)
			return ret - len + sz_read;
		len -= write_to(buf, 1, sz, writer);
	}
	return ret;
}
