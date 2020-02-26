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
