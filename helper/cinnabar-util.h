#ifndef CINNABAR_UTILS_H
#define CINNABAR_UTILS_H

#include <stdio.h>
#include "strbuf.h"

struct writer {
	size_t (*write)(char *buf, size_t size, size_t nmemb, void *context);
	void *context;
};

extern size_t write_to_strbuf(char *buf, size_t size, size_t nmemb, void *context);

extern size_t write_to_file(char *buf, size_t size, size_t nmemb, void *context);

static inline
size_t write_to(char *buf, size_t size, size_t nmemb, struct writer *writer)
{
	return writer->write(buf, size, nmemb, writer->context);
}

extern size_t copy_to(FILE *in, size_t len, struct writer *writer);

#endif
