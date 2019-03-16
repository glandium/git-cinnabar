#ifndef CINNABAR_UTILS_H
#define CINNABAR_UTILS_H

#include <stdio.h>
#include "strbuf.h"

typedef size_t (*write_callback)(char *ptr, size_t eltsize, size_t nmemb, void *context);

#ifdef NO_CURL
extern size_t fwrite_buffer(char *ptr, size_t eltsize, size_t nmemb, void *strbuf);
#endif

struct writer {
	write_callback write;
	void *context;
};

static inline
size_t write_to(char *buf, size_t size, size_t nmemb, struct writer *writer)
{
	return writer->write(buf, size, nmemb, writer->context);
}

extern size_t copy_to(FILE *in, size_t len, struct writer *writer);

#endif
