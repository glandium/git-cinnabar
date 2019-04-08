#ifndef CINNABAR_UTILS_H
#define CINNABAR_UTILS_H

#include <stdio.h>
#include "strbuf.h"

typedef size_t (*write_callback)(char *ptr, size_t size, size_t nmemb, void *context);
typedef int (*close_callback)(void *context);

#ifdef NO_CURL
extern size_t fwrite_buffer(char *ptr, size_t size, size_t nmemb, void *strbuf);
#endif

struct writer {
	write_callback write;
	close_callback close;
	void *context;
};

static inline
size_t write_to(char *buf, size_t size, size_t nmemb, struct writer *writer)
{
	return writer->write(buf, size, nmemb, writer->context);
}

static inline
int writer_close(struct writer* writer)
{
	if (writer->close)
		return writer->close(writer->context);
	return 0;
}

extern size_t copy_to(FILE *in, size_t len, struct writer *writer);

extern void bufferize_writer(struct writer *writer);

extern void inflate_writer(struct writer *writer);

extern void pipe_writer(struct writer *writer, const char **argv);

#endif
