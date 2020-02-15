#ifndef CINNABAR_UTILS_H
#define CINNABAR_UTILS_H

#include <stdio.h>
#include "strbuf.h"

typedef size_t (*write_callback)(char *ptr, size_t size, size_t nmemb, void *context);
typedef int (*close_callback)(void *context);

struct writer {
	write_callback write;
	close_callback close;
	void *context;
};

size_t write_to(char *buf, size_t size, size_t nmemb, struct writer *writer);

int writer_close(struct writer* writer);

size_t copy_to(FILE *in, size_t len, struct writer *writer);

void bufferize_writer(struct writer *writer);

void inflate_writer(struct writer *writer);

void pipe_writer(struct writer *writer, const char **argv);

void prefix_writer(struct writer *writer, const char *prefix);

#endif
