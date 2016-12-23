#ifndef BUNDLE_H
#define BUNDLE_H

#include "strbuf.h"
#include <stdio.h>

struct bundle_writer {
	union {
		FILE *file;
		struct strbuf *buf;
	} out;
	int type;
};

#define WRITER_FILE 1
#define WRITER_STRBUF 2

extern size_t write_data(const unsigned char *buf, size_t size,
			 struct bundle_writer *out);
extern size_t copy_data(size_t len, FILE *in, struct bundle_writer *out);

extern void copy_bundle(FILE *in, FILE *out);
extern void copy_bundle_to_strbuf(FILE *in, struct strbuf *out);

#endif
