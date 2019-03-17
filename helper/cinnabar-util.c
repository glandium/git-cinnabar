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
#else
#include "http.h"
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

struct buffered_context {
	struct strbuf buf;
	struct writer out;
};

static size_t buffered_write(char *ptr, size_t eltsize, size_t nmemb, void *context_)
{
	struct buffered_context *context = context_;
	return fwrite_buffer(ptr, eltsize, nmemb, &context->buf);
}

static int buffered_close(void *context_)
{
	struct buffered_context *context = context_;
	int ret;
	write_to(context->buf.buf, 1, context->buf.len, &context->out);
	ret = writer_close(&context->out);
	free(context);
	return ret;
}

void bufferize_writer(struct writer *writer)
{
	struct buffered_context *context = xmalloc(sizeof(struct buffered_context));
	strbuf_init(&context->buf, 1024 * 1024);
	context->out = *writer;
	writer->write = buffered_write;
	writer->close = buffered_close;
	writer->context = context;
}
