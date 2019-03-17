#include "cache.h"
#include "thread-utils.h"
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

#define BUFFER_SIZE (1024 * 1024)

struct buffered_context {
	char *current_buf;
	size_t left;
	char **buffers;
	size_t nr_buffers;
	size_t alloc_buffers;
	size_t buffered;
	struct writer out;
};

static void create_buffer(struct buffered_context *context) {
	ALLOC_GROW(context->buffers, context->nr_buffers + 1, context->alloc_buffers);
	context->buffers[context->nr_buffers] = xmalloc(BUFFER_SIZE);
	context->current_buf = context->buffers[context->nr_buffers++];
	context->left = BUFFER_SIZE;
}

static size_t buffered_write(char *ptr, size_t eltsize, size_t nmemb, void *context_)
{
	struct buffered_context *context = context_;
	size_t len = eltsize * nmemb;
	do {
		size_t fill = len > context->left ? context->left : len;
		memcpy(context->current_buf, ptr, fill);
		ptr += fill;
		len -= fill;
		if (fill == context->left) {
			create_buffer(context);
		} else {
			context->current_buf += fill;
			context->left -= fill;
		}
		context->buffered += fill;
	} while (len);
	return eltsize * nmemb;
}

static int buffered_close(void *context_)
{
	struct buffered_context *context = context_;
	size_t i;
	int ret;
	for (i = 0; context->buffered; i++) {
		size_t fill = context->buffered > BUFFER_SIZE ?
			BUFFER_SIZE : context->buffered;
		write_to(context->buffers[i], 1, fill, &context->out);
		free(context->buffers[i]);
		context->buffered -= fill;
	}
	ret = writer_close(&context->out);
	free(context->buffers);
	free(context);
	return ret;
}

void bufferize_writer(struct writer *writer)
{
	if (HAVE_THREADS) {
		struct buffered_context *context = xcalloc(1, sizeof(struct buffered_context));
		create_buffer(context);
		context->out = *writer;
		writer->write = buffered_write;
		writer->close = buffered_close;
		writer->context = context;
	}
}
