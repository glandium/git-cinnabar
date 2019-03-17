#include "cache.h"
#include "thread-utils.h"
#include "cinnabar-util.h"

#ifdef NO_CURL
size_t fwrite_buffer(char *ptr, size_t size, size_t nmemb, void *buffer_)
{
	size_t size = size * nmemb;
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
	/* List of buffers of fixed size. */
	char **buffers;
	size_t nr_buffers;
	size_t alloc_buffers;
	/* Location where to append data to. */
	char *append;
	/* Amount we can append. Storing more data would require using a new
	 *buffer. */
	size_t left;
	/* Amount of data buffered in total */
	size_t buffered;
	/* Offset in buffers[0] where buffered data starts. */
	size_t offset;
	/* Whether the buffered writer was closed by the caller, meaning
	 * nothing more will be written (and thus the background thread
	 * doesn't have to wait for more data anymore). */
	int closed;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t thread;
	struct writer out;
};

static void create_buffer(struct buffered_context *context) {
	ALLOC_GROW(context->buffers, context->nr_buffers + 1, context->alloc_buffers);
	context->buffers[context->nr_buffers] = xmalloc(BUFFER_SIZE);
	context->append = context->buffers[context->nr_buffers++];
	context->left = BUFFER_SIZE;
}

static size_t buffered_write(char *ptr, size_t size, size_t nmemb, void *context_)
{
	struct buffered_context *context = context_;
	size_t len = size * nmemb;
	do {
		size_t fill = len > context->left ? context->left : len;
		memcpy(context->append, ptr, fill);
		ptr += fill;
		len -= fill;
		pthread_mutex_lock(&context->mutex);
		if (fill == context->left) {
			create_buffer(context);
		} else {
			context->append += fill;
			context->left -= fill;
		}
		context->buffered += fill;
		pthread_cond_signal(&context->cond);
		pthread_mutex_unlock(&context->mutex);
	} while (len);
	return size * nmemb;
}

static int buffered_close(void *context_)
{
	struct buffered_context *context = context_;
	int ret, i;
	pthread_mutex_lock(&context->mutex);
	context->closed = 1;
	pthread_cond_signal(&context->cond);
	pthread_mutex_unlock(&context->mutex);
	pthread_join(context->thread, NULL);
	ret = writer_close(&context->out);
	pthread_cond_destroy(&context->cond);
	pthread_mutex_destroy(&context->mutex);
	for (i = 0; i < context->nr_buffers; i++)
		free(context->buffers[0]);
	free(context->buffers);
	free(context);
	return ret;
}

void *buffered_thread(void *context_)
{
	struct buffered_context *context = context_;
	size_t fill, left, offset;
	int free_buf;
	char *buf;
	pthread_mutex_lock(&context->mutex);
	while (!context->closed || context->buffered) {
		if (!context->buffered)
			pthread_cond_wait(&context->cond, &context->mutex);
		offset = context->offset;
		/* Maximum amount of data we can read from buffers[0]. */
		left = BUFFER_SIZE - offset;
		/* Amount of data actually available from buffers[0]. */
		fill = context->buffered > left ? left : context->buffered;
		/* Pop the first buffer if it's full, otherwise keep it in
		 * place for context->append, and adjust the offset for next
		 * round. */
		buf = context->buffers[0];
		if (fill == left) {
			memmove(context->buffers, context->buffers + 1,
			        (--context->nr_buffers) * sizeof(char *));
			context->offset = 0;
		} else
			context->offset += fill;
		context->buffered -= fill;
		/* We'll free the buffer if it was full. */
		free_buf = (fill == left);
		/* We can perform the possibly blocking write and the buffer
		 * freeing without locking because it's not shared state with
		 * the other thread anymore. */
		pthread_mutex_unlock(&context->mutex);
		write_to(buf + offset, 1, fill, &context->out);
		if (free_buf)
			free(buf);
		pthread_mutex_lock(&context->mutex);
		/* If while we were writing, the other thread didn't write more
		 * data, and we've writted out everything, and there's possibly
		 * more data incoming, make the data go at the beginning of the
		 * first buffer, rather than wherever we were at. */
		if (!context->buffered && !context->closed) {
			context->append = context->buffers[0];
			context->left = BUFFER_SIZE;
			context->offset = 0;
		}
	}
	pthread_mutex_unlock(&context->mutex);
	return NULL;
}

void bufferize_writer(struct writer *writer)
{
	if (HAVE_THREADS) {
		struct buffered_context *context = xcalloc(1, sizeof(struct buffered_context));
		create_buffer(context);
		pthread_mutex_init(&context->mutex, NULL);
		pthread_cond_init(&context->cond, NULL);
		context->out = *writer;
		if (pthread_create(&context->thread, NULL, buffered_thread, context)) {
			free(context);
			return;
		}
		writer->write = buffered_write;
		writer->close = buffered_close;
		writer->context = context;
	}
}
