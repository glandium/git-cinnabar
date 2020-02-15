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

#define BUFFER_SIZE (1024 * 1024)

struct buffered_context {
	/* List of buffers of fixed size. */
	char **buffers;
	size_t nr_buffers;
	size_t alloc_buffers;
	/* Location where to append data to. */
	struct strslice append_buf;
	/* (Unwritten out) buffered data in buffers[0] */
	struct strslice buffered;
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
	context->append_buf.buf = context->buffers[context->nr_buffers++];
	context->append_buf.len = BUFFER_SIZE;
}

static size_t buffered_write(char *ptr, size_t size, size_t nmemb, void *context_)
{
	struct buffered_context *context = context_;
	struct strslice in = { size * nmemb, ptr };
	do {
		struct strslice in_slice =
			strslice_slice(in, 0, context->append_buf.len);
		in = strslice_slice(in, in_slice.len, SIZE_MAX);
		memcpy((void *)context->append_buf.buf, in_slice.buf, in_slice.len);
		pthread_mutex_lock(&context->mutex);
		/* strslice_slice would set buf to strbuf_slop */
		context->append_buf.buf += in_slice.len;
		context->append_buf.len -= in_slice.len;
		if (context->nr_buffers == 1)
			context->buffered.len += in_slice.len;
		pthread_cond_signal(&context->cond);
		if (context->append_buf.len == 0)
			create_buffer(context);
		pthread_mutex_unlock(&context->mutex);
	} while (in.len);
	return nmemb;
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
		free(context->buffers[i]);
	free(context->buffers);
	free(context);
	return ret;
}

void *buffered_thread(void *context_)
{
	struct buffered_context *context = context_;
	pthread_mutex_lock(&context->mutex);
	while (!context->closed || context->buffered.len || context->nr_buffers > 1) {
		if (!context->buffered.len)
			pthread_cond_wait(&context->cond, &context->mutex);
		struct strslice out_slice = context->buffered;
		/* strslice_slice would set buf to strbuf_slop */
		context->buffered.buf += context->buffered.len;
		context->buffered.len = 0;
		/* We can perform the possibly blocking write and the buffer
		 * freeing without locking because it's not shared state with
		 * the other thread anymore. */
		pthread_mutex_unlock(&context->mutex);
		write_to((void*)out_slice.buf, 1, out_slice.len, &context->out);
		pthread_mutex_lock(&context->mutex);
		/* If buffers[0] was emptied out, and there are more buffers,
		 * free that first buffer and shift everything. */
		if (!context->buffered.len && context->nr_buffers > 1) {
			free(context->buffers[0]);
			memmove(context->buffers, context->buffers + 1,
			        (--context->nr_buffers) * sizeof(char *));
			context->buffered.buf = context->buffers[0];
			if (context->nr_buffers == 1)
				context->buffered.len =
					context->append_buf.buf - context->buffered.buf;
			else
				context->buffered.len = BUFFER_SIZE;
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
		context->buffered.buf = context->buffers[0];
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

struct inflate_context {
	struct writer out;
	git_zstream strm;
};

static size_t inflate_to(char *ptr, size_t size, size_t nmemb, void *data)
{
	char buf[4096];
	struct inflate_context *context = data;
	int ret;

	context->strm.next_in = (void *)ptr;
	context->strm.avail_in = size * nmemb;

	do {
		context->strm.next_out = (void *)buf;
		context->strm.avail_out = sizeof(buf);
		ret = git_inflate(&context->strm, Z_SYNC_FLUSH);
		write_to(buf, 1, sizeof(buf) - context->strm.avail_out, &context->out);
	} while (context->strm.avail_in && ret == Z_OK);

	return nmemb;
}

static int inflate_close(void *data)
{
	struct inflate_context *context = data;
	int ret;
	git_inflate_end(&context->strm);
	ret = writer_close(&context->out);
	free(context);
	return ret;
}

void inflate_writer(struct writer *writer) {
	struct inflate_context *context = xcalloc(1, sizeof(struct inflate_context));
	git_inflate_init(&context->strm);
	context->out = *writer;
	writer->write = inflate_to;
	writer->close = inflate_close;
	writer->context = context;
}

struct pipe_context {
	struct child_process proc;
	FILE *pipe;
};

static size_t pipe_write(char *ptr, size_t size, size_t nmemb, void *data)
{
	struct pipe_context *context = data;
	return fwrite(ptr, size, nmemb, context->pipe);
}

static int pipe_close(void *data)
{
	struct pipe_context *context = data;
	int ret;
	fclose(context->pipe);
	close(context->proc.in);
	ret = finish_command(&context->proc);
	free(context);
	return ret;
}

void pipe_writer(struct writer *writer, const char **argv) {
	struct pipe_context *context = xcalloc(1, sizeof(struct pipe_context));

	if (writer->write != (write_callback)fwrite &&
	    writer->close != (close_callback)fflush)
		die("pipe_writer can only redirect an fwrite writer");

	writer_close(writer);
	child_process_init(&context->proc);
	context->proc.argv = argv;
	context->proc.in = -1;
	context->proc.out = fileno((FILE*)writer->context);
	context->proc.no_stderr = 1;
	start_command(&context->proc);
	context->pipe = xfdopen(context->proc.in, "w");
	writer->write = pipe_write;
	writer->close = pipe_close;
	writer->context = context;
}

struct prefix_context {
	struct writer out;
	size_t prefix_len;
	struct strbuf buf;
};

static size_t prefix_write(char *ptr, size_t size, size_t nmemb, void *data)
{
	struct prefix_context *context = data;
	size_t len = size * nmemb;
	struct strslice slice = { len, ptr };
	for (;;) {
		struct strslice line = strslice_split_once(&slice, '\n');
		strbuf_addslice(&context->buf, line);
		if (slice.len != len) {
			strbuf_addch(&context->buf, '\n');
			write_to(context->buf.buf, 1, context->buf.len,
			         &context->out);
			strbuf_setlen(&context->buf, context->prefix_len);
			len = slice.len;
		} else {
			break;
		}
	}
	strbuf_addslice(&context->buf, slice);
	return size * nmemb;
}

static int prefix_close(void *data)
{
	struct prefix_context *context = data;
	int ret;
	if (context->buf.len > context->prefix_len)
		write_to(context->buf.buf, 1, context->buf.len, &context->out);
	strbuf_release(&context->buf);
	ret = writer_close(&context->out);
	free(context);
	return ret;
}

void prefix_writer(struct writer *writer, const char *prefix)
{
	struct prefix_context *context = xcalloc(1, sizeof(struct prefix_context));
	context->out = *writer;
	strbuf_init(&context->buf, 0);
	strbuf_addstr(&context->buf, prefix);
	context->prefix_len = context->buf.len;
	writer->write = prefix_write;
	writer->close = prefix_close;
	writer->context = context;
}
