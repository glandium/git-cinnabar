#ifndef STRSLICE_H
#define STRSLICE_H

#include <string.h>
#include "strbuf.h"

struct strslice {
	size_t len;
	const char *buf;
};


static inline
struct strslice strslice_slice(struct strslice slice, size_t start, size_t len)
{
	struct strslice result;
	if (start >= slice.len)
		len = 0;
	else if (slice.len - start < len)
		len = slice.len - start;
	result.len = len;
	result.buf = len ? slice.buf + start : strbuf_slopbuf;
	return result;
}

static inline struct strslice strbuf_slice(const struct strbuf *buf,
                                           size_t start, size_t len)
{
	struct strslice slice;
	slice.buf = buf->buf;
	slice.len = buf->len;
	return strslice_slice(slice, start, len);
}

static inline size_t strslice_index(struct strslice slice, int c)
{
	const char *needle = memchr(slice.buf, c, slice.len);
	return needle ? needle - slice.buf : SIZE_MAX;
}

static inline size_t strslice_rindex(struct strslice slice, int c)
{
	size_t i;
	for (i = slice.len; i;) {
		if (slice.buf[--i] == c)
			return i;
	}
	return SIZE_MAX;
}

static inline
struct strslice strslice_split_at(struct strslice *slice, size_t off)
{
	struct strslice result;
	result = strslice_slice(*slice, 0, off == SIZE_MAX ? 0 : off);
	*slice = strslice_slice(*slice, result.len ? result.len + 1 : 0,
	                        SIZE_MAX);
	return result;
}

static inline
struct strslice strslice_split_index(struct strslice *slice, int c)
{
	return strslice_split_at(slice, strslice_index(*slice, c));
}

static inline
struct strslice strslice_split_rindex(struct strslice *slice, int c)
{
	return strslice_split_at(slice, strslice_rindex(*slice, c));
}

static inline int strslice_cmp(const struct strslice a,
                               const struct strslice b)
{
	size_t len = a.len < b.len ? a.len : b.len;
	int cmp = memcmp(a.buf, b.buf, len);
	if (cmp)
		return cmp;
	return a.len < b.len ? -1 : a.len != b.len;
}

static inline int strslice_startswith(const struct strslice a,
                                      const struct strslice b)
{
	if (b.len <= a.len) {
		struct strslice prefix = { b.len, a.buf };
		return strslice_cmp(prefix, b) == 0;
	} else {
		return 0;
	}
}

#endif
