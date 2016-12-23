#ifndef HG_CONNECT_INTERNAL_H
#define HG_CONNECT_INTERNAL_H

#include "hg-connect.h"

extern void split_capabilities(struct string_list *list, const char *buf);

extern struct hg_connection *hg_connect_stdio(const char *url, int flags);
extern struct hg_connection *hg_connect_http(const char *url, int flags);

extern struct hg_connection *hg_connect_bundle(const char *path);

/* Generic helpers to handle passing parameters through the mercurial
 * wire protocol. Meant for internal use in hg-connect*.c only. */
union param_value {
	size_t size;
	const char *value;
};

typedef void (*command_add_param_t)(void *data, const char *name,
				    union param_value value);

extern void prepare_command(void *data, command_add_param_t command_add_param,
			    va_list ap);

#endif
