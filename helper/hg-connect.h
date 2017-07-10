#ifndef HG_CONNECT_H
#define HG_CONNECT_H

#include "run-command.h"
#include "sha1-array.h"
#include "string-list.h"

struct hg_connection {
	struct string_list capabilities;

	void (*simple_command)(struct hg_connection *, struct strbuf *response,
			       const char *command, ...);

	void (*changegroup_command)(struct hg_connection *, FILE *out,
				    const char *command, ...);

	void (*push_command)(struct hg_connection *, struct strbuf *response,
			     FILE *in, off_t len, const char *command, ...);

	int (*finish)(struct hg_connection *);

	union {
		struct {
			struct child_process proc;
			FILE *out;
		} stdio;
		struct {
			char *url;
			int initial_request;
		} http;
	};
};

extern struct hg_connection *hg_connect(const char *url, int flags);

extern const char *hg_get_capability(struct hg_connection *conn,
				     const char *name);

extern int hg_finish_connect(struct hg_connection *conn);

extern void hg_get_repo_state(struct hg_connection *conn,
			      struct strbuf *branchmap, struct strbuf *heads,
			      struct strbuf *bookmarks);

extern void hg_known(struct hg_connection *conn, struct strbuf *result,
		     struct oid_array *nodes);

extern void hg_getbundle(struct hg_connection *conn, FILE *out,
			 struct oid_array *heads, struct oid_array *common,
			 const char *bundle2caps);

extern void hg_unbundle(struct hg_connection *conn, struct strbuf *response,
			FILE *in, struct oid_array *heads);

extern void hg_pushkey(struct hg_connection *conn, struct strbuf *response,
		       const char *namespace, const char *key, const char *old,
		       const char *new);

extern void hg_listkeys(struct hg_connection *conn, struct strbuf *result,
			const char *namespace);

extern void hg_lookup(struct hg_connection *conn, struct strbuf *result,
		      const char *key);

extern void hg_clonebundles(struct hg_connection *conn, struct strbuf *result);

#endif
