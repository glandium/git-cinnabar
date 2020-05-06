#ifndef HG_CONNECT_H
#define HG_CONNECT_H

#include "run-command.h"
#include "sha1-array.h"

struct hg_connection_stdio {
	FILE *out;
	int is_remote;
	struct child_process *proc;
	pthread_t thread;
};

struct hg_connection;

struct hg_connection *hg_connect(const char *url, int flags);

const char *hg_get_capability(struct hg_connection *conn,
                              const char *name);

int hg_finish_connect(struct hg_connection *conn);

void hg_get_repo_state(struct hg_connection *conn,
                       struct strbuf *branchmap, struct strbuf *heads,
                       struct strbuf *bookmarks);

void hg_pushkey(struct hg_connection *conn, struct strbuf *response,
                const char *namespace, const char *key, const char *old,
                const char *new);

void hg_listkeys(struct hg_connection *conn, struct strbuf *result,
                 const char *namespace);

void hg_lookup(struct hg_connection *conn, struct strbuf *result,
               const char *key);

void hg_clonebundles(struct hg_connection *conn, struct strbuf *result);

void hg_cinnabarclone(struct hg_connection *conn, struct strbuf *result);

#endif
