#ifndef HG_CONNECT_INTERNAL_H
#define HG_CONNECT_INTERNAL_H

#include "hg-connect.h"

void split_capabilities(struct hg_connection *conn, const char *buf);

struct hg_connection *hg_connect_stdio(const char *url, int flags);
struct hg_connection *hg_connect_http(const char *url, int flags);

struct hg_connection *hg_connect_bundle(const char *path);

#endif
