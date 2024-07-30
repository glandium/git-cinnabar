/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef HG_DATA_H
#define HG_DATA_H

#include "hash.h"
#include "hex.h"
#include "strbuf.h"
#include "strslice.h"
#include "cinnabar-notes.h"

struct hg_object_id {
	unsigned char hash[20];
};

extern const struct hg_object_id hg_null_oid;

static inline char *hg_oid_to_hex(const struct hg_object_id *oid)
{
	return hash_to_hex_algop(oid->hash, &hash_algos[GIT_HASH_SHA1]);
}

static inline int hg_oidcmp(const struct hg_object_id *oid1,
                            const struct hg_object_id *oid2)
{
	return memcmp(oid1->hash, oid2->hash, 20);
}

static inline int hg_oideq(const struct hg_object_id *oid1,
                           const struct hg_object_id *oid2)
{
	return !hg_oidcmp(oid1, oid2);
}

static inline void hg_oidclr(struct hg_object_id *oid)
{
	memset(oid->hash, 0, 20);
}

static inline void hg_oidcpy(struct hg_object_id *dst,
                             const struct hg_object_id *src)
{
	memcpy(dst->hash, src->hash, 20);
}

static inline void hg_oidcpy2git(struct object_id *dst,
                                 const struct hg_object_id *src)
{
	memcpy(dst->hash, src->hash, 20);
	memset(dst->hash + 20, 0, the_hash_algo->rawsz - 20);
	dst->algo = GIT_HASH_SHA1;
}

static inline void oidcpy2hg(struct hg_object_id *dst,
                             const struct object_id *src)
{
	assert(src->algo == GIT_HASH_SHA1);
	memcpy(dst->hash, src->hash, 20);
}

int is_null_hg_oid(const struct hg_object_id *oid);

#endif
