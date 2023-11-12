/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "git-compat-util.h"
#include "hg-data.h"

static const struct hg_object_id empty_hg_file = {{
	0xb8, 0x0d, 0xe5, 0xd1, 0x38, 0x75, 0x85, 0x41, 0xc5, 0xf0,
	0x52, 0x65, 0xad, 0x14, 0x4a, 0xb9, 0xfa, 0x86, 0xd1, 0xdb,
}};

const struct hg_object_id hg_null_oid = {{ 0, }};

int is_null_hg_oid(const struct hg_object_id *oid)
{
	return hg_oideq(&hg_null_oid, oid);
}

int is_empty_hg_file(const struct hg_object_id *oid)
{
	return hg_oideq(&empty_hg_file, oid);
}
