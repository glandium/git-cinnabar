/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define USE_THE_REPOSITORY_VARIABLE
#include "git-compat-util.h"
#include "hg-data.h"

const struct hg_object_id hg_null_oid = {{ 0, }};

int is_null_hg_oid(const struct hg_object_id *oid)
{
	return hg_oideq(&hg_null_oid, oid);
}
