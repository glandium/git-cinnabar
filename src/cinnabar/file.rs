/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::git::{git_oid_type, BlobId};

git_oid_type!(GitFileId(BlobId));
git_oid_type!(GitFileMetadataId(BlobId));
