/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{git_oid_type, GitObjectId};

use hex_literal::hex;

git_oid_type!(BlobId(GitObjectId));

super::raw_object!(OBJ_BLOB | BlobId => RawBlob);

impl RawBlob {
    pub const EMPTY_OID: BlobId =
        BlobId::from_raw_bytes_array(hex!("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"));
}
