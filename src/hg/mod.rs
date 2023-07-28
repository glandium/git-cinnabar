/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use sha1::Sha1;

mod changeset;
pub use changeset::*;
mod file;
pub use file::*;
mod manifest;
pub use manifest::*;

use crate::oid::oid_type;

oid_type!(HgObjectId for Sha1);

#[test]
fn test_abbrev_hg_object_id() {
    use std::str::FromStr;

    use crate::oid::{Abbrev, ObjectId};

    let hex = "123456789abcdef00123456789abcdefedcba987";
    for len in 1..40 {
        let abbrev = HgObjectId::from_str("123456789abcdef00123456789abcdefedcba987")
            .unwrap()
            .abbrev(len);
        let result = format!("{}", abbrev);
        assert_eq!(&result, &hex[..len]);

        let abbrev2 = Abbrev::<HgObjectId>::from_str(&result).unwrap();
        assert_eq!(abbrev, abbrev2);
    }

    assert_ne!(
        Abbrev::<HgObjectId>::from_str("123").unwrap(),
        Abbrev::<HgObjectId>::from_str("124").unwrap()
    );
    assert_eq!(
        Abbrev::<HgObjectId>::from_str("123a").unwrap(),
        Abbrev::<HgObjectId>::from_str("123A").unwrap()
    );
}
