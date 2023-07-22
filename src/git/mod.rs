/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use sha1::Sha1;

mod blob;
pub use blob::*;
mod commit;
pub use commit::*;
mod tree;
pub use tree::*;

oid_type!(GitObjectId for Sha1);

#[macro_export]
macro_rules! git_oid_type {
    ($name:ident($base_type:ident)) => {
        oid_type!($name($base_type));

        impl From<$name> for $crate::libgit::object_id {
            fn from(oid: $name) -> $crate::libgit::object_id {
                $crate::git::GitObjectId::from(oid).into()
            }
        }

        git_oid_type!(@ $name($base_type));
    };
    (@ $name:ident(GitObjectId)) => {};
    (@ $name:ident($base_type:ident)) => {
        oid_impl!($name($crate::git::GitObjectId));
    };
}
