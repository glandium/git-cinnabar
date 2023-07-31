/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{git_oid_type, GitObjectId, TreeId, TreeIsh};
use crate::libgit::RawCommit;

git_oid_type!(CommitId(GitObjectId));

impl TreeIsh for CommitId {
    type TreeId = TreeId;

    fn get_tree_id(self) -> Self::TreeId {
        let commit = RawCommit::read(self).unwrap();
        let commit = commit.parse().unwrap();
        commit.tree()
    }
}
