/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use bstr::ByteSlice;
use getset::{CopyGetters, Getters};

use super::{git_oid_type, GitObjectId, TreeId, TreeIsh};
use crate::util::{FromBytes, SliceExt};

git_oid_type!(CommitId(GitObjectId));

impl TreeIsh for CommitId {
    type TreeId = TreeId;

    fn get_tree_id(self) -> Self::TreeId {
        let commit = RawCommit::read(self).unwrap();
        let commit = commit.parse().unwrap();
        commit.tree()
    }
}

super::raw_object!(OBJ_COMMIT | CommitId => RawCommit);

impl RawCommit {
    pub fn parse(&self) -> Option<Commit<'_>> {
        let [header, body] = self.as_bytes().splitn_exact(&b"\n\n"[..])?;
        let mut tree = None;
        let mut parents = Vec::new();
        let mut author = None;
        let mut committer = None;
        for line in header.lines() {
            if line.is_empty() {
                break;
            }
            match line.splitn_exact(b' ')? {
                [b"tree", t] => tree = Some(TreeId::from_bytes(t).ok()?),
                [b"parent", p] => parents.push(CommitId::from_bytes(p).ok()?),
                [b"author", a] => author = Some(a),
                [b"committer", a] => committer = Some(a),
                _ => {}
            }
        }
        Some(Commit {
            tree: tree?,
            parents,
            author: author?,
            committer: committer?,
            body,
        })
    }
}

#[derive(CopyGetters, Getters)]
pub struct Commit<'a> {
    #[getset(get_copy = "pub")]
    tree: TreeId,
    parents: Vec<CommitId>,
    #[getset(get_copy = "pub")]
    author: &'a [u8],
    #[getset(get_copy = "pub")]
    committer: &'a [u8],
    #[getset(get_copy = "pub")]
    body: &'a [u8],
}

impl Commit<'_> {
    pub fn parents(&self) -> &[CommitId] {
        &self.parents[..]
    }
}
