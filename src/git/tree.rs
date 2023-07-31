/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use digest::OutputSizeUser;
use either::Either;

use super::{git_oid_type, GitObjectId, GitOid};
use crate::libgit::{FileMode, RawTree};
use crate::oid::ObjectId;
use crate::tree_util::{Empty, MayRecurse, ParseTree, RecurseAs, TreeIter, WithPath};
use crate::util::{FromBytes, SliceExt};

git_oid_type!(TreeId(GitObjectId));

pub trait TreeIsh: ObjectId {
    type TreeId: ObjectId;
    fn get_tree_id(self) -> Self::TreeId;
}

impl TreeIsh for TreeId {
    type TreeId = TreeId;
    fn get_tree_id(self) -> TreeId {
        self
    }
}

impl RawTree {
    pub fn read_treeish<T: TreeIsh<TreeId = TreeId>>(t: T) -> Option<RawTree> {
        RawTree::read(t.get_tree_id())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursedTreeEntry {
    pub oid: GitOid,
    pub mode: FileMode,
}

pub type TreeEntry = Either<TreeId, RecursedTreeEntry>;

impl MayRecurse for TreeEntry {
    fn may_recurse(&self) -> bool {
        self.is_left()
    }
}

impl AsRef<[u8]> for RawTree {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Empty for RawTree {
    fn empty() -> RawTree {
        RawTree::EMPTY
    }
}

#[derive(Debug)]
pub struct MalformedTree;

impl ParseTree for RawTree {
    type Inner = TreeEntry;
    type Error = MalformedTree;

    fn parse_one_entry(buf: &mut &[u8]) -> Result<WithPath<Self::Inner>, Self::Error> {
        (|| {
            let [mode, remainder] = buf.splitn_exact(b' ')?;
            let mode = FileMode::from_bytes(mode).ok()?;
            let [path, remainder] = remainder.splitn_exact(b'\0')?;
            if path.is_empty() {
                return None;
            }
            let (oid, remainder) =
                remainder.split_at(<GitObjectId as ObjectId>::Digest::output_size());
            *buf = remainder;
            Some(WithPath::new(
                path,
                match GitOid::from((GitObjectId::from_raw_bytes(oid).unwrap(), mode)) {
                    GitOid::Tree(tree_id) => Either::Left(tree_id),
                    oid => Either::Right(RecursedTreeEntry { oid, mode }),
                },
            ))
        })()
        .ok_or(MalformedTree)
    }

    fn write_one_entry(_entry: &WithPath<Self::Inner>, _buf: &mut Vec<u8>) {
        todo!()
    }
}

impl IntoIterator for RawTree {
    type Item = WithPath<TreeEntry>;
    type IntoIter = TreeIter<RawTree>;

    fn into_iter(self) -> TreeIter<RawTree> {
        TreeIter::new(self)
    }
}

impl RecurseAs<TreeIter<RawTree>> for TreeEntry {
    type NonRecursed = RecursedTreeEntry;

    fn maybe_recurse(self) -> Either<TreeIter<RawTree>, RecursedTreeEntry> {
        self.map_left(|tree_id| RawTree::read(tree_id).unwrap().into_iter())
    }
}
