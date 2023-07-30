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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    pub oid: GitOid,
    pub mode: FileMode,
}

impl MayRecurse for TreeEntry {
    fn may_recurse(&self) -> bool {
        self.oid.is_tree()
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
                TreeEntry {
                    oid: (GitObjectId::from_raw_bytes(oid).unwrap(), mode).into(),
                    mode,
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
    type NonRecursed = Self;

    fn maybe_recurse(self) -> Either<TreeIter<RawTree>, Self> {
        if let GitOid::Tree(tree_id) = self.oid {
            Either::Left(RawTree::read(tree_id).unwrap().into_iter())
        } else {
            Either::Right(self)
        }
    }
}
