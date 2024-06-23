/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{self, Write};

use digest::OutputSizeUser;
use either::Either;
use hex_literal::hex;

use super::{git_oid_type, GitObjectId, GitOid};
use crate::libgit::FileMode;
use crate::oid::ObjectId;
use crate::tree_util::{Empty, MayRecurse, ParseTree, RecurseAs, TreeIter, WithPath};
use crate::util::SliceExt;

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
            let mut mode = 0u16;
            let mut bytes = buf.iter();
            for b in &mut bytes {
                match b {
                    b' ' => break,
                    b'0'..=b'7' => {
                        mode <<= 3;
                        mode += (b - b'0') as u16;
                    }
                    _ => return None,
                }
            }
            let mode = FileMode::from(mode);
            let [path, remainder] = bytes.as_slice().splitn_exact(b'\0')?;
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

    fn write_one_entry<W: Write>(_entry: &WithPath<Self::Inner>, _w: W) -> io::Result<()> {
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

super::raw_object!(OBJ_TREE | TreeId => RawTree);

impl RawTree {
    pub const EMPTY_OID: TreeId =
        TreeId::from_raw_bytes_array(hex!("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));

    pub const EMPTY: RawTree = RawTree(None);
}
