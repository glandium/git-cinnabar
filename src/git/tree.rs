/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use bstr::BString;
use digest::OutputSizeUser;

use super::{GitObjectId, GitOid};
use crate::git_oid_type;
use crate::libgit::{FileMode, RawTree};
use crate::oid::ObjectId;
use crate::util::{FromBytes, ImmutBString, SliceExt};

git_oid_type!(TreeId(GitObjectId));

pub struct IntoIterTree {
    tree: RawTree,
    remaining: usize,
}

impl IntoIterator for RawTree {
    type Item = TreeEntry;
    type IntoIter = IntoIterTree;

    fn into_iter(self) -> IntoIterTree {
        let remaining = self.as_bytes().len();
        IntoIterTree {
            tree: self,
            remaining,
        }
    }
}

pub struct IntoRecursiveIterTree {
    prefix: BString,
    stack: Vec<(IntoIterTree, usize)>,
}

impl RawTree {
    pub fn into_recursive_iter(self) -> IntoRecursiveIterTree {
        IntoRecursiveIterTree {
            prefix: BString::from(Vec::<u8>::new()),
            stack: vec![(self.into_iter(), 0)],
        }
    }
}

#[derive(Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct TreeEntry {
    pub oid: GitOid,
    #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
    pub path: ImmutBString,
    pub mode: FileMode,
}

impl Iterator for IntoIterTree {
    type Item = TreeEntry;

    fn next(&mut self) -> Option<TreeEntry> {
        let buf = self.tree.as_bytes();
        let buf = &buf[buf.len() - self.remaining..];
        if buf.is_empty() {
            return None;
        }
        Some(
            (|| {
                let [mode, remainder] = buf.splitn_exact(b' ')?;
                let mode = FileMode::from_bytes(mode).ok()?;
                let [path, remainder] = remainder.splitn_exact(b'\0')?;
                if path.is_empty() {
                    return None;
                }
                let (oid, remainder) =
                    remainder.split_at(<GitObjectId as ObjectId>::Digest::output_size());
                self.remaining = remainder.len();
                Some(TreeEntry {
                    oid: (GitObjectId::from_raw_bytes(oid).unwrap(), mode).into(),
                    path: path.to_vec().into_boxed_slice(),
                    mode,
                })
            })()
            .expect("malformed tree"),
        )
    }
}

impl Iterator for IntoRecursiveIterTree {
    type Item = TreeEntry;

    fn next(&mut self) -> Option<TreeEntry> {
        loop {
            if let Some((iter, prefix_len)) = self.stack.last_mut() {
                if let Some(entry) = iter.next() {
                    if let GitOid::Tree(tree_id) = entry.oid {
                        let tree = RawTree::read(tree_id).unwrap();
                        self.stack.push((tree.into_iter(), self.prefix.len()));
                        self.prefix.extend_from_slice(&entry.path);
                        self.prefix.push(b'/');
                    } else {
                        let mut full_path = self.prefix.clone();
                        full_path.extend_from_slice(&entry.path);
                        return Some(TreeEntry {
                            oid: entry.oid,
                            path: full_path.to_vec().into_boxed_slice(),
                            mode: entry.mode,
                        });
                    }
                } else {
                    self.prefix.truncate(*prefix_len);
                    self.stack.pop();
                }
            } else {
                return None;
            }
        }
    }
}
