/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use bstr::BString;
use digest::OutputSizeUser;
use itertools::EitherOrBoth::{self, Both, Left, Right};

use super::{git_oid_type, GitObjectId, GitOid};
use crate::libgit::{FileMode, RawTree};
use crate::oid::ObjectId;
use crate::tree_util::{diff_by_path, DiffByPath, MayRecurse, ParseTree, TreeIter, WithPath};
use crate::util::{FromBytes, SliceExt};

git_oid_type!(TreeId(GitObjectId));

#[derive(Debug, PartialEq, Eq)]
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

pub struct IntoRecursiveIterTree {
    prefix: BString,
    stack: Vec<(TreeIter<RawTree>, usize)>,
}

pub type DiffTreeEntry = WithPath<EitherOrBoth<TreeEntry, TreeEntry>>;

pub type IntoIterDiff = DiffByPath<TreeIter<RawTree>, TreeIter<RawTree>>;

pub struct IntoRecursiveIterDiff {
    prefix: BString,
    stack: Vec<(IntoIterDiff, usize)>,
}

impl TreeIter<RawTree> {
    pub fn recurse(self) -> IntoRecursiveIterTree {
        IntoRecursiveIterTree {
            prefix: BString::from(Vec::new()),
            stack: vec![(self, 0)],
        }
    }
}

impl IntoIterDiff {
    pub fn recurse(self) -> IntoRecursiveIterDiff {
        IntoRecursiveIterDiff {
            prefix: BString::from(Vec::new()),
            stack: vec![(self, 0)],
        }
    }
}

impl Iterator for IntoRecursiveIterTree {
    type Item = WithPath<TreeEntry>;

    fn next(&mut self) -> Option<WithPath<TreeEntry>> {
        loop {
            if let Some((iter, prefix_len)) = self.stack.last_mut() {
                if let Some((path, entry)) = iter.next().map(WithPath::unzip) {
                    if let GitOid::Tree(tree_id) = entry.oid {
                        let tree = RawTree::read(tree_id).unwrap();
                        self.stack.push((tree.into_iter(), self.prefix.len()));
                        self.prefix.extend_from_slice(&path);
                        self.prefix.push(b'/');
                    } else {
                        let mut full_path = self.prefix.clone();
                        full_path.extend_from_slice(&path);
                        return Some(WithPath::new(Vec::from(full_path), entry));
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

trait EitherOrBothExt<T> {
    fn map<F: Fn(T) -> U, U>(self, f: F) -> EitherOrBoth<U, U>;
    fn filter<F: Fn(&T) -> bool>(self, f: F) -> Option<EitherOrBoth<T, T>>;
    fn filter_map<F: Fn(T) -> Option<U>, U>(self, f: F) -> Option<EitherOrBoth<U, U>>;
}

impl<T> EitherOrBothExt<T> for EitherOrBoth<T, T> {
    fn map<F: Fn(T) -> U, U>(self, f: F) -> EitherOrBoth<U, U> {
        self.map_any(&f, &f)
    }

    fn filter<F: Fn(&T) -> bool>(self, f: F) -> Option<EitherOrBoth<T, T>> {
        match self {
            Left(a) => f(&a).then_some(Left(a)),
            Right(b) => f(&b).then_some(Right(b)),
            Both(a, b) => match (f(&a), f(&b)) {
                (false, false) => None,
                (true, false) => Some(Left(a)),
                (false, true) => Some(Right(b)),
                (true, true) => Some(Both(a, b)),
            },
        }
    }

    fn filter_map<F: Fn(T) -> Option<U>, U>(self, f: F) -> Option<EitherOrBoth<U, U>> {
        match self {
            Left(a) => f(a).map(Left),
            Right(b) => f(b).map(Right),
            Both(a, b) => match (f(a), f(b)) {
                (None, None) => None,
                (Some(a), None) => Some(Left(a)),
                (None, Some(b)) => Some(Right(b)),
                (Some(a), Some(b)) => Some(Both(a, b)),
            },
        }
    }
}

impl Iterator for IntoRecursiveIterDiff {
    type Item = DiffTreeEntry;

    fn next(&mut self) -> Option<DiffTreeEntry> {
        loop {
            if let Some((diff, prefix_len)) = self.stack.last_mut() {
                if let Some((path, entry)) = diff.next().map(WithPath::unzip) {
                    let is_tree = entry.as_ref().map(|e| e.oid.is_tree()).reduce(|a, b| {
                        assert_eq!(a, b);
                        a && b
                    });
                    if is_tree {
                        let len = self.prefix.len();
                        self.prefix.extend_from_slice(&path);
                        self.prefix.push(b'/');
                        let (a, b) = entry
                            .map(|e| RawTree::read(e.oid.try_into().unwrap()).unwrap())
                            .or(RawTree::EMPTY, RawTree::EMPTY);
                        self.stack.push((diff_by_path(a, b), len));
                    } else {
                        let mut full_path = self.prefix.clone();
                        full_path.extend_from_slice(&path);
                        return Some(WithPath::new(Vec::from(full_path), entry));
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
