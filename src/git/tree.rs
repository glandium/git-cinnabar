/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use bstr::BString;
use digest::OutputSizeUser;
use itertools::EitherOrBoth::{self, Both, Left, Right};
use itertools::Itertools;

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

pub type DiffTreeEntry = EitherOrBoth<TreeEntry, TreeEntry>;

pub struct IntoRecursiveIterDiff {
    prefix: BString,
    stack: Vec<(Box<dyn Iterator<Item = DiffTreeEntry>>, usize)>,
}

impl RawTree {
    pub fn into_recursive_iter(self) -> IntoRecursiveIterTree {
        IntoRecursiveIterTree {
            prefix: BString::from(Vec::<u8>::new()),
            stack: vec![(self.into_iter(), 0)],
        }
    }

    pub fn into_diff(self, other: RawTree) -> impl Iterator<Item = DiffTreeEntry> {
        Itertools::merge_join_by(self.into_iter(), other.into_iter(), |a, b| {
            <[u8]>::cmp(&a.path, &b.path)
        })
        .filter(|entry| match entry {
            Both(a, b) => a != b,
            _ => true,
        })
    }

    pub fn into_recursive_diff(self, other: RawTree) -> IntoRecursiveIterDiff {
        IntoRecursiveIterDiff {
            prefix: BString::from(Vec::<u8>::new()),
            stack: vec![(Box::new(Self::into_diff(self, other)), 0)],
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
                if let Some(entry) = diff.next() {
                    let non_trees = entry.as_ref().filter(|e| !e.oid.is_tree());
                    let trees = entry.as_ref().filter_map(|e| {
                        e.oid
                            .try_into()
                            .ok()
                            .map(|tree_id| RawTree::read(tree_id).unwrap())
                    });
                    let path = entry.as_ref().map(|e| &e.path).reduce(|a, _| a);
                    let result = non_trees.map(|non_trees| {
                        let mut full_path = self.prefix.clone();
                        full_path.extend_from_slice(&entry.as_ref().reduce(|a, _| a).path);
                        non_trees.map(|e| TreeEntry {
                            oid: e.oid,
                            path: full_path.to_vec().into_boxed_slice(),
                            mode: e.mode,
                        })
                    });
                    if let Some(trees) = trees {
                        let (a, b) = trees.or(RawTree::EMPTY, RawTree::EMPTY);
                        self.stack
                            .push((Box::new(RawTree::into_diff(a, b)), self.prefix.len()));
                        self.prefix.extend_from_slice(path);
                        self.prefix.push(b'/');
                    }
                    if result.is_some() {
                        return result;
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
