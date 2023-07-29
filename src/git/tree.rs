/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp::Ordering;

use bstr::BString;
use digest::OutputSizeUser;
use itertools::EitherOrBoth::{self, Both, Left, Right};
use itertools::Itertools;

use super::{git_oid_type, GitObjectId, GitOid};
use crate::libgit::{FileMode, RawTree};
use crate::oid::ObjectId;
use crate::tree_util::WithPath;
use crate::util::{FromBytes, SliceExt, Transpose};

git_oid_type!(TreeId(GitObjectId));

pub struct IntoIterTree {
    tree: RawTree,
    remaining: usize,
}

impl IntoIterator for RawTree {
    type Item = WithPath<TreeEntry>;
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

pub type DiffTreeEntry = WithPath<EitherOrBoth<TreeEntry, TreeEntry>>;

pub struct IntoIterDiff(Box<dyn Iterator<Item = DiffTreeEntry>>);

pub struct IntoRecursiveIterDiff {
    prefix: BString,
    stack: Vec<(IntoIterDiff, usize)>,
}

fn cmp_leaf_name(a: &[u8], a_is_tree: bool, b: &[u8], b_is_tree: bool) -> Ordering {
    // Trees need to be sorted as if they were recursed, so that
    // foo.bar comes before foo when foo is a tree.
    if !a_is_tree && !b_is_tree {
        a.cmp(b)
    } else {
        let shortest_len = std::cmp::min(a.len(), b.len());
        match a[..shortest_len].cmp(&b[..shortest_len]) {
            Ordering::Equal => match a.len().cmp(&b.len()) {
                Ordering::Equal => match (a_is_tree, b_is_tree) {
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    _ => Ordering::Equal,
                },
                Ordering::Greater if b_is_tree => a[shortest_len..].cmp(b"/"),
                Ordering::Less if a_is_tree => b"/"[..].cmp(&b[shortest_len..]),
                o => o,
            },
            o => o,
        }
    }
}

#[test]
fn test_cmp_leaf_name() {
    let examples = ["foo", "bar", "foobar", "foo.bar", "foo_", "foo.", "qux"];
    let example_dirs = examples.iter().map(|x| format!("{}/", x)).collect_vec();
    let all_examples = example_dirs.iter().map(|x| &**x).chain(examples);

    for (a, b) in Itertools::cartesian_product(all_examples.clone(), all_examples) {
        let expected = a.cmp(b);
        let (a_stripped, a_is_tree) = a.strip_suffix('/').map_or((a, false), |x| (x, true));
        let (b_stripped, b_is_tree) = b.strip_suffix('/').map_or((b, false), |x| (x, true));
        assert_eq!(
            cmp_leaf_name(
                a_stripped.as_bytes(),
                a_is_tree,
                b_stripped.as_bytes(),
                b_is_tree
            ),
            expected,
            "comparing {} and {}",
            a,
            b
        );
    }
}

impl RawTree {
    pub fn into_diff(self, other: RawTree) -> IntoIterDiff {
        IntoIterDiff(Box::new(
            Itertools::merge_join_by(self.into_iter(), other.into_iter(), |a, b| {
                cmp_leaf_name(
                    a.path(),
                    a.inner().oid.is_tree(),
                    b.path(),
                    b.inner().oid.is_tree(),
                )
            })
            .map(|entry| entry.transpose().unwrap())
            .filter(|entry| match entry.inner() {
                Both(a, b) => a != b,
                _ => true,
            }),
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TreeEntry {
    pub oid: GitOid,
    pub mode: FileMode,
}

impl Iterator for IntoIterTree {
    type Item = WithPath<TreeEntry>;

    fn next(&mut self) -> Option<WithPath<TreeEntry>> {
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
                Some(WithPath::new(
                    path,
                    TreeEntry {
                        oid: (GitObjectId::from_raw_bytes(oid).unwrap(), mode).into(),
                        mode,
                    },
                ))
            })()
            .expect("malformed tree"),
        )
    }
}

impl IntoIterTree {
    pub fn recurse(self) -> IntoRecursiveIterTree {
        IntoRecursiveIterTree {
            prefix: BString::from(Vec::new()),
            stack: vec![(self, 0)],
        }
    }
}

impl Iterator for IntoIterDiff {
    type Item = DiffTreeEntry;

    fn next(&mut self) -> Option<DiffTreeEntry> {
        self.0.next()
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
                        self.stack.push((RawTree::into_diff(a, b), len));
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
