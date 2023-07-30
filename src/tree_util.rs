/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![warn(missing_docs)]

//! Helpers related to trees.

use std::cmp::Ordering;
use std::iter::{zip, Peekable};

use bstr::{BStr, ByteSlice};
use either::Either;
use itertools::EitherOrBoth;

use crate::util::{ImmutBString, Map, MapMap, Transpose};

/// Wrapper type that pairs a value of any type with a path string.
#[derive(Clone, Derivative, PartialEq, Eq, PartialOrd, Ord)]
#[derivative(Debug)]
pub struct WithPath<T> {
    #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
    path: ImmutBString,
    inner: T,
}

impl<T> WithPath<T> {
    /// Pairs a value with a path string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use git_cinnabar::tree_util::WithPath;
    /// let forty_two = WithPath::new(*b"some/path", 42);
    /// ```
    pub fn new(path: impl Into<ImmutBString>, inner: T) -> Self {
        WithPath {
            path: path.into(),
            inner,
        }
    }

    /// Gets the path associated with the value.
    pub fn path(&self) -> &BStr {
        self.path.as_bstr()
    }

    /// Gets a reference to the associated value.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Unwraps the value, consuming the `WithPath`.
    ///
    /// # Examples
    /// ```
    /// # use git_cinnabar::tree_util::WithPath;
    /// let forty_two = WithPath::new(*b"some/path", 42);
    /// assert_eq!(forty_two.into_inner(), 42);
    /// ```
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Maps a `WithPath<T>` to `WithPath<U>` by applying a function to
    /// the associated value.
    ///
    /// # Examples
    /// ```
    /// # use git_cinnabar::tree_util::WithPath;
    /// let forty_two = WithPath::new(*b"some/path", 42);
    /// let twenty_one = forty_two.map(|n| n / 2);
    /// assert_eq!(twenty_one.inner(), &21);
    /// assert_eq!(twenty_one.path(), &b"some/path"[..]);
    /// ```
    pub fn map<F: FnOnce(T) -> U, U>(self, f: F) -> WithPath<U> {
        WithPath::new(self.path, f(self.inner))
    }

    /// Unwraps the path and the value, returning both.
    ///
    /// # Examples
    /// ```
    /// # use git_cinnabar::tree_util::WithPath;
    /// let forty_two = WithPath::new(*b"some/path", 42);
    /// let (path, value) = forty_two.unzip();
    /// ```
    pub fn unzip(self) -> (ImmutBString, T) {
        (self.path, self.inner)
    }
}

/// Indicates whether the inner value within a [`WithPath`] represents a
/// tree that may further be recursed. See [`WithPath::cmp_path`].
pub trait MayRecurse {
    /// Returns whether the value represents a tree that may be recursed.
    fn may_recurse(&self) -> bool;
}

impl<T: MayRecurse> WithPath<T> {
    /// Compares the paths of two [`WithPath`] instances.
    ///
    /// When comparing paths in a non-recursive listing, the name of a tree
    /// is compared to the name of non-trees as if it was suffixed with a `/`.
    /// This is because we must consider the recursed directory listing.
    ///
    /// For example, the following is the proper order in a recursed listing:
    ///   - `foo.bar`
    ///   - `foo/bar`
    ///   - `foobar`
    ///
    /// In the non-recursed case, when `foo` is the directory that may contain
    /// `bar`, it still needs to appear after `foo.bar`.
    pub fn cmp_path<U: MayRecurse>(&self, other: &WithPath<U>) -> Ordering {
        // Trees need to be sorted as if they were recursed, so that
        // foo.bar comes before foo when foo is a tree.
        let a = self.path();
        let b = other.path();
        let a_is_tree = self.inner().may_recurse();
        let b_is_tree = other.inner().may_recurse();
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
                    Ordering::Greater if b_is_tree => a[shortest_len..].cmp(b"/".as_bstr()),
                    Ordering::Less if a_is_tree => b"/"[..].cmp(&b[shortest_len..]),
                    o => o,
                },
                o => o,
            }
        }
    }
}

#[test]
fn test_cmp_path() {
    use itertools::Itertools;

    struct Tree(bool);

    impl MayRecurse for Tree {
        fn may_recurse(&self) -> bool {
            self.0
        }
    }

    let examples = ["foo", "bar", "foobar", "foo.bar", "foo_", "foo.", "qux"];
    let example_dirs = examples.iter().map(|x| format!("{}/", x)).collect_vec();
    let all_examples = example_dirs.iter().map(|x| &**x).chain(examples);

    for (a, b) in Itertools::cartesian_product(all_examples.clone(), all_examples) {
        let expected = a.cmp(b);
        let (a_stripped, a_is_tree) = a.strip_suffix('/').map_or((a, false), |x| (x, true));
        let (b_stripped, b_is_tree) = b.strip_suffix('/').map_or((b, false), |x| (x, true));
        let a_path = WithPath::new(a_stripped.as_bytes(), Tree(a_is_tree));
        let b_path = WithPath::new(b_stripped.as_bytes(), Tree(b_is_tree));
        assert_eq!(
            WithPath::cmp_path(&a_path, &b_path),
            expected,
            "comparing {} and {}",
            a,
            b
        );
    }
}

impl<T> Transpose for WithPath<Option<T>> {
    type Target = Option<WithPath<T>>;

    fn transpose(self) -> Option<WithPath<T>> {
        let (path, option) = self.unzip();
        option.map(|val| WithPath::new(path, val))
    }
}

impl<L, R> Transpose for WithPath<Either<L, R>> {
    type Target = Either<WithPath<L>, WithPath<R>>;

    fn transpose(self) -> Either<WithPath<L>, WithPath<R>> {
        let (path, value) = self.unzip();
        match value {
            Either::Left(l) => Either::Left(WithPath::new(path, l)),
            Either::Right(r) => Either::Right(WithPath::new(path, r)),
        }
    }
}

impl<L, R> Transpose for Either<WithPath<L>, WithPath<R>> {
    type Target = WithPath<Either<L, R>>;

    fn transpose(self) -> WithPath<Either<L, R>> {
        match self {
            Either::Left(l) => l.map(Either::Left),
            Either::Right(r) => r.map(Either::Right),
        }
    }
}

impl<L, R> Transpose for WithPath<EitherOrBoth<L, R>> {
    type Target = EitherOrBoth<WithPath<L>, WithPath<R>>;

    fn transpose(self) -> EitherOrBoth<WithPath<L>, WithPath<R>> {
        let (path, inner) = self.unzip();
        match inner {
            EitherOrBoth::Left(l) => EitherOrBoth::Left(WithPath::new(path, l)),
            EitherOrBoth::Right(r) => EitherOrBoth::Right(WithPath::new(path, r)),
            EitherOrBoth::Both(l, r) => {
                EitherOrBoth::Both(WithPath::new(path.clone(), l), WithPath::new(path, r))
            }
        }
    }
}

impl<L, R> Transpose for EitherOrBoth<WithPath<L>, WithPath<R>> {
    type Target = Result<WithPath<EitherOrBoth<L, R>>, Self>;

    fn transpose(self) -> Result<WithPath<EitherOrBoth<L, R>>, Self> {
        match self {
            EitherOrBoth::Left(l) => Ok(l.map(EitherOrBoth::Left)),
            EitherOrBoth::Right(r) => Ok(r.map(EitherOrBoth::Right)),
            EitherOrBoth::Both(l, r) if l.path() == r.path() => {
                Ok(l.map(|l| EitherOrBoth::Both(l, r.into_inner())))
            }
            _ => Err(self),
        }
    }
}

impl<T> Map for WithPath<T> {
    type Input = T;
    type Target<U> = WithPath<U>;

    fn map<U, F: FnMut(Self::Input) -> U>(self, f: F) -> Self::Target<U> {
        self.map(f)
    }
}

impl<T: Map> MapMap for WithPath<T>
where
    Self::Input: Map,
{
    fn map_map<U, F: FnMut(T::Input) -> U>(
        self,
        f: F,
    ) -> Self::Target<<Self::Input as Map>::Target<U>> {
        self.map(|inner| inner.map(f))
    }
}

/// Helper trait for other trait bounds.
///
/// Only meant to be implemented for [`WithPath`].
pub trait IsWithPath {
    /// Type wrapped by [`WithPath`].
    type Inner;

    /// Returns the concrete [`WithPath`].
    fn realize(self) -> WithPath<Self::Inner>;

    /// Returns a ref to the concrete [`WithPath`].
    fn realize_as_ref(&self) -> &WithPath<Self::Inner>;
}

impl<T> IsWithPath for WithPath<T> {
    type Inner = T;

    fn realize(self) -> WithPath<Self::Inner> {
        self
    }

    fn realize_as_ref(&self) -> &WithPath<Self::Inner> {
        self
    }
}

/// Parsing interface for trees
///
/// A type implementing this trait can be used with [`TreeIter`] to iterate over
/// the parsed entries.
pub trait ParseTree: AsRef<[u8]> {
    /// Inner type of the parsed entry.
    type Inner;
    /// Parsing error.
    type Error: std::fmt::Debug;

    /// Parse one entry from the given buffer.
    ///
    /// The method is called by [`TreeIter`]. The method reads one entry, and
    /// advances `buf` to the beginning of next entry.
    fn parse_one_entry(buf: &mut &[u8]) -> Result<WithPath<Self::Inner>, Self::Error>;

    /// Write one entry into the given buffer.
    fn write_one_entry(entry: &WithPath<Self::Inner>, buf: &mut Vec<u8>);

    /// Iterates the tree
    fn iter(&self) -> TreeIter<&Self> {
        TreeIter::new(self)
    }
}

impl<T: ParseTree + ?Sized> ParseTree for &T {
    type Inner = T::Inner;
    type Error = T::Error;

    fn parse_one_entry(buf: &mut &[u8]) -> Result<WithPath<Self::Inner>, Self::Error> {
        T::parse_one_entry(buf)
    }

    fn write_one_entry(entry: &WithPath<Self::Inner>, buf: &mut Vec<u8>) {
        T::write_one_entry(entry, buf);
    }
}

/// An iterator for parsed trees
pub struct TreeIter<T: ParseTree> {
    tree: T,
    remaining: usize,
}

impl<T: ParseTree> TreeIter<T> {
    /// Constructs a tree iterator
    pub fn new(t: T) -> Self {
        let remaining = t.as_ref().len();
        TreeIter { tree: t, remaining }
    }
}

impl<T: ParseTree> Iterator for TreeIter<T> {
    type Item = WithPath<T::Inner>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.tree.as_ref();
        let mut buf = &buf[buf.len() - self.remaining..];
        if buf.is_empty() {
            return None;
        }
        let result = T::parse_one_entry(&mut buf).unwrap();
        self.remaining = buf.len();
        Some(result)
    }
}

/// An iterator adaptor that merges items from the two base iterators in ascending
/// order of the path associated with their items.
///
/// See [`merge_join_by_path()`] for more information.
pub struct MergeJoinByPath<I: Iterator, J: Iterator> {
    left: Peekable<I>,
    right: Peekable<J>,
}

/// Create an iterator that merges items from the specified iterators in ascending
/// order of the path associated with their items.
///
/// From iterators `I` and `J` respectively emitting `WithPath<L>` and `WithPath<R>`, the
/// resulting iterator will emit `WithPath<EitherOrBoth<L, R>>`.
///
/// Notes:
/// - The specified iterators are expected to be ordered by order of [`WithPath::cmp_path`].
/// - If both iterators have entries with the same path, but one may be recursed and the
///   other may not, they are emitted separately (per [`WithPath::cmp_path`] not returning
///   [`Ordering::Equal`] in that case).
///
/// This is equivalent to
/// ```
/// Itertools::merge_join_by(left, right, |l, r| l.cmp_path(r))
///     .map(|x| x.transpose().unwrap())
/// ```
pub fn merge_join_by_path<I: IntoIterator, J: IntoIterator>(
    left: I,
    right: J,
) -> MergeJoinByPath<I::IntoIter, J::IntoIter>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
{
    MergeJoinByPath {
        left: left.into_iter().peekable(),
        right: right.into_iter().peekable(),
    }
}

impl<I: Iterator, J: Iterator> Iterator for MergeJoinByPath<I, J>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
    <I::Item as IsWithPath>::Inner: MayRecurse,
    <J::Item as IsWithPath>::Inner: MayRecurse,
{
    type Item =
        WithPath<EitherOrBoth<<I::Item as IsWithPath>::Inner, <J::Item as IsWithPath>::Inner>>;

    fn next(&mut self) -> Option<Self::Item> {
        let order = match (self.left.peek(), self.right.peek()) {
            (Some(l), Some(r)) => Some(WithPath::cmp_path(l.realize_as_ref(), r.realize_as_ref())),
            (Some(_), None) => Some(Ordering::Less),
            (None, Some(_)) => Some(Ordering::Greater),
            (None, None) => None,
        }?;
        match order {
            Ordering::Less => self
                .left
                .next()
                .map(IsWithPath::realize)
                .map_map(EitherOrBoth::Left),
            Ordering::Greater => self
                .right
                .next()
                .map(IsWithPath::realize)
                .map_map(EitherOrBoth::Right),
            Ordering::Equal => {
                let l = self.left.next();
                let r = self.right.next();
                zip(l, r).next().map(|(l, r)| {
                    l.realize()
                        .map(|l| EitherOrBoth::Both(l, r.realize().into_inner()))
                })
            }
        }
    }
}

#[test]
fn test_merge_join_by_path() {
    use itertools::Itertools;

    #[derive(Debug, PartialEq)]
    struct NonTree<T>(T);
    impl<T> MayRecurse for NonTree<T> {
        fn may_recurse(&self) -> bool {
            false
        }
    }

    let merged = merge_join_by_path(
        [
            WithPath::new(*b"foo", NonTree(1)),
            WithPath::new(*b"hoge", NonTree(2)),
            WithPath::new(*b"qux", NonTree(3)),
        ],
        [
            WithPath::new(*b"bar", NonTree("a")),
            WithPath::new(*b"foo", NonTree("b")),
            WithPath::new(*b"fuga", NonTree("c")),
            WithPath::new(*b"hoge", NonTree("d")),
            WithPath::new(*b"toto", NonTree("e")),
        ],
    )
    .collect_vec();
    assert_eq!(
        &merged,
        &[
            WithPath::new(*b"bar", EitherOrBoth::Right(NonTree("a"))),
            WithPath::new(*b"foo", EitherOrBoth::Both(NonTree(1), NonTree("b"))),
            WithPath::new(*b"fuga", EitherOrBoth::Right(NonTree("c"))),
            WithPath::new(*b"hoge", EitherOrBoth::Both(NonTree(2), NonTree("d"))),
            WithPath::new(*b"qux", EitherOrBoth::Left(NonTree(3))),
            WithPath::new(*b"toto", EitherOrBoth::Right(NonTree("e"))),
        ]
    );
}
