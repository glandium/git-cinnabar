/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![warn(missing_docs)]

//! Helpers related to trees.

use std::cmp::Ordering;
use std::io::{self, Write};
use std::iter::{zip, Peekable};

use bstr::{BStr, BString, ByteSlice};
use derive_more::Debug;
use either::Either;
use itertools::EitherOrBoth;

use crate::util::{ImmutBString, Map, MapMap, Transpose};

/// Wrapper type that pairs a value of any type with a path string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WithPath<T> {
    #[debug("{}", path.as_bstr())]
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
    fn write_one_entry<W: Write>(entry: &WithPath<Self::Inner>, w: W) -> io::Result<()>;

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

    fn write_one_entry<W: Write>(entry: &WithPath<Self::Inner>, w: W) -> io::Result<()> {
        T::write_one_entry(entry, w)
    }
}

/// An iterator for parsed trees
#[derive(Default)]
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

impl<I: Iterator + Empty, J: Iterator + Empty> Empty for MergeJoinByPath<I, J>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
{
    fn empty() -> Self {
        merge_join_by_path(I::empty(), J::empty())
    }
}

/// Wrapper type to force non-recursion in `merge_join_by_path` and `diff_by_path`.
#[derive(Debug, PartialEq)]
pub struct NoRecurse<T>(pub T);
impl<T> MayRecurse for NoRecurse<T> {
    fn may_recurse(&self) -> bool {
        false
    }
}

#[test]
fn test_merge_join_by_path() {
    use itertools::Itertools;

    let merged = merge_join_by_path(
        [
            WithPath::new(*b"foo", NoRecurse(1)),
            WithPath::new(*b"hoge", NoRecurse(2)),
            WithPath::new(*b"qux", NoRecurse(3)),
        ],
        [
            WithPath::new(*b"bar", NoRecurse("a")),
            WithPath::new(*b"foo", NoRecurse("b")),
            WithPath::new(*b"fuga", NoRecurse("c")),
            WithPath::new(*b"hoge", NoRecurse("d")),
            WithPath::new(*b"toto", NoRecurse("e")),
        ],
    )
    .collect_vec();
    assert_eq!(
        &merged,
        &[
            WithPath::new(*b"bar", EitherOrBoth::Right(NoRecurse("a"))),
            WithPath::new(*b"foo", EitherOrBoth::Both(NoRecurse(1), NoRecurse("b"))),
            WithPath::new(*b"fuga", EitherOrBoth::Right(NoRecurse("c"))),
            WithPath::new(*b"hoge", EitherOrBoth::Both(NoRecurse(2), NoRecurse("d"))),
            WithPath::new(*b"qux", EitherOrBoth::Left(NoRecurse(3))),
            WithPath::new(*b"toto", EitherOrBoth::Right(NoRecurse("e"))),
        ]
    );
}

/// An iterator adaptor that emits differences between items from the two
/// base iterators in ascending order of the path associated with their items.
///
/// See [`diff_by_path()`] for more information.
pub struct DiffByPath<I: Iterator, J: Iterator>(MergeJoinByPath<I, J>);

/// Create an iterator that emits differences between items from the specified
/// iterators in ascending order of the path associated with their items.
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
/// merge_join_by_path(left, right).filter(|x| match x.inner() {
///     EitherOrBoth::Both(a, b) => a != b,
///     _ => true,
/// })
/// ```
pub fn diff_by_path<I: IntoIterator, J: IntoIterator>(
    left: I,
    right: J,
) -> DiffByPath<I::IntoIter, J::IntoIter>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
{
    DiffByPath(merge_join_by_path(left, right))
}

impl<I: Iterator, J: Iterator> Iterator for DiffByPath<I, J>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
    <I::Item as IsWithPath>::Inner: MayRecurse + PartialEq<<J::Item as IsWithPath>::Inner>,
    <J::Item as IsWithPath>::Inner: MayRecurse,
{
    type Item = <MergeJoinByPath<I, J> as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.find(|entry| match entry.inner() {
            EitherOrBoth::Both(a, b) => a != b,
            _ => true,
        })
    }
}

impl<I: Iterator + Empty, J: Iterator + Empty> Empty for DiffByPath<I, J>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
{
    fn empty() -> Self {
        diff_by_path(I::empty(), J::empty())
    }
}

#[test]
fn test_diff_by_path() {
    use itertools::Itertools;

    #[derive(Debug, PartialEq)]
    struct NonTree<T>(T);
    impl<T> MayRecurse for NonTree<T> {
        fn may_recurse(&self) -> bool {
            false
        }
    }

    let diffed = diff_by_path(
        [
            WithPath::new(*b"foo", NonTree(1)),
            WithPath::new(*b"hoge", NonTree(2)),
            WithPath::new(*b"qux", NonTree(3)),
        ],
        [
            WithPath::new(*b"bar", NonTree(0)),
            WithPath::new(*b"foo", NonTree(1)),
            WithPath::new(*b"fuga", NonTree(2)),
            WithPath::new(*b"hoge", NonTree(3)),
            WithPath::new(*b"toto", NonTree(4)),
        ],
    )
    .collect_vec();
    assert_eq!(
        &diffed,
        &[
            WithPath::new(*b"bar", EitherOrBoth::Right(NonTree(0))),
            WithPath::new(*b"fuga", EitherOrBoth::Right(NonTree(2))),
            WithPath::new(*b"hoge", EitherOrBoth::Both(NonTree(2), NonTree(3))),
            WithPath::new(*b"qux", EitherOrBoth::Left(NonTree(3))),
            WithPath::new(*b"toto", EitherOrBoth::Right(NonTree(4)))
        ]
    );
}

/// An iterator adaptor that recurses through tree entries of its base iterator.
///
/// See [`RecurseTree::recurse`] for more information.
pub struct RecurseTreeIter<I: Iterator> {
    prefix: BString,
    stack: Vec<(I, usize)>,
}

/// Recursion driver for [`RecurseTreeIter`]
pub trait RecurseAs<I>: MayRecurse {
    /// The type returned by [`RecurseAs::maybe_recurse`] when not recursing.
    type NonRecursed;

    /// Method called by [`RecurseTreeIter`] for each item in its base iterator.
    ///
    /// For each of the tree items (where [`MayRecurse::may_recurse`] returns `true`),
    /// this method may return a tree iterator of the same type as base iterator
    /// of the calling [`RecurseTreeIter`].
    ///
    /// The calling [`RecurseTreeIter`] will emit items of the type `WithPath<NonRecursed>`.
    fn maybe_recurse(self) -> Either<I, Self::NonRecursed>;
}

impl<I: Iterator> RecurseTreeIter<I>
where
    I::Item: IsWithPath,
    <I::Item as IsWithPath>::Inner: RecurseAs<I>,
{
    /// Constructs a recursive tree iterator.
    pub fn new(iter: I) -> Self {
        RecurseTreeIter {
            prefix: BString::from(Vec::new()),
            stack: vec![(iter, 0)],
        }
    }
}

impl<I: Iterator> Iterator for RecurseTreeIter<I>
where
    I::Item: IsWithPath,
    <I::Item as IsWithPath>::Inner: RecurseAs<I>,
{
    type Item = WithPath<<<I::Item as IsWithPath>::Inner as RecurseAs<I>>::NonRecursed>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((iter, prefix_len)) = self.stack.last_mut() {
                if let Some((path, entry)) =
                    iter.next().map(IsWithPath::realize).map(WithPath::unzip)
                {
                    match entry.maybe_recurse() {
                        Either::Left(recursed) => {
                            self.stack.push((recursed.into_iter(), self.prefix.len()));
                            self.prefix.extend_from_slice(&path);
                            self.prefix.push(b'/');
                        }
                        Either::Right(entry) => {
                            let mut full_path = self.prefix.clone();
                            full_path.extend_from_slice(&path);
                            return Some(WithPath::new(Vec::from(full_path), entry));
                        }
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

#[allow(missing_docs)]
pub trait Mergeish {
    type I: Iterator;
    type J: Iterator;
    fn merge(left: Self::I, right: Self::J) -> Self;
}

impl<I: Iterator, J: Iterator> Mergeish for MergeJoinByPath<I, J>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
{
    type I = I;
    type J = J;

    fn merge(left: Self::I, right: Self::J) -> Self {
        merge_join_by_path(left, right)
    }
}

impl<I: Iterator, J: Iterator> Mergeish for DiffByPath<I, J>
where
    I::Item: IsWithPath,
    J::Item: IsWithPath,
{
    type I = I;
    type J = J;

    fn merge(left: Self::I, right: Self::J) -> Self {
        diff_by_path(left, right)
    }
}

impl<L: MayRecurse, R: MayRecurse> MayRecurse for EitherOrBoth<L, R> {
    fn may_recurse(&self) -> bool {
        self.as_ref()
            .map_any(MayRecurse::may_recurse, MayRecurse::may_recurse)
            .reduce(|l, r| {
                assert_eq!(
                    l, r,
                    "Both ends of EitherOrBoth need to agree for may_recurse"
                );
                l && r
            })
    }
}

#[allow(missing_docs)]
pub trait Empty {
    fn empty() -> Self;
}

impl<T: Empty + ParseTree> Empty for TreeIter<T> {
    fn empty() -> Self {
        TreeIter::new(T::empty())
    }
}

impl<T: Mergeish, L: RecurseAs<T::I>, R: RecurseAs<T::J>> RecurseAs<T> for EitherOrBoth<L, R>
where
    T::I: Empty,
    T::J: Empty,
{
    type NonRecursed = EitherOrBoth<L::NonRecursed, R::NonRecursed>;

    fn maybe_recurse(self) -> Either<T, Self::NonRecursed> {
        use EitherOrBoth::{Both, Left, Right};
        match self.map_any(RecurseAs::maybe_recurse, RecurseAs::maybe_recurse) {
            Both(Either::Left(l), Either::Left(r)) => Either::Left(Both(l, r)),
            Both(Either::Right(l), Either::Right(r)) => Either::Right(Both(l, r)),
            Both(_, _) => unreachable!(),
            Left(l) => l.map_left(Left).map_right(Left),
            Right(r) => r.map_left(Right).map_right(Right),
        }
        .map_left(|l| {
            let (a, b) = l.or_else(Empty::empty, Empty::empty);
            T::merge(a, b)
        })
    }
}

#[allow(missing_docs)]
pub trait RecurseTree {
    type RecurseType;

    fn recurse(self) -> Self::RecurseType;
}

impl<T: RecurseAs<I>, I: Iterator<Item = WithPath<T>>> RecurseTree for I {
    type RecurseType = RecurseTreeIter<I>;

    fn recurse(self) -> Self::RecurseType {
        RecurseTreeIter::new(self)
    }
}

#[cfg(test)]
impl<T> Empty for std::vec::IntoIter<T> {
    fn empty() -> Self {
        vec![].into_iter()
    }
}

#[test]
fn test_recurse_tree_iter() {
    use std::cell::RefCell;

    use itertools::Itertools;
    use once_cell::sync::Lazy;
    use Either::{Left, Right};

    #[derive(Debug, Clone, PartialEq)]
    struct TreeId(usize);

    type Tree = Vec<WithPath<Either<TreeId, &'static str>>>;

    static TREES: Lazy<[Tree; 7]> = Lazy::new(|| {
        [
            vec![
                WithPath::new(*b"bar", Right("bar")),
                WithPath::new(*b"foo", Left(TreeId(1))),
                WithPath::new(*b"fuga", Right("fuga")),
                WithPath::new(*b"hoge", Left(TreeId(2))),
                WithPath::new(*b"qux", Right("qux")),
            ],
            vec![
                WithPath::new(*b"bar", Right("foobar")),
                WithPath::new(*b"baz", Right("foobaz")),
                WithPath::new(*b"toto", Left(TreeId(3))),
            ],
            vec![WithPath::new(*b"hoge", Right("hoge"))],
            vec![WithPath::new(*b"titi", Right("footototiti"))],
            vec![
                WithPath::new(*b"bar", Right("bar")),
                WithPath::new(*b"foo", Left(TreeId(5))),
                WithPath::new(*b"fuga", Right("fuga")),
                WithPath::new(*b"hoge", Left(TreeId(2))),
                WithPath::new(*b"qux", Right("qux")),
            ],
            vec![
                WithPath::new(*b"bar", Right("foobar")),
                WithPath::new(*b"foo", Right("foofoo")),
                WithPath::new(*b"toto", Left(TreeId(6))),
            ],
            vec![
                WithPath::new(*b"a", Right("a")),
                WithPath::new(*b"titi", Right("titi")),
            ],
        ]
    });
    thread_local! {
        static COUNTS: RefCell<[usize; 7]> = const { RefCell::new([0; 7]) };
    }

    impl MayRecurse for Either<TreeId, &'static str> {
        fn may_recurse(&self) -> bool {
            self.is_left()
        }
    }

    impl RecurseAs<<Tree as IntoIterator>::IntoIter> for Either<TreeId, &'static str> {
        type NonRecursed = &'static str;

        fn maybe_recurse(self) -> Either<<Tree as IntoIterator>::IntoIter, &'static str> {
            self.map_left(|l| {
                COUNTS.with(|counts| counts.borrow_mut()[l.0] += 1);
                TREES[l.0].clone().into_iter()
            })
        }
    }

    let counts = COUNTS.with(RefCell::take);
    assert_eq!(counts, [0; 7]);

    let recursed = TREES[0].clone().into_iter().recurse().collect_vec();

    assert_eq!(
        &recursed,
        &[
            WithPath::new(*b"bar", "bar"),
            WithPath::new(*b"foo/bar", "foobar"),
            WithPath::new(*b"foo/baz", "foobaz"),
            WithPath::new(*b"foo/toto/titi", "footototiti"),
            WithPath::new(*b"fuga", "fuga"),
            WithPath::new(*b"hoge/hoge", "hoge"),
            WithPath::new(*b"qux", "qux"),
        ]
    );

    let counts = COUNTS.with(RefCell::take);
    assert_eq!(counts, [0, 1, 1, 1, 0, 0, 0]);

    let recursed = TREES[4].clone().into_iter().recurse().collect_vec();

    assert_eq!(
        &recursed,
        &[
            WithPath::new(*b"bar", "bar"),
            WithPath::new(*b"foo/bar", "foobar"),
            WithPath::new(*b"foo/foo", "foofoo"),
            WithPath::new(*b"foo/toto/a", "a"),
            WithPath::new(*b"foo/toto/titi", "titi"),
            WithPath::new(*b"fuga", "fuga"),
            WithPath::new(*b"hoge/hoge", "hoge"),
            WithPath::new(*b"qux", "qux"),
        ]
    );

    let counts = COUNTS.with(RefCell::take);
    assert_eq!(counts, [0, 0, 1, 0, 0, 1, 1]);

    let diff_recursed = diff_by_path(TREES[0].clone(), TREES[4].clone())
        .recurse()
        .collect_vec();
    assert_eq!(
        &diff_recursed,
        &[
            WithPath::new(*b"foo/baz", EitherOrBoth::Left("foobaz")),
            WithPath::new(*b"foo/foo", EitherOrBoth::Right("foofoo")),
            WithPath::new(*b"foo/toto/a", EitherOrBoth::Right("a")),
            WithPath::new(*b"foo/toto/titi", EitherOrBoth::Both("footototiti", "titi")),
        ]
    );

    let counts = COUNTS.with(RefCell::take);
    assert_eq!(counts, [0, 1, 0, 1, 0, 1, 1]);

    let merge_recursed = merge_join_by_path(TREES[0].clone(), TREES[4].clone())
        .recurse()
        .collect_vec();
    let counts = COUNTS.with(RefCell::take);
    assert_eq!(counts, [0, 1, 2, 1, 0, 1, 1]);

    assert_eq!(
        &merge_recursed,
        &[
            WithPath::new(*b"bar", EitherOrBoth::Both("bar", "bar")),
            WithPath::new(*b"foo/bar", EitherOrBoth::Both("foobar", "foobar")),
            WithPath::new(*b"foo/baz", EitherOrBoth::Left("foobaz")),
            WithPath::new(*b"foo/foo", EitherOrBoth::Right("foofoo")),
            WithPath::new(*b"foo/toto/a", EitherOrBoth::Right("a")),
            WithPath::new(*b"foo/toto/titi", EitherOrBoth::Both("footototiti", "titi")),
            WithPath::new(*b"fuga", EitherOrBoth::Both("fuga", "fuga")),
            WithPath::new(*b"hoge/hoge", EitherOrBoth::Both("hoge", "hoge")),
            WithPath::new(*b"qux", EitherOrBoth::Both("qux", "qux")),
        ]
    );

    let pairs_a = merge_join_by_path(TREES[0].clone(), TREES[0].clone());
    let pairs_b = merge_join_by_path(TREES[4].clone(), TREES[4].clone());
    let diff_pairs_recursed = diff_by_path(pairs_a, pairs_b).recurse().collect_vec();

    let counts = COUNTS.with(RefCell::take);
    assert_eq!(counts, [0, 2, 0, 2, 0, 2, 2]);

    assert_eq!(
        &diff_pairs_recursed,
        &[
            WithPath::new(
                *b"foo/baz",
                EitherOrBoth::Left(EitherOrBoth::Both("foobaz", "foobaz"))
            ),
            WithPath::new(
                *b"foo/foo",
                EitherOrBoth::Right(EitherOrBoth::Both("foofoo", "foofoo"))
            ),
            WithPath::new(
                *b"foo/toto/a",
                EitherOrBoth::Right(EitherOrBoth::Both("a", "a"))
            ),
            WithPath::new(
                *b"foo/toto/titi",
                EitherOrBoth::Both(
                    EitherOrBoth::Both("footototiti", "footototiti"),
                    EitherOrBoth::Both("titi", "titi")
                )
            ),
        ]
    );
}
