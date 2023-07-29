/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![warn(missing_docs)]

//! Helpers related to trees.

use bstr::{BStr, ByteSlice};
use either::Either;
use itertools::EitherOrBoth;

use crate::util::{ImmutBString, Transpose};

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
