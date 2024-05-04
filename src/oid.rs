/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::str::{self, FromStr};

use digest::{Digest, OutputSizeUser};

use crate::util::assert_le;

pub trait ObjectId: Sized + Copy {
    type Digest: Digest;

    const NULL: Self;

    fn as_raw_bytes(&self) -> &[u8];
    fn as_raw_bytes_mut(&mut self) -> &mut [u8];
    fn is_null(&self) -> bool {
        self.as_raw_bytes().iter().all(|&b| b == 0)
    }
    fn create() -> OidCreator<Self> {
        OidCreator(Self::Digest::new())
    }
    fn from_digest(h: Self::Digest) -> Self;
    fn from_raw_bytes(b: &[u8]) -> Option<Self> {
        (b.len() == <Self::Digest as digest::OutputSizeUser>::output_size()).then(|| {
            let mut result = Self::NULL;
            let slice = result.as_raw_bytes_mut();
            slice.clone_from_slice(&b[..slice.len()]);
            result
        })
    }
    fn abbrev(self, len: usize) -> Abbrev<Self> {
        assert_le!(
            len,
            2 * <<Self::Digest as OutputSizeUser>::OutputSize as typenum::marker_traits::Unsigned>::USIZE
        );
        Abbrev { oid: self, len }
    }
}

macro_rules! oid_impl {
    ($name:ident($base_type:ty)) => {
        impl From<$name> for $base_type {
            fn from(o: $name) -> $base_type {
                use $crate::oid::ObjectId;
                let mut result = <$base_type>::NULL;
                let slice = result.as_raw_bytes_mut();
                slice.clone_from_slice(&o.0[..slice.len()]);
                result
            }
        }

        impl PartialEq<$base_type> for $name {
            fn eq(&self, other: &$base_type) -> bool {
                use $crate::oid::ObjectId;
                self.as_raw_bytes() == other.as_raw_bytes()
            }
        }

        impl PartialEq<$name> for $base_type {
            fn eq(&self, other: &$name) -> bool {
                use $crate::oid::ObjectId;
                self.as_raw_bytes() == other.as_raw_bytes()
            }
        }
    };
}
pub(crate) use oid_impl;

macro_rules! oid_type {
    ($name:ident($base_type:ident)) => {
        $crate::oid::oid_type!($name for <$base_type as $crate::oid::ObjectId>::Digest);

        impl $name {
            pub fn from_unchecked(o: $base_type) -> Self {
                use $crate::oid::ObjectId;
                Self(o.as_raw_bytes().try_into().unwrap())
            }
        }

        $crate::oid::oid_impl!($name($base_type));
    };
    ($name:ident for $typ:ty) => {
        #[repr(C)]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; <<$typ as digest::OutputSizeUser>::OutputSize as typenum::marker_traits::Unsigned>::USIZE]);

        impl $name {
            pub const fn from_raw_bytes_array(b: [u8; <<$typ as digest::OutputSizeUser>::OutputSize as typenum::marker_traits::Unsigned>::USIZE]) -> Self {
                Self(b)
            }
        }

        impl $crate::oid::ObjectId for $name {
            type Digest = $typ;

            const NULL: Self = Self([0; <<$typ as digest::OutputSizeUser>::OutputSize as typenum::marker_traits::Unsigned>::USIZE]);

            fn as_raw_bytes(&self) -> &[u8] {
                &self.0
            }

            fn as_raw_bytes_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }

            fn from_digest(h: Self::Digest) -> Self {
                use digest::Digest;
                Self(h.finalize().into())
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                use $crate::oid::ObjectId;
                for x in self.as_raw_bytes() {
                    write!(f, "{:02x}", x)?;
                }
                Ok(())
            }
        }

        $crate::util::derive_debug_display!($name);
        $crate::util::derive_debug_display!($crate::oid::Abbrev<$name>);
        impl ::std::str::FromStr for $name {
            type Err = hex::FromHexError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use $crate::oid::ObjectId;
                let mut result = Self::NULL;
                hex::decode_to_slice(s, &mut result.as_raw_bytes_mut())?;
                Ok(result)
             }
        }
    };
}
pub(crate) use oid_type;

pub struct OidCreator<O: ObjectId>(O::Digest);

impl<O: ObjectId> OidCreator<O> {
    pub fn update<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.update(data);
    }

    pub fn finalize(self) -> O {
        O::from_digest(self.0)
    }
}

#[derive(Clone, Copy)]
pub struct Abbrev<O: ObjectId> {
    oid: O,
    len: usize,
}

impl<O: ObjectId> Abbrev<O> {
    pub unsafe fn as_object_id(&self) -> O {
        self.oid
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<O: ObjectId> PartialEq for Abbrev<O> {
    fn eq(&self, other: &Self) -> bool {
        let self_oid = self.oid.as_raw_bytes();
        let other_oid = other.oid.as_raw_bytes();
        if self.len == other.len
            && self_oid[..self.len / 2] == other_oid[..self.len / 2]
            && (self.len % 2 == 0
                || self_oid[self.len / 2] & 0xf0 == other_oid[self.len / 2] & 0xf0)
        {
            return true;
        }
        false
    }
}

impl<O: ObjectId> std::fmt::Display for Abbrev<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        const BUF_LEN: usize = 40;
        assert!(
            <<O::Digest as OutputSizeUser>::OutputSize as typenum::marker_traits::Unsigned>::USIZE
                * 2
                <= BUF_LEN
        );
        let mut hex = [0u8; BUF_LEN];
        let len = (self.len + 1) / 2;
        hex::encode_to_slice(&self.oid.as_raw_bytes()[..len], &mut hex[..len * 2]).unwrap();
        f.write_str(str::from_utf8(&hex[..self.len]).unwrap())
    }
}

impl<O: ObjectId> FromStr for Abbrev<O> {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 40 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut result = Abbrev {
            oid: O::NULL,
            len: s.len(),
        };
        let s = if s.len() % 2 == 0 {
            Cow::Borrowed(s)
        } else {
            Cow::Owned(s.to_string() + "0")
        };
        hex::decode_to_slice(
            s.as_bytes(),
            &mut result.oid.as_raw_bytes_mut()[..s.len() / 2],
        )?;
        Ok(result)
    }
}
