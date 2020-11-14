/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::str::{self, FromStr};

use digest::Digest;
use sha1::Sha1;

pub trait ObjectId: Sized {
    type Digest: Digest;
    fn as_raw_bytes(&self) -> &[u8];
    fn as_raw_bytes_mut(&mut self) -> &mut [u8];
    fn null() -> Self;
    fn create() -> OidCreator<Self> {
        OidCreator(Self::Digest::new())
    }
    fn from_digest(h: Self::Digest) -> Self;
    fn abbrev(self, len: usize) -> Abbrev<Self> {
        assert_le!(
            len,
            2 * <<Self::Digest as Digest>::OutputSize as typenum::marker_traits::Unsigned>::USIZE
        );
        Abbrev { oid: self, len }
    }
}

#[macro_export]
macro_rules! oid_type {
    ($name:ident($base_type:ident)) => {
        #[repr(transparent)]
        #[derive(Clone, Deref, Display, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name($base_type);

        impl $crate::oid::ObjectId for $name {
            type Digest = <$base_type as $crate::oid::ObjectId>::Digest;

            fn as_raw_bytes(&self) -> &[u8] {
                self.0.as_raw_bytes()
            }

            fn as_raw_bytes_mut(&mut self) -> &mut [u8] {
                self.0.as_raw_bytes_mut()
            }

            fn null() -> Self {
                Self($base_type::null())
            }

            fn from_digest(h: Self::Digest) -> Self {
                Self(<$base_type as $crate::oid::ObjectId>::from_digest(h))
            }
        }
        impl $name {
            pub unsafe fn from(o: $base_type) -> Self {
                Self(o)
            }
        }

        oid_type!(@other $name);
    };
    ($name:ident for $typ:ty) => {
        #[repr(C)]
        #[derive(Clone, Eq)]
        pub struct $name([u8; <<$typ as digest::Digest>::OutputSize as typenum::marker_traits::Unsigned>::USIZE]);

        impl $crate::oid::ObjectId for $name {
            type Digest = $typ;

            fn as_raw_bytes(&self) -> &[u8] {
                &self.0
            }

            fn as_raw_bytes_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }

            fn null() -> Self {
                Self([0; <<$typ as digest::Digest>::OutputSize as typenum::marker_traits::Unsigned>::USIZE])
            }

            fn from_digest(h: Self::Digest) -> Self {
                Self(h.finalize().into())
            }
        }

        oid_type!(@traits $name);
        oid_type!(@other $name);
    };
    (@traits $name:ident) => {
        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                for x in self.as_raw_bytes() {
                    write!(f, "{:02x}", x)?;
                }
                Ok(())
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.as_raw_bytes() == other.as_raw_bytes()
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
                Some(self.as_raw_bytes().cmp(other.as_raw_bytes()))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
                self.as_raw_bytes().cmp(other.as_raw_bytes())
            }
        }
    };
    (@other $name:ident) => {
        derive_debug_display!($name);
        derive_debug_display!($crate::oid::Abbrev<$name>);
        impl ::std::str::FromStr for $name {
            type Err = hex::FromHexError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut result = Self::null();
                hex::decode_to_slice(s, &mut result.as_raw_bytes_mut())?;
                Ok(result)
             }
        }
    };
}

pub struct OidCreator<O: ObjectId>(O::Digest);

impl<O: ObjectId> OidCreator<O> {
    pub fn update<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.update(data)
    }

    pub fn finalize(self) -> O {
        O::from_digest(self.0)
    }
}

pub struct Abbrev<O: ObjectId> {
    oid: O,
    len: usize,
}

impl<O: ObjectId> Abbrev<O> {
    pub unsafe fn as_object_id(&self) -> &O {
        &self.oid
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<O: ObjectId> PartialEq for Abbrev<O> {
    fn eq(&self, other: &Self) -> bool {
        let self_oid = self.oid.as_raw_bytes();
        let other_oid = other.oid.as_raw_bytes();
        if self.len == other.len && self_oid[..self.len / 2] == other_oid[..self.len / 2] {
            if self.len % 2 == 0 {
                return true;
            } else if self_oid[self.len / 2] & 0xf0 == other_oid[self.len / 2] & 0xf0 {
                return true;
            }
        }
        false
    }
}

impl<O: ObjectId> std::fmt::Display for Abbrev<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        const BUF_LEN: usize = 40;
        assert!(
            <<O::Digest as Digest>::OutputSize as typenum::marker_traits::Unsigned>::USIZE * 2
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
            oid: O::null(),
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

#[test]
fn test_abbrev_hg_object_id() {
    let hex = "123456789abcdef00123456789abcdefedcba987";
    for len in 1..40 {
        let abbrev = HgObjectId([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0xed, 0xcb, 0xa9, 0x87,
        ])
        .abbrev(len);
        let result = format!("{}", abbrev);
        assert_eq!(&result, &hex[..len]);

        let abbrev2 = Abbrev::<HgObjectId>::from_str(&result).unwrap();
        assert_eq!(abbrev, abbrev2);
    }

    assert_ne!(
        Abbrev::<HgObjectId>::from_str("123").unwrap(),
        Abbrev::<HgObjectId>::from_str("124").unwrap()
    );
    assert_eq!(
        Abbrev::<HgObjectId>::from_str("123a").unwrap(),
        Abbrev::<HgObjectId>::from_str("123A").unwrap()
    );
}

oid_type!(GitObjectId for Sha1);
oid_type!(HgObjectId for Sha1);
