/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::fmt;
use std::os::raw::{c_char, c_int};
use std::str::{self, FromStr};

use libc::FILE;
use sha1::{Digest, Sha1};

use crate::libgit::{child_process, get_note, notes_tree, object_id, strbuf};

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct hg_object_id([u8; 20]);

//TODO: Share code with object_id.
impl hg_object_id {
    pub fn create() -> hg_object_id_creator {
        hg_object_id_creator(Sha1::new())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub const fn null() -> Self {
        hg_object_id([0; 20])
    }
}

impl fmt::Display for hg_object_id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut hex = [0u8; 40];
        hex::encode_to_slice(&self.0, &mut hex).unwrap();
        f.write_str(str::from_utf8(&hex).unwrap())
    }
}

impl FromStr for hg_object_id {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = hg_object_id([0; 20]);
        hex::decode_to_slice(s, &mut result.0)?;
        Ok(result)
    }
}

#[allow(non_camel_case_types)]
pub struct hg_object_id_creator(Sha1);

impl hg_object_id_creator {
    pub fn result(self) -> hg_object_id {
        let mut result = hg_object_id([0; 20]);
        result.0.copy_from_slice(self.0.result().as_slice());
        result
    }

    pub fn input(&mut self, data: &[u8]) {
        self.0.input(data)
    }
}

pub struct AbbrevHgObjectId {
    oid: hg_object_id,
    len: usize,
}

impl fmt::Display for AbbrevHgObjectId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut hex = [0u8; 40];
        let len = self.len / 2;
        hex::encode_to_slice(&self.oid.0[..len], &mut hex[..len * 2]).unwrap();
        if self.len % 2 == 1 {
            let partial = [self.oid.0[len] & 0xf0];
            hex::encode_to_slice(&partial, &mut hex[len * 2..self.len + 1]).unwrap();
        }
        f.write_str(str::from_utf8(&hex[..self.len]).unwrap())
    }
}

impl fmt::Debug for AbbrevHgObjectId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HgOid({})", self)
    }
}

impl FromStr for AbbrevHgObjectId {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 40 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut result = AbbrevHgObjectId {
            oid: hg_object_id([0; 20]),
            len: s.len(),
        };
        let s = if s.len() % 2 == 0 {
            Cow::Borrowed(s)
        } else {
            Cow::Owned(s.to_string() + "0")
        };
        hex::decode_to_slice(s.as_bytes(), &mut result.oid.0[..s.len() / 2])?;
        Ok(result)
    }
}

impl PartialEq for AbbrevHgObjectId {
    fn eq(&self, other: &Self) -> bool {
        if self.len == other.len && self.oid.0[..self.len / 2] == other.oid.0[..self.len / 2] {
            if self.len % 2 == 0 {
                return true;
            } else if self.oid.0[self.len / 2] & 0xf0 == other.oid.0[self.len / 2] & 0xf0 {
                return true;
            }
        }
        false
    }
}

#[test]
fn test_abbrev_hg_object_id() {
    let hex = "123456789abcdef00123456789abcdefedcba987";
    for len in 1..40 {
        let abbrev = AbbrevHgObjectId {
            oid: hg_object_id([
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0xed, 0xcb, 0xa9, 0x87,
            ]),
            len,
        };
        let result = format!("{}", abbrev);
        assert_eq!(&result, &hex[..len]);

        let abbrev2 = AbbrevHgObjectId::from_str(&result).unwrap();
        assert_eq!(abbrev, abbrev2);
    }

    assert_ne!(
        AbbrevHgObjectId::from_str("123").unwrap(),
        AbbrevHgObjectId::from_str("124").unwrap()
    );
    assert_eq!(
        AbbrevHgObjectId::from_str("123a").unwrap(),
        AbbrevHgObjectId::from_str("123A").unwrap()
    );
}

extern "C" {
    pub static mut git2hg: git_notes_tree;
    pub static mut hg2git: hg_notes_tree;
    pub static mut files_meta: hg_notes_tree;

    pub fn ensure_notes(t: *mut notes_tree);

    pub fn get_note_hg(notes: *mut notes_tree, oid: *const hg_object_id) -> *const object_id;

    pub fn resolve_hg(t: *mut notes_tree, oid: *const hg_object_id, len: usize)
        -> *const object_id;

    pub fn generate_manifest(oid: *const object_id) -> *const strbuf;
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct git_notes_tree(notes_tree);

impl git_notes_tree {
    pub fn get_note(&mut self, oid: &object_id) -> Option<object_id> {
        unsafe {
            ensure_notes(&mut self.0);
            get_note(&mut self.0, oid).as_ref().cloned()
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct hg_notes_tree(notes_tree);

impl hg_notes_tree {
    pub fn get_note(&mut self, oid: &hg_object_id) -> Option<object_id> {
        unsafe {
            ensure_notes(&mut self.0);
            get_note_hg(&mut self.0, oid).as_ref().cloned()
        }
    }

    pub fn get_note_abbrev(&mut self, oid: &AbbrevHgObjectId) -> Option<object_id> {
        unsafe {
            ensure_notes(&mut self.0);
            resolve_hg(&mut self.0, &oid.oid, oid.len)
                .as_ref()
                .cloned()
        }
    }
}

impl AbbrevHgObjectId {
    pub fn to_git(&self) -> Option<object_id> {
        unsafe { hg2git.get_note_abbrev(self) }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct hg_connection_stdio {
    pub out: *mut FILE,
    pub is_remote: c_int,
}

extern "C" {
    pub fn hg_connect_stdio(
        userhost: *const c_char,
        port: *const c_char,
        path: *const c_char,
        flags: c_int,
    ) -> *mut child_process;

    pub fn stdio_finish(conn: *mut child_process) -> c_int;
}
