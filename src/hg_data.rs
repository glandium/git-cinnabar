/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::os::raw::{c_char, c_int};
use std::ptr;

use crate::libgit::{ident_split, split_ident_line};
use crate::util::FromBytes;

pub struct Authorship {
    name: Vec<u8>,
    email: Vec<u8>,
    timestamp: u64,
    utcoffset: i32,
}

impl Authorship {
    pub fn from_git_bytes(s: &[u8]) -> Self {
        let mut split = ident_split {
            name_begin: ptr::null(),
            name_end: ptr::null(),
            mail_begin: ptr::null(),
            mail_end: ptr::null(),
            date_begin: ptr::null(),
            date_end: ptr::null(),
            tz_begin: ptr::null(),
            tz_end: ptr::null(),
        };
        unsafe {
            assert!(
                split_ident_line(&mut split, s.as_ptr() as *const c_char, s.len() as c_int) == 0
            );

            unsafe fn to_slice<'a>(begin: *const c_char, end: *const c_char) -> &'a [u8] {
                assert!(!begin.is_null() && !end.is_null());
                let size = end.offset_from(begin);
                std::slice::from_raw_parts(begin as *const u8, size as usize)
            }

            let utcoffset = to_slice(split.tz_begin, split.tz_end);
            let utcoffset = i32::from_bytes(utcoffset).unwrap();
            let sign = -utcoffset.signum();
            let utcoffset = utcoffset.abs();
            let utcoffset = (utcoffset / 100) * 60 + (utcoffset % 100);
            Authorship {
                name: to_slice(split.name_begin, split.name_end).to_owned(),
                email: to_slice(split.mail_begin, split.mail_end).to_owned(),
                timestamp: u64::from_bytes(to_slice(split.date_begin, split.date_end)).unwrap(),
                utcoffset: sign * utcoffset * 60,
            }
        }
    }

    pub fn to_hg_parts(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let who = if self.name.is_empty() {
            let mut who = vec![b'<'];
            who.extend_from_slice(&self.email);
            who.push(b'>');
            who
        } else if self.email.is_empty() {
            self.name.clone()
        } else {
            let mut who = Vec::new();
            who.extend_from_slice(&self.name);
            who.extend_from_slice(b" <");
            who.extend_from_slice(&self.email);
            who.push(b'>');
            who
        };
        (
            who,
            self.timestamp.to_string().into_bytes(),
            self.utcoffset.to_string().into_bytes(),
        )
    }

    pub fn to_hg_bytes(&self) -> Vec<u8> {
        let (mut who, mut timestamp, mut utcoffset) = self.to_hg_parts();
        who.push(b' ');
        who.append(&mut timestamp);
        who.push(b' ');
        who.append(&mut utcoffset);
        who
    }
}

//TODO: more tests from python, and more tests that don't exist in python.
#[test]
fn test_authorship_from_git() {
    // The test strings are \n-suffixed because that's how they would appear
    // in context in git commits, and split_ident_line doesn't stop at the
    // last character of the slice if the data section contains digit
    // characters after the string.
    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 0 +0000\n");
    assert_eq!(a.name, b"Foo Bar");
    assert_eq!(a.email, b"foo@bar");

    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 1482880019 -0100\n");
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, 3600);

    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 1482880019 +0200\n");
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, -7200);
}
