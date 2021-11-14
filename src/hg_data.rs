/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use bstr::ByteSlice;

use crate::libgit::split_ident;
use crate::util::{FromBytes, ImmutBString, ToBoxed};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Authorship {
    #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
    name: ImmutBString,
    #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
    email: ImmutBString,
    timestamp: u64,
    utcoffset: i32,
}

impl Authorship {
    pub fn from_git_bytes(s: &[u8]) -> Self {
        let ident = split_ident(s.as_bstr()).unwrap();
        let utcoffset = i32::from_bytes(ident.tz).unwrap();
        let sign = -utcoffset.signum();
        let utcoffset = utcoffset.abs();
        let utcoffset = (utcoffset / 100) * 60 + (utcoffset % 100);
        Authorship {
            name: ident.name.to_boxed(),
            email: ident.mail.to_boxed(),
            timestamp: u64::from_bytes(ident.date).unwrap(),
            utcoffset: sign * utcoffset * 60,
        }
    }

    pub fn to_hg_parts(&self) -> (ImmutBString, ImmutBString, ImmutBString) {
        let who = if self.name.is_empty() {
            let mut who = vec![b'<'];
            who.extend_from_slice(&self.email);
            who.push(b'>');
            who.into()
        } else if self.email.is_empty() {
            self.name.clone()
        } else {
            let mut who = Vec::new();
            who.extend_from_slice(&self.name);
            who.extend_from_slice(b" <");
            who.extend_from_slice(&self.email);
            who.push(b'>');
            who.into()
        };
        (
            who,
            self.timestamp.to_string().into_bytes().into(),
            self.utcoffset.to_string().into_bytes().into(),
        )
    }

    pub fn to_hg_bytes(&self) -> ImmutBString {
        let (who, timestamp, utcoffset) = self.to_hg_parts();
        let mut who = who.to_vec();
        who.push(b' ');
        who.extend_from_slice(&timestamp);
        who.push(b' ');
        who.extend_from_slice(&utcoffset);
        who.into()
    }
}

//TODO: more tests from python, and more tests that don't exist in python.
#[test]
fn test_authorship_from_git() {
    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 0 +0000");
    assert_eq!(&*a.name, b"Foo Bar");
    assert_eq!(&*a.email, b"foo@bar");

    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 1482880019 -0100");
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, 3600);

    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 1482880019 +0200");
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, -7200);
}
