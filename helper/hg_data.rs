/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::util::{FromBytes, SliceExt};

// TODO: This doesn't actually need to be a regexp
static WHO_RE: Lazy<Regex> = Lazy::new(|| Regex::new("^(?-u)(.*?) ?(?:<(.*?)>)").unwrap());

pub struct Authorship {
    name: Vec<u8>,
    email: Vec<u8>,
    timestamp: u64,
    utcoffset: i32,
}

impl Authorship {
    pub fn from_git_bytes(s: &[u8]) -> Self {
        // We don't ever expect a git `who` information not to match the
        // split+regexp, as git is very conservative in what it accepts.
        let (who, timestamp, utcoffset) = s.rsplit3(b' ').unwrap();
        let caps = WHO_RE.captures(who).unwrap();
        let utcoffset = i32::from_bytes(utcoffset).unwrap();
        let sign = -utcoffset.signum();
        let utcoffset = utcoffset.abs();
        let utcoffset = (utcoffset / 100) * 60 + (utcoffset % 100);
        Authorship {
            name: caps.get(1).unwrap().as_bytes().to_owned(),
            email: caps.get(2).unwrap().as_bytes().to_owned(),
            timestamp: u64::from_bytes(timestamp).unwrap(),
            utcoffset: sign * utcoffset * 60,
        }
    }

    pub fn to_hg_parts(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let who = if self.name.is_empty() {
            let mut who = vec![b'<'];
            who.extend_from_slice(&self.email);
            who.push(b'>');
            who
        } else if self.email.is_empty() {
            self.name.to_owned()
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
    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 0 +0000");
    assert_eq!(a.name, b"Foo Bar");
    assert_eq!(a.email, b"foo@bar");

    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 1482880019 -0100");
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, 3600);

    let a = Authorship::from_git_bytes(b"Foo Bar <foo@bar> 1482880019 +0200");
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, -7200);
}
