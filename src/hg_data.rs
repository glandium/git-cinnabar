/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::io::Write;

use bstr::{BStr, ByteSlice};
use derive_more::Debug;
use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::hg::{HgFileId, HgObjectId};
use crate::oid::ObjectId;
use crate::util::{FromBytes, SliceExt};

// TODO: This doesn't actually need to be a regexp
static WHO_RE: Lazy<Regex> = Lazy::new(|| Regex::new("^(?-u)(.*?) ?(?:<(.*?)>)").unwrap());

#[derive(Clone)]
pub struct GitAuthorship<B: AsRef<[u8]>>(pub B);

#[derive(Clone)]
pub struct HgAuthorship<B: AsRef<[u8]>> {
    pub author: B,
    pub timestamp: B,
    pub utcoffset: B,
}

#[derive(Clone)]
pub struct HgCommitter<B: AsRef<[u8]>>(pub B);

#[derive(Debug)]
struct Authorship<'a> {
    #[debug("{}", name.as_bstr())]
    name: Cow<'a, [u8]>,
    #[debug("{}", email.as_bstr())]
    email: Cow<'a, [u8]>,
    timestamp: u64,
    utcoffset: i32,
}

fn utcoffset_from_git_tz(tz: i32) -> i32 {
    let sign = -tz.signum();
    let tz = tz.abs();
    let utcoffset = (tz / 100) * 60 + (tz % 100);
    sign * utcoffset * 60
}

impl<'a, B: AsRef<[u8]>> From<&'a GitAuthorship<B>> for Authorship<'a> {
    fn from(a: &'a GitAuthorship<B>) -> Self {
        // We don't ever expect a git `who` information not to match the
        // split+regexp, as git is very conservative in what it accepts.
        let [who, timestamp, tz] = a.0.as_ref().rsplitn_exact(b' ').unwrap();
        let caps = WHO_RE.captures(who).unwrap();
        let tz = i32::from_bytes(tz).unwrap();
        let utcoffset = utcoffset_from_git_tz(tz);
        Authorship {
            name: Cow::Borrowed(caps.get(1).unwrap().as_bytes()),
            email: Cow::Borrowed(caps.get(2).unwrap().as_bytes()),
            timestamp: u64::from_bytes(timestamp).unwrap(),
            utcoffset,
        }
    }
}

impl<'a> From<Authorship<'a>> for GitAuthorship<Box<[u8]>> {
    fn from(a: Authorship<'a>) -> Self {
        let sign = if a.utcoffset.is_positive() { '-' } else { '+' };
        let utcoffset = a.utcoffset.abs() / 60;
        let mut result = Vec::new();
        result.extend_from_slice(&a.name);
        result.extend_from_slice(b" <");
        result.extend_from_slice(&a.email);
        result.extend_from_slice(b"> ");
        write!(
            &mut result,
            "{} {}{:02}{:02}",
            a.timestamp,
            sign,
            utcoffset / 60,
            utcoffset % 60
        )
        .unwrap();
        GitAuthorship(result.into())
    }
}

fn normalize_hg_author(author: &[u8]) -> (Cow<[u8]>, Cow<[u8]>) {
    fn cleanup(s: &BStr) -> Cow<[u8]> {
        if s.find_byteset(b"<>").is_some() {
            let mut s = s.to_vec();
            s.retain(|&b| b != b'<' && b != b'>');
            Cow::Owned(s)
        } else {
            Cow::Borrowed(s)
        }
    }
    let author = author.as_bstr();
    let (name, mail) = if let Some(caps) = WHO_RE.captures(author) {
        (
            caps.get(1).unwrap().as_bytes().as_bstr(),
            caps.get(2).unwrap().as_bytes().as_bstr(),
        )
    } else if author.find_byte(b'@').is_some() {
        (b"".as_bstr(), author)
    } else {
        (author, b"".as_bstr())
    };
    (cleanup(name), cleanup(mail))
}

impl<'a, B: AsRef<[u8]>> From<&'a HgAuthorship<B>> for Authorship<'a> {
    fn from(a: &'a HgAuthorship<B>) -> Self {
        let (name, email) = normalize_hg_author(a.author.as_ref());
        let timestamp = u64::from_bytes(a.timestamp.as_ref()).unwrap();
        let utcoffset = i32::from_bytes(a.utcoffset.as_ref()).unwrap();
        Authorship {
            name,
            email,
            timestamp,
            utcoffset,
        }
    }
}

impl<'a> From<Authorship<'a>> for HgAuthorship<Box<[u8]>> {
    fn from(a: Authorship<'a>) -> Self {
        let author = if a.name.is_empty() {
            let mut result = Vec::with_capacity(a.email.len() + 2);
            result.push(b'<');
            result.extend_from_slice(&a.email);
            result.push(b'>');
            result.into()
        } else if a.email.is_empty() {
            a.name.into_owned().into()
        } else {
            let mut result = Vec::with_capacity(a.name.len() + a.email.len() + 3);
            result.extend_from_slice(&a.name);
            result.extend_from_slice(b" <");
            result.extend_from_slice(&a.email);
            result.push(b'>');
            result.into()
        };
        let timestamp = a.timestamp.to_string().into_bytes().into();
        let utcoffset = a.utcoffset.to_string().into_bytes().into();
        HgAuthorship {
            author,
            timestamp,
            utcoffset,
        }
    }
}

impl<'a, B: AsRef<[u8]>> From<&'a HgCommitter<B>> for Authorship<'a> {
    fn from(a: &'a HgCommitter<B>) -> Self {
        let [author, timestamp, utcoffset] = a.0.as_ref().rsplitn_exact(b' ').unwrap();
        let (name, email) = normalize_hg_author(author);
        let timestamp = u64::from_bytes(timestamp).unwrap();
        // The UTC offset in mercurial author info is in seconds, formatted as
        // %d. It also has an opposite sign compared to traditional UTC offsets.
        // However, committer info stored in mercurial by hg-git can have
        // git-style UTC offsets, in the form [+-]hhmm.

        // When what we have is in the form +xxxx or -0yyy, it is obviously the
        // latter. When it's -1yyy, it could be either, so we assume th at a
        // valid UTC offset is always a multiple of 15 minutes. By that
        // definition, a number between -1000 and -1800 can't be simultaneously
        // a valid UTC offset in seconds and a valid UTC offset in hhmm form.

        // (cf. https://en.wikipedia.org/wiki/List_of_UTC_time_offsets lists
        // there exist a few 15-minutes aligned time zones, but they don't match
        // anything that could match here anyways, but just in case someone one
        // day creates one, assume it won't be finer grained)
        let utcoffset_num = i32::from_bytes(utcoffset).unwrap();
        let is_git = match utcoffset {
            [b'+', ..] | [b'-', b'0', ..] => true,
            [b'-', b'1', ..]
                if utcoffset_num > -1800
                    && utcoffset_num % 900 != 0
                    && (utcoffset_num % 100) % 15 == 0 =>
            {
                true
            }
            _ => false,
        };
        let utcoffset = if is_git {
            utcoffset_from_git_tz(utcoffset_num)
        } else {
            utcoffset_num
        };
        Authorship {
            name,
            email,
            timestamp,
            utcoffset,
        }
    }
}

impl<'a> From<Authorship<'a>> for HgCommitter<Box<[u8]>> {
    fn from(a: Authorship<'a>) -> Self {
        let a = HgAuthorship::from(a);
        HgCommitter(
            [
                a.author.as_ref(),
                a.timestamp.as_ref(),
                a.utcoffset.as_ref(),
            ]
            .join(&b' ')
            .into(),
        )
    }
}

impl<B: AsRef<[u8]>> From<GitAuthorship<B>> for HgAuthorship<Box<[u8]>> {
    fn from(a: GitAuthorship<B>) -> Self {
        Authorship::from(&a).into()
    }
}

impl<B: AsRef<[u8]>> From<GitAuthorship<B>> for HgCommitter<Box<[u8]>> {
    fn from(a: GitAuthorship<B>) -> Self {
        Authorship::from(&a).into()
    }
}

impl<B: AsRef<[u8]>> From<HgAuthorship<B>> for GitAuthorship<Box<[u8]>> {
    fn from(a: HgAuthorship<B>) -> Self {
        Authorship::from(&a).into()
    }
}

impl<B: AsRef<[u8]>> From<HgCommitter<B>> for GitAuthorship<Box<[u8]>> {
    fn from(a: HgCommitter<B>) -> Self {
        Authorship::from(&a).into()
    }
}

//TODO: more tests that don't exist in python.
#[test]
fn test_authorship_from_hg() {
    // Simple common cases
    let a = Authorship::from(&HgAuthorship {
        author: "Foo Bar",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"Foo Bar".as_bstr());
    assert_eq!(a.email.as_bstr(), b"".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "foo@bar",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "<foo@bar>",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "Foo Bar <foo@bar>",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"Foo Bar".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    // Corner cases that exist in the wild, and that may or may not be
    // handled the nicest way they could, but changing that now would affect
    // the corresponding git commit sha1.
    let a = Authorship::from(&HgAuthorship {
        author: "Foo Bar<foo@bar>",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"Foo Bar".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "Foo Bar  <foo@bar>",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"Foo Bar ".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "Foo Bar <foo@bar>, Bar Baz <bar@baz>",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"Foo Bar".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "Foo Bar (foo@bar)",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"".as_bstr());
    assert_eq!(a.email.as_bstr(), b"Foo Bar (foo@bar)".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "<Foo Bar> foo@bar",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"".as_bstr());
    assert_eq!(a.email.as_bstr(), b"Foo Bar".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "\"Foo Bar <foo@bar>\"",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.name.as_bstr(), b"\"Foo Bar".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&HgAuthorship {
        author: "Foo Bar <foo@bar>",
        timestamp: "1482880019",
        utcoffset: "3600",
    });
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, 3600);

    let a = Authorship::from(&HgCommitter("Foo Bar <foo@bar> 1482880019 3600"));
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, 3600);

    let a = Authorship::from(&HgCommitter("Foo Bar <foo@bar> 1482880019 -1100"));
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, 39600);

    let a = Authorship::from(&HgCommitter("Foo Bar <foo@bar> 1482880019 -3600"));
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, -3600);
}

#[test]
fn test_authorship_from_git() {
    let a = Authorship::from(&GitAuthorship(b"Foo Bar <foo@bar> 0 +0000"));
    assert_eq!(a.name.as_bstr(), b"Foo Bar".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&GitAuthorship(b"Foo Bar  <foo@bar> 0 +0000"));
    assert_eq!(a.name.as_bstr(), b"Foo Bar ".as_bstr());
    assert_eq!(a.email.as_bstr(), b"foo@bar".as_bstr());

    let a = Authorship::from(&GitAuthorship(b"Foo Bar <foo@bar> 1482880019 -0100"));
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, 3600);

    let a = Authorship::from(&GitAuthorship(b"Foo Bar <foo@bar> 1482880019 +0200"));
    assert_eq!(a.timestamp, 1482880019);
    assert_eq!(a.utcoffset, -7200);
}

#[test]
fn test_authorship_to_hg() {
    let a = HgAuthorship::from(GitAuthorship("Foo Bar <foo@bar> 1482880019 +0200"));
    assert_eq!(a.author.as_bstr(), b"Foo Bar <foo@bar>".as_bstr());
    assert_eq!(a.timestamp.as_bstr(), b"1482880019".as_bstr());
    assert_eq!(a.utcoffset.as_bstr(), b"-7200".as_bstr());

    for author in [
        "Foo Bar",
        "<foo@bar>",
        "Foo Bar <foo@bar>",
        "Foo Bar  <foo@bar>",
    ] {
        let a = HgAuthorship {
            author,
            timestamp: "0",
            utcoffset: "0",
        };
        let a = HgAuthorship::from(Authorship::from(&a));
        assert_eq!(a.author.as_bstr(), author.as_bytes().as_bstr());
    }
}

#[test]
fn test_authorship_to_git() {
    let a = GitAuthorship::from(HgAuthorship {
        author: "Foo Bar",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.0.as_bstr(), b"Foo Bar <> 0 +0000".as_bstr());

    let a = GitAuthorship::from(HgAuthorship {
        author: "foo@bar",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.0.as_bstr(), b" <foo@bar> 0 +0000".as_bstr());

    let a = GitAuthorship::from(HgAuthorship {
        author: "Foo Bar <foo@bar>",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.0.as_bstr(), b"Foo Bar <foo@bar> 0 +0000".as_bstr());

    let a = GitAuthorship::from(HgAuthorship {
        author: "Foo Bar  <foo@bar>",
        timestamp: "0",
        utcoffset: "0",
    });
    assert_eq!(a.0.as_bstr(), b"Foo Bar  <foo@bar> 0 +0000".as_bstr());

    let a = GitAuthorship::from(HgAuthorship {
        author: "Foo Bar <foo@bar>",
        timestamp: "1482880019",
        utcoffset: "-7200",
    });
    assert_eq!(
        a.0.as_bstr(),
        b"Foo Bar <foo@bar> 1482880019 +0200".as_bstr()
    );
}

pub fn hash_data(
    parent1: Option<HgObjectId>,
    parent2: Option<HgObjectId>,
    data: &[u8],
) -> HgObjectId {
    let mut hash = HgObjectId::create();
    let parent1 = parent1.unwrap_or(HgObjectId::NULL);
    let parent2 = parent2.unwrap_or(HgObjectId::NULL);
    let mut parents = [parent1, parent2];
    parents.sort();
    hash.update(parents[0].as_raw_bytes());
    hash.update(parents[1].as_raw_bytes());
    hash.update(data);
    hash.finalize()
}

pub fn find_file_parents(
    node: HgFileId,
    parent1: Option<HgFileId>,
    parent2: Option<HgFileId>,
    data: &[u8],
) -> Option<[Option<HgFileId>; 2]> {
    for [parent1, parent2] in [
        [parent1, parent2],
        // In some cases, only one parent is stored in a merge, because
        // the other parent is actually an ancestor of the first one, but
        // checking that is likely more expensive than to check if the
        // sha1 matches with either parent.
        [parent1, None],
        [parent2, None],
        // Some mercurial versions store the first parent twice in merges.
        [parent1, parent1],
        // And because we don't necessarily have the same parent order as
        // what mercurial recorded, it might be the second parent twice.
        [parent2, parent2],
        // As last resord, try without any parents.
        [None, None],
    ] {
        if hash_data(parent1.map(Into::into), parent2.map(Into::into), data) == node {
            return Some([parent1, parent2]);
        }
    }
    None
}
