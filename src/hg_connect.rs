/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::{stderr, BufReader, Read, Write};
use std::str::FromStr;
use std::time::Instant;

use bstr::{BStr, ByteSlice};
use either::Either;
use itertools::Itertools;
use once_cell::sync::OnceCell;
use percent_encoding::{percent_decode, percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rand::prelude::IteratorRandom;
use sha1::{Digest, Sha1};
use url::Url;

use crate::cinnabar::GitChangesetId;
use crate::git::{CommitId, GitObjectId};
use crate::hg::HgChangesetId;
use crate::hg_bundle::{BundleConnection, BundleReader, BundleSpec};
use crate::hg_connect_http::{get_http_connection, HttpRequest};
use crate::hg_connect_stdio::get_stdio_connection;
use crate::libgit::{
    die, http_follow_config, remote, resolve_ref, rev_list, rev_list_with_parents,
};
use crate::oid::ObjectId;
use crate::store::{has_metadata, merge_metadata, store_changegroup, Dag, Store};
use crate::util::{
    DurationExt, FromBytes, ImmutBString, OsStrExt, PrefixWriter, SliceExt, ToBoxed,
};
use crate::{
    check_enabled, free_refs, get_config_remote, get_next_ref, get_ref_name, get_stale_refs,
    graft_config_enabled, logging, r#ref, Checks,
};

pub enum HgArgValue<'a> {
    String(&'a str),
    ChangesetArray(&'a [HgChangesetId]),
}

impl HgArgValue<'_> {
    pub fn as_string(&self) -> Cow<str> {
        match self {
            HgArgValue::String(s) => Cow::Borrowed(s),
            HgArgValue::ChangesetArray(a) => a.iter().join(" ").into(),
        }
    }
}

impl<'a> From<&'a str> for HgArgValue<'a> {
    fn from(value: &'a str) -> Self {
        HgArgValue::String(value)
    }
}

impl<'a> From<&'a String> for HgArgValue<'a> {
    fn from(value: &'a String) -> Self {
        HgArgValue::String(value)
    }
}

impl<'a> From<&'a [HgChangesetId]> for HgArgValue<'a> {
    fn from(value: &'a [HgChangesetId]) -> Self {
        HgArgValue::ChangesetArray(value)
    }
}

pub struct OneHgArg<'a> {
    pub name: &'a str,
    pub value: HgArgValue<'a>,
}

pub struct HgArgs<'a> {
    pub args: &'a [OneHgArg<'a>],
    pub extra_args: Option<&'a [OneHgArg<'a>]>,
}

macro_rules! args {
    ($($n:ident : $v:expr,)* $(*: $a:expr)?) => {
        HgArgs {
            args: $crate::hg_connect::args!(@args $($n:$v),*),
            extra_args: $crate::hg_connect::args!(@extra $($a)?),
        }
    };
    ($($n:ident : $v:expr),*) => { $crate::hg_connect::args!($($n:$v,)*) };
    (@args $($n:ident : $v:expr),*) => {&[
        $(OneHgArg { name: stringify!($n), value: $crate::hg_connect::HgArgValue::from($v) }),*
    ]};
    (@extra) => { None };
    (@extra $a:expr) => { Some($a) };
}
pub(crate) use args;

#[derive(Default)]
pub struct HgCapabilities {
    capabilities: Vec<(ImmutBString, ImmutBString)>,
}

impl HgCapabilities {
    /* Split the list of capabilities a mercurial server returned. Also url-decode
     * the bundle2 value (TODO: in place). */
    pub fn new_from(buf: &[u8]) -> Self {
        let mut capabilities = Vec::new();
        for item in buf.split(|&b| b == b' ') {
            let (name, value) = match item.find_byte(b'=') {
                Some(off) => {
                    let (name, value) = item.split_at(off);
                    (name, &value[1..])
                }
                None => (item, &b""[..]),
            };
            capabilities.push((
                name.to_boxed(),
                if name == b"bundle2" {
                    percent_decode(value).collect_vec().into()
                } else {
                    value.to_boxed()
                },
            ));
        }
        HgCapabilities { capabilities }
    }

    pub fn get_capability(&self, needle: &[u8]) -> Option<&BStr> {
        for (name, value) in self.capabilities.iter() {
            if &**name == needle {
                return Some(value.as_bstr());
            }
        }
        None
    }
}

pub enum UnbundleResponse<'a> {
    Raw(ImmutBString),
    Bundlev2(Box<dyn Read + 'a>),
}

pub trait HgConnectionBase {
    fn get_url(&self) -> Option<&Url> {
        None
    }

    fn get_capability(&self, _name: &[u8]) -> Option<&BStr> {
        None
    }

    fn require_capability(&self, name: &[u8]) -> &BStr {
        if let Some(cap) = self.get_capability(name) {
            cap
        } else {
            die!(
                "Mercurial repository doesn't support the required \"{}\" capability.",
                name.as_bstr()
            );
        }
    }

    fn sample_size(&self) -> usize {
        100
    }

    fn sync(&mut self) {}
}

pub trait HgWireConnection: HgConnectionBase {
    fn simple_command(&mut self, command: &str, args: HgArgs) -> ImmutBString;

    fn changegroup_command<'a>(
        &'a mut self,
        command: &str,
        args: HgArgs,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString>;

    fn push_command(&mut self, input: File, command: &str, args: HgArgs) -> UnbundleResponse;
}

pub trait HgConnection: HgConnectionBase {
    fn getbundle<'a>(
        &'a mut self,
        _heads: &[HgChangesetId],
        _common: &[HgChangesetId],
        _bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
        unimplemented!();
    }

    fn unbundle(&mut self, _heads: Option<&[HgChangesetId]>, _input: File) -> UnbundleResponse {
        unimplemented!();
    }

    fn pushkey(&mut self, _namespace: &str, _key: &str, _old: &str, _new: &str) -> ImmutBString {
        unimplemented!();
    }

    fn lookup(&mut self, _key: &str) -> ImmutBString {
        unimplemented!();
    }

    fn clonebundles(&mut self) -> ImmutBString {
        unimplemented!();
    }

    fn cinnabarclone(&mut self) -> ImmutBString {
        unimplemented!();
    }
}

impl<T: HgWireConnection> HgConnection for T {
    fn getbundle<'a>(
        &'a mut self,
        heads: &[HgChangesetId],
        common: &[HgChangesetId],
        bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
        let mut args = Vec::new();
        args.push(OneHgArg {
            name: "heads",
            value: heads.into(),
        });
        args.push(OneHgArg {
            name: "common",
            value: common.into(),
        });
        if let Some(caps) = bundle2caps {
            if !caps.is_empty() {
                args.push(OneHgArg {
                    name: "bundlecaps",
                    value: caps.into(),
                });
            }
        }
        self.changegroup_command("getbundle", args!(*: &args[..]))
    }

    fn unbundle(&mut self, heads: Option<&[HgChangesetId]>, input: File) -> UnbundleResponse {
        let heads = if let Some(heads) = heads {
            if self.get_capability(b"unbundlehash").is_none() {
                Either::Left(heads)
            } else {
                let mut hash = Sha1::new();
                for h in heads.iter().sorted().dedup() {
                    hash.update(h.as_raw_bytes());
                }
                Either::Right(format!("{} {:x}", hex::encode("hashed"), hash.finalize()))
            }
        } else {
            Either::Right(hex::encode("force"))
        };
        let heads = heads.as_ref().either(|&l| l.into(), HgArgValue::from);

        self.push_command(input, "unbundle", args!(heads: heads))
    }

    fn pushkey(&mut self, namespace: &str, key: &str, old: &str, new: &str) -> ImmutBString {
        //TODO: handle the response being a mix of return code and output
        self.simple_command(
            "pushkey",
            args!(namespace: namespace, key: key, old: old, new: new,),
        )
    }

    fn lookup(&mut self, key: &str) -> ImmutBString {
        self.simple_command("lookup", args!(key: key))
    }

    fn clonebundles(&mut self) -> ImmutBString {
        self.simple_command("clonebundles", args!())
    }

    fn cinnabarclone(&mut self) -> ImmutBString {
        self.simple_command("cinnabarclone", args!())
    }
}

pub trait HgRepo: HgConnection {
    fn branchmap(&mut self) -> ImmutBString;

    fn heads(&mut self) -> ImmutBString;

    fn bookmarks(&mut self) -> ImmutBString;

    fn phases(&mut self) -> ImmutBString;

    fn known(&mut self, _nodes: &[HgChangesetId]) -> Box<[bool]>;
}

struct LogWireConnection<C: HgWireConnection> {
    logging_enabled: bool,
    conn: C,
}

impl<C: HgWireConnection> LogWireConnection<C> {
    fn new(conn: C, logging_enabled: bool) -> Self {
        LogWireConnection {
            logging_enabled,
            conn,
        }
    }

    fn log(command: &str, f: impl FnOnce(log::Level) -> String) {
        let target = format!("wire::{}", command);
        let level = logging::max_log_level(&target, log::Level::Debug).to_level();
        if let Some(level) = level {
            log!(target: &target, level, "{}", f(level));
        }
    }

    fn log_command(command: &str, args: &HgArgs) {
        Self::log(command, |level| {
            let mut data = String::new();
            for OneHgArg { name, value } in args
                .args
                .iter()
                .chain(args.extra_args.into_iter().flatten())
            {
                if !data.is_empty() {
                    data.push(' ');
                }
                data.push_str(name);
                data.push_str(": ");
                match value {
                    HgArgValue::String(s) => data.push_str(s),
                    HgArgValue::ChangesetArray(a) => {
                        data.push('[');
                        if !a.is_empty() {
                            if level == log::Level::Debug {
                                data.push_str(&a.len().to_string());
                                data.push_str(" changeset");
                                if a.len() > 1 {
                                    data.push('s');
                                }
                            } else {
                                for (n, cs) in a.iter().enumerate() {
                                    if n > 0 {
                                        data.push(' ');
                                    }
                                    data.push_str(&cs.to_string());
                                }
                            }
                        }
                        data.push(']');
                    }
                }
            }
            data
        });
    }
}

impl<C: HgWireConnection> HgConnectionBase for LogWireConnection<C> {
    fn get_url(&self) -> Option<&Url> {
        self.conn.get_url()
    }

    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        self.conn.get_capability(name)
    }

    fn require_capability(&self, name: &[u8]) -> &BStr {
        self.conn.require_capability(name)
    }

    fn sample_size(&self) -> usize {
        self.conn.sample_size()
    }

    fn sync(&mut self) {
        self.conn.sync();
    }
}

impl<C: HgWireConnection> HgWireConnection for LogWireConnection<C> {
    fn simple_command(&mut self, command: &str, args: HgArgs) -> ImmutBString {
        let mut start = None;
        if self.logging_enabled {
            start = check_enabled(Checks::TIME).then(Instant::now);
            Self::log_command(command, &args);
        }
        let result = self.conn.simple_command(command, args);
        if let Some(start) = start {
            Self::log(command, |_| {
                format!("{} elapsed.", start.elapsed().fuzzy_display())
            });
        }
        result
    }

    fn changegroup_command<'a>(
        &'a mut self,
        command: &str,
        args: HgArgs,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
        if self.logging_enabled {
            Self::log_command(command, &args);
        }
        self.conn.changegroup_command(command, args)
    }

    fn push_command(&mut self, input: File, command: &str, args: HgArgs) -> UnbundleResponse {
        if self.logging_enabled {
            Self::log_command(command, &args);
        }
        self.conn.push_command(input, command, args)
    }
}

struct CachedInfo {
    branchmap: ImmutBString,
    heads: ImmutBString,
    bookmarks: ImmutBString,
}

pub struct HgWired<C: HgWireConnection> {
    cached_info: OnceCell<CachedInfo>,
    conn: LogWireConnection<C>,
}

impl<C: HgWireConnection> HgWired<C> {
    pub fn new(conn: C) -> Self {
        const REQUIRED_CAPS: [&str; 2] = ["getbundle", "branchmap"];

        let logging_enabled = ["wire", "wire::*"]
            .into_iter()
            .any(|target| log_enabled!(target: target, log::Level::Debug));
        let conn = LogWireConnection::new(conn, logging_enabled);

        for cap in &REQUIRED_CAPS {
            conn.require_capability(cap.as_bytes());
        }

        HgWired {
            cached_info: OnceCell::new(),
            conn,
        }
    }

    fn cached_info(&mut self) -> &CachedInfo {
        self.cached_info.get_or_init(|| {
            let mut branchmap;
            let mut heads;
            let bookmarks;
            let conn = &mut self.conn;

            if conn.get_capability(b"batch").is_none() {
                // Get bookmarks first because if we get them last and they have been
                // updated after we got the heads, they may contain changesets we won't
                // be pulling.
                bookmarks = conn.simple_command("listkeys", args!(namespace: "bookmarks"));
                loop {
                    branchmap = conn.simple_command("branchmap", args!());
                    heads = conn.simple_command("heads", args!());
                    // Some heads in the branchmap can be non-heads topologically, and
                    // won't appear in the heads list, but if the opposite happens, then
                    // the repo was updated between both calls and we need to try again
                    // for coherency.
                    if heads
                        .split(|&b| b == b' ')
                        .collect::<HashSet<_>>()
                        .is_subset(
                            &ByteSlice::lines(&*branchmap)
                                .flat_map(|l| l.split(|&b| b == b' ').skip(1))
                                .collect::<HashSet<_>>(),
                        )
                    {
                        break;
                    }
                }
            } else {
                let out = conn.simple_command(
                    "batch",
                    args!(
                        cmds: "branchmap ;heads ;listkeys namespace=bookmarks",
                        *: &[]
                    ),
                );
                let split: [_; 3] = out.splitn_exact(b';').unwrap();
                branchmap = unescape_batched_output(split[0]);
                heads = unescape_batched_output(split[1]);
                bookmarks = unescape_batched_output(split[2]);
            }
            CachedInfo {
                branchmap,
                heads,
                bookmarks,
            }
        })
    }
}

impl<C: HgWireConnection> HgConnectionBase for HgWired<C> {
    fn get_url(&self) -> Option<&Url> {
        self.conn.get_url()
    }

    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        self.conn.get_capability(name)
    }

    fn sample_size(&self) -> usize {
        self.conn.sample_size()
    }

    fn sync(&mut self) {
        self.conn.sync();
    }
}

impl<C: HgWireConnection> HgConnection for HgWired<C> {
    fn getbundle<'a>(
        &'a mut self,
        heads: &[HgChangesetId],
        common: &[HgChangesetId],
        bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
        self.conn.getbundle(heads, common, bundle2caps)
    }

    fn unbundle(&mut self, heads: Option<&[HgChangesetId]>, input: File) -> UnbundleResponse {
        self.conn.unbundle(heads, input)
    }

    fn pushkey(&mut self, namespace: &str, key: &str, old: &str, new: &str) -> ImmutBString {
        self.conn.pushkey(namespace, key, old, new)
    }

    fn lookup(&mut self, key: &str) -> ImmutBString {
        self.conn.lookup(key)
    }

    fn clonebundles(&mut self) -> ImmutBString {
        self.conn.clonebundles()
    }

    fn cinnabarclone(&mut self) -> ImmutBString {
        self.conn.cinnabarclone()
    }
}

impl<C: HgWireConnection> HgRepo for HgWired<C> {
    fn branchmap(&mut self) -> ImmutBString {
        self.cached_info().branchmap.clone()
    }

    fn heads(&mut self) -> ImmutBString {
        self.cached_info().heads.clone()
    }

    fn bookmarks(&mut self) -> ImmutBString {
        self.cached_info().bookmarks.clone()
    }

    fn phases(&mut self) -> ImmutBString {
        self.conn
            .simple_command("listkeys", args!(namespace: "phases"))
    }

    fn known(&mut self, nodes: &[HgChangesetId]) -> Box<[bool]> {
        self.conn
            .simple_command(
                "known",
                args!(
                    nodes: nodes,
                    *: &[]
                ),
            )
            .iter()
            .map(|b| *b == b'1')
            .collect_vec()
            .into()
    }
}

fn unescape_batched_output(out: &[u8]) -> ImmutBString {
    // This will fail if `split` has more than 3 items.
    let mut start = 0;
    let mut out = out;
    let mut buf = Vec::new();
    loop {
        if let Some(colon) = out[start..].find_byte(b':') {
            let (before, after) = out.split_at(start + colon);
            let replace = match after.get(..2) {
                Some(b":e") => Some(b"="),
                Some(b":s") => Some(b";"),
                Some(b":o") => Some(b","),
                Some(b":c") => Some(b":"),
                // This is not supposed to happen, but just in case:
                // XXX: throw an error?
                _ => None,
            };
            if let Some(replace) = replace {
                buf.extend_from_slice(before);
                buf.extend_from_slice(replace);
                out = &after[2..];
                if out.is_empty() {
                    break;
                }
            } else {
                start += colon + 1;
            }
        } else {
            buf.extend_from_slice(out);
            break;
        }
    }
    buf.into()
}

#[test]
fn test_unescape_batched_output() {
    let buf = unescape_batched_output(b"");
    assert_eq!(buf.as_bstr(), b"".as_bstr());

    let buf = unescape_batched_output(b"abc");
    assert_eq!(buf.as_bstr(), b"abc".as_bstr());

    let buf = unescape_batched_output(b"abc:def");
    assert_eq!(buf.as_bstr(), b"abc:def".as_bstr());

    let buf = unescape_batched_output(b"abc:def:");
    assert_eq!(buf.as_bstr(), b"abc:def:".as_bstr());

    let buf = unescape_batched_output(b"abc:edef:");
    assert_eq!(buf.as_bstr(), b"abc=def:".as_bstr());

    let buf = unescape_batched_output(b"abc:edef:c");
    assert_eq!(buf.as_bstr(), b"abc=def:".as_bstr());

    let buf = unescape_batched_output(b"abc:edef:c:s:e:oz");
    assert_eq!(buf.as_bstr(), b"abc=def:;=,z".as_bstr());
}

const PYTHON_QUOTE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

pub fn encodecaps(
    caps: impl IntoIterator<
        Item = (
            impl AsRef<str>,
            Option<impl IntoIterator<Item = impl AsRef<str>>>,
        ),
    >,
) -> Box<str> {
    caps.into_iter()
        .map(|(k, v)| {
            let k = percent_encode(k.as_ref().as_bytes(), PYTHON_QUOTE_SET).to_string();
            match v {
                Some(v) => format!(
                "{}={}",
                k,
                v.into_iter()
                    .map(|v| percent_encode(v.as_ref().as_bytes(), PYTHON_QUOTE_SET).to_string())
                    .join(",")
            ),
                None => k,
            }
        })
        .join("\n")
        .into_boxed_str()
}

#[allow(clippy::type_complexity)]
pub fn decodecaps(
    caps: &BStr,
) -> impl '_ + Iterator<Item = Option<(Box<str>, Option<Box<[Box<str>]>>)>> {
    ByteSlice::lines(&**caps).map(|l| {
        let mut l = l.splitn(2, |&b| b == b'=');
        l.next().and_then(|k| {
            let k = percent_decode(k).decode_utf8().ok()?;
            let v = l
                .next()
                .map(|v| {
                    v.split(|&b| b == b',')
                        .map(|v| {
                            percent_decode(v)
                                .decode_utf8()
                                .map(|v| v.into_owned().into_boxed_str())
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(Vec::into_boxed_slice)
                })
                .transpose()
                .ok()?;
            Some((k.into_owned().into_boxed_str(), v))
        })
    })
}

#[test]
fn test_encode_decode_caps() {
    fn test_one<const N: usize>(caps: [(&str, Option<&[&str]>); N], expected: &str) {
        let encoded = encodecaps(caps);
        let caps = HashMap::from(caps);
        assert_eq!(&*encoded, expected);

        let decoded = decodecaps(expected.as_bytes().as_bstr())
            .collect::<Option<HashMap<_, _>>>()
            .unwrap();
        assert_eq!(
            caps.keys().copied().sorted().collect_vec(),
            decoded.keys().map(|k| &**k).sorted().collect_vec()
        );
        for (k, v) in decoded {
            assert_eq!(caps[&*k].is_none(), v.is_none());
            if let Some(v) = v {
                assert_eq!(caps[&*k].unwrap(), &v.iter().map(|v| &**v).collect_vec());
            }
        }
    }

    let caps = [("HG20", None), ("changegroup", Some(&["01", "02"][..]))];
    test_one(caps, "HG20\nchangegroup=01,02");

    // Real case
    let caps = [
        ("HG20", None),
        ("bookmarks", None),
        ("changegroup", Some(&["01", "02"][..])),
        ("digests", Some(&["md5", "sha1", "sha512"])),
        (
            "error",
            Some(&["abort", "unsupportedcontent", "pushraced", "pushkey"]),
        ),
        ("hgtagsfnodes", None),
        ("listkeys", None),
        ("phases", Some(&["heads"])),
        ("pushkey", None),
        ("remote-changegroup", Some(&["http", "https"])),
    ];
    test_one(
        caps,
        "HG20\n\
         bookmarks\n\
         changegroup=01,02\n\
         digests=md5,sha1,sha512\n\
         error=abort,unsupportedcontent,pushraced,pushkey\n\
         hgtagsfnodes\n\
         listkeys\n\
         phases=heads\n\
         pushkey\n\
         remote-changegroup=http,https",
    );

    // Hypothetical case
    let caps = [
        ("ab%d", Some(&["foo\nbar"][..])),
        ("qux\n", None),
        ("hoge", Some(&["fuga,", "toto"])),
    ];
    test_one(
        caps,
        "ab%25d=foo%0Abar\n\
         qux%0A\n\
         hoge=fuga%2C,toto",
    );

    assert_eq!(
        decodecaps(b"\xfe".as_bstr()).collect::<Option<Vec<_>>>(),
        None
    );
    assert_eq!(
        decodecaps(b"foo=\xfe".as_bstr()).collect::<Option<Vec<_>>>(),
        None
    );
}

pub fn get_store_bundle(
    store: &Store,
    conn: &mut dyn HgRepo,
    heads: &[HgChangesetId],
    common: &[HgChangesetId],
) -> Result<(), ImmutBString> {
    let bundle2caps = if check_enabled(Checks::NO_BUNDLE2) {
        None
    } else {
        conn.get_capability(b"bundle2").map(|_| {
            let bundle2caps = [("HG20", None), ("changegroup", Some(&["01", "02"]))];
            format!(
                "HG20,bundle2={}",
                percent_encode(encodecaps(bundle2caps).as_bytes(), PYTHON_QUOTE_SET)
            )
        })
    };
    conn.getbundle(heads, common, bundle2caps.as_deref())
        .and_then(|r| {
            let mut bundle = BundleReader::new(r).unwrap();
            while let Some(part) = bundle.next_part().unwrap() {
                if &*part.part_type == "changegroup" {
                    let version = part
                        .get_param("version")
                        .map_or(1, |v| u8::from_str(v).unwrap());
                    store_changegroup(store, BufReader::new(part), version);
                } else if &*part.part_type == "stream2" {
                    return Err(b"Stream bundles are not supported."
                        .to_vec()
                        .into_boxed_slice());
                }
            }
            Ok(())
        })
}

#[derive(Default, Debug)]
struct FindCommonInfo {
    hg_node: Cell<Option<HgChangesetId>>,
    known: Cell<Option<bool>>,
}

pub fn find_common(
    store: &Store,
    conn: &mut dyn HgRepo,
    hgheads: impl Into<Vec<HgChangesetId>>,
    remote: Option<&str>,
) -> Vec<HgChangesetId> {
    let mut rng = rand::thread_rng();
    let hgheads = hgheads.into();
    if hgheads.is_empty() {
        return vec![];
    }
    let sample_size = conn.sample_size();

    let mut undetermined = Vec::new();
    let mut undetermined_set = HashSet::new();

    // If we have a remote, also use the heads we have stored under refs/remotes,
    // because they are very more likely to be known on the remote than our
    // global set of heads.
    if let Some(remote) = remote {
        let remote = remote::get(remote.as_ref());
        unsafe {
            // By giving an empty list of refs to get_stale_refs, we get the
            // existing list of refs, which is what we're after.
            let refs = get_stale_refs(remote, std::ptr::null_mut());
            let mut r = refs as *const r#ref;
            while !r.is_null() {
                let refname = CStr::from_ptr(get_ref_name(r)).to_bytes();
                if let Some(csid) = resolve_ref(OsStr::from_bytes(refname))
                    .and_then(|cid| GitChangesetId::from_unchecked(cid).to_hg(store))
                {
                    if undetermined_set.insert(csid) {
                        undetermined.push(csid);
                    }
                }
                r = get_next_ref(r);
            }
            free_refs(refs);
        }
        debug!(target: "find-common", "[heads] using {} head{} from existing remote", undetermined.len(), if undetermined.len() == 1 { "" } else { "s" });
    }

    for csid in hgheads.into_iter() {
        if undetermined_set.insert(csid) {
            undetermined.push(csid);
        }
    }
    std::mem::drop(undetermined_set);

    debug!(target: "find-common", "[heads] undetermined: {}, sample size: {}", undetermined.len(), sample_size);

    let (known, unknown): (Vec<_>, Vec<_>) = conn
        .known(&undetermined[..std::cmp::min(undetermined.len(), sample_size)])
        .iter()
        .zip(&undetermined)
        .partition_map(|(&known, &head)| {
            if known {
                Either::Left(head)
            } else {
                Either::Right(head)
            }
        });

    let still_undetermined = undetermined.len() - unknown.len() - known.len();
    debug!(target: "find-common", "[heads] known: {}, unknown: {}, undetermined: {}", known.len(), unknown.len(), still_undetermined);

    if still_undetermined == 0 && unknown.is_empty() {
        return known;
    }

    let known = known
        .into_iter()
        .filter_map(|cs| cs.to_git(store).map(|c| (cs, c)))
        .collect_vec();
    let undetermined = undetermined
        .into_iter()
        .filter_map(|cs| cs.to_git(store).map(|c| (cs, c)))
        .collect_vec();
    let unknown = unknown
        .into_iter()
        .filter_map(|cs| cs.to_git(store).map(|c| (cs, c)))
        .collect_vec();

    let args = [
        "--reverse".to_string(),
        "--topo-order".to_string(),
        "--full-history".to_string(),
    ]
    .into_iter()
    .chain(known.iter().map(|(_, k)| format!("^{}^@", k)))
    .chain(
        undetermined
            .iter()
            .chain(unknown.iter())
            .chain(known.iter())
            .map(|(_, c)| c.to_string()),
    );

    let mut dag = Dag::new();
    let mut total_count = 0;
    let mut known_count = 0;
    let mut unknown_count = 0;
    for (cid, parents) in rev_list_with_parents(args) {
        dag.add(cid, &parents, FindCommonInfo::default());
        total_count += 1;
    }
    let total_count = total_count;
    for (cs, c) in known {
        if let Some((_, data)) = dag.get_mut(c.into()) {
            data.hg_node = Cell::new(Some(cs));
            data.known = Cell::new(Some(true));
            known_count += 1;
        }
    }
    for (_, c) in unknown {
        if let Some((_, data)) = dag.get_mut(c.into()) {
            data.known = Cell::new(Some(false));
            unknown_count += 1;
        }
    }
    for &(cs, c) in &undetermined {
        if let Some((_, data)) = dag.get_mut(c.into()) {
            data.hg_node = Cell::new(Some(cs));
        }
    }

    let is_undetermined = |_, data: &FindCommonInfo| data.known.get().is_none();
    std::mem::drop(undetermined);

    while known_count + unknown_count < total_count {
        debug!(target: "find-common", "known: {}, unknown: {}, undetermined: {}", known_count, unknown_count, total_count - known_count - unknown_count);

        let mut undetermined = dag.roots(is_undetermined).take(sample_size).collect_vec();
        let roots_count = undetermined.len();
        let mut heads_count = 0;
        let mut other_count = 0;
        if undetermined.len() < sample_size {
            let mut undetermined_set = undetermined
                .iter()
                .map(|&(c, _)| c)
                .collect::<BTreeSet<_>>();
            undetermined.extend(
                dag.heads(is_undetermined)
                    .filter(|(n, data)| is_undetermined(**n, data) && undetermined_set.insert(*n))
                    .take(sample_size - undetermined.len()),
            );
            heads_count = undetermined.len() - roots_count;
            if undetermined.len() < sample_size {
                undetermined.extend(
                    // TODO: this would or maybe would not be faster if traversing the dag instead.
                    dag.iter()
                        .filter(|(n, data)| {
                            is_undetermined(**n, data) && !undetermined_set.contains(n)
                        })
                        .choose_multiple(&mut rng, sample_size - undetermined.len())
                        .into_iter(),
                );
                other_count = undetermined.len() - roots_count - heads_count;
            }
        }
        debug!(target: "find-common", "sample: roots: {}, heads: {}, other: {}", roots_count, heads_count, other_count);
        let (sample_hg, sample_git): (Vec<_>, Vec<_>) = undetermined
            .into_iter()
            .map(|(&c, data): (&CommitId, &FindCommonInfo)| {
                let git_cs = GitChangesetId::from_unchecked(c);
                (
                    data.hg_node.get().unwrap_or_else(|| {
                        data.hg_node.set(git_cs.to_hg(store));
                        data.hg_node.get().unwrap()
                    }),
                    git_cs,
                )
            })
            .unzip();

        let (known, unknown): (Vec<_>, Vec<_>) = conn
            .known(&sample_hg)
            .iter()
            .zip(sample_git)
            .partition_map(|(&known, head)| {
                if known {
                    Either::Left(CommitId::from(head))
                } else {
                    Either::Right(CommitId::from(head))
                }
            });

        dag.traverse_parents(&known, is_undetermined)
            .for_each(|(_, data)| {
                if data.known.get().is_none() {
                    data.known.set(Some(true));
                    known_count += 1;
                } else {
                    assert_eq!(data.known.get(), Some(true));
                }
            });
        dag.traverse_children(&unknown, is_undetermined)
            .for_each(|(_, data)| {
                if data.known.get().is_none() {
                    data.known.set(Some(false));
                    unknown_count += 1;
                } else {
                    assert_eq!(data.known.get(), Some(false));
                }
            });
    }
    debug!(target: "find-common", "known: {}, unknown: {}", known_count, unknown_count);
    let result = dag
        .heads(|_, data| data.known.get() == Some(true))
        .map(|(_, data)| data.hg_node.get().unwrap())
        .collect_vec();
    debug!(target: "find-common", "minimal known set: {}", result.len());
    result
}

pub fn get_bundle(
    store: &mut Store,
    conn: &mut dyn HgRepo,
    heads: &[HgChangesetId],
    topological_heads: Option<&[HgChangesetId]>,
    branch_names: &HashSet<Box<BStr>>,
    remote: Option<&str>,
) -> Result<(), String> {
    let known_branch_heads = |store: &Store| {
        store
            .changeset_heads()
            .branch_heads()
            .filter_map(|(h, b)| {
                (branch_names.is_empty() || branch_names.contains(b)).then_some(*h)
            })
            .collect_vec()
    };

    let mut heads = Cow::Borrowed(heads);
    let mut common = find_common(store, conn, known_branch_heads(store), remote);
    if common.is_empty() && !has_metadata(store) && get_initial_bundle(store, conn, remote)? {
        // Eliminate the heads that we got from the clonebundle or
        // cinnabarclone
        heads = Cow::Owned(
            heads
                .iter()
                .filter(|h| h.to_git(store).is_none())
                .copied()
                .collect_vec(),
        );
        if heads.is_empty() {
            return Ok(());
        }
        common = find_common(store, conn, known_branch_heads(store), None);
    }

    // TODO: Mercurial can be an order of magnitude slower when
    // creating a bundle when not giving topological heads, which
    // some of the branch heads might not be.
    // http://bz.selenic.com/show_bug.cgi?id=4595
    // The heads we've been asked for either come from the repo
    // branchmap, and are a superset of its topological heads.
    // That means if the heads we don't know in those we were asked for
    // are a superset of the topological heads we don't know, then we
    // should use those instead.
    let mut original_heads = None;
    if !branch_names.is_empty() {
        if let Some(topological_heads) = topological_heads {
            let unknown_wanted_heads = heads
                .iter()
                .filter(|h| h.to_git(store).is_none())
                .copied()
                .collect::<Vec<_>>();
            let unknown_topological_heads = topological_heads
                .iter()
                .filter(|h| h.to_git(store).is_none())
                .copied()
                .collect::<Vec<_>>();
            if unknown_wanted_heads
                .iter()
                .collect::<HashSet<_>>()
                .is_superset(&unknown_topological_heads.iter().collect())
            {
                original_heads = Some(std::mem::replace(
                    &mut heads,
                    Cow::Owned(unknown_topological_heads),
                ));
            }
        }
    }
    get_store_bundle(store, conn, &heads, &common)
        .and_then(|()| {
            // Try one more time if there are still some heads left because
            // we removed too many above, which can happen when for some
            // reason the server advertizes topological heads in the branchmap
            // without advertizing them in the list of heads.
            let unknown_wanted_heads = original_heads
                .map(|original_heads| {
                    original_heads
                        .iter()
                        .filter(|h| h.to_git(store).is_none())
                        .copied()
                        .collect_vec()
                })
                .unwrap_or_default();
            if !unknown_wanted_heads.is_empty() {
                common = find_common(store, conn, known_branch_heads(store), None);
                get_store_bundle(store, conn, &unknown_wanted_heads, &common)
            } else {
                Ok(())
            }
        })
        .map_err(|e| {
            let stderr = stderr();
            let mut writer = PrefixWriter::new("remote: ", stderr.lock());
            writer.write_all(&e).unwrap();
            "".to_string()
        })
}

fn get_initial_bundle(
    store: &mut Store,
    conn: &mut dyn HgRepo,
    remote: Option<&str>,
) -> Result<bool, String> {
    if let Some((manifest, limit_schemes)) = get_config_remote("clone", remote)
        .map(|m| (m.as_bytes().to_boxed(), false))
        .or_else(|| {
            // If no cinnabar.clone config was given, but a
            // cinnabar.clonebundle config was, act as if an empty
            // cinnabar.clone config had been given, and proceed with
            // the mercurial clonebundle.
            (conn.get_capability(b"cinnabarclone").is_some()
                && get_config_remote("clonebundle", remote)
                    .filter(|c| !c.is_empty())
                    .is_none())
            .then(|| (conn.cinnabarclone(), true))
        })
        .filter(|(m, _)| !m.is_empty())
    {
        match get_cinnabarclone_url(&manifest, remote).ok_or(Some(
            "Server advertizes cinnabarclone but didn't provide a git repository url to fetch from."
        )).and_then(|(url, branch)| {
            if limit_schemes && !["http", "https", "git"].contains(&url.scheme()) {
                Err(Some("Server advertizes cinnabarclone but provided a non http/https git repository. Skipping."))
            } else {
                eprintln!("Fetching cinnabar metadata from {}", url);
                merge_metadata(store, url, conn.get_url().cloned(), branch.as_deref()).then_some(()).ok_or(None)
            }
        }) {
            Ok(()) => {
                return Ok(true);
            }
            Err(e) => {
                if let Some(e) = e {
                    warn!(target: "root", "{}", e);
                }
                if check_enabled(Checks::CINNABARCLONE) {
                    return Err("cinnabarclone failed".to_string());
                }
                warn!(target: "root", "Falling back to normal clone.");
            }
        }
    }

    if conn.get_capability(b"clonebundles").is_some() {
        if let Some(url) = get_config_remote("clonebundle", remote)
            .map(|url| (!url.is_empty()).then(|| Url::parse(url.to_str().unwrap()).unwrap()))
            .or_else(|| Some(get_clonebundle_url(conn)))
            .flatten()
        {
            eprintln!("Getting clone bundle from {}", url);
            let mut bundle_conn = get_bundle_connection(&url).unwrap();
            match get_store_bundle(store, &mut *bundle_conn, &[], &[]) {
                Ok(()) => {
                    return Ok(true);
                }
                Err(e) => {
                    let stderr = stderr();
                    let mut writer = PrefixWriter::new("remote: ", stderr.lock());
                    writer.write_all(&e).unwrap();
                    if check_enabled(Checks::CLONEBUNDLES) {
                        return Err("clonebundles failed".to_string());
                    }
                }
            };
        }
    }
    Ok(false)
}

fn can_use_clonebundle(line: &[u8]) -> Result<Option<Url>, String> {
    let mut line = line.splitn(2, |&b| b == b' ');
    let url = match line.next() {
        None => return Ok(None),
        Some(url) => std::str::from_utf8(url)
            .ok()
            .and_then(|url| Url::parse(url).ok())
            .ok_or("invalid url")?,
    };
    if !["http", "https"].contains(&url.scheme()) {
        return Err("non http/https url".to_string());
    }
    let attributes = line
        .next()
        .map(|l| {
            l.split(|&b| b == b' ')
                .map(|a| {
                    a.splitn_exact::<2>(b'=').map(|[a, b]| {
                        (
                            // TODO: Ideally, we'd avoid the extra allocations here.
                            percent_decode(a).collect_vec().as_bstr().to_boxed(),
                            percent_decode(b).collect_vec().as_bstr().to_boxed(),
                        )
                    })
                })
                .collect::<Option<HashMap<_, _>>>()
                .ok_or("failed to decode")
        })
        .transpose()?;
    trace!(target: "clonebundle", "{:?}", attributes);

    //TODO: should we care about REQUIRESNI, or can we assume curl always supports
    //SNI? (for now, we assume it does).

    let mut bundlespec = attributes
        .as_ref()
        .and_then(|attrs| attrs.get(b"BUNDLESPEC".as_bstr()))
        .ok_or("missing BUNDLE_SPEC")?
        .split(|&b| b == b';');
    BundleSpec::try_from(bundlespec.next().ok_or("empty BUNDLESPEC?")?)?;
    let params = bundlespec
        .map(|b| {
            b.splitn_exact::<2>(b'=')
                .map(|[k, v]| (k.as_bstr(), v.as_bstr()))
        })
        .collect::<Option<HashMap<_, _>>>()
        .ok_or("failed to decode BUNDLESPEC")?;
    trace!(target: "clonebundle", "{:?}", params);

    Ok((!params.contains_key(b"stream".as_bstr()))
        .then_some(Some(url))
        .ok_or("stream bundles are not supported")?)
}

pub fn get_clonebundle_url(conn: &mut dyn HgRepo) -> Option<Url> {
    let bundles = conn.clonebundles();

    for line in ByteSlice::lines(&*bundles) {
        debug!(target: "clonebundle", "{:?}", line.as_bstr());
        match can_use_clonebundle(line) {
            Ok(None) => {}
            Ok(Some(url)) => {
                return Some(url);
            }
            Err(e) => {
                debug!(target: "clonebundle", " Skipping ({})", e);
            }
        }
    }
    None
}

struct CinnabarCloneInfo<'a> {
    url: Url,
    branch: Option<&'a [u8]>,
    graft: Vec<GitObjectId>,
}

fn cinnabar_clone_info(line: &[u8]) -> Result<Option<CinnabarCloneInfo>, String> {
    let mut line = line.splitn(2, |&b| b == b' ');
    let (url, branch) = match line.next() {
        None => return Ok(None),
        Some(spec) => {
            let mut spec = spec.splitn(2, |&b| b == b'#');
            let url = match spec.next() {
                None => return Ok(None),
                Some(url) => std::str::from_utf8(url)
                    .ok()
                    .and_then(|url| {
                        Url::parse(url)
                            .or_else(|_| Url::parse(&format!("file://{}", url)))
                            .ok()
                    })
                    .ok_or("invalid url")?,
            };
            (url, spec.next())
        }
    };
    let mut params = line
        .next()
        .map(|p| {
            p.split(u8::is_ascii_whitespace)
                .filter(|b| !b.is_empty())
                .map(|b| b.splitn_exact(b'=').map(|[a, b]| (a, b)))
                .collect::<Option<HashMap<_, _>>>()
                .ok_or("Parsing Error")
        })
        .transpose()?
        .unwrap_or_default();
    let graft = params
        .remove(&b"graft"[..])
        .map(|b| {
            b.split(|&b| b == b',')
                .map(GitObjectId::from_bytes)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    if !params.is_empty() {
        // Future proofing: ignore lines with unknown params, even if we support
        // some that are preset.
        return Err("Unknown parameters".into());
    }
    Ok(Some(CinnabarCloneInfo { url, branch, graft }))
}

pub fn get_cinnabarclone_url(
    manifest: &[u8],
    remote: Option<&str>,
) -> Option<(Url, Option<Box<[u8]>>)> {
    let graft = graft_config_enabled(remote).unwrap();
    let mut candidates = Vec::new();

    for line in ByteSlice::lines(manifest) {
        if line.is_empty() {
            continue;
        }
        debug!(target: "cinnabarclone", "{:?}", line.as_bstr());
        match cinnabar_clone_info(line) {
            Ok(None) => {}
            Ok(Some(info)) => {
                // When grafting, ignore lines without a graft revision.
                if graft == Some(true) && info.graft.is_empty() {
                    debug!(target: "cinnabarclone", " Skipping (graft enabled but not a graft)");
                    continue;
                }
                // When explicitly disabling graft, ignore lines with a graft revision.
                if graft == Some(false) && !info.graft.is_empty() {
                    debug!(target: "cinnabarclone", " Skipping (graft disabled)");
                    continue;
                }
                if !info.graft.is_empty() {
                    if !info.graft.iter().all(|g| CommitId::try_from(*g).is_ok()) {
                        debug!(target: "cinnabarclone", " Skipping (missing commit(s) for graft)");
                        continue;
                    }
                    // We apparently have all the grafted revisions locally, ensure
                    // they're actually reachable.
                    let args = [
                        "--branches",
                        "--tags",
                        "--remotes",
                        "--max-count=1",
                        "--ancestry-path",
                    ];
                    let other_args = info.graft.iter().map(|c| format!("^{}^@", c)).collect_vec();
                    if rev_list(args.into_iter().chain(other_args.iter().map(|x| &**x)))
                        .next()
                        .is_none()
                    {
                        debug!(target: "cinnabarclone", " Skipping (graft commit(s) unreachable)");
                        continue;
                    }
                }
                candidates.push(info);
            }
            Err(e) => {
                debug!(target: "cinnabarclone", " Skipping ({})", e);
            }
        }
    }
    // When graft is not explicitly enabled or disabled, pick any kind of bundle,
    // but prefer a grafted one, even if it appears after.
    let graft_filters = if graft != Some(false) {
        &[true, false][..]
    } else {
        &[false]
    };
    for graft_filter in graft_filters {
        for candidate in &candidates {
            if candidate.graft.is_empty() != *graft_filter {
                return Some((
                    candidate.url.clone(),
                    candidate.branch.map(ToBoxed::to_boxed),
                ));
            }
        }
    }
    None
}

pub fn get_bundle_connection(url: &Url) -> Option<Box<dyn HgRepo>> {
    let mut req = HttpRequest::new(url.clone());
    if unsafe { http_follow_config } == http_follow_config::HTTP_FOLLOW_INITIAL {
        req.follow_redirects(true);
    }
    req.set_log_target("raw-wire::clonebundle".to_string());
    Some(Box::new(BundleConnection::new(req.execute().ok()?)))
}

pub fn get_connection(url: &Url) -> Option<Box<dyn HgRepo>> {
    let conn = if ["http", "https"].contains(&url.scheme()) {
        get_http_connection(url)?
    } else if ["ssh", "file"].contains(&url.scheme()) {
        get_stdio_connection(url, 0)?
    } else {
        die!("protocol '{}' is not supported", url.scheme());
    };

    const REQUIRED_CAPS: [&str; 2] = ["getbundle", "branchmap"];

    for cap in &REQUIRED_CAPS {
        conn.require_capability(cap.as_bytes());
    }

    Some(conn)
}
