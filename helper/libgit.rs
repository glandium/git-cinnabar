/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp::Ordering;
use std::convert::TryInto;
use std::ffi::c_void;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::os::raw::{c_char, c_int, c_long, c_ulong};
use std::str::FromStr;

use bstr::ByteSlice;
use curl_sys::{CURLcode, CURL, CURL_ERROR_SIZE};
use derive_more::{Deref, DerefMut, Display};
use getset::Getters;

use crate::util::{FromBytes, SliceExt};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct oid_array {
    oid: *const object_id,
    nr: c_int,
    alloc: c_int,
    sorted: c_int,
}

#[allow(non_camel_case_types)]
pub struct oid_array_iter<'a> {
    array: &'a oid_array,
    next: Option<c_int>,
}

impl oid_array {
    pub fn is_empty(&self) -> bool {
        self.nr == 0
    }

    pub fn iter(&self) -> oid_array_iter {
        oid_array_iter {
            array: self,
            next: Some(0),
        }
    }
}

impl<'a> Iterator for oid_array_iter<'a> {
    type Item = &'a object_id;
    fn next(&mut self) -> Option<Self::Item> {
        let i = self.next.take()?;
        let result = unsafe { self.array.oid.offset(i as isize).as_ref()? };
        self.next = i.checked_add(1).filter(|&x| x < self.array.nr);
        Some(result)
    }
}

const GIT_SHA1_RAWSZ: usize = 20;
const GIT_MAX_RAWSZ: usize = 32;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Eq)]
pub struct object_id([u8; GIT_MAX_RAWSZ]);

impl FromStr for object_id {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = object_id([0; GIT_MAX_RAWSZ]);
        hex::decode_to_slice(s, &mut result.0[..GIT_SHA1_RAWSZ])?;
        Ok(result)
    }
}

impl Display for object_id {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for x in self.raw() {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

impl fmt::Debug for object_id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Oid({})", self)
    }
}

impl object_id {
    pub fn raw(&self) -> &[u8] {
        &self.0[..GIT_SHA1_RAWSZ]
    }

    pub const fn null() -> object_id {
        object_id([0; GIT_MAX_RAWSZ])
    }
}

impl PartialEq for object_id {
    fn eq(&self, other: &Self) -> bool {
        self.raw() == other.raw()
    }
}

impl PartialOrd for object_id {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.raw().cmp(other.raw()))
    }
}

impl Ord for object_id {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw().cmp(other.raw())
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct strbuf {
    alloc: usize,
    len: usize,
    buf: *mut c_char,
}

extern "C" {
    static strbuf_slopbuf: [c_char; 1];
    fn strbuf_add(buf: *mut strbuf, data: *const c_void, len: usize);
    fn strbuf_release(buf: *mut strbuf);
}

impl strbuf {
    pub fn new() -> Self {
        strbuf {
            alloc: 0,
            len: 0,
            buf: unsafe { strbuf_slopbuf.as_ptr() as *mut _ },
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buf as *const u8, self.len) }
    }

    pub fn extend_from_slice(&mut self, s: &[u8]) {
        unsafe { strbuf_add(self, s.as_ptr() as *const c_void, s.len()) }
    }
}

impl Write for strbuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for strbuf {
    fn drop(&mut self) {
        unsafe {
            strbuf_release(self);
        }
    }
}

extern "C" {
    pub fn die(fmt: *const c_char, ...) -> !;
}

pub(crate) fn _die(s: String) -> ! {
    unsafe {
        let s = std::ffi::CString::new(s).unwrap();
        die(s.as_ptr())
    }
}

macro_rules! die {
    ($($e:expr),+) => {
        $crate::libgit::_die(format!($($e),+))
    }
}

extern "C" {
    pub fn credential_fill(auth: *mut credential);

    pub static mut http_auth: credential;

    pub fn http_init(remote: *mut remote, url: *const c_char, proactive_auth: c_int);
    pub fn http_cleanup();

    pub fn get_active_slot() -> *mut active_request_slot;

    pub fn run_one_slot(slot: *mut active_request_slot, results: *mut slot_results) -> c_int;

    pub static curl_errorstr: [c_char; CURL_ERROR_SIZE];
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct credential(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct remote(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct child_process(c_void);

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct active_request_slot {
    pub curl: *mut CURL,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct slot_results {
    curl_result: CURLcode,
    http_code: c_long,
    auth_avail: c_long,
    http_connectcode: c_long,
}

impl slot_results {
    pub fn new() -> Self {
        slot_results {
            curl_result: 0,
            http_code: 0,
            auth_avail: 0,
            http_connectcode: 0,
        }
    }
}

pub const HTTP_OK: c_int = 0;
pub const HTTP_REAUTH: c_int = 4;

#[allow(dead_code, non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub enum http_follow_config {
    HTTP_FOLLOW_NONE,
    HTTP_FOLLOW_ALWAYS,
    HTTP_FOLLOW_INITIAL,
}

extern "C" {
    pub static http_follow_config: http_follow_config;
}

#[repr(C)]
pub struct repository {
    gitdir: *const c_char,
    commondir: *const c_char,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub enum object_type {
    OBJ_BAD = -1,
    OBJ_NONE = 0,
    OBJ_COMMIT = 1,
    OBJ_TREE = 2,
    OBJ_BLOB = 3,
    OBJ_TAG = 4,
    OBJ_OFS_DELTA = 6,
    OBJ_REF_DELTA = 7,
    OBJ_ANY,
    OBJ_MAX,
}

extern "C" {
    fn read_object_file_extended(
        r: *mut repository,
        oid: *const object_id,
        typ: *mut object_type,
        size: *mut c_ulong,
        lookup_replace: c_int,
    ) -> *const c_void;
}

pub struct RawObject {
    buf: *const c_void,
    len: usize,
}

impl RawObject {
    fn read(oid: &object_id) -> Option<(object_type, RawObject)> {
        let mut t = object_type::OBJ_NONE;
        let mut len: c_ulong = 0;
        let buf = unsafe { read_object_file_extended(the_repository, oid, &mut t, &mut len, 0) };
        if buf.is_null() {
            return None;
        }
        let raw = RawObject {
            buf,
            len: len.try_into().unwrap(),
        };
        Some((t, raw))
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buf as *const u8, self.len) }
    }
}

impl Drop for RawObject {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.buf as *mut _);
        }
    }
}

#[macro_export]
macro_rules! oid_type {
    ($name:ident($oid_type:ident)) => {
        #[derive(Clone, Deref, DerefMut, Display, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $name($oid_type);

        impl $name {
            pub fn null() -> Self {
                $name($oid_type::null())
            }

            pub unsafe fn from(oid: $oid_type) -> Self {
                $name(oid)
            }
        }

        impl FromBytes for $name {
            type Err = <$oid_type as FromBytes>::Err;
            fn from_bytes(b: &[u8]) -> Result<Self, Self::Err> {
                $oid_type::from_bytes(b).map(Self)
            }
        }
    };
}

oid_type!(CommitId(object_id));
oid_type!(TreeId(object_id));
oid_type!(BlobId(object_id));

macro_rules! raw_object {
    ($t:ident | $oid_type:ident => $name:ident) => {
        #[derive(Deref)]
        pub struct $name(RawObject);

        impl $name {
            pub fn read(oid: &$oid_type) -> Option<Self> {
                match RawObject::read(oid)? {
                    (object_type::$t, o) => Some($name(o)),
                    _ => None,
                }
            }
        }
    };
}

raw_object!(OBJ_COMMIT | CommitId => RawCommit);
raw_object!(OBJ_TREE | TreeId => RawTree);
raw_object!(OBJ_BLOB | BlobId => RawBlob);

#[derive(Getters)]
pub struct Commit<'a> {
    #[getset(get = "pub")]
    tree: TreeId,
    parents: Vec<CommitId>,
    #[getset(get = "pub")]
    author: &'a [u8],
    #[getset(get = "pub")]
    committer: &'a [u8],
    #[getset(get = "pub")]
    body: &'a [u8],
}

impl<'a> Commit<'a> {
    pub fn parents(&self) -> &[CommitId] {
        &self.parents[..]
    }
}

impl RawCommit {
    pub fn parse(&self) -> Option<Commit> {
        let (header, body) = self.as_bytes().split2(&b"\n\n"[..])?;
        let mut tree = None;
        let mut parents = Vec::new();
        let mut author = None;
        let mut committer = None;
        for line in header.lines() {
            if line.is_empty() {
                break;
            }
            match line.split2(b' ')? {
                (b"tree", t) => tree = Some(TreeId::from_bytes(t).ok()?),
                (b"parent", p) => parents.push(CommitId::from_bytes(p).ok()?),
                (b"author", a) => author = Some(a),
                (b"committer", a) => committer = Some(a),
                _ => {}
            }
        }
        Some(Commit {
            tree: tree?,
            parents,
            author: author?,
            committer: committer?,
            body,
        })
    }
}

#[repr(C)]
pub struct notes_tree {
    root: *mut c_void,
    oid: object_id,
}

extern "C" {
    pub static mut the_repository: *mut repository;

    pub fn repo_get_oid_committish(
        r: *mut repository,
        s: *const c_char,
        oid: *mut object_id,
    ) -> c_int;

    pub fn repo_lookup_replace_object(
        r: *mut repository,
        oid: *const object_id,
    ) -> *const object_id;

    pub fn get_note(t: *mut notes_tree, oid: *const object_id) -> *const object_id;
}
