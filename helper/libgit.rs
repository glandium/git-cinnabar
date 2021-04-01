/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString, OsStr};
use std::fmt;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort};

use bstr::ByteSlice;
use cstr::cstr;
use curl_sys::{CURLcode, CURL, CURL_ERROR_SIZE};
use derive_more::{Deref, Display};
use getset::Getters;

use crate::oid::{GitObjectId, ObjectId};
use crate::util::{BorrowKey, CStrExt, FromBytes, OsStrExt, SliceExt};

const GIT_MAX_RAWSZ: usize = 32;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone)]
pub struct object_id([u8; GIT_MAX_RAWSZ]);

impl From<GitObjectId> for object_id {
    fn from(oid: GitObjectId) -> Self {
        let mut result = Self([0; GIT_MAX_RAWSZ]);
        let oid = oid.as_raw_bytes();
        result.0[..oid.len()].clone_from_slice(oid);
        result
    }
}

impl From<object_id> for GitObjectId {
    fn from(oid: object_id) -> Self {
        let mut result = Self::null();
        let slice = result.as_raw_bytes_mut();
        slice.clone_from_slice(&oid.0[..slice.len()]);
        result
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

    pub fn reset(&mut self) {
        self.len = 0;
        unsafe {
            if self.buf != strbuf_slopbuf.as_ptr() as *mut _ {
                *self.buf = 0;
            }
        }
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
        let s = CString::new(s).unwrap();
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

#[allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
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

#[allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(C)]
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
    fn read(oid: &GitObjectId) -> Option<(object_type, RawObject)> {
        let mut t = object_type::OBJ_NONE;
        let mut len: c_ulong = 0;
        let buf = unsafe {
            read_object_file_extended(the_repository, &oid.clone().into(), &mut t, &mut len, 0)
        };
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

oid_type!(CommitId(GitObjectId));
oid_type!(TreeId(GitObjectId));
oid_type!(BlobId(GitObjectId));

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
        let [header, body] = self.as_bytes().splitn_exact(&b"\n\n"[..])?;
        let mut tree = None;
        let mut parents = Vec::new();
        let mut author = None;
        let mut committer = None;
        for line in header.lines() {
            if line.is_empty() {
                break;
            }
            match line.splitn_exact(b' ')? {
                [b"tree", t] => tree = Some(TreeId::from_bytes(t).ok()?),
                [b"parent", p] => parents.push(CommitId::from_bytes(p).ok()?),
                [b"author", a] => author = Some(a),
                [b"committer", a] => committer = Some(a),
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

    fn repo_get_oid_committish(r: *mut repository, s: *const c_char, oid: *mut object_id) -> c_int;

    fn repo_lookup_replace_object(r: *mut repository, oid: *const object_id) -> *const object_id;

    pub fn get_note(t: *mut notes_tree, oid: *const object_id) -> *const object_id;
}

pub fn get_oid_committish(s: &[u8]) -> Option<CommitId> {
    unsafe {
        let c = CString::new(s).unwrap();
        let mut oid = object_id([0; GIT_MAX_RAWSZ]);
        if repo_get_oid_committish(the_repository, c.as_ptr(), &mut oid) == 0 {
            Some(CommitId(oid.into()))
        } else {
            None
        }
    }
}

pub fn lookup_replace_commit(c: &CommitId) -> Cow<CommitId> {
    unsafe {
        let oid = object_id::from(c.0.clone());
        let replaced = repo_lookup_replace_object(the_repository, &oid);
        if replaced == &oid {
            Cow::Borrowed(c)
        } else {
            //TODO: we should actually check the object is a commit.
            Cow::Owned(CommitId::from(replaced.as_ref().unwrap().clone().into()))
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct string_list {
    items: *const string_list_item,
    nr: c_uint,
    /* there are more but we don't use them */
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct string_list_item {
    string: *const c_char,
    util: *const c_void,
}

#[allow(non_camel_case_types)]
pub struct string_list_iter<'a> {
    list: &'a string_list,
    next: Option<c_uint>,
}

impl string_list {
    pub fn is_empty(&self) -> bool {
        self.nr == 0
    }

    pub fn iter(&self) -> string_list_iter {
        string_list_iter {
            list: self,
            next: Some(0),
        }
    }
}

impl<'a> Iterator for string_list_iter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let i = self.next.take()?;
        let result = unsafe { self.list.items.offset(i as isize).as_ref()? };
        self.next = i.checked_add(1).filter(|&x| x < self.list.nr);
        Some(unsafe { CStr::from_ptr(result.string) }.to_bytes())
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct rev_info(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct commit(c_void);

extern "C" {
    fn commit_oid(c: *const commit) -> *const object_id;

    fn get_revision(revs: *mut rev_info) -> *const commit;

    fn rev_list_new(argc: c_int, argv: *const *const c_char) -> *mut rev_info;

    fn rev_list_finish(revs: *mut rev_info);
}

pub struct RevList {
    revs: *mut rev_info,
}

pub fn rev_list(args: &[&OsStr]) -> RevList {
    let args: Vec<_> = Some(OsStr::new(""))
        .iter()
        .chain(args)
        .map(|a| a.to_cstring())
        .collect();
    let mut argv: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    RevList {
        revs: unsafe { rev_list_new(args.len().try_into().unwrap(), &argv[0]) },
    }
}

impl Drop for RevList {
    fn drop(&mut self) {
        unsafe {
            rev_list_finish(self.revs);
        }
    }
}

impl Iterator for RevList {
    type Item = CommitId;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            get_revision(self.revs)
                .as_ref()
                .map(|c| CommitId::from(GitObjectId::from(commit_oid(c).as_ref().unwrap().clone())))
        }
    }
}

const DIFF_STATUS_ADDED: c_char = b'A' as c_char;
const DIFF_STATUS_COPIED: c_char = b'C' as c_char;
const DIFF_STATUS_DELETED: c_char = b'D' as c_char;
const DIFF_STATUS_MODIFIED: c_char = b'M' as c_char;
const DIFF_STATUS_TYPE_CHANGED: c_char = b'T' as c_char;
const DIFF_STATUS_RENAMED: c_char = b'R' as c_char;

#[allow(non_camel_case_types)]
#[repr(C)]
struct diff_tree_file {
    oid: *const object_id,
    path: *const c_char,
    mode: c_ushort,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct diff_tree_item {
    a: diff_tree_file,
    b: diff_tree_file,
    score: c_ushort,
    status: c_char,
}

extern "C" {
    fn diff_tree_(
        argc: c_int,
        argv: *const *const c_char,
        cb: unsafe extern "C" fn(*mut c_void, *const diff_tree_item),
        context: *const c_void,
    );
}

pub struct FileMode(u16);

impl fmt::Debug for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:06o}", self.0)
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub enum DiffTreeItem {
    Added {
        #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
        path: Box<[u8]>,
        mode: FileMode,
        oid: BlobId,
    },
    Deleted {
        #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
        path: Box<[u8]>,
        mode: FileMode,
        oid: BlobId,
    },
    Modified {
        #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
        path: Box<[u8]>,
        from_mode: FileMode,
        from_oid: BlobId,
        to_mode: FileMode,
        to_oid: BlobId,
    },
    Renamed {
        #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
        to_path: Box<[u8]>,
        to_mode: FileMode,
        to_oid: BlobId,
        #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
        from_path: Box<[u8]>,
        from_mode: FileMode,
        from_oid: BlobId,
    },
    Copied {
        #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
        to_path: Box<[u8]>,
        to_mode: FileMode,
        to_oid: BlobId,
        #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
        from_path: Box<[u8]>,
        from_mode: FileMode,
        from_oid: BlobId,
    },
}

impl BorrowKey for DiffTreeItem {
    type Key = Box<[u8]>;
    fn borrow_key(&self) -> &Self::Key {
        match self {
            DiffTreeItem::Added { path, .. } => path,
            DiffTreeItem::Deleted { path, .. } => path,
            DiffTreeItem::Modified { path, .. } => path,
            DiffTreeItem::Renamed { to_path, .. } => to_path,
            DiffTreeItem::Copied { to_path, .. } => to_path,
        }
    }
}

unsafe extern "C" fn diff_tree_fill(diff_tree: *mut c_void, item: *const diff_tree_item) {
    let diff_tree = (diff_tree as *mut Vec<DiffTreeItem>).as_mut().unwrap();
    let item = item.as_ref().unwrap();
    let item = match item.status {
        DIFF_STATUS_MODIFIED | DIFF_STATUS_TYPE_CHANGED => DiffTreeItem::Modified {
            path: {
                let a_path: Box<[u8]> = CStr::from_ptr(item.a.path).to_bytes().into();
                let b_path = CStr::from_ptr(item.b.path).to_bytes();
                assert_eq!(a_path.as_bstr(), b_path.as_bstr());
                a_path
            },
            from_oid: BlobId::from(GitObjectId::from(item.a.oid.as_ref().unwrap().clone())),
            from_mode: FileMode(item.a.mode),
            to_oid: BlobId::from(GitObjectId::from(item.b.oid.as_ref().unwrap().clone())),
            to_mode: FileMode(item.b.mode),
        },
        DIFF_STATUS_ADDED => DiffTreeItem::Added {
            path: CStr::from_ptr(item.b.path).to_bytes().into(),
            oid: BlobId::from(GitObjectId::from(item.b.oid.as_ref().unwrap().clone())),
            mode: FileMode(item.b.mode),
        },
        DIFF_STATUS_DELETED => DiffTreeItem::Deleted {
            path: CStr::from_ptr(item.a.path).to_bytes().into(),
            oid: BlobId::from(GitObjectId::from(item.a.oid.as_ref().unwrap().clone())),
            mode: FileMode(item.a.mode),
        },
        DIFF_STATUS_RENAMED => DiffTreeItem::Renamed {
            to_path: CStr::from_ptr(item.b.path).to_bytes().into(),
            to_oid: BlobId::from(GitObjectId::from(item.b.oid.as_ref().unwrap().clone())),
            to_mode: FileMode(item.b.mode),
            from_path: CStr::from_ptr(item.a.path).to_bytes().into(),
            from_oid: BlobId::from(GitObjectId::from(item.a.oid.as_ref().unwrap().clone())),
            from_mode: FileMode(item.a.mode),
        },
        DIFF_STATUS_COPIED => DiffTreeItem::Copied {
            to_path: CStr::from_ptr(item.b.path).to_bytes().into(),
            to_oid: BlobId::from(GitObjectId::from(item.b.oid.as_ref().unwrap().clone())),
            to_mode: FileMode(item.b.mode),
            from_path: CStr::from_ptr(item.a.path).to_bytes().into(),
            from_oid: BlobId::from(GitObjectId::from(item.a.oid.as_ref().unwrap().clone())),
            from_mode: FileMode(item.a.mode),
        },
        c => panic!("Unknown diff state: {}", c),
    };
    diff_tree.push(item);
}

pub fn diff_tree(a: &CommitId, b: &CommitId) -> impl Iterator<Item = DiffTreeItem> {
    let a = CString::new(format!("{}", a)).unwrap();
    let b = CString::new(format!("{}", b)).unwrap();
    let args = [
        cstr!(""),
        &a,
        &b,
        cstr!("--ignore-submodules=dirty"),
        cstr!("--"),
    ];
    let mut argv: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut result = Vec::<DiffTreeItem>::new();
    unsafe {
        diff_tree_(
            args.len().try_into().unwrap(),
            &argv[0],
            diff_tree_fill,
            &mut result as *mut _ as *mut c_void,
        );
    }
    result.into_iter()
}

extern "C" {
    fn remote_get(name: *const c_char) -> *mut remote;

    fn remote_get_name(remote: *const remote) -> *const c_char;

    fn remote_get_url(remote: *const remote, url: *mut *const *const c_char, url_nr: *mut c_int);

    fn remote_skip_default_update(remote: *const remote) -> c_int;
}

impl remote {
    pub fn get(name: &OsStr) -> &'static mut remote {
        // /!\ This potentially leaks memory.
        unsafe { remote_get(name.to_cstring().into_raw()).as_mut().unwrap() }
    }

    pub fn name(&self) -> Option<&OsStr> {
        unsafe {
            remote_get_name(self)
                .as_ref()
                .map(|n| OsStr::from_bytes(CStr::from_ptr(n).to_bytes()))
        }
    }

    pub fn get_url(&self) -> &OsStr {
        let mut urls: *const *const c_char = std::ptr::null();
        let mut url_nr: c_int = 0;
        unsafe {
            remote_get_url(self, &mut urls, &mut url_nr);
        }
        let urls = unsafe { std::slice::from_raw_parts(urls, url_nr as usize) };
        unsafe { CStr::from_ptr(urls[0]).to_osstr() }
    }

    pub fn skip_default_update(&self) -> bool {
        unsafe { remote_skip_default_update(self) != 0 }
    }
}

mod remotes {
    use super::*;
    extern "C" {
        pub fn for_each_remote(
            cb: unsafe extern "C" fn(*const remote, *mut c_void) -> c_int,
            cb_data: *mut c_void,
        ) -> c_int;
    }
}

pub fn for_each_remote<E, F: FnMut(&remote) -> Result<(), E>>(f: F) -> Result<(), E> {
    let mut cb_data = (f, None);

    unsafe extern "C" fn each_remote_cb<E, F: FnMut(&remote) -> Result<(), E>>(
        remot: *const remote,
        cb_data: *mut c_void,
    ) -> c_int {
        let (func, ref mut error) = (cb_data as *mut (F, Option<E>)).as_mut().unwrap();
        let remot = remot.as_ref().unwrap();
        match func(remot) {
            Ok(()) => 0,
            Err(e) => {
                *error = Some(e);
                -1
            }
        }
    }

    unsafe {
        if 0 == remotes::for_each_remote(
            each_remote_cb::<E, F>,
            &mut cb_data as *mut (F, Option<E>) as *mut c_void,
        ) {
            Ok(())
        } else {
            Err(cb_data.1.take().unwrap())
        }
    }
}

mod refs {
    use super::*;
    extern "C" {
        pub fn for_each_ref_in(
            prefix: *const c_char,
            cb: unsafe extern "C" fn(*const c_char, *const object_id, c_int, *mut c_void) -> c_int,
            cb_data: *mut c_void,
        ) -> c_int;
    }
}

pub fn for_each_ref_in<E, F: FnMut(&OsStr, &GitObjectId) -> Result<(), E>>(
    prefix: &OsStr,
    f: F,
) -> Result<(), Option<E>> {
    let mut cb_data = (f, None);
    let prefix = prefix.to_cstring();

    unsafe extern "C" fn each_ref_cb<E, F: FnMut(&OsStr, &GitObjectId) -> Result<(), E>>(
        refname: *const c_char,
        oid: *const object_id,
        _flags: c_int,
        cb_data: *mut c_void,
    ) -> c_int {
        let (func, ref mut error) = (cb_data as *mut (F, Option<E>)).as_mut().unwrap();
        let refname = OsStr::from_bytes(CStr::from_ptr(refname).to_bytes());
        let oid = GitObjectId::from(oid.as_ref().unwrap().clone());
        match func(refname, &oid) {
            Ok(()) => 0,
            Err(e) => {
                *error = Some(e);
                -1
            }
        }
    }

    unsafe {
        if 0 == refs::for_each_ref_in(
            prefix.as_ptr(),
            each_ref_cb::<E, F>,
            &mut cb_data as *mut (F, Option<E>) as *mut c_void,
        ) {
            Ok(())
        } else {
            Err(cb_data.1.take())
        }
    }
}
