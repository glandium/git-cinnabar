/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{c_void, CStr, CString, OsStr, OsString};
use std::fmt;
use std::io::{self, Write};
use std::num::ParseIntError;
use std::os::raw::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort};
use std::str::FromStr;
use std::sync::RwLock;

use bstr::ByteSlice;
use cstr::cstr;
use curl_sys::{CURLcode, CURL, CURL_ERROR_SIZE};
use derive_more::Deref;
use getset::{CopyGetters, Getters};
use hex_literal::hex;
use itertools::EitherOrBoth;
use itertools::Itertools;
use once_cell::sync::Lazy;

use crate::git::{BlobId, CommitId, GitObjectId, GitOid, RecursedTreeEntry, TreeId};
use crate::oid::{Abbrev, ObjectId};
use crate::tree_util::WithPath;
use crate::util::{CStrExt, FromBytes, OptionExt, OsStrExt, SliceExt, Transpose};

const GIT_MAX_RAWSZ: usize = 32;
const GIT_HASH_SHA1: c_int = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone)]
pub struct object_id([u8; GIT_MAX_RAWSZ], c_int);

impl object_id {
    pub fn as_raw_bytes(&self) -> &[u8] {
        assert_eq!(self.1, GIT_HASH_SHA1);
        &self.0[..<sha1::Sha1 as digest::OutputSizeUser>::output_size()]
    }
}

impl Default for object_id {
    fn default() -> Self {
        Self([0; GIT_MAX_RAWSZ], GIT_HASH_SHA1)
    }
}

impl From<GitObjectId> for object_id {
    fn from(oid: GitObjectId) -> Self {
        let mut result = object_id::default();
        let oid = oid.as_raw_bytes();
        result.0[..oid.len()].clone_from_slice(oid);
        result
    }
}

impl From<object_id> for GitObjectId {
    fn from(oid: object_id) -> Self {
        let mut result = Self::NULL;
        let slice = result.as_raw_bytes_mut();
        slice.clone_from_slice(&oid.0[..slice.len()]);
        result
    }
}

extern "C" {
    pub static mut metadata_oid: object_id;
    pub static mut changesets_oid: object_id;
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

    pub fn as_ptr(&mut self) -> *mut c_char {
        self.buf
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

macro_rules! die {
    ($($e:expr),+) => {
        panic!($($e),+)
    }
}
pub(crate) use die;

extern "C" {
    pub fn credential_fill(auth: *mut credential);

    pub static mut http_auth: credential;

    pub fn http_init(remote: *mut remote, url: *const c_char, proactive_auth: c_int);
    pub fn http_cleanup();

    pub fn get_active_slot() -> *mut active_request_slot;

    pub fn run_one_slot(slot: *mut active_request_slot, results: *mut slot_results) -> c_int;

    pub static curl_errorstr: [c_char; CURL_ERROR_SIZE];

    pub static ssl_cainfo: *mut c_char;
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
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum http_follow_config {
    HTTP_FOLLOW_NONE,
    HTTP_FOLLOW_ALWAYS,
    HTTP_FOLLOW_INITIAL,
}

extern "C" {
    pub static http_follow_config: http_follow_config;
}

#[allow(non_camel_case_types)]
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

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct object_info {
    typep: *mut object_type,
    sizep: *mut c_ulong,
    disk_sizep: *mut u64,
    delta_base_oid: *mut object_id,
    type_name: *mut strbuf,
    contentp: *mut *const c_void,
    whence: c_int, // In reality, it's an inline enum.
    // In reality, following is a union with one struct.
    u_packed_pack: *mut c_void, // packed_git.
    u_packed_offset: u64,
    u_packed_is_delta: c_uint,
}

impl Default for object_info {
    fn default() -> Self {
        object_info {
            typep: std::ptr::null_mut(),
            sizep: std::ptr::null_mut(),
            disk_sizep: std::ptr::null_mut(),
            delta_base_oid: std::ptr::null_mut(),
            type_name: std::ptr::null_mut(),
            contentp: std::ptr::null_mut(),
            whence: 0,
            u_packed_pack: std::ptr::null_mut(),
            u_packed_offset: 0,
            u_packed_is_delta: 0,
        }
    }
}

extern "C" {
    fn oid_object_info_extended(
        r: *mut repository,
        oid: *const object_id,
        oi: *mut object_info,
        flags: c_uint,
    ) -> c_int;
}

pub struct RawObject {
    buf: *const c_void,
    len: usize,
}

impl RawObject {
    fn read(oid: GitObjectId) -> Option<(object_type, RawObject)> {
        let mut info = object_info::default();
        let mut t = object_type::OBJ_NONE;
        let mut len: c_ulong = 0;
        let mut buf = std::ptr::null();
        info.typep = &mut t;
        info.sizep = &mut len;
        info.contentp = &mut buf;
        (unsafe { oid_object_info_extended(the_repository, &oid.into(), &mut info, 0) } == 0).then(
            || {
                let raw = RawObject {
                    buf,
                    len: len.try_into().unwrap(),
                };
                (t, raw)
            },
        )
    }

    fn get_type<O: Into<GitObjectId>>(oid: O) -> Option<object_type> {
        let mut info = object_info::default();
        let mut t = object_type::OBJ_NONE;
        info.typep = &mut t;
        (unsafe { oid_object_info_extended(the_repository, &oid.into().into(), &mut info, 0) } == 0)
            .then_some(t)
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

macro_rules! raw_object {
    ($t:ident | $oid_type:ident => $name:ident) => {
        #[derive(Deref)]
        pub struct $name(RawObject);

        impl $name {
            pub fn read(oid: $oid_type) -> Option<Self> {
                match RawObject::read(oid.into())? {
                    (object_type::$t, o) => Some($name(o)),
                    _ => None,
                }
            }
        }

        impl TryFrom<GitObjectId> for $oid_type {
            type Error = ();
            fn try_from(oid: GitObjectId) -> std::result::Result<Self, ()> {
                match RawObject::get_type(oid).ok_or(())? {
                    object_type::$t => Ok($oid_type::from_unchecked(oid)),
                    _ => Err(()),
                }
            }
        }
    };
}

raw_object!(OBJ_COMMIT | CommitId => RawCommit);
raw_object!(OBJ_TREE | TreeId => RawTree);
raw_object!(OBJ_BLOB | BlobId => RawBlob);

impl RawBlob {
    pub const EMPTY_OID: BlobId =
        BlobId::from_raw_bytes_array(hex!("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"));
}

impl RawTree {
    pub const EMPTY_OID: TreeId =
        TreeId::from_raw_bytes_array(hex!("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));

    pub const EMPTY: RawTree = RawTree(RawObject {
        buf: std::ptr::null(),
        len: 0,
    });
}

#[derive(CopyGetters, Getters)]
pub struct Commit<'a> {
    #[getset(get_copy = "pub")]
    tree: TreeId,
    parents: Vec<CommitId>,
    #[getset(get_copy = "pub")]
    author: &'a [u8],
    #[getset(get_copy = "pub")]
    committer: &'a [u8],
    #[getset(get_copy = "pub")]
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

extern "C" {
    pub static mut the_repository: *mut repository;

    static default_abbrev: c_int;

    fn repo_get_oid_committish(r: *mut repository, s: *const c_char, oid: *mut object_id) -> c_int;

    fn repo_get_oid_blob(repo: *mut repository, name: *const c_char, oid: *mut object_id) -> c_int;

    fn repo_find_unique_abbrev_r(
        r: *mut repository,
        hex: *mut c_char,
        oid: *const object_id,
        len: c_int,
    ) -> c_int;

    fn repo_lookup_replace_object(r: *mut repository, oid: *const object_id) -> *const object_id;
}

pub fn get_oid_committish(s: &[u8]) -> Option<CommitId> {
    unsafe {
        let mut s = s.to_vec();
        s.extend_from_slice(b"^{commit}");
        let c = CString::new(s).unwrap();
        let mut oid = object_id::default();
        (repo_get_oid_committish(the_repository, c.as_ptr(), &mut oid) == 0)
            .then(|| CommitId::from_unchecked(oid.into()))
    }
}

pub fn get_oid_blob(s: &[u8]) -> Option<BlobId> {
    unsafe {
        let c = CString::new(s).unwrap();
        let mut oid = object_id::default();
        (repo_get_oid_blob(the_repository, c.as_ptr(), &mut oid) == 0)
            .then(|| BlobId::from_unchecked(oid.into()))
    }
}

pub fn get_unique_abbrev<O: ObjectId + Into<object_id>>(oid: O) -> Abbrev<O> {
    let mut hex: [c_char; GIT_MAX_RAWSZ * 2 + 1] = [0; GIT_MAX_RAWSZ * 2 + 1];
    let len = unsafe {
        repo_find_unique_abbrev_r(
            the_repository,
            hex.as_mut_ptr(),
            &oid.into(),
            default_abbrev,
        )
    };
    let s = unsafe { CStr::from_ptr(hex.as_ptr()) }.to_str().unwrap();
    assert_eq!(s.len(), len as usize);
    Abbrev::from_str(s).unwrap()
}

pub fn lookup_replace_commit(c: CommitId) -> CommitId {
    unsafe {
        let oid = object_id::from(c);
        let replaced = repo_lookup_replace_object(the_repository, &oid);
        if replaced == &oid {
            c
        } else {
            //TODO: we should actually check the object is a commit.
            CommitId::from_unchecked(replaced.as_ref().unwrap().clone().into())
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

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct commit_list(c_void);

extern "C" {
    fn commit_oid(c: *const commit) -> *const object_id;

    fn get_revision(revs: *mut rev_info) -> *const commit;

    fn rev_list_new(argc: c_int, argv: *const *const c_char) -> *mut rev_info;

    fn rev_list_finish(revs: *mut rev_info);

    fn maybe_boundary(revs: *const rev_info, c: *const commit) -> c_int;
}

pub struct RevList {
    revs: *mut rev_info,
}

pub fn rev_list(args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> RevList {
    let args: Vec<_> = Some(OsStr::new("").to_cstring())
        .into_iter()
        .chain(args.into_iter().map(|a| a.as_ref().to_cstring()))
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
            get_revision(self.revs).as_ref().map(|c| {
                CommitId::from_unchecked(GitObjectId::from(commit_oid(c).as_ref().unwrap().clone()))
            })
        }
    }
}

pub struct RevListWithBoundaries(RevList);

pub fn rev_list_with_boundaries(
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> RevListWithBoundaries {
    let args = args.into_iter().collect_vec();
    let args = args
        .iter()
        .map(AsRef::as_ref)
        .chain([OsStr::new("--boundary")]);
    RevListWithBoundaries(rev_list(args))
}

pub enum MaybeBoundary {
    Commit(CommitId),
    Boundary(CommitId),
    Shallow,
}

impl Iterator for RevListWithBoundaries {
    type Item = MaybeBoundary;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            get_revision(self.0.revs).as_ref().map(|c| {
                let cid = CommitId::from_unchecked(GitObjectId::from(
                    commit_oid(c).as_ref().unwrap().clone(),
                ));
                match maybe_boundary(self.0.revs, c) {
                    0 => MaybeBoundary::Commit(cid),
                    1 => MaybeBoundary::Boundary(cid),
                    2 => MaybeBoundary::Shallow,
                    _ => unreachable!(),
                }
            })
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
        context: *mut c_void,
    );
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FileMode(u16);

impl fmt::Debug for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:06o}", self.0)
    }
}

impl FromBytes for FileMode {
    type Err = ParseIntError;

    fn from_bytes(b: &[u8]) -> Result<Self, Self::Err> {
        u16::from_str_radix(std::str::from_utf8(b).unwrap(), 8).map(FileMode)
    }
}

#[allow(clippy::unnecessary_cast)]
impl FileMode {
    pub const REGULAR: Self = FileMode(0o100_000);
    pub const SYMLINK: Self = FileMode(0o120_000);
    pub const DIRECTORY: Self = FileMode(0o040_000);
    pub const GITLINK: Self = FileMode(0o160_000);
    pub const RW: Self = FileMode(0o644);
    pub const RWX: Self = FileMode(0o755);
    pub const NONE: Self = FileMode(0);

    pub fn typ(&self) -> FileMode {
        FileMode(self.0 & 0o170_000)
    }

    pub fn perms(&self) -> FileMode {
        FileMode(self.0 & !0o170_000)
    }
}

impl std::ops::BitOr for FileMode {
    type Output = FileMode;

    fn bitor(self, rhs: Self) -> Self::Output {
        FileMode(self.0 | rhs.0)
    }
}

#[derive(Debug)]
pub enum DiffTreeItem {
    Added(RecursedTreeEntry),
    Deleted(RecursedTreeEntry),
    Modified {
        from: RecursedTreeEntry,
        to: RecursedTreeEntry,
    },
    Renamed {
        from: WithPath<RecursedTreeEntry>,
        to: RecursedTreeEntry,
    },
    Copied {
        from: WithPath<RecursedTreeEntry>,
        to: RecursedTreeEntry,
    },
}

unsafe extern "C" fn diff_tree_fill(diff_tree: *mut c_void, item: *const diff_tree_item) {
    fn gitoid(f: &diff_tree_file) -> GitOid {
        unsafe {
            (
                GitObjectId::from(f.oid.as_ref().unwrap().clone()),
                FileMode(f.mode),
            )
                .into()
        }
    }

    let diff_tree = (diff_tree as *mut Vec<WithPath<DiffTreeItem>>)
        .as_mut()
        .unwrap();
    let item = item.as_ref().unwrap();
    let item = match item.status {
        DIFF_STATUS_MODIFIED | DIFF_STATUS_TYPE_CHANGED => {
            let a_path = CStr::from_ptr(item.a.path).to_bytes();
            let b_path = CStr::from_ptr(item.b.path).to_bytes();
            EitherOrBoth::Both(WithPath::new(a_path, ()), WithPath::new(b_path, ()))
                .transpose()
                .unwrap()
                .map(|_| DiffTreeItem::Modified {
                    from: RecursedTreeEntry {
                        oid: gitoid(&item.a),
                        mode: FileMode(item.a.mode),
                    },
                    to: RecursedTreeEntry {
                        oid: gitoid(&item.b),
                        mode: FileMode(item.b.mode),
                    },
                })
        }
        DIFF_STATUS_ADDED => WithPath::new(
            CStr::from_ptr(item.b.path).to_bytes(),
            DiffTreeItem::Added(RecursedTreeEntry {
                oid: gitoid(&item.b),
                mode: FileMode(item.b.mode),
            }),
        ),
        DIFF_STATUS_DELETED => WithPath::new(
            CStr::from_ptr(item.b.path).to_bytes(),
            DiffTreeItem::Deleted(RecursedTreeEntry {
                oid: gitoid(&item.a),
                mode: FileMode(item.a.mode),
            }),
        ),
        DIFF_STATUS_RENAMED => WithPath::new(
            CStr::from_ptr(item.b.path).to_bytes(),
            DiffTreeItem::Renamed {
                from: WithPath::new(
                    CStr::from_ptr(item.a.path).to_bytes(),
                    RecursedTreeEntry {
                        oid: gitoid(&item.a),
                        mode: FileMode(item.a.mode),
                    },
                ),
                to: RecursedTreeEntry {
                    oid: gitoid(&item.b),
                    mode: FileMode(item.b.mode),
                },
            },
        ),
        DIFF_STATUS_COPIED => WithPath::new(
            CStr::from_ptr(item.b.path).to_bytes(),
            DiffTreeItem::Copied {
                from: WithPath::new(
                    CStr::from_ptr(item.a.path).to_bytes(),
                    RecursedTreeEntry {
                        oid: gitoid(&item.a),
                        mode: FileMode(item.a.mode),
                    },
                ),
                to: RecursedTreeEntry {
                    oid: gitoid(&item.b),
                    mode: FileMode(item.b.mode),
                },
            },
        ),
        c => panic!("Unknown diff state: {}", c),
    };
    diff_tree.push(item);
}

pub fn diff_tree_with_copies(
    a: CommitId,
    b: CommitId,
) -> impl Iterator<Item = WithPath<DiffTreeItem>> {
    let a = CString::new(format!("{}", a)).unwrap();
    let b = CString::new(format!("{}", b)).unwrap();
    let args = [
        cstr!(""),
        &a,
        &b,
        cstr!("--ignore-submodules=dirty"),
        cstr!("-C"),
        cstr!("-C100%"),
        cstr!("--"),
    ];
    let mut argv: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut result = Vec::<WithPath<DiffTreeItem>>::new();
    unsafe {
        diff_tree_(
            (argv.len() - 1).try_into().unwrap(),
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

static REFS_LOCK: Lazy<RwLock<()>> = Lazy::new(|| RwLock::new(()));

pub fn for_each_ref_in<E, S: AsRef<OsStr>, F: FnMut(&OsStr, CommitId) -> Result<(), E>>(
    prefix: S,
    f: F,
) -> Result<(), E> {
    let _locked = REFS_LOCK.read().unwrap();
    let mut cb_data = (f, None);
    let prefix = prefix.as_ref().to_cstring();

    unsafe extern "C" fn each_ref_cb<E, F: FnMut(&OsStr, CommitId) -> Result<(), E>>(
        refname: *const c_char,
        oid: *const object_id,
        _flags: c_int,
        cb_data: *mut c_void,
    ) -> c_int {
        let (func, ref mut error) = (cb_data as *mut (F, Option<E>)).as_mut().unwrap();
        let refname = OsStr::from_bytes(CStr::from_ptr(refname).to_bytes());
        if let Ok(oid) = CommitId::try_from(GitObjectId::from(oid.as_ref().unwrap().clone())) {
            match func(refname, oid) {
                Ok(()) => 0,
                Err(e) => {
                    *error = Some(e);
                    -1
                }
            }
        } else {
            // We only interate refs that point to commits. Refs may technically also
            // point to tags, but we don't expect to rely on finding tags this way.
            0
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
            Err(cb_data.1.unwrap())
        }
    }
}

extern "C" {
    fn read_ref(refname: *const c_char, oid: *mut object_id) -> c_int;
}

pub fn resolve_ref<S: AsRef<OsStr>>(refname: S) -> Option<CommitId> {
    let _locked = REFS_LOCK.read().unwrap();
    let mut oid = object_id::default();
    unsafe {
        if read_ref(refname.as_ref().to_cstring().as_ptr(), &mut oid) == 0 {
            // We ignore tags. See comment in for_each_ref_in.
            CommitId::try_from(GitObjectId::from(oid)).ok()
        } else {
            None
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct ref_transaction(c_void);

extern "C" {
    fn ref_transaction_begin(err: *mut strbuf) -> *mut ref_transaction;

    fn ref_transaction_free(tr: *mut ref_transaction);

    fn ref_transaction_update(
        tr: *mut ref_transaction,
        refname: *const c_char,
        new_oid: *const object_id,
        old_oid: *const object_id,
        flags: c_uint,
        msg: *const c_char,
        err: *mut strbuf,
    ) -> c_int;

    fn ref_transaction_delete(
        tr: *mut ref_transaction,
        refname: *const c_char,
        old_oid: *const object_id,
        flags: c_uint,
        msg: *const c_char,
        err: *mut strbuf,
    ) -> c_int;

    fn ref_transaction_commit(tr: *mut ref_transaction, err: *mut strbuf) -> c_int;

    fn ref_transaction_abort(tr: *mut ref_transaction, err: *mut strbuf) -> c_int;
}

pub struct RefTransaction {
    tr: *mut ref_transaction,
    err: strbuf,
}

impl RefTransaction {
    pub fn new() -> Option<Self> {
        let mut err = strbuf::new();
        Some(RefTransaction {
            tr: unsafe { ref_transaction_begin(&mut err).as_mut()? },
            err,
        })
    }

    pub fn commit(mut self) -> Result<(), String> {
        let _locked = REFS_LOCK.try_write().unwrap();
        let tr = std::mem::replace(&mut self.tr, std::ptr::null_mut());
        let ret = unsafe { ref_transaction_commit(tr, &mut self.err) };
        unsafe {
            ref_transaction_free(tr);
        }
        if ret == 0 {
            Ok(())
        } else {
            Err(self.err.as_bytes().to_str_lossy().to_string())
        }
    }

    pub fn abort(mut self) -> Result<(), String> {
        let tr = std::mem::replace(&mut self.tr, std::ptr::null_mut());
        let ret = unsafe { ref_transaction_abort(tr, &mut self.err) };
        if ret == 0 {
            Ok(())
        } else {
            Err(self.err.as_bytes().to_str_lossy().to_string())
        }
    }

    pub fn update<S: AsRef<OsStr>>(
        &mut self,
        refname: S,
        new_oid: CommitId,
        old_oid: Option<CommitId>,
        msg: &str,
    ) -> Result<(), String> {
        let msg = CString::new(msg).unwrap();
        let ret = unsafe {
            ref_transaction_update(
                self.tr,
                refname.as_ref().to_cstring().as_ptr(),
                &new_oid.into(),
                old_oid.map(object_id::from).as_ref().as_ptr(),
                0,
                msg.as_ptr(),
                &mut self.err,
            )
        };
        let result = if ret == 0 {
            Ok(())
        } else {
            Err(self.err.as_bytes().to_str_lossy().to_string())
        };
        self.err.reset();
        result
    }

    pub fn delete<S: AsRef<OsStr>>(
        &mut self,
        refname: S,
        old_oid: Option<CommitId>,
        msg: &str,
    ) -> Result<(), String> {
        let msg = CString::new(msg).unwrap();
        let ret = unsafe {
            ref_transaction_delete(
                self.tr,
                refname.as_ref().to_cstring().as_ptr(),
                old_oid.map(object_id::from).as_ref().as_ptr(),
                0,
                msg.as_ptr(),
                &mut self.err,
            )
        };
        let result = if ret == 0 {
            Ok(())
        } else {
            Err(self.err.as_bytes().to_str_lossy().to_string())
        };
        self.err.reset();
        result
    }
}

impl Drop for RefTransaction {
    fn drop(&mut self) {
        if !self.tr.is_null() {
            RefTransaction {
                tr: std::mem::replace(&mut self.tr, std::ptr::null_mut()),
                err: std::mem::replace(&mut self.err, strbuf::new()),
            }
            .abort()
            .unwrap();
        }
    }
}

extern "C" {
    fn git_config_get_value(key: *const c_char, value: *mut *const c_char) -> c_int;
    fn git_config_set(key: *const c_char, value: *const c_char);
}

pub fn config_get_value(key: &str) -> Option<OsString> {
    let mut value = std::ptr::null();
    let key = CString::new(key).unwrap();
    (unsafe { git_config_get_value(key.as_ptr(), &mut value) } == 0)
        .then(|| unsafe { CStr::from_ptr(value) }.to_osstr().to_os_string())
}

pub fn config_set_value<S: ToString>(key: &str, value: S) {
    let key = CString::new(key).unwrap();
    let value = CString::new(value.to_string()).unwrap();
    unsafe {
        git_config_set(key.as_ptr(), value.as_ptr());
    }
}

extern "C" {
    fn get_reachable_subset(
        from: *const *const commit,
        nr_from: c_int,
        to: *const *const commit,
        nr_to: c_int,
        reachable_flag: c_uint,
    ) -> *mut commit_list;

    fn commit_list_count(l: *const commit_list) -> c_uint;

    fn free_commit_list(list: *mut commit_list);

    pub fn lookup_commit(r: *mut repository, oid: *const object_id) -> *const commit;
}

pub struct CommitList {
    list: *mut commit_list,
}

impl CommitList {
    pub fn is_empty(&self) -> bool {
        unsafe { commit_list_count(self.list) == 0 }
    }
}

impl Drop for CommitList {
    fn drop(&mut self) {
        unsafe {
            free_commit_list(self.list);
        }
    }
}

pub fn reachable_subset(
    from: impl IntoIterator<Item = CommitId>,
    to: impl IntoIterator<Item = CommitId>,
) -> CommitList {
    let from = from
        .into_iter()
        .map(|cid| {
            let oid = object_id::from(cid);
            unsafe { lookup_commit(the_repository, &oid) }
        })
        .collect::<Vec<_>>();
    let to = to
        .into_iter()
        .map(|cid| {
            let oid = object_id::from(cid);
            unsafe { lookup_commit(the_repository, &oid) }
        })
        .collect::<Vec<_>>();
    CommitList {
        list: unsafe {
            get_reachable_subset(
                from.as_ptr(),
                from.len().try_into().unwrap(),
                to.as_ptr(),
                to.len().try_into().unwrap(),
                0,
            )
        },
    }
}
