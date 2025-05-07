/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{c_void, CStr, CString, OsStr, OsString};
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort};
use std::ptr::{self, NonNull};
use std::str::FromStr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use bstr::ByteSlice;
use cstr::cstr;
use curl_sys::{CURLcode, CURL, CURL_ERROR_SIZE};
use itertools::{EitherOrBoth, Itertools};

use crate::git::{BlobId, CommitId, GitObjectId, GitOid, RecursedTreeEntry};
use crate::oid::{Abbrev, ObjectId};
use crate::tree_util::WithPath;
use crate::util::{CStrExt, DurationExt, ImmutBString, OptionExt, OsStrExt, Transpose};
use crate::{check_enabled, experiment_similarity, logging, Checks};

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
    pub fn credential_fill(repo: *mut repository, auth: *mut credential, all_capabilities: c_int);

    pub static mut http_auth: credential;

    pub fn http_init(remote: *mut remote, url: *const c_char, proactive_auth: c_int);
    pub fn http_cleanup();

    pub fn get_active_slot() -> *mut active_request_slot;

    pub fn run_one_slot(slot: *mut active_request_slot, results: *mut slot_results) -> c_int;

    pub static curl_errorstr: [c_char; CURL_ERROR_SIZE];

    pub static ssl_cainfo: *mut c_char;
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct credential([u8; 0]);

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct remote([u8; 0]);

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct object_entry([u8; 0]);

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
    contentp: *mut *mut c_void,
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

pub struct FfiBox<T: ?Sized> {
    ptr: NonNull<T>,
    marker: PhantomData<T>,
}

impl<T: ?Sized> FfiBox<T> {
    pub unsafe fn from_raw(raw: *mut T) -> FfiBox<T> {
        FfiBox {
            ptr: NonNull::new(raw).unwrap(),
            marker: PhantomData,
        }
    }
}

impl<T> FfiBox<[T]> {
    pub unsafe fn from_raw_parts(raw: *mut T, len: usize) -> FfiBox<[T]> {
        FfiBox {
            ptr: NonNull::slice_from_raw_parts(NonNull::new(raw).unwrap(), len),
            marker: PhantomData,
        }
    }
}

impl<T: ?Sized> Deref for FfiBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for FfiBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl Clone for FfiBox<[u8]> {
    fn clone(&self) -> Self {
        let mut cloned = strbuf::new();
        cloned.extend_from_slice(self.as_bytes());
        let buf = cloned.as_ptr() as *mut _;
        let len = cloned.as_bytes().len();
        mem::forget(cloned);
        unsafe { FfiBox::from_raw_parts(buf, len) }
    }
}

impl<T: ?Sized> Drop for FfiBox<T> {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.ptr.cast().as_ptr());
        }
    }
}

impl From<strbuf> for Option<FfiBox<[u8]>> {
    fn from(value: strbuf) -> Self {
        (value.len != 0).then(|| {
            let ptr = value.buf as *mut _;
            let len = value.len;
            mem::forget(value);
            unsafe { FfiBox::from_raw_parts(ptr, len) }
        })
    }
}

pub fn git_object_info(
    oid: impl Into<GitObjectId>,
    with_content: bool,
) -> Option<(object_type, Option<FfiBox<[u8]>>)> {
    let mut info = object_info::default();
    let mut t = object_type::OBJ_NONE;
    let mut len: c_ulong = 0;
    let mut buf = std::ptr::null_mut();
    info.typep = &mut t;
    if with_content {
        info.sizep = &mut len;
        info.contentp = &mut buf;
    }
    (unsafe { oid_object_info_extended(the_repository, &oid.into().into(), &mut info, 0) } == 0)
        .then(|| {
            (
                t,
                with_content.then(|| unsafe {
                    FfiBox::from_raw_parts(buf as *mut _, len.try_into().unwrap())
                }),
            )
        })
}

extern "C" {
    pub static mut the_repository: *mut repository;

    pub static local_repo_env: [*const c_char; 1];

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
pub struct rev_info([u8; 0]);

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct commit([u8; 0]);

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct commit_list([u8; 0]);

extern "C" {
    pub fn commit_oid(c: *const commit) -> *const object_id;

    fn get_revision(revs: *mut rev_info) -> *const commit;

    fn rev_list_new(argc: c_int, argv: *const *const c_char) -> *mut rev_info;

    fn rev_list_finish(revs: *mut rev_info);

    fn maybe_boundary(revs: *const rev_info, c: *const commit) -> c_int;

    fn get_saved_parents(revs: *mut rev_info, c: *const commit) -> *const commit_list;
}

pub struct RevList {
    revs: *mut rev_info,
    duration: Option<(Duration, Duration)>,
}

pub fn rev_list(args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> RevList {
    let log_level = logging::max_log_level("rev-list", log::Level::Debug).to_level();
    let start = (check_enabled(Checks::TIME) && log_level.is_some()).then(Instant::now);
    let args: Vec<_> = Some(OsStr::new("").to_cstring())
        .into_iter()
        .chain(args.into_iter().map(|a| a.as_ref().to_cstring()))
        .collect();
    if let Some(log_level) = log_level {
        let mut data = String::new();
        let mut commits = 0;
        let mut substracted_commits = 0;

        let maybe_add_commits = |data: &mut String, commits: usize, substracted_commits: usize| {
            if !data.is_empty() {
                data.push(' ');
            }
            for (commits, name) in [
                (commits, "commit"),
                (substracted_commits, "substracted commit"),
            ] {
                if commits > 0 {
                    data.push('[');
                    data.push_str(&commits.to_string());
                    data.push(' ');
                    data.push_str(name);
                    if commits > 1 {
                        data.push('s');
                    }
                    data.push(']');
                }
            }
        };
        for arg in args.iter().skip(1) {
            if arg.as_bytes().starts_with(b"-") || log_level == log::Level::Trace {
                maybe_add_commits(&mut data, commits, substracted_commits);
                if !data.is_empty() {
                    data.push(' ');
                }
                data.push_str(&arg.to_string_lossy());
                commits = 0;
                substracted_commits = 0;
            } else if arg.as_bytes().starts_with(b"^") {
                substracted_commits += 1;
            } else {
                commits += 1;
            }
        }
        maybe_add_commits(&mut data, commits, substracted_commits);
        log!(target: "rev-list", log_level, "{}", data);
    }
    let mut argv: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    RevList {
        revs: unsafe { rev_list_new(args.len().try_into().unwrap(), &argv[0]) },
        duration: start.map(|start| (start.elapsed(), Duration::ZERO)),
    }
}

impl Drop for RevList {
    fn drop(&mut self) {
        let start = self.duration.is_some().then(Instant::now);
        unsafe {
            rev_list_finish(self.revs);
        }
        if let Some(((init_duration, duration), start)) = self.duration.as_mut().zip(start) {
            *duration += start.elapsed();
            debug!(target: "rev-list", "{} elapsed initially, then {}.", init_duration.fuzzy_display(), duration.fuzzy_display());
        }
    }
}

impl Iterator for RevList {
    type Item = CommitId;
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.duration.is_some().then(Instant::now);
        let result = unsafe {
            get_revision(self.revs).as_ref().map(|c| {
                CommitId::from_unchecked(GitObjectId::from(commit_oid(c).as_ref().unwrap().clone()))
            })
        };
        if let Some(((_, duration), start)) = self.duration.as_mut().zip(start) {
            *duration += start.elapsed();
        }
        result
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MaybeBoundary {
    Commit,
    Boundary,
    Shallow,
}

impl Iterator for RevListWithBoundaries {
    type Item = (CommitId, MaybeBoundary);
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.0.duration.is_some().then(Instant::now);
        let result = unsafe {
            get_revision(self.0.revs).as_ref().map(|c| {
                let cid = CommitId::from_unchecked(GitObjectId::from(
                    commit_oid(c).as_ref().unwrap().clone(),
                ));
                let maybe_boundary = match maybe_boundary(self.0.revs, c) {
                    0 => MaybeBoundary::Commit,
                    1 => MaybeBoundary::Boundary,
                    2 => MaybeBoundary::Shallow,
                    _ => unreachable!(),
                };
                (cid, maybe_boundary)
            })
        };
        if let Some(((_, duration), start)) = self.0.duration.as_mut().zip(start) {
            *duration += start.elapsed();
        }
        result
    }
}

pub struct RevListWithParents(RevList);

pub fn rev_list_with_parents(
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> RevListWithParents {
    let args = args.into_iter().collect_vec();
    let args = args
        .iter()
        .map(AsRef::as_ref)
        .chain([OsStr::new("--parents")]);
    RevListWithParents(rev_list(args))
}

impl Iterator for RevListWithParents {
    type Item = (CommitId, Box<[CommitId]>);
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.0.duration.is_some().then(Instant::now);
        let result = unsafe {
            get_revision(self.0.revs).as_ref().map(|c| {
                let mut parents_commit_list = get_saved_parents(self.0.revs, c);
                let mut parents = Vec::new();
                loop {
                    if parents_commit_list.is_null() {
                        break;
                    }
                    parents.push(CommitId::from_unchecked(GitObjectId::from(
                        commit_oid(commit_list_item(parents_commit_list))
                            .as_ref()
                            .unwrap()
                            .clone(),
                    )));
                    parents_commit_list = commit_list_next(parents_commit_list);
                }
                (
                    CommitId::from_unchecked(GitObjectId::from(
                        commit_oid(c).as_ref().unwrap().clone(),
                    )),
                    parents.into(),
                )
            })
        };
        if let Some(((_, duration), start)) = self.0.duration.as_mut().zip(start) {
            *duration += start.elapsed();
        }
        result
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

impl From<FileMode> for u16 {
    fn from(value: FileMode) -> Self {
        value.0
    }
}

impl From<u16> for FileMode {
    fn from(value: u16) -> Self {
        FileMode(value)
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
        experiment_similarity(),
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
        let mut remote_name = strbuf::new();
        remote_name.extend_from_slice(name.as_bytes());
        let result = unsafe { remote_get(remote_name.as_ptr()).as_mut().unwrap() };
        if (result.get_url() as *const OsStr as *const c_char) == remote_name.as_ptr() {
            // In some cases remote_get takes ownership of the name given, if it's an url.
            // But only the first time for a give url. When that happens, we want to leak it.
            std::mem::forget(remote_name);
        }
        result
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

extern "C" {
    pub fn get_main_ref_store(r: *mut repository) -> *mut ref_store;

    pub fn refs_for_each_ref_in(
        refs: *const ref_store,
        prefix: *const c_char,
        cb: unsafe extern "C" fn(
            *const c_char,
            *const c_char,
            *const object_id,
            c_int,
            *mut c_void,
        ) -> c_int,
        cb_data: *mut c_void,
    ) -> c_int;
}

static REFS_LOCK: RwLock<()> = RwLock::new(());

pub fn for_each_ref_in<E, S: AsRef<OsStr>, F: FnMut(&OsStr, CommitId) -> Result<(), E>>(
    prefix: S,
    f: F,
) -> Result<(), E> {
    let _locked = REFS_LOCK.read().unwrap();
    let mut cb_data = (f, None);
    let prefix = prefix.as_ref().to_cstring();

    unsafe extern "C" fn each_ref_cb<E, F: FnMut(&OsStr, CommitId) -> Result<(), E>>(
        refname: *const c_char,
        _referent: *const c_char,
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
        if 0 == refs_for_each_ref_in(
            get_main_ref_store(the_repository),
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
    fn refs_read_ref(refs: *const ref_store, refname: *const c_char, oid: *mut object_id) -> c_int;
}

pub fn resolve_ref<S: AsRef<OsStr>>(refname: S) -> Option<CommitId> {
    let _locked = REFS_LOCK.read().unwrap();
    let mut oid = object_id::default();
    unsafe {
        if refs_read_ref(
            get_main_ref_store(the_repository),
            refname.as_ref().to_cstring().as_ptr(),
            &mut oid,
        ) == 0
        {
            // We ignore tags. See comment in for_each_ref_in.
            CommitId::try_from(GitObjectId::from(oid)).ok()
        } else {
            None
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct ref_transaction(c_void);

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct ref_store(c_void);

extern "C" {
    fn ref_store_transaction_begin(
        refs: *const ref_store,
        flags: c_uint,
        err: *mut strbuf,
    ) -> *mut ref_transaction;

    fn ref_transaction_free(tr: *mut ref_transaction);

    fn ref_transaction_update(
        tr: *mut ref_transaction,
        refname: *const c_char,
        new_oid: *const object_id,
        old_oid: *const object_id,
        new_target: *const c_char,
        old_target: *const c_char,
        flags: c_uint,
        msg: *const c_char,
        err: *mut strbuf,
    ) -> c_int;

    fn ref_transaction_delete(
        tr: *mut ref_transaction,
        refname: *const c_char,
        old_oid: *const object_id,
        old_target: *const c_char,
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
        Self::new_with_ref_store(unsafe { get_main_ref_store(the_repository).as_ref().unwrap() })
    }

    pub fn new_with_ref_store(refs: &ref_store) -> Option<Self> {
        let mut err = strbuf::new();
        Some(RefTransaction {
            tr: unsafe { ref_store_transaction_begin(refs, 0, &mut err).as_mut()? },
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
                ptr::null(),
                ptr::null(),
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
                ptr::null(),
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
    fn repo_config_get_value(
        r: *mut repository,
        key: *const c_char,
        value: *mut *const c_char,
    ) -> c_int;
}

pub fn config_get_value(key: &str) -> Option<OsString> {
    let mut value = std::ptr::null();
    let key = CString::new(key).unwrap();
    (unsafe { repo_config_get_value(the_repository, key.as_ptr(), &mut value) } == 0)
        .then(|| unsafe { CStr::from_ptr(value) }.to_osstr().to_os_string())
}

extern "C" {
    fn get_reachable_subset(
        from: *const *const commit,
        nr_from: usize,
        to: *const *const commit,
        nr_to: usize,
        reachable_flag: c_uint,
    ) -> *mut commit_list;

    fn commit_list_count(l: *const commit_list) -> c_uint;

    fn free_commit_list(list: *mut commit_list);

    fn commit_list_next(list: *const commit_list) -> *const commit_list;

    fn commit_list_item(list: *const commit_list) -> *const commit;

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
        list: unsafe { get_reachable_subset(from.as_ptr(), from.len(), to.as_ptr(), to.len(), 0) },
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct notes_tree {
    root: *mut c_void,
    first_non_note: *mut c_void,
    prev_non_note: *mut c_void,
    r#ref: *const c_char,
    update_ref: *const c_char,
    combine_notes:
        unsafe extern "C" fn(cur_oid: *mut object_id, new_oid: *const object_id) -> c_int,
    initialized: c_int,
    dirty: c_int,
}

extern "C" {
    pub fn combine_notes_ignore(cur_oid: *mut object_id, new_oid: *const object_id) -> c_int;

    pub fn init_notes(
        notes: *mut notes_tree,
        notes_ref: *const c_char,
        combine_notes_fn: unsafe extern "C" fn(
            cur_oid: *mut object_id,
            new_oid: *const object_id,
        ) -> c_int,
        flags: c_int,
    );

    pub fn free_notes(notes: *mut notes_tree);
}

impl notes_tree {
    pub const fn new() -> Self {
        notes_tree {
            root: ptr::null_mut(),
            first_non_note: ptr::null_mut(),
            prev_non_note: ptr::null_mut(),
            r#ref: ptr::null(),
            update_ref: ptr::null(),
            combine_notes: combine_notes_ignore,
            initialized: 0,
            dirty: 0,
        }
    }

    pub const fn initialized(&self) -> bool {
        self.initialized != 0
    }

    pub const fn dirty(&self) -> bool {
        self.dirty != 0
    }
}

mod ident {
    use std::os::raw::{c_char, c_int};

    extern "C" {
        pub fn git_committer_info(flag: c_int) -> *const c_char;
        pub fn git_author_info(flag: c_int) -> *const c_char;
    }
}

pub fn git_committer_info() -> ImmutBString {
    unsafe { CStr::from_ptr(ident::git_committer_info(0).as_ref().unwrap()) }
        .to_bytes()
        .to_vec()
        .into()
}

pub fn git_author_info() -> ImmutBString {
    unsafe { CStr::from_ptr(ident::git_author_info(0).as_ref().unwrap()) }
        .to_bytes()
        .to_vec()
        .into()
}
