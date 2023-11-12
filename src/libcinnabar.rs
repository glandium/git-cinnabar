/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::CString;
use std::io::Write;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;

use crate::git::{CommitId, GitObjectId, TreeId};
use crate::hg::HgObjectId;
use crate::libgit::{
    child_process, combine_notes_ignore, free_notes, init_notes, notes_tree, object_id, strbuf,
    FileMode, RawTree,
};
use crate::oid::{Abbrev, ObjectId};
use crate::store::{store_git_commit, METADATA};

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
#[repr(C)]
pub struct strslice<'a> {
    len: usize,
    buf: *const c_char,
    marker: PhantomData<&'a [u8]>,
}

impl strslice<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buf as *const u8, self.len) }
    }
}

impl<'a, T: AsRef<[u8]> + 'a> From<T> for strslice<'a> {
    fn from(buf: T) -> Self {
        let buf = buf.as_ref();
        strslice {
            len: buf.len(),
            buf: buf.as_ptr() as *const c_char,
            marker: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct strslice_mut<'a> {
    len: usize,
    buf: *mut c_char,
    marker: PhantomData<&'a mut [u8]>,
}

impl<'a> From<&'a mut [u8]> for strslice_mut<'a> {
    fn from(buf: &'a mut [u8]) -> Self {
        strslice_mut {
            len: buf.len(),
            buf: buf.as_mut_ptr() as *mut c_char,
            marker: PhantomData,
        }
    }
}

impl<'a> From<&'a mut [MaybeUninit<u8>]> for strslice_mut<'a> {
    fn from(buf: &'a mut [MaybeUninit<u8>]) -> Self {
        strslice_mut {
            len: buf.len(),
            buf: buf.as_mut_ptr() as *mut c_char,
            marker: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Default)]
pub struct hg_object_id([u8; 20]);

impl<H: ObjectId + Into<HgObjectId>> From<H> for hg_object_id {
    fn from(oid: H) -> Self {
        let mut result = Self([0; 20]);
        let oid = oid.as_raw_bytes();
        result.0[..oid.len()].clone_from_slice(oid);
        result
    }
}

impl From<hg_object_id> for HgObjectId {
    fn from(oid: hg_object_id) -> Self {
        let mut result = Self::NULL;
        let slice = result.as_raw_bytes_mut();
        slice.clone_from_slice(&oid.0[..slice.len()]);
        result
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct cinnabar_notes_tree {
    current: notes_tree,
    additions: notes_tree,
    init_flags: c_int,
}

impl Drop for cinnabar_notes_tree {
    fn drop(&mut self) {
        unsafe {
            if self.current.initialized() {
                free_notes(&mut self.current);
                free_notes(&mut self.additions);
            }
        }
    }
}

impl cinnabar_notes_tree {
    pub fn new_with(c: CommitId) -> Self {
        let mut result = cinnabar_notes_tree {
            current: notes_tree::new(),
            additions: notes_tree::new(),
            init_flags: 0,
        };
        let oid = CString::new(c.to_string()).unwrap();
        let flags = if c.is_null() { NOTES_INIT_EMPTY } else { 0 };
        unsafe {
            init_notes(
                &mut result.current,
                oid.as_ptr(),
                combine_notes_ignore,
                flags,
            );
            init_notes(
                &mut result.additions,
                oid.as_ptr(),
                combine_notes_ignore,
                NOTES_INIT_EMPTY,
            );
            result.init_flags = flags;
        }
        result
    }
}

extern "C" {
    fn cinnabar_get_note(
        notes: *mut cinnabar_notes_tree,
        oid: *const object_id,
    ) -> *const object_id;

    fn get_abbrev_note(
        notes: *mut cinnabar_notes_tree,
        oid: *const object_id,
        len: usize,
    ) -> *const object_id;

    fn cinnabar_for_each_note(
        notes: *mut cinnabar_notes_tree,
        flags: c_int,
        cb: unsafe extern "C" fn(
            oid: *const object_id,
            note_oid: *const object_id,
            note_path: *const c_char,
            cb_data: *mut c_void,
        ) -> c_int,
        cb_data: *mut c_void,
    ) -> c_int;

    fn cinnabar_add_note(
        notes: *mut cinnabar_notes_tree,
        object_oid: *const object_id,
        note_oid: *const object_id,
    ) -> c_int;

    fn cinnabar_remove_note(notes: *mut cinnabar_notes_tree, object_sha1: *const u8);

    fn cinnabar_write_notes_tree(
        notes: *mut cinnabar_notes_tree,
        result: *mut object_id,
        mode: c_uint,
    ) -> c_int;
}

const NOTES_INIT_EMPTY: c_int = 1;

fn for_each_note_in<F: FnMut(GitObjectId, GitObjectId)>(notes: &mut cinnabar_notes_tree, mut f: F) {
    unsafe extern "C" fn each_note_cb<F: FnMut(GitObjectId, GitObjectId)>(
        oid: *const object_id,
        note_oid: *const object_id,
        _note_path: *const c_char,
        cb_data: *mut c_void,
    ) -> c_int {
        let cb = (cb_data as *mut F).as_mut().unwrap();
        let o = oid.as_ref().unwrap().clone().into();
        let n = note_oid.as_ref().unwrap().clone().into();
        cb(o, n);
        0
    }

    unsafe {
        cinnabar_for_each_note(notes, 0, each_note_cb::<F>, &mut f as *mut F as *mut c_void);
    }
}

#[no_mangle]
pub unsafe extern "C" fn resolve_hg2git(oid: *const hg_object_id) -> *const object_id {
    let git_oid =
        GitObjectId::from_raw_bytes(HgObjectId::from(oid.as_ref().unwrap().clone()).as_raw_bytes())
            .unwrap();
    cinnabar_get_note(&mut METADATA.hg2git_mut().0, &git_oid.into())
}

#[no_mangle]
pub unsafe extern "C" fn add_hg2git(oid: *const hg_object_id, note_oid: *const object_id) {
    METADATA.hg2git_mut().add_note(
        HgObjectId::from(oid.as_ref().unwrap().clone()),
        note_oid.as_ref().unwrap().clone().into(),
    );
}

pub fn store_metadata_notes(notes: &mut cinnabar_notes_tree, reference: CommitId) -> CommitId {
    let mut result = object_id::default();
    let mut tree = object_id::default();
    if notes.current.dirty() || notes.additions.dirty() {
        let mode = if ptr::eq(notes, unsafe { &METADATA.hg2git().0 }) {
            FileMode::GITLINK
        } else {
            FileMode::REGULAR | FileMode::RW
        };
        unsafe {
            cinnabar_write_notes_tree(notes, &mut tree, u16::from(mode).into());
        }
    }
    let mut tree = TreeId::from_unchecked(GitObjectId::from(tree));
    if tree.is_null() {
        result = reference.into();
        if GitObjectId::from(result.clone()).is_null() {
            tree = RawTree::EMPTY_OID;
        }
    }
    if !tree.is_null() {
        let mut buf = strbuf::new();
        writeln!(buf, "tree {}", tree).ok();
        buf.extend_from_slice(
            b"author  <cinnabar@git> 0 +0000\ncommitter  <cinnabar@git> 0 +0000\n\n",
        );
        unsafe {
            store_git_commit(buf.as_bytes().into(), &mut result);
        }
    }
    CommitId::from_unchecked(result.into())
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct git_notes_tree(cinnabar_notes_tree);

impl git_notes_tree {
    pub fn new_with(c: CommitId) -> Self {
        git_notes_tree(cinnabar_notes_tree::new_with(c))
    }

    pub fn get_note(&mut self, oid: GitObjectId) -> Option<GitObjectId> {
        unsafe {
            cinnabar_get_note(&mut self.0, &oid.into())
                .as_ref()
                .cloned()
                .map(Into::into)
        }
    }

    pub fn for_each<F: FnMut(GitObjectId, GitObjectId)>(&mut self, f: F) {
        for_each_note_in(&mut self.0, f);
    }

    pub fn add_note(&mut self, oid: GitObjectId, note_oid: GitObjectId) {
        unsafe {
            cinnabar_add_note(&mut self.0, &oid.into(), &note_oid.into());
        }
    }

    pub fn remove_note(&mut self, oid: GitObjectId) {
        unsafe {
            cinnabar_remove_note(&mut self.0, oid.as_raw_bytes().as_ptr());
        }
    }

    pub fn store(&mut self, reference: CommitId) -> CommitId {
        store_metadata_notes(&mut self.0, reference)
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct hg_notes_tree(cinnabar_notes_tree);

impl hg_notes_tree {
    #[allow(dead_code)]
    pub fn new_with(c: CommitId) -> Self {
        hg_notes_tree(cinnabar_notes_tree::new_with(c))
    }

    pub fn get_note(&mut self, oid: HgObjectId) -> Option<GitObjectId> {
        unsafe {
            let git_oid = GitObjectId::from_raw_bytes(oid.as_raw_bytes()).unwrap();
            cinnabar_get_note(&mut self.0, &git_oid.into())
                .as_ref()
                .cloned()
                .map(Into::into)
        }
    }

    pub fn get_note_abbrev<H: ObjectId + Into<hg_object_id>>(
        &mut self,
        oid: Abbrev<H>,
    ) -> Option<GitObjectId> {
        unsafe {
            {
                let len = oid.len();
                let git_oid = GitObjectId::from_raw_bytes(oid.as_object_id().as_raw_bytes())
                    .unwrap()
                    .into();
                // get_abbrev_note relied on cinnabar_get_note having run first.
                let note = cinnabar_get_note(&mut self.0, &git_oid);
                if len == 40 {
                    note
                } else {
                    get_abbrev_note(&mut self.0, &git_oid, len)
                }
            }
            .as_ref()
            .cloned()
            .map(Into::into)
        }
    }

    pub fn for_each<F: FnMut(HgObjectId, GitObjectId)>(&mut self, mut f: F) {
        for_each_note_in(&mut self.0, |h, g| {
            let h = HgObjectId::from_raw_bytes(h.as_raw_bytes()).unwrap();
            f(h, g);
        });
    }

    pub fn add_note(&mut self, oid: HgObjectId, note_oid: GitObjectId) {
        unsafe {
            cinnabar_add_note(
                &mut self.0,
                &GitObjectId::from_raw_bytes(oid.as_raw_bytes())
                    .unwrap()
                    .into(),
                &note_oid.into(),
            );
        }
    }

    pub fn remove_note(&mut self, oid: HgObjectId) {
        unsafe {
            cinnabar_remove_note(&mut self.0, oid.as_raw_bytes().as_ptr());
        }
    }

    pub fn store(&mut self, reference: CommitId) -> CommitId {
        store_metadata_notes(&mut self.0, reference)
    }
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
