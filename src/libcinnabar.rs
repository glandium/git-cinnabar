/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::os::raw::{c_char, c_int, c_void};

use crate::libgit::{child_process, object_id, strbuf};
use crate::oid::{Abbrev, GitObjectId, HgObjectId, ObjectId};

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
    root: *mut c_void,
    // ...
}

extern "C" {
    pub static mut git2hg: git_notes_tree;
    pub static mut hg2git: hg_notes_tree;
    pub static mut files_meta: hg_notes_tree;

    fn ensure_notes(t: *mut cinnabar_notes_tree);

    fn cinnabar_get_note(
        notes: *mut cinnabar_notes_tree,
        oid: *const object_id,
    ) -> *const object_id;

    fn get_note_hg(notes: *mut cinnabar_notes_tree, oid: *const hg_object_id) -> *const object_id;

    fn resolve_hg(
        t: *mut cinnabar_notes_tree,
        oid: *const hg_object_id,
        len: usize,
    ) -> *const object_id;

    pub fn generate_manifest(oid: *const object_id) -> *const strbuf;

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
}

fn for_each_note_in<O: ObjectId, N: ObjectId, F: FnMut(O, N)>(
    notes: &mut cinnabar_notes_tree,
    mut f: F,
) {
    unsafe extern "C" fn each_note_cb<O: ObjectId, N: ObjectId, F: FnMut(O, N)>(
        oid: *const object_id,
        note_oid: *const object_id,
        _note_path: *const c_char,
        cb_data: *mut c_void,
    ) -> c_int {
        let cb = (cb_data as *mut F).as_mut().unwrap();
        let o = O::from_raw_bytes(oid.as_ref().unwrap().as_raw_bytes()).unwrap();
        let n = N::from_raw_bytes(note_oid.as_ref().unwrap().as_raw_bytes()).unwrap();
        cb(o, n);
        0
    }

    unsafe {
        cinnabar_for_each_note(
            notes,
            0,
            each_note_cb::<O, N, F>,
            &mut f as *mut F as *mut c_void,
        );
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct git_notes_tree(cinnabar_notes_tree);

impl git_notes_tree {
    pub fn get_note(&mut self, oid: GitObjectId) -> Option<GitObjectId> {
        unsafe {
            ensure_notes(&mut self.0);
            cinnabar_get_note(&mut self.0, &oid.into())
                .as_ref()
                .cloned()
                .map(Into::into)
        }
    }

    pub fn for_each<F: FnMut(GitObjectId, GitObjectId)>(&mut self, f: F) {
        for_each_note_in(&mut self.0, f);
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct hg_notes_tree(cinnabar_notes_tree);

impl hg_notes_tree {
    pub fn get_note(&mut self, oid: HgObjectId) -> Option<GitObjectId> {
        unsafe {
            ensure_notes(&mut self.0);
            get_note_hg(&mut self.0, &oid.into())
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
            ensure_notes(&mut self.0);
            resolve_hg(&mut self.0, &oid.as_object_id().into(), oid.len())
                .as_ref()
                .cloned()
                .map(Into::into)
        }
    }

    pub fn for_each<F: FnMut(HgObjectId, GitObjectId)>(&mut self, f: F) {
        for_each_note_in(&mut self.0, f);
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
