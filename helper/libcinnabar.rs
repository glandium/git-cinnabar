/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::os::raw::{c_char, c_int};

use libc::FILE;

use crate::libgit::{child_process, get_note, notes_tree, object_id, strbuf};
use crate::oid::{Abbrev, HgObjectId};

#[allow(non_camel_case_types)]
type hg_object_id = HgObjectId;

extern "C" {
    pub static mut git2hg: git_notes_tree;
    pub static mut hg2git: hg_notes_tree;
    pub static mut files_meta: hg_notes_tree;

    pub fn ensure_notes(t: *mut notes_tree);

    pub fn get_note_hg(notes: *mut notes_tree, oid: *const hg_object_id) -> *const object_id;

    pub fn resolve_hg(t: *mut notes_tree, oid: *const hg_object_id, len: usize)
        -> *const object_id;

    pub fn generate_manifest(oid: *const object_id) -> *const strbuf;
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct git_notes_tree(notes_tree);

impl git_notes_tree {
    pub fn get_note(&mut self, oid: &object_id) -> Option<object_id> {
        unsafe {
            ensure_notes(&mut self.0);
            get_note(&mut self.0, oid).as_ref().cloned()
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct hg_notes_tree(notes_tree);

impl hg_notes_tree {
    pub fn get_note(&mut self, oid: &HgObjectId) -> Option<object_id> {
        unsafe {
            ensure_notes(&mut self.0);
            get_note_hg(&mut self.0, oid).as_ref().cloned()
        }
    }

    pub fn get_note_abbrev(&mut self, oid: &Abbrev<HgObjectId>) -> Option<object_id> {
        unsafe {
            ensure_notes(&mut self.0);
            resolve_hg(&mut self.0, oid.as_object_id(), oid.len())
                .as_ref()
                .cloned()
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct hg_connection_stdio {
    pub out: *mut FILE,
    pub is_remote: c_int,
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
