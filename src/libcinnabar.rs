/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::Write;
use std::ops::Deref;
use std::os::raw::{c_char, c_int};

use libc::FILE;

use crate::libc::FdFile;
use crate::libgit::{child_process, get_note, notes_tree, object_id, strbuf};
use crate::oid::{Abbrev, GitObjectId, HgObjectId, ObjectId};

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone)]
pub struct hg_object_id([u8; 20]);

impl From<HgObjectId> for hg_object_id {
    fn from(oid: HgObjectId) -> Self {
        let mut result = Self([0; 20]);
        let oid = oid.as_raw_bytes();
        result.0[..oid.len()].clone_from_slice(oid);
        result
    }
}

impl<H: ObjectId + Deref<Target = HgObjectId>> From<H> for hg_object_id {
    fn from(oid: H) -> Self {
        let mut result = Self([0; 20]);
        let oid = oid.as_raw_bytes();
        result.0[..oid.len()].clone_from_slice(oid);
        result
    }
}

impl From<hg_object_id> for HgObjectId {
    fn from(oid: hg_object_id) -> Self {
        let mut result = Self::null();
        let slice = result.as_raw_bytes_mut();
        slice.clone_from_slice(&oid.0[..slice.len()]);
        result
    }
}

extern "C" {
    pub static mut git2hg: git_notes_tree;
    pub static mut hg2git: hg_notes_tree;
    pub static mut files_meta: hg_notes_tree;

    fn ensure_notes(t: *mut notes_tree);

    fn get_note_hg(notes: *mut notes_tree, oid: *const hg_object_id) -> *const object_id;

    fn resolve_hg(t: *mut notes_tree, oid: *const hg_object_id, len: usize) -> *const object_id;

    pub fn generate_manifest(oid: *const object_id) -> *const strbuf;
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct git_notes_tree(notes_tree);

impl git_notes_tree {
    pub fn get_note(&mut self, oid: &GitObjectId) -> Option<GitObjectId> {
        unsafe {
            ensure_notes(&mut self.0);
            get_note(&mut self.0, &oid.into())
                .as_ref()
                .cloned()
                .map(Into::into)
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct hg_notes_tree(notes_tree);

impl hg_notes_tree {
    pub fn get_note(&mut self, oid: &HgObjectId) -> Option<GitObjectId> {
        unsafe {
            ensure_notes(&mut self.0);
            get_note_hg(&mut self.0, &oid.clone().into())
                .as_ref()
                .cloned()
                .map(Into::into)
        }
    }

    pub fn get_note_abbrev<H: ObjectId + Clone + Deref<Target = HgObjectId>>(
        &mut self,
        oid: &Abbrev<H>,
    ) -> Option<GitObjectId> {
        unsafe {
            ensure_notes(&mut self.0);
            resolve_hg(&mut self.0, &oid.as_object_id().clone().into(), oid.len())
                .as_ref()
                .cloned()
                .map(Into::into)
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

#[no_mangle]
pub unsafe extern "C" fn send_buffer(fd: c_int, buf: *const strbuf) {
    let mut out = FdFile::from_raw_fd(fd);
    send_buffer_to(buf.as_ref().map(strbuf::as_bytes), &mut out);
}

pub fn send_buffer_to<'a>(buf: impl Into<Option<&'a [u8]>>, out: &mut impl Write) {
    if let Some(buf) = buf.into() {
        writeln!(out, "{}", buf.len()).unwrap();
        out.write_all(buf).unwrap();
        writeln!(out).unwrap();
    } else {
        write!(out, "-1\n\n").unwrap();
    }
}
