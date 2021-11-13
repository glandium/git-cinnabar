/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryInto;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_long, c_ulong};

use bstr::ByteSlice;

use crate::util::ImmutBString;

#[allow(non_camel_case_types)]
#[repr(C)]
struct mmfile_t<'a> {
    ptr: *const c_char,
    size: c_long,
    marker: PhantomData<&'a ()>,
}

impl<'a> From<&'a [u8]> for mmfile_t<'a> {
    fn from(buf: &'a [u8]) -> Self {
        mmfile_t {
            ptr: buf.as_ptr() as *const c_char,
            size: buf.len().try_into().unwrap(),
            marker: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Derivative)]
#[derivative(Default)]
struct xpparam_t {
    flags: c_ulong,
    #[derivative(Default(value = "std::ptr::null()"))]
    anchors: *const *const c_char,
    anchors_nr: usize,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Derivative)]
#[derivative(Default)]
struct xdemitconf_t {
    ctxlen: c_long,
    interhunkctxlen: c_long,
    flags: c_ulong,
    find_func:
        Option<extern "C" fn(*const c_char, c_long, *const c_char, c_long, *mut c_void) -> c_long>,
    #[derivative(Default(value = "std::ptr::null_mut()"))]
    find_func_priv: *mut c_void,
    hunk_func: Option<extern "C" fn(c_long, c_long, c_long, c_long, *mut c_void) -> c_int>,
}

extern "C" {
    fn xdi_diff_outf(
        mf1: *const mmfile_t,
        mf2: *const mmfile_t,
        hunk_fn: Option<
            extern "C" fn(*mut c_void, c_long, c_long, c_long, c_long, *const c_char, c_long),
        >,
        line_fn: Option<extern "C" fn(*mut c_void, *const c_char, c_ulong)>,
        consume_callback_data: *mut c_void,
        xpp: *const xpparam_t,
        xecfg: *const xdemitconf_t,
    ) -> c_int;
}

#[derive(Clone, Copy, Derivative)]
#[derivative(Debug)]
pub struct PatchInfo<S: AsRef<[u8]>> {
    pub start: usize,
    pub end: usize,
    #[derivative(Debug(format_with = "crate::util::bstr_fmt"))]
    pub data: S,
}

impl<S: AsRef<[u8]>, R: AsRef<[u8]>> PartialEq<PatchInfo<S>> for PatchInfo<R> {
    fn eq(&self, other: &PatchInfo<S>) -> bool {
        self.start == other.start
            && self.end == other.end
            && self.data.as_ref() == other.data.as_ref()
    }
}

pub fn apply<S: AsRef<[u8]>>(
    patch: impl Iterator<Item = PatchInfo<S>>,
    input: &[u8],
) -> ImmutBString {
    let mut patched = Vec::new();
    let mut last_end = 0;
    for PatchInfo { start, end, data } in patch {
        patched.extend_from_slice(&input[last_end..start]);
        patched.extend_from_slice(data.as_ref());
        last_end = end;
    }
    patched.extend_from_slice(&input[last_end..]);
    patched.into()
}

struct HunkContext<'a> {
    patch_info: Vec<PatchInfo<&'a [u8]>>,
    a_line_offsets: Vec<usize>,
    b_line_offsets: Vec<usize>,
    b: &'a [u8],
}

extern "C" fn hunk_cb(
    data: *mut c_void,
    old_begin: c_long,
    old_nr: c_long,
    new_begin: c_long,
    new_nr: c_long,
    _func: *const c_char,
    _funclen: c_long,
) {
    let ctx = unsafe { (data as *mut HunkContext).as_mut().unwrap() };
    let mut old_begin: usize = old_begin.try_into().unwrap();
    let old_nr: usize = old_nr.try_into().unwrap();
    let mut new_begin: usize = new_begin.try_into().unwrap();
    let new_nr: usize = new_nr.try_into().unwrap();
    if old_nr == 0 {
        old_begin += 1;
    }
    if new_nr == 0 {
        new_begin += 1;
    }
    ctx.patch_info.push(PatchInfo {
        start: ctx.a_line_offsets[old_begin],
        end: ctx.a_line_offsets[old_begin + old_nr],
        data: ctx.b[ctx.b_line_offsets[new_begin]..ctx.b_line_offsets[new_begin + new_nr]].into(),
    });
}

fn line_offsets(buf: &[u8]) -> Vec<usize> {
    [0, 0]
        .iter()
        .copied()
        .chain(buf.lines_with_terminator().scan(0, |off, l| {
            *off += l.len();
            Some(*off)
        }))
        .collect()
}

pub fn textdiff<'a>(a: &[u8], b: &'a [u8]) -> Vec<PatchInfo<&'a [u8]>> {
    let mut ctx = HunkContext {
        patch_info: Vec::new(),
        a_line_offsets: line_offsets(a),
        b_line_offsets: line_offsets(b),
        b,
    };
    let a = mmfile_t::from(a);
    let b = mmfile_t::from(b);
    let xpp = xpparam_t::default();
    let xecfg = xdemitconf_t::default();
    unsafe {
        if xdi_diff_outf(
            &a,
            &b,
            Some(hunk_cb),
            None,
            &mut ctx as *mut _ as *mut c_void,
            &xpp,
            &xecfg,
        ) != 0
        {
            panic!("failed to generate diff");
        }
    }
    ctx.patch_info
}

#[test]
fn test_textdiff() {
    let a = ["foo", "bar", "baz", "qux"].join("\n");
    let b = ["foo", "baz", "hoge", "fuga", "qux"].join("\n");
    let result = textdiff(a.as_bytes(), b.as_bytes());
    assert_eq!(
        result,
        vec![
            PatchInfo {
                start: 4,
                end: 8,
                data: b"".as_bstr()
            },
            PatchInfo {
                start: 12,
                end: 12,
                data: b"hoge\nfuga\n".as_bstr()
            },
        ]
    );

    let b = ["foo", "hoge", "fuga", "qux"].join("\n");
    let result = textdiff(a.as_bytes(), b.as_bytes());
    assert_eq!(
        result,
        vec![PatchInfo {
            start: 4,
            end: 12,
            data: b"hoge\nfuga\n".as_bstr()
        },]
    );

    let b = ["foo", "baz", "hoge", "fuga"].join("\n");
    let result = textdiff(a.as_bytes(), b.as_bytes());
    assert_eq!(
        result,
        vec![
            PatchInfo {
                start: 4,
                end: 8,
                data: b"".as_bstr()
            },
            PatchInfo {
                start: 12,
                end: a.len(),
                data: b"hoge\nfuga".as_bstr()
            },
        ]
    );
}
