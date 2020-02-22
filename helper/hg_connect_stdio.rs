/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{c_void, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::c_int;
use std::ptr;

use bstr::BString;
use libc::off_t;
use url::Url;

use crate::args;
use crate::hg_connect::{
    param_value, prepare_command, split_capabilities, HgArgs, HgConnection, HgWireConnection,
    OneHgArg,
};
use crate::libcinnabar::{
    bufferize_writer, copy_bundle, hg_connect_stdio, hg_connection_stdio, stdio_finish,
    stdio_read_response, stdio_write, writer,
};
use crate::libgit::strbuf;

pub type HgStdIOConnection = HgConnection<*mut hg_connection_stdio>;

/* The mercurial "stdio" protocol is used for both local repositories and
 * remote ssh repositories.
 * A mercurial client sends commands in the following form:
 *   <command> LF
 *   (<param> SP <length> LF <value>)*
 *   ('*' SP <num> LF (<param> SP <length> LF <value>){num})
 *
 * <value> is <length> bytes long. The number of parameters depends on the
 * command.
 *
 * The '*' special parameter introduces a variable number of extra parameters.
 * The number following the '*' is the number of extra parameters.
 *
 * The server response, for simple commands, is of the following form:
 *   <length> LF
 *   <content>
 *
 * <content> is <length> bytes long.
 */
fn stdio_command_add_param(data: &mut BString, name: &str, value: param_value) {
    let is_asterisk = name == "*";
    let len = match value {
        param_value::size(s) => {
            assert!(is_asterisk);
            s
        }
        param_value::value(v) => {
            assert!(!is_asterisk);
            v.len()
        }
    };
    data.extend(name.as_bytes());
    writeln!(data, " {}", len).unwrap();
    match value {
        param_value::value(v) => {
            assert!(!is_asterisk);
            data.extend(v)
        }
        _ => assert!(is_asterisk),
    };
}

fn stdio_send_command(conn: &mut hg_connection_stdio, command: &str, args: HgArgs) {
    let mut data = BString::from(Vec::<u8>::new());
    data.extend(command.as_bytes());
    data.push(b'\n');
    prepare_command(
        |name, value| stdio_command_add_param(&mut data, name, value),
        args,
    );
    unsafe {
        stdio_write(conn, data.as_ptr(), data.len());
    }
}

impl HgWireConnection for HgStdIOConnection {
    unsafe fn simple_command(&mut self, response: &mut strbuf, command: &str, args: HgArgs) {
        let stdio = self.inner.as_mut().unwrap();
        stdio_send_command(stdio, command, args);
        stdio_read_response(stdio, response);
    }

    unsafe fn changegroup_command(&mut self, writer: &mut writer, command: &str, args: HgArgs) {
        let stdio = self.inner.as_mut().unwrap();
        stdio_send_command(stdio, command, args);

        /* We're going to receive a stream, but we don't know how big it is
         * going to be in advance, so we have to read it according to its
         * format: changegroup or bundle2.
         */
        if stdio.is_remote > 0 {
            bufferize_writer(writer);
        }
        copy_bundle(stdio.out, writer);
    }

    unsafe fn push_command(
        &mut self,
        response: &mut strbuf,
        mut input: File,
        len: off_t,
        command: &str,
        args: HgArgs,
    ) {
        let stdio = self.inner.as_mut().unwrap();
        stdio_send_command(stdio, command, args);
        /* The server normally sends an empty response before reading the data
         * it's sent if not, it's an error (typically, the remote will
         * complain here if there was a lost push race). */
        //TODO: handle that error.
        let mut header = strbuf::new();
        stdio_read_response(stdio, &mut header);

        //TODO: chunk in smaller pieces.
        header.extend_from_slice(format!("{}\n", len).as_bytes());
        stdio_write(stdio, header.as_bytes().as_ptr(), header.as_bytes().len());
        drop(header);

        let is_bundle2 = if len > 4 {
            let mut header = [0u8; 4];
            input.read_exact(&mut header).unwrap();
            input.seek(SeekFrom::Start(0)).unwrap();
            &header == b"HG20"
        } else {
            false
        };

        let mut len = len;
        let mut buf = [0u8; 4096];
        while len > 0 {
            let read = input.read(&mut buf).unwrap();
            len -= read as off_t;
            stdio_write(stdio, buf.as_ptr(), read);
        }

        stdio_write(stdio, "0\n".as_ptr(), 2);
        if is_bundle2 {
            copy_bundle(stdio.out, &mut writer::new(response));
        } else {
            /* There are two responses, one for output, one for actual response. */
            //TODO: actually handle output here
            let mut header = strbuf::new();
            stdio_read_response(stdio, &mut header);
            drop(header);
            stdio_read_response(stdio, response);
        }
    }

    unsafe fn finish(&mut self) -> c_int {
        let code = stdio_finish(self.inner);
        libc::free(mem::replace(&mut self.inner, ptr::null_mut()) as *mut c_void);
        code
    }
}

#[no_mangle]
unsafe extern "C" fn stdio_send_empty_command(conn: *mut hg_connection_stdio) {
    let conn = conn.as_mut().unwrap();
    stdio_send_command(conn, "", args!());
}

impl HgStdIOConnection {
    pub fn new(url: &Url, flags: c_int) -> Option<Self> {
        let userhost = url.host_str().map(|host| {
            let username = url.username();
            let host = if username.is_empty() {
                host.to_owned()
            } else {
                format!("{}@{}", username, host)
            };
            CString::new(host).unwrap()
        });
        let port = url
            .port()
            .map(|port| CString::new(port.to_string()).unwrap());
        let mut path = url.path();
        if url.scheme() == "ssh" {
            path = path.trim_start_matches('/');
        }
        let path = CString::new(path.to_string()).unwrap();
        let inner = if let Some(inner) = unsafe {
            hg_connect_stdio(
                userhost.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                port.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                path.as_ref().as_ptr(),
                flags,
            )
            .as_mut()
        } {
            inner
        } else {
            return None;
        };

        /* Very old versions of the mercurial server (< 0.9) would ignore
         * unknown commands, and didn't know the "capabilities" command we want
         * to use to retrieve the server capabilities.
         * So, we also emit a command that is supported by those old versions,
         * and will see if we get a response for one or both commands.
         * Note the "capabilities" command is not supported over the stdio
         * protocol before mercurial 1.7, but we require features from at
         * least mercurial 1.9 anyways. Server versions between 0.9 and 1.7
         * will return an empty result for the "capabilities" command, as
         * opposed to no result at all with older servers. */
        stdio_send_command(inner, "capabilities", args!());
        stdio_send_command(
            inner,
            "between",
            args!(
                pairs: b"0000000000000000000000000000000000000000-0000000000000000000000000000000000000000"
            ),
        );

        let mut conn = HgStdIOConnection {
            capabilities: Vec::new(),
            inner,
        };

        let mut buf = strbuf::new();
        unsafe {
            stdio_read_response(inner, &mut buf);
        }
        if buf.as_bytes() != b"\n" {
            mem::swap(
                &mut conn.capabilities,
                &mut split_capabilities(buf.as_bytes()),
            );
            /* Now read the response for the "between" command. */
            unsafe {
                stdio_read_response(inner, &mut buf);
            }
        }

        Some(conn)
    }
}
