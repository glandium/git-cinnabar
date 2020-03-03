/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::CString;
use std::fs::File;
use std::io::{copy, stderr, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::c_int;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::ptr;
use std::str::FromStr;
use std::thread::{spawn, JoinHandle};

use bstr::BString;
use percent_encoding::percent_decode;
use url::Url;

use crate::args;
use crate::hg_bundle::{copy_bundle, DecompressBundleReader};
use crate::hg_connect::{split_capabilities, HgArgs, HgConnection, HgWireConnection, OneHgArg};
use crate::libc::FdFile;
use crate::libcinnabar::{hg_connect_stdio, stdio_finish};
use crate::libgit::{child_process, strbuf};
use crate::util::{BufferedWriter, PrefixWriter, SeekExt};

#[allow(non_camel_case_types)]
pub struct hg_connection_stdio {
    pub proc_in: FdFile,
    pub proc_out: crate::libc::File,
    pub is_remote: bool,
    pub proc: *mut child_process,
    pub thread: Option<JoinHandle<()>>,
}

pub type HgStdIOConnection = HgConnection<hg_connection_stdio>;

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
fn stdio_command_add_param(data: &mut BString, name: &str, value: &str) {
    data.extend(name.as_bytes());
    writeln!(data, " {}", value.len()).unwrap();
    data.extend(value.as_bytes())
}

fn stdio_send_command(conn: &mut hg_connection_stdio, command: &str, args: HgArgs) {
    let mut data = BString::from(Vec::<u8>::new());
    data.extend(command.as_bytes());
    data.push(b'\n');
    for OneHgArg { name, value } in args.args {
        stdio_command_add_param(&mut data, name, value);
    }
    if let Some(extra_args) = args.extra_args {
        writeln!(data, "* {}", extra_args.len()).unwrap();
        for OneHgArg { name, value } in extra_args {
            stdio_command_add_param(&mut data, name, value);
        }
    }
    conn.proc_in.write_all(&data).unwrap()
}

extern "C" {
    fn strbuf_getline_lf(buf: *mut strbuf, file: *mut libc::FILE);

    fn strbuf_fread(buf: *mut strbuf, len: usize, file: *mut libc::FILE);
}

fn stdio_read_response(conn: &mut hg_connection_stdio, response: &mut strbuf) {
    let mut length_str = strbuf::new();
    unsafe {
        strbuf_getline_lf(&mut length_str, conn.proc_out.raw());
    }
    let length = usize::from_str(std::str::from_utf8(length_str.as_bytes()).unwrap()).unwrap();
    unsafe {
        strbuf_fread(response, length, conn.proc_out.raw());
    }
}

impl HgWireConnection for HgStdIOConnection {
    fn simple_command(&mut self, response: &mut strbuf, command: &str, args: HgArgs) {
        let stdio = &mut self.inner;
        stdio_send_command(stdio, command, args);
        stdio_read_response(stdio, response);
    }

    fn changegroup_command(&mut self, out: Box<dyn Write + Send>, command: &str, args: HgArgs) {
        let stdio = &mut self.inner;
        stdio_send_command(stdio, command, args);

        /* We're going to receive a stream, but we don't know how big it is
         * going to be in advance, so we have to read it according to its
         * format: changegroup or bundle2.
         */
        let mut writer = if stdio.is_remote {
            Box::new(BufferedWriter::new(out))
        } else {
            out
        };
        copy_bundle(&mut stdio.proc_out, &mut writer).unwrap();
    }

    fn push_command(
        &mut self,
        mut response: &mut strbuf,
        mut input: File,
        command: &str,
        args: HgArgs,
    ) {
        let stdio = &mut self.inner;
        stdio_send_command(stdio, command, args);
        /* The server normally sends an empty response before reading the data
         * it's sent if not, it's an error (typically, the remote will
         * complain here if there was a lost push race). */
        //TODO: handle that error.
        let mut header = strbuf::new();
        stdio_read_response(stdio, &mut header);

        let len = input.stream_len_().unwrap();
        //TODO: chunk in smaller pieces.
        header.extend_from_slice(format!("{}\n", len).as_bytes());
        stdio.proc_in.write_all(header.as_bytes()).unwrap();
        drop(header);

        let is_bundle2 = if len > 4 {
            let mut header = [0u8; 4];
            input.read_exact(&mut header).unwrap();
            input.seek(SeekFrom::Start(0)).unwrap();
            &header == b"HG20"
        } else {
            false
        };

        copy(&mut input.take(len), &mut stdio.proc_in).unwrap();

        stdio.proc_in.write_all(b"0\n").unwrap();
        if is_bundle2 {
            copy_bundle(&mut stdio.proc_out, &mut response).unwrap();
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
        stdio_send_command(&mut self.inner, "", args!());
        libc::close(self.inner.proc_in.raw());
        libc::fclose(self.inner.proc_out.raw());
        self.inner.thread.take().map(|t| t.join());
        stdio_finish(self.inner.proc)
    }
}

extern "C" {
    fn proc_in(proc: *mut child_process) -> c_int;

    fn proc_out(proc: *mut child_process) -> c_int;

    fn proc_err(proc: *mut child_process) -> c_int;
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
        let path = if url.scheme() == "ssh" {
            percent_decode(url.path().trim_start_matches('/').as_bytes()).collect::<Vec<u8>>()
        } else {
            let path = url.to_file_path().unwrap();
            if path.metadata().map(|m| m.is_file()).unwrap_or(false) {
                // TODO: Eventually we want to have a hg_connection
                // for bundles, but for now, just send the stream to
                // stdout and return NULL.
                let mut f = DecompressBundleReader::new(File::open(path).unwrap());
                let mut out = unsafe { crate::libc::FdFile::stdout() };
                out.write_all(b"bundle\n").unwrap();
                copy(&mut f, &mut out).unwrap();
                return None;
            }
            #[cfg(windows)]
            let path = path.to_str().unwrap().as_bytes();
            #[cfg(unix)]
            let path = path.as_os_str().as_bytes();
            path.to_owned()
        };
        let path = CString::new(path).unwrap();
        let proc = unsafe {
            hg_connect_stdio(
                userhost.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                port.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                path.as_ref().as_ptr(),
                flags,
            )
        };
        if proc.is_null() {
            return None;
        }

        let mut inner = hg_connection_stdio {
            proc_in: unsafe { FdFile::from_raw_fd(proc_in(proc)) },
            proc_out: unsafe {
                crate::libc::File::new(libc::fdopen(proc_out(proc), cstr!("r").as_ptr()))
            },
            is_remote: url.scheme() == "ssh",
            proc,
            thread: None,
        };

        let mut proc_err = unsafe { FdFile::from_raw_fd(proc_err(proc)) };

        inner.thread = Some(spawn(move || {
            let stderr = stderr();
            let mut writer = PrefixWriter::new(b"remote: ", stderr.lock());
            copy(&mut proc_err, &mut writer).unwrap();
        }));

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
        stdio_send_command(&mut inner, "capabilities", args!());
        stdio_send_command(
            &mut inner,
            "between",
            args!(
                pairs: "0000000000000000000000000000000000000000-0000000000000000000000000000000000000000"
            ),
        );

        let mut conn = HgStdIOConnection {
            capabilities: Vec::new(),
            inner,
        };

        let mut buf = strbuf::new();
        stdio_read_response(&mut conn.inner, &mut buf);
        if buf.as_bytes() != b"\n" {
            mem::swap(
                &mut conn.capabilities,
                &mut split_capabilities(buf.as_bytes()),
            );
            /* Now read the response for the "between" command. */
            stdio_read_response(&mut conn.inner, &mut buf);
        }

        Some(conn)
    }
}
