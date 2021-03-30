/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{copy, stderr, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::c_int;
use std::path::PathBuf;
use std::ptr;
use std::str::FromStr;
use std::thread::{spawn, JoinHandle};

use bstr::BString;
use cstr::cstr;
use percent_encoding::percent_decode_str;
use url::Url;

use crate::args;
use crate::hg_bundle::{copy_bundle, DecompressBundleReader};
use crate::hg_connect::{
    HgArgs, HgCapabilities, HgConnection, HgConnectionBase, HgWireConnection, OneHgArg,
};
use crate::libc::FdFile;
use crate::libcinnabar::{hg_connect_stdio, stdio_finish};
use crate::libgit::{child_process, strbuf};
use crate::store::HgChangesetId;
use crate::util::{BufferedWriter, OsStrExt, PrefixWriter, SeekExt};

pub struct HgStdIOConnection {
    capabilities: HgCapabilities,
    proc_in: FdFile,
    proc_out: crate::libc::File,
    is_remote: bool,
    proc: *mut child_process,
    thread: Option<JoinHandle<()>>,
}

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

fn stdio_send_command(conn: &mut HgStdIOConnection, command: &str, args: HgArgs) {
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

fn stdio_read_response(conn: &mut HgStdIOConnection, response: &mut strbuf) {
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
        stdio_send_command(self, command, args);
        stdio_read_response(self, response);
    }

    fn changegroup_command(&mut self, out: &mut (dyn Write + Send), command: &str, args: HgArgs) {
        stdio_send_command(self, command, args);

        /* We're going to receive a stream, but we don't know how big it is
         * going to be in advance, so we have to read it according to its
         * format: changegroup or bundle2.
         */
        if self.is_remote {
            crossbeam::thread::scope(|scope| {
                copy_bundle(&mut self.proc_out, &mut BufferedWriter::new(out, scope)).unwrap();
            })
            .unwrap();
        } else {
            copy_bundle(&mut self.proc_out, out).unwrap();
        };
    }

    fn push_command(
        &mut self,
        mut response: &mut strbuf,
        mut input: File,
        command: &str,
        args: HgArgs,
    ) {
        stdio_send_command(self, command, args);
        /* The server normally sends an empty response before reading the data
         * it's sent if not, it's an error (typically, the remote will
         * complain here if there was a lost push race). */
        //TODO: handle that error.
        let mut header = strbuf::new();
        stdio_read_response(self, &mut header);

        let len = input.stream_len_().unwrap();
        //TODO: chunk in smaller pieces.
        header.extend_from_slice(format!("{}\n", len).as_bytes());
        self.proc_in.write_all(header.as_bytes()).unwrap();
        drop(header);

        let is_bundle2 = if len > 4 {
            let mut header = [0u8; 4];
            input.read_exact(&mut header).unwrap();
            input.seek(SeekFrom::Start(0)).unwrap();
            &header == b"HG20"
        } else {
            false
        };

        copy(&mut input.take(len), &mut self.proc_in).unwrap();

        self.proc_in.write_all(b"0\n").unwrap();
        if is_bundle2 {
            copy_bundle(&mut self.proc_out, &mut response).unwrap();
        } else {
            /* There are two responses, one for output, one for actual response. */
            //TODO: actually handle output here
            let mut header = strbuf::new();
            stdio_read_response(self, &mut header);
            drop(header);
            stdio_read_response(self, response);
        }
    }
}

impl HgConnectionBase for HgStdIOConnection {
    fn get_capability(&self, name: &[u8]) -> Option<&CStr> {
        self.capabilities.get_capability(name)
    }
}

impl Drop for HgStdIOConnection {
    fn drop(&mut self) {
        stdio_send_command(self, "", args!());
        unsafe {
            libc::close(self.proc_in.raw());
            libc::fclose(self.proc_out.raw());
            self.thread.take().map(|t| t.join());
            stdio_finish(self.proc);
        }
    }
}

pub struct HgStdIOBundle {
    path: PathBuf,
}

// Because we don't support getbundle fully, we don't override get_capability
// to say we handle it.
impl HgConnectionBase for HgStdIOBundle {}
impl HgConnection for HgStdIOBundle {
    fn getbundle(
        &mut self,
        out: &mut (dyn Write + Send),
        heads: &[HgChangesetId],
        common: &[HgChangesetId],
        bundle2caps: Option<&str>,
    ) {
        assert!(heads.is_empty());
        assert!(common.is_empty());
        assert!(bundle2caps.is_none());

        let mut f = DecompressBundleReader::new(File::open(&self.path).unwrap());
        copy(&mut f, out).unwrap();
    }
}

extern "C" {
    fn proc_in(proc: *mut child_process) -> c_int;

    fn proc_out(proc: *mut child_process) -> c_int;

    fn proc_err(proc: *mut child_process) -> c_int;
}

pub fn get_stdio_connection(url: &Url, flags: c_int) -> Option<Box<dyn HgConnection>> {
    let userhost = url.host_str().map(|host| {
        let username = percent_decode_str(url.username()).collect::<Vec<_>>();
        let userhost = if username.is_empty() {
            host.as_bytes().to_owned()
        } else {
            let mut userhost = username;
            userhost.push(b'@');
            userhost.extend_from_slice(host.as_bytes());
            userhost
        };
        CString::new(userhost).unwrap()
    });
    let port = url
        .port()
        .map(|port| CString::new(port.to_string()).unwrap());
    let path = if url.scheme() == "ssh" {
        percent_decode_str(url.path().trim_start_matches('/')).collect::<Vec<u8>>()
    } else {
        let path = url.to_file_path().unwrap();
        if path.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Some(Box::new(HgStdIOBundle { path }));
        }
        path.as_os_str().as_bytes().to_owned()
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

    let mut conn = HgStdIOConnection {
        capabilities: Default::default(),
        proc_in: unsafe { FdFile::from_raw_fd(proc_in(proc)) },
        proc_out: unsafe {
            crate::libc::File::new(libc::fdopen(proc_out(proc), cstr!("r").as_ptr()))
        },
        is_remote: url.scheme() == "ssh",
        proc,
        thread: None,
    };

    let mut proc_err = unsafe { FdFile::from_raw_fd(proc_err(proc)) };

    conn.thread = Some(spawn(move || {
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
    stdio_send_command(&mut conn, "capabilities", args!());
    stdio_send_command(
        &mut conn,
        "between",
        args!(
            pairs: "0000000000000000000000000000000000000000-0000000000000000000000000000000000000000"
        ),
    );

    let mut buf = strbuf::new();
    stdio_read_response(&mut conn, &mut buf);
    if buf.as_bytes() != b"\n" {
        mem::swap(
            &mut conn.capabilities,
            &mut HgCapabilities::new_from(buf.as_bytes()),
        );
        /* Now read the response for the "between" command. */
        stdio_read_response(&mut conn, &mut buf);
    }

    Some(Box::new(Box::new(conn) as Box<dyn HgWireConnection>))
}
