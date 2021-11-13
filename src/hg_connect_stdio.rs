/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::CString;
use std::fs::File;
use std::io::{copy, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::c_int;
use std::path::PathBuf;
use std::ptr;
use std::str::FromStr;
use std::thread::{spawn, JoinHandle};

use bstr::{BStr, BString};
use itertools::Itertools;
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
use crate::util::{BufferedReader, OsStrExt, PrefixWriter, SeekExt};

pub struct HgStdioConnection {
    capabilities: HgCapabilities,
    proc_in: FdFile,
    proc_out: BufReader<FdFile>,
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
    data.extend(value.as_bytes());
}

fn stdio_send_command(conn: &mut HgStdioConnection, command: &str, args: HgArgs) {
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
    conn.proc_in.write_all(&data).unwrap();
}

extern "C" {
    fn strbuf_fread(buf: *mut strbuf, len: usize, file: *mut libc::FILE);
}

fn stdio_read_response(conn: &mut HgStdioConnection) -> Box<[u8]> {
    let mut length_str = String::new();
    conn.proc_out.read_line(&mut length_str).unwrap();
    let length = usize::from_str(length_str.trim_end_matches('\n')).unwrap();
    let mut response = vec![0; length].into_boxed_slice();
    conn.proc_out.read_exact(&mut response).unwrap();
    response
}

impl HgWireConnection for HgStdioConnection {
    fn simple_command(&mut self, command: &str, args: HgArgs) -> Box<[u8]> {
        stdio_send_command(self, command, args);
        stdio_read_response(self)
    }

    fn changegroup_command<'a>(
        &'a mut self,
        command: &str,
        args: HgArgs,
    ) -> Result<Box<dyn Read + 'a>, BString> {
        stdio_send_command(self, command, args);

        /* We assume the caller is only going to read the right amount of data according
         * format: changegroup or bundle2.
         */
        if self.is_remote {
            // We buffer as much as we can to avoid any network glitches due to slow processing.
            Ok(Box::new(BufferedReader::new(&mut self.proc_out)))
        } else {
            Ok(Box::new(&mut self.proc_out))
        }
    }

    fn push_command(&mut self, mut input: File, command: &str, args: HgArgs) -> Box<[u8]> {
        stdio_send_command(self, command, args);
        /* The server normally sends an empty response before reading the data
         * it's sent if not, it's an error (typically, the remote will
         * complain here if there was a lost push race). */
        //TODO: handle that error.
        let header = stdio_read_response(self);
        self.proc_in.write_all(&header).unwrap();
        drop(header);

        let len = input.stream_len_().unwrap();
        //TODO: chunk in smaller pieces.
        writeln!(self.proc_in, "{}", len).unwrap();

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
            let mut response = Vec::new();
            copy_bundle(&mut self.proc_out, &mut response).unwrap();
            response.into_boxed_slice()
        } else {
            /* There are two responses, one for output, one for actual response. */
            //TODO: actually handle output here
            drop(stdio_read_response(self));
            stdio_read_response(self)
        }
    }
}

impl HgConnectionBase for HgStdioConnection {
    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        self.capabilities.get_capability(name)
    }
}

impl Drop for HgStdioConnection {
    fn drop(&mut self) {
        stdio_send_command(self, "", args!());
        unsafe {
            libc::close(self.proc_in.raw());
            libc::close(self.proc_out.get_mut().raw());
            self.thread.take().map(JoinHandle::join);
            stdio_finish(self.proc);
        }
    }
}

pub struct HgStdioBundle {
    path: PathBuf,
}

// Because we don't support getbundle fully, we don't override get_capability
// to say we handle it.
impl HgConnectionBase for HgStdioBundle {}
impl HgConnection for HgStdioBundle {
    fn getbundle<'a>(
        &'a mut self,
        heads: &[HgChangesetId],
        common: &[HgChangesetId],
        bundle2caps: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, BString> {
        assert!(heads.is_empty());
        assert!(common.is_empty());
        assert!(bundle2caps.is_none());

        let f = DecompressBundleReader::new(File::open(&self.path).unwrap());
        Ok(Box::new(f))
    }
}

extern "C" {
    fn proc_in(proc: *mut child_process) -> c_int;

    fn proc_out(proc: *mut child_process) -> c_int;

    fn proc_err(proc: *mut child_process) -> c_int;
}

pub fn get_stdio_connection(url: &Url, flags: c_int) -> Option<Box<dyn HgConnection>> {
    let userhost = url.host_str().map(|host| {
        let username = percent_decode_str(url.username()).collect_vec();
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
        percent_decode_str(url.path().trim_start_matches('/')).collect_vec()
    } else {
        let path = url.to_file_path().unwrap();
        if path.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Some(Box::new(HgStdioBundle { path }));
        }
        path.as_os_str().as_bytes().to_owned()
    };
    let path = CString::new(path).unwrap();
    let proc = unsafe {
        hg_connect_stdio(
            userhost.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            port.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            path.as_ref().as_ptr(),
            flags,
        )
    };
    if proc.is_null() {
        return None;
    }

    let mut conn = HgStdioConnection {
        capabilities: HgCapabilities::default(),
        proc_in: unsafe { FdFile::from_raw_fd(proc_in(proc)) },
        proc_out: BufReader::new(unsafe { FdFile::from_raw_fd(proc_out(proc)) }),
        is_remote: url.scheme() == "ssh",
        proc,
        thread: None,
    };

    let mut proc_err = unsafe { FdFile::from_raw_fd(proc_err(proc)) };

    conn.thread = Some(spawn(move || {
        /* Because we read from a raw fd for a pipe, we need to use a raw fd
         * to send data verbatim to stderr, because it's not necessarily data
         * that std::io::stderr will like on Windows (i.e. not UTF-8 on e.g.
         * Japanese locale) */
        let stderr = unsafe { FdFile::stderr() };
        let mut writer = PrefixWriter::new(b"remote: ", stderr);
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

    let buf = stdio_read_response(&mut conn);
    if *buf != b"\n"[..] {
        mem::swap(&mut conn.capabilities, &mut HgCapabilities::new_from(&buf));
        /* Now read the response for the "between" command. */
        stdio_read_response(&mut conn);
    }

    Some(Box::new(Box::new(conn) as Box<dyn HgWireConnection>))
}
