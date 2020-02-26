/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp;
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::{c_char, c_int, c_long};
use std::ptr;
use std::str::FromStr;

use bstr::{BString, ByteSlice};
use curl_sys::{
    curl_easy_getinfo, curl_easy_setopt, curl_off_t, curl_slist, curl_slist_append,
    curl_slist_free_all, CURL, CURLINFO_CONTENT_TYPE, CURLINFO_EFFECTIVE_URL,
    CURLINFO_REDIRECT_COUNT, CURLOPT_FAILONERROR, CURLOPT_FILE, CURLOPT_FOLLOWLOCATION,
    CURLOPT_HTTPGET, CURLOPT_HTTPHEADER, CURLOPT_NOBODY, CURLOPT_POST, CURLOPT_POSTFIELDSIZE,
    CURLOPT_POSTFIELDSIZE_LARGE, CURLOPT_READDATA, CURLOPT_READFUNCTION, CURLOPT_URL,
    CURLOPT_USERAGENT, CURLOPT_WRITEFUNCTION,
};
use either::Either;
use flate2::write::ZlibDecoder;
use libc::off_t;
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
use replace_with::replace_with_or_abort;
use url::Url;

use crate::args;
use crate::hg_bundle::DecompressBundleWriter;
use crate::hg_connect::{
    split_capabilities, HgArgs, HgCapabilities, HgConnection, HgWireConnection, OneHgArg,
};
use crate::libcinnabar::{get_stderr, writer};
use crate::libgit::{
    credential_fill, curl_errorstr, fwrite_buffer, get_active_slot, http_auth, http_cleanup,
    http_follow_config, http_init, run_one_slot, slot_results, strbuf, HTTP_OK, HTTP_REAUTH,
};
use crate::util::{BufferedWriter, PrefixWriter};

#[allow(non_camel_case_types)]
pub struct hg_connection_http {
    pub url: CString,
    pub initial_request: bool,
}

pub type HgHTTPConnection = HgConnection<hg_connection_http>;

#[allow(non_camel_case_types)]
struct command_request_data<'a, 'b> {
    conn: &'a mut HgHTTPConnection,
    prepare_request_cb: Box<dyn FnMut(*mut CURL, *mut curl_slist) + 'b>,
    command: &'a str,
    args: BString,
}

#[allow(non_camel_case_types)]
struct http_request_info {
    retcode: c_int,
    redirect_url: Option<BString>,
}

fn http_request(data: &mut command_request_data) -> http_request_info {
    unsafe {
        let slot = get_active_slot().as_mut().unwrap();
        curl_easy_setopt(slot.curl, CURLOPT_FAILONERROR, 0);
        curl_easy_setopt(slot.curl, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(slot.curl, CURLOPT_NOBODY, 0);

        let mut headers = ptr::null_mut();
        headers = curl_slist_append(headers, cstr!("Accept: application/mercurial-0.1").as_ptr());
        prepare_command_request(slot.curl, headers, data);

        curl_easy_setopt(slot.curl, CURLOPT_HTTPHEADER, headers);
        /* Strictly speaking, this is not necessary, but bitbucket does
         * user-agent sniffing, and git's user-agent gets 404 on mercurial
         * urls. */
        curl_easy_setopt(
            slot.curl,
            CURLOPT_USERAGENT,
            cstr!("mercurial/proto-1.0").as_ptr(),
        );

        let mut results = slot_results::new();
        let ret = run_one_slot(slot, &mut results);
        curl_slist_free_all(headers);

        let mut redirects: c_long = 0;
        curl_easy_getinfo(slot.curl, CURLINFO_REDIRECT_COUNT, &mut redirects);

        http_request_info {
            retcode: ret,
            redirect_url: if redirects > 0 {
                let mut effective_url: *const c_char = ptr::null();
                curl_easy_getinfo(slot.curl, CURLINFO_EFFECTIVE_URL, &mut effective_url);
                Some(
                    CStr::from_ptr(effective_url.as_ref().unwrap())
                        .to_bytes()
                        .to_owned()
                        .into(),
                )
            } else {
                None
            },
        }
    }
}

fn http_request_reauth(data: &mut command_request_data) -> c_int {
    let http_request_info {
        retcode: ret,
        redirect_url,
    } = http_request(data);

    if ret != HTTP_OK && ret != HTTP_REAUTH {
        return ret;
    }

    if let Some(effective_url) = redirect_url {
        if let Some(query_idx) = effective_url.find("?cmd=") {
            let http = &mut data.conn.inner;
            let new_url = effective_url[..query_idx].to_owned();
            eprintln!("warning: redirecting to {}", new_url.as_bstr());
            http.url = CString::new(new_url).unwrap();
        }
    }

    if ret != HTTP_REAUTH {
        return ret;
    }

    unsafe {
        credential_fill(&mut http_auth);
    }
    http_request(data).retcode
}

/* The Mercurial HTTP protocol uses HTTP requests for each individual command.
 * The command name is passed as "cmd" query parameter.
 * The command arguments can be passed in several different ways, but for now,
 * only the following is supported:
 * - each argument is passed as a query parameter.
 *
 * The command results are simply the corresponding HTTP responses.
 */
const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'*')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b' ');

fn http_query_add_param(data: &mut BString, name: &str, value: &[u8]) {
    let value = percent_encode(value, QUERY_ENCODE_SET)
        .to_string()
        .replace(" ", "+");
    data.extend_from_slice(b"&");
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(b"=");
    data.extend_from_slice(value.as_bytes());
}

unsafe fn prepare_command_request(
    curl: *mut CURL,
    headers: *mut curl_slist,
    data: &mut command_request_data,
) {
    let mut command_url: BString = Vec::new().into();
    let httpheader = data
        .conn
        .get_capability(b"httpheader")
        .and_then(|c| c.to_str().ok())
        .and_then(|s| usize::from_str(s).ok())
        .unwrap_or(0);

    let http = &mut data.conn.inner;
    if http_follow_config == http_follow_config::HTTP_FOLLOW_INITIAL && http.initial_request {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        http.initial_request = false;
    }

    (data.prepare_request_cb)(curl, headers);

    command_url.extend_from_slice(http.url.as_bytes());
    command_url.extend_from_slice(b"?cmd=");
    command_url.extend_from_slice(data.command.as_bytes());

    let args = data.args.as_bytes();
    if httpheader > 0 && !args.is_empty() {
        let mut args = &args[1..];
        let mut headers = headers;
        let mut num = 1;
        while !args.is_empty() {
            let mut header = BString::from(format!("X-HgArg-{}: ", num).into_bytes());
            num += 1;
            let (chunk, remainder) = args.split_at(cmp::min(args.len(), httpheader - header.len()));
            header.extend_from_slice(chunk);
            let header = CString::new(header).unwrap();
            headers = curl_slist_append(headers, header.as_ptr());
            args = remainder;
        }
    } else {
        command_url.extend_from_slice(args);
    }

    let command_url = CString::new(command_url).unwrap();
    curl_easy_setopt(curl, CURLOPT_URL, command_url.as_ptr());
}

fn http_command(
    conn: &mut HgHTTPConnection,
    prepare_request_cb: Box<dyn FnMut(*mut CURL, *mut curl_slist) + '_>,
    command: &str,
    args: HgArgs,
) {
    let mut request_data = command_request_data {
        conn,
        prepare_request_cb,
        command,
        args: Vec::new().into(),
    };
    for OneHgArg { name, value } in Iterator::chain(
        args.args.iter(),
        args.extra_args.as_ref().unwrap_or(&&[][..]).iter(),
    ) {
        http_query_add_param(&mut request_data.args, name, value)
    }
    if http_request_reauth(&mut request_data) != HTTP_OK {
        unsafe {
            die!(
                "unable to access '{}': {}",
                conn.inner.url.as_bytes().as_bstr(),
                CStr::from_ptr(curl_errorstr.as_ptr()).to_bytes().as_bstr()
            );
        }
    }
}

unsafe fn prepare_simple_request(curl: *mut CURL, data: *mut strbuf) {
    curl_easy_setopt(curl, CURLOPT_FILE, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite_buffer as *const c_void);
}

#[allow(non_camel_case_types)]
struct changegroup_response_data {
    curl: *mut CURL,
    writer: Box<dyn Write + Send>,
}

unsafe extern "C" fn changegroup_write(
    ptr: *const c_char,
    size: usize,
    nmemb: usize,
    data: *mut c_void,
) -> usize {
    let mut response_data = (data as *mut changegroup_response_data).as_mut().unwrap();
    if !response_data.curl.is_null() {
        let mut content_type: *const c_char = ptr::null();
        if curl_easy_getinfo(response_data.curl, CURLINFO_CONTENT_TYPE, &mut content_type) == 0
            && !content_type.is_null()
        {
            match CStr::from_ptr(content_type).to_bytes() {
                b"application/mercurial-0.1" => {
                    replace_with_or_abort(&mut response_data.writer, |w| {
                        Box::new(ZlibDecoder::new(w))
                    });
                }
                b"application/hg-error" => {
                    response_data.writer.write_all(b"err\n").unwrap();

                    mem::replace(
                        &mut response_data.writer,
                        Box::new(PrefixWriter::new(
                            b"remote: ",
                            crate::libc::File::new(get_stderr()),
                        )),
                    );
                }
                _ => unimplemented!(),
            }
        }
        replace_with_or_abort(&mut response_data.writer, |w| {
            Box::new(BufferedWriter::new(w))
        });
        response_data.curl = ptr::null_mut();
    }

    let buf = std::slice::from_raw_parts_mut(ptr as *mut u8, size.checked_mul(nmemb).unwrap());
    response_data.writer.write_all(buf).unwrap();
    nmemb
}

impl HgWireConnection for HgHTTPConnection {
    unsafe fn simple_command(&mut self, response: &mut strbuf, command: &str, args: HgArgs) {
        let is_pushkey = command == "pushkey";
        http_command(
            self,
            Box::new(|curl, headers| {
                prepare_simple_request(curl, response);
                if is_pushkey {
                    curl_easy_setopt(curl, CURLOPT_POST, 1);
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);
                    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
                    let headers = curl_slist_append(
                        headers,
                        cstr!("Content-Type: application/mercurial-0.1").as_ptr(),
                    );
                    curl_slist_append(headers, cstr!("Expect:").as_ptr());
                }
            }),
            command,
            args,
        )
    }

    /* The changegroup, changegroupsubset and getbundle commands return a raw
     *  * zlib stream when called over HTTP. */
    unsafe fn changegroup_command(
        &mut self,
        out: Box<dyn Write + Send>,
        command: &str,
        args: HgArgs,
    ) {
        let mut response_data = changegroup_response_data {
            curl: ptr::null_mut(),
            writer: out,
        };
        http_command(
            self,
            Box::new(|curl, _headers| {
                response_data.curl = curl;
                curl_easy_setopt(curl, CURLOPT_FILE, &mut response_data);
                curl_easy_setopt(
                    curl,
                    CURLOPT_WRITEFUNCTION,
                    changegroup_write as *const c_void,
                );
            }),
            command,
            args,
        );
    }

    unsafe fn push_command(
        &mut self,
        response: &mut strbuf,
        mut input: File,
        len: off_t,
        command: &str,
        args: HgArgs,
    ) {
        let mut http_response = strbuf::new();
        //TODO: handle errors.
        http_command(
            self,
            Box::new(|curl, headers| {
                prepare_simple_request(curl, &mut http_response);
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, curl_off_t::from(len));
                /* Ensure we have no state from a previous attempt that failed because
                 * of authentication (401). */
                input.seek(SeekFrom::Start(0)).unwrap();
                mem::replace(&mut http_response, strbuf::new());
                curl_easy_setopt(curl, CURLOPT_READDATA, &input);
                curl_easy_setopt(
                    curl,
                    CURLOPT_READFUNCTION,
                    read_from_read::<File> as *const c_void,
                );

                let headers = curl_slist_append(
                    headers,
                    cstr!("Content-Type: application/mercurial-0.1").as_ptr(),
                );
                curl_slist_append(headers, cstr!("Expect:").as_ptr());
            }),
            command,
            args,
        );

        let http_response = http_response.as_bytes();
        if http_response.get(..4) == Some(b"HG20") {
            response.extend_from_slice(http_response);
        } else {
            let file = crate::libc::File::new(get_stderr());
            match &http_response.splitn_str(2, "\n").collect::<Vec<_>>()[..] {
                [stdout_, stderr_] => {
                    response.extend_from_slice(stdout_);
                    let mut writer = PrefixWriter::new(b"remote: ", file);
                    writer.write_all(stderr_).unwrap();
                }
                //TODO: better eror handling.
                _ => panic!("Bad output from server"),
            }
        }
    }

    unsafe fn finish(&mut self) -> c_int {
        http_cleanup();
        0
    }
}

unsafe extern "C" fn read_from_read<R: Read>(
    ptr: *mut c_char,
    size: usize,
    nmemb: usize,
    data: *const c_void,
) -> usize {
    let read = (data as *mut R).as_mut().unwrap();
    let mut buf = std::slice::from_raw_parts_mut(ptr as *mut u8, size.checked_mul(nmemb).unwrap());
    read.read(&mut buf).unwrap()
}

/* The first request we send is a "capabilities" request. This sends to
 * the repo url with a query string "?cmd=capabilities". If the remote
 * url is not actually a repo, but a bundle, the content will start with
 * 'HG10' or 'HG20', which is not something that would appear as the first
 * four characters for the "capabilities" answer. In that case, we output
 * the stream to stdout.
 * (Note this assumes HTTP servers serving bundles don't care about query
 * strings)
 * Ideally, it would be good to pause the curl request, return a
 * hg_connection, and give control back to the caller, but git's http.c
 * doesn't allow pauses.
 */
unsafe extern "C" fn caps_request_write(
    ptr: *const c_char,
    size: usize,
    nmemb: usize,
    data: *const c_void,
) -> usize {
    let writers = (data as *mut Either<&mut writer, writer>).as_mut().unwrap();
    let len = size.checked_mul(nmemb).unwrap();
    let input = std::slice::from_raw_parts(ptr as *const u8, len);
    if writers.is_left() {
        match input.get(..4) {
            Some(b"HG10") | Some(b"HG20") => {
                let mut out = crate::libc::FdFile::stdout();
                out.write_all(b"bundle\n").unwrap();
                let new_writer = writer::new(BufferedWriter::new(DecompressBundleWriter::new(out)));
                mem::replace(writers, Either::Right(new_writer));
            }
            _ => {}
        }
    };
    match writers {
        &mut Either::Left(&mut ref mut writer) | &mut Either::Right(ref mut writer) => {
            writer.write_all(input).unwrap()
        }
    }
    len
}

fn http_capabilities_command(
    conn: &mut HgHTTPConnection,
    writers: &mut Either<&mut writer, writer>,
) {
    http_command(
        conn,
        Box::new(|curl, _| unsafe {
            curl_easy_setopt(curl, CURLOPT_FILE, writers as *mut _);
            curl_easy_setopt(
                curl,
                CURLOPT_WRITEFUNCTION,
                caps_request_write as *const c_void,
            );
        }),
        "capabilities",
        args!(),
    );
}

impl HgHTTPConnection {
    pub fn new(url: &Url) -> Option<Self> {
        let url = url.as_str().as_bytes();
        let mut conn = HgHTTPConnection {
            capabilities: Vec::new(),
            inner: hg_connection_http {
                url: CString::new(url.to_owned()).unwrap(),
                initial_request: true,
            },
        };

        unsafe {
            http_init(ptr::null_mut(), conn.inner.url.as_ptr(), 0);
        }

        let mut caps = Vec::<u8>::new();
        let mut writer = writer::new(&mut caps);
        let mut writers = Either::Left(&mut writer);
        http_capabilities_command(&mut conn, &mut writers);
        /* Cf. comment above caps_request_write. If the bundle stream was
         * sent to stdout, the writer was switched to the right. */
        if writers.is_right() {
            drop(writer);
            unsafe {
                conn.finish();
            }
            return None;
        }
        mem::swap(&mut conn.capabilities, &mut split_capabilities(&caps));

        Some(conn)
    }
}
