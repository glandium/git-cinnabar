/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp;
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::{stderr, Read, Seek, SeekFrom, Write};
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
use replace_with::replace_with_or_abort;
use url::{form_urlencoded, Url};

use crate::args;
use crate::hg_bundle::DecompressBundleWriter;
use crate::hg_connect::{
    split_capabilities, HgArgs, HgCapabilities, HgConnection, HgWireConnection, OneHgArg,
};
use crate::libgit::{
    credential_fill, curl_errorstr, fwrite_buffer, get_active_slot, http_auth, http_cleanup,
    http_follow_config, http_init, run_one_slot, slot_results, strbuf, HTTP_OK, HTTP_REAUTH,
};
use crate::util::{BufferedWriter, PrefixWriter};

#[allow(non_camel_case_types)]
pub struct hg_connection_http {
    pub url: Url,
    pub initial_request: bool,
}

pub type HgHTTPConnection = HgConnection<hg_connection_http>;

/* The Mercurial HTTP protocol uses HTTP requests for each individual command.
 * The command name is passed as "cmd" query parameter.
 * The command arguments can be passed in several different ways, but for now,
 * only the following is supported:
 * - each argument is passed as a query parameter.
 *
 * The command results are simply the corresponding HTTP responses.
 */
fn http_command(
    conn: &mut HgHTTPConnection,
    mut prepare_request_cb: Box<dyn FnMut(*mut CURL, *mut curl_slist) + '_>,
    command: &str,
    args: HgArgs,
) {
    let args = Iterator::chain(
        args.args.iter(),
        args.extra_args.as_ref().unwrap_or(&&[][..]).iter(),
    )
    .map(|OneHgArg { name, value }| (name, value))
    .collect::<Vec<_>>();

    unsafe {
        let mut reauth = false;
        let ret = loop {
            let slot = get_active_slot().as_mut().unwrap();
            curl_easy_setopt(slot.curl, CURLOPT_FAILONERROR, 0);
            curl_easy_setopt(slot.curl, CURLOPT_HTTPGET, 1);
            curl_easy_setopt(slot.curl, CURLOPT_NOBODY, 0);

            let mut headers = ptr::null_mut();
            headers =
                curl_slist_append(headers, cstr!("Accept: application/mercurial-0.1").as_ptr());

            let httpheader = conn
                .get_capability(b"httpheader")
                .and_then(|c| c.to_str().ok())
                .and_then(|s| usize::from_str(s).ok())
                .unwrap_or(0);

            let http = &mut conn.inner;
            if http_follow_config == http_follow_config::HTTP_FOLLOW_INITIAL && http.initial_request
            {
                curl_easy_setopt(slot.curl, CURLOPT_FOLLOWLOCATION, 1);
                http.initial_request = false;
            }

            (prepare_request_cb)(slot.curl, headers);

            let mut command_url = http.url.clone();
            let mut query_pairs = command_url.query_pairs_mut();
            query_pairs.append_pair("cmd", command);

            if httpheader > 0 && !args.is_empty() {
                let mut encoder = form_urlencoded::Serializer::new(String::new());
                for (name, value) in args.iter() {
                    encoder.append_pair(name, value);
                }
                let args = encoder.finish();
                let mut args = &args[..];
                let mut headers = headers;
                let mut num = 1;
                while !args.is_empty() {
                    let mut header = BString::from(format!("X-HgArg-{}: ", num).into_bytes());
                    num += 1;
                    let (chunk, remainder) =
                        args.split_at(cmp::min(args.len(), httpheader - header.len()));
                    header.extend_from_slice(chunk.as_bytes());
                    let header = CString::new(header).unwrap();
                    headers = curl_slist_append(headers, header.as_ptr());
                    args = remainder;
                }
            } else {
                for (name, value) in args.iter() {
                    query_pairs.append_pair(name, value);
                }
            }
            drop(query_pairs);

            let command_url = CString::new(command_url.to_string()).unwrap();
            curl_easy_setopt(slot.curl, CURLOPT_URL, command_url.as_ptr());

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

            if (ret != HTTP_OK && ret != HTTP_REAUTH) || reauth {
                break ret;
            }

            if redirects > 0 {
                let mut effective_url: *const c_char = ptr::null();
                curl_easy_getinfo(slot.curl, CURLINFO_EFFECTIVE_URL, &mut effective_url);
                let mut new_url = Url::parse(
                    CStr::from_ptr(effective_url.as_ref().unwrap())
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                new_url.set_query(None);
                eprintln!("warning: redirecting to {}", new_url.as_str());
                http.url = new_url;
            }
            if ret != HTTP_REAUTH {
                break ret;
            }
            credential_fill(&mut http_auth);
            reauth = true;
        };
        if ret != HTTP_OK {
            die!(
                "unable to access '{}': {}",
                conn.inner.url,
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

                    //XXX: Can't easily pass a StderrLock here.
                    mem::replace(
                        &mut response_data.writer,
                        Box::new(PrefixWriter::new(b"remote: ", stderr())),
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
            let stderr = stderr();
            match &http_response.splitn_str(2, "\n").collect::<Vec<_>>()[..] {
                [stdout_, stderr_] => {
                    response.extend_from_slice(stdout_);
                    let mut writer = PrefixWriter::new(b"remote: ", stderr.lock());
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
    let writers = (data as *mut Either<&mut dyn Write, Box<dyn Write>>)
        .as_mut()
        .unwrap();
    let len = size.checked_mul(nmemb).unwrap();
    let input = std::slice::from_raw_parts(ptr as *const u8, len);
    if writers.is_left() {
        match input.get(..4) {
            Some(b"HG10") | Some(b"HG20") => {
                let mut out = crate::libc::FdFile::stdout();
                out.write_all(b"bundle\n").unwrap();
                let new_writer = Box::new(BufferedWriter::new(DecompressBundleWriter::new(out)));
                mem::replace(writers, Either::Right(new_writer));
            }
            _ => {}
        }
    };
    match writers {
        Either::Left(ref mut writer) => writer.write_all(input).unwrap(),
        Either::Right(ref mut writer) => writer.write_all(input).unwrap(),
    }
    len
}

fn http_capabilities_command(
    conn: &mut HgHTTPConnection,
    writers: &mut Either<&mut dyn Write, Box<dyn Write>>,
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
        let mut conn = HgHTTPConnection {
            capabilities: Vec::new(),
            inner: hg_connection_http {
                url: url.clone(),
                initial_request: true,
            },
        };

        let c_url = CString::new(url.to_string()).unwrap();
        unsafe {
            http_init(ptr::null_mut(), c_url.as_ptr(), 0);
        }

        let mut caps = Vec::<u8>::new();
        let mut writers = Either::Left(&mut caps as &mut dyn Write);
        http_capabilities_command(&mut conn, &mut writers);
        /* Cf. comment above caps_request_write. If the bundle stream was
         * sent to stdout, the writer was switched to the right. */
        if writers.is_right() {
            unsafe {
                conn.finish();
            }
            return None;
        }
        mem::swap(&mut conn.capabilities, &mut split_capabilities(&caps));

        Some(conn)
    }
}
