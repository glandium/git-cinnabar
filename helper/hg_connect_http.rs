/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp;
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::{self, copy, stderr, Cursor, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::{c_char, c_int, c_long};
use std::ptr;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{self, JoinHandle};

use bstr::ByteSlice;
use byteorder::ReadBytesExt;
use bzip2::read::BzDecoder;
use cstr::cstr;
use curl_sys::{
    curl_easy_getinfo, curl_easy_setopt, curl_slist_append, curl_slist_free_all, CURL,
    CURLINFO_CONTENT_TYPE, CURLINFO_EFFECTIVE_URL, CURLINFO_REDIRECT_COUNT, CURLINFO_RESPONSE_CODE,
    CURLOPT_FAILONERROR, CURLOPT_FILE, CURLOPT_FOLLOWLOCATION, CURLOPT_HTTPGET, CURLOPT_HTTPHEADER,
    CURLOPT_NOBODY, CURLOPT_POST, CURLOPT_POSTFIELDSIZE_LARGE, CURLOPT_READDATA,
    CURLOPT_READFUNCTION, CURLOPT_URL, CURLOPT_USERAGENT, CURLOPT_WRITEFUNCTION,
};
use either::Either;
use flate2::read::ZlibDecoder;
use url::{form_urlencoded, Url};
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::args;
use crate::hg_bundle::DecompressBundleReader;
use crate::hg_connect::{
    split_capabilities, HgArgs, HgCapabilities, HgConnection, HgWireConnection, OneHgArg,
};
use crate::libgit::{
    credential_fill, curl_errorstr, get_active_slot, http_auth, http_cleanup, http_follow_config,
    http_init, run_one_slot, slot_results, strbuf, HTTP_OK, HTTP_REAUTH,
};
use crate::util::{PrefixWriter, ReadExt, SeekExt, SliceExt};

#[allow(non_camel_case_types)]
pub struct hg_connection_http {
    pub url: Url,
    pub initial_request: bool,
    client: HTTPClient,
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

trait ReadAndSeek: Read + Seek {}

impl<T: Read + Seek> ReadAndSeek for T {}

struct HTTPClient {
    initial_request: bool,
}

struct HTTPRequest {
    url: Url,
    headers: Vec<(String, String)>,
    body: Option<Box<dyn ReadAndSeek + Send>>,
    follow_redirects: bool,
}

#[derive(Debug)]
struct HTTPResponseInfo {
    http_status: usize,
    redirected_to: Option<Url>,
    content_type: Option<String>,
}

#[derive(Debug)]
struct HTTPResponse {
    info: HTTPResponseInfo,
    thread: Option<JoinHandle<Result<(), (c_int, HTTPRequest)>>>,
    cursor: Cursor<Vec<u8>>,
    receiver: Option<Receiver<HTTPRequestChannelData>>,
}

type HTTPRequestChannelData = Either<HTTPResponseInfo, Vec<u8>>;

struct HTTPThreadData {
    sender: Sender<HTTPRequestChannelData>,
    curl: *mut CURL,
    first: bool,
}

impl HTTPClient {
    fn new() -> Self {
        HTTPClient {
            initial_request: true,
        }
    }

    fn request(&mut self, url: Url) -> HTTPRequest {
        let mut req = HTTPRequest::new(url);
        let follow_config = unsafe { http_follow_config };
        if (follow_config == http_follow_config::HTTP_FOLLOW_INITIAL && self.initial_request)
            || follow_config == http_follow_config::HTTP_FOLLOW_ALWAYS
        {
            req.follow_redirects(true);
        }
        if self.initial_request {
            self.initial_request = false;
        }
        req
    }
}

impl HTTPRequest {
    fn new(url: Url) -> Self {
        HTTPRequest {
            url,
            headers: Vec::new(),
            body: None,
            follow_redirects: false,
        }
    }

    fn follow_redirects(&mut self, enable: bool) {
        self.follow_redirects = enable;
    }

    fn header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn post_data(&mut self, data: Box<dyn ReadAndSeek + Send>) {
        self.body = Some(data);
    }

    fn execute_once(mut self) -> Result<HTTPResponse, (c_int, Self)> {
        let (sender, receiver) = channel::<HTTPRequestChannelData>();
        let thread = thread::spawn(move || unsafe {
            let url = CString::new(self.url.to_string()).unwrap();
            let slot = get_active_slot().as_mut().unwrap();
            curl_easy_setopt(slot.curl, CURLOPT_URL, url.as_ptr());
            curl_easy_setopt(slot.curl, CURLOPT_FAILONERROR, 0);
            curl_easy_setopt(slot.curl, CURLOPT_NOBODY, 0);
            /* Strictly speaking, this is not necessary, but bitbucket does
             * user-agent sniffing, and git's user-agent gets 404 on mercurial
             * urls. */
            curl_easy_setopt(
                slot.curl,
                CURLOPT_USERAGENT,
                cstr!("mercurial/proto-1.0").as_ptr(),
            );
            let mut data = HTTPThreadData {
                sender,
                curl: slot.curl,
                first: true,
            };
            curl_easy_setopt(slot.curl, CURLOPT_FILE, &mut data);
            curl_easy_setopt(
                slot.curl,
                CURLOPT_WRITEFUNCTION,
                http_request_execute as *const c_void,
            );
            let mut headers = ptr::null_mut();
            if let Some(ref mut body) = self.body {
                curl_easy_setopt(slot.curl, CURLOPT_POST, 1);
                curl_easy_setopt(
                    slot.curl,
                    CURLOPT_POSTFIELDSIZE_LARGE,
                    body.stream_len_().unwrap(),
                );
                /* Ensure we have no state from a previous attempt that failed because
                 * of authentication (401). */
                body.seek(SeekFrom::Start(0)).unwrap();
                curl_easy_setopt(slot.curl, CURLOPT_READDATA, &mut *body);
                curl_easy_setopt(
                    slot.curl,
                    CURLOPT_READFUNCTION,
                    read_from_read::<&mut (dyn ReadAndSeek + Send)> as *const c_void,
                );
                curl_easy_setopt(slot.curl, CURLOPT_FOLLOWLOCATION, 0);
                headers = curl_slist_append(headers, cstr!("Expect:").as_ptr());
            } else {
                if self.follow_redirects {
                    curl_easy_setopt(slot.curl, CURLOPT_FOLLOWLOCATION, 1);
                }
                curl_easy_setopt(slot.curl, CURLOPT_HTTPGET, 1);
            }
            for (name, value) in self.headers.iter() {
                let header_line = CString::new(format!("{}: {}", name, value)).unwrap();
                headers = curl_slist_append(headers, header_line.as_ptr());
            }
            curl_easy_setopt(slot.curl, CURLOPT_HTTPHEADER, headers);
            let mut results = slot_results::new();
            let result = run_one_slot(slot, &mut results);
            curl_slist_free_all(headers);
            http_send_info(&mut data);
            if result == HTTP_OK {
                Ok(())
            } else {
                Err((result, self))
            }
        });

        match receiver.recv() {
            Ok(Either::Left(info)) if info.http_status < 300 => Ok(HTTPResponse {
                info,
                thread: Some(thread),
                cursor: Cursor::new(Vec::new()),
                receiver: Some(receiver),
            }),
            Ok(Either::Right(_)) => unreachable!(),
            _ => {
                while receiver.recv().is_ok() {}
                drop(receiver);
                thread.join().unwrap()?;
                unreachable!();
            }
        }
    }

    fn execute(self) -> Result<HTTPResponse, ()> {
        self.execute_once()
            .or_else(|(result, this)| {
                if result == HTTP_REAUTH {
                    unsafe { credential_fill(&mut http_auth) };
                    this.execute_once()
                } else {
                    Err((result, this))
                }
            })
            .map_err(|(_, mut this)| unsafe {
                this.url.set_query(None);
                die!(
                    "unable to access '{}': {}",
                    this.url,
                    CStr::from_ptr(curl_errorstr.as_ptr()).to_bytes().as_bstr()
                );
            })
    }
}

impl Read for HTTPResponse {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.cursor.read(buf)?;
        if n == 0 && self.receiver.is_some() {
            match self.receiver.as_ref().unwrap().recv() {
                Ok(Either::Right(mut data)) => {
                    self.cursor.set_position(0);
                    mem::swap(self.cursor.get_mut(), &mut data);
                    self.cursor.read(buf)
                }
                Err(_) => Ok(0),
                _ => unreachable!(),
            }
        } else {
            Ok(n)
        }
    }
}

impl Drop for HTTPResponse {
    fn drop(&mut self) {
        drop(self.receiver.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join().unwrap();
        }
    }
}

impl HTTPResponse {
    fn content_type(&self) -> Option<&str> {
        self.info.content_type.as_ref().map(|s| &s[..])
    }

    fn redirected_to(&self) -> Option<&Url> {
        self.info.redirected_to.as_ref()
    }
}

fn http_send_info(data: &mut HTTPThreadData) {
    if data.first {
        unsafe {
            data.first = false;
            let mut http_status: c_long = 0;
            curl_easy_getinfo(data.curl, CURLINFO_RESPONSE_CODE, &mut http_status);
            let redirected_to = {
                let mut redirects: c_long = 0;
                curl_easy_getinfo(data.curl, CURLINFO_REDIRECT_COUNT, &mut redirects);

                if redirects > 0 {
                    let mut effective_url: *const c_char = ptr::null();
                    curl_easy_getinfo(data.curl, CURLINFO_EFFECTIVE_URL, &mut effective_url);
                    Some(
                        Url::parse(
                            CStr::from_ptr(effective_url.as_ref().unwrap())
                                .to_str()
                                .unwrap(),
                        )
                        .unwrap(),
                    )
                } else {
                    None
                }
            };
            let content_type = {
                let mut content_type: *const c_char = ptr::null();
                if curl_easy_getinfo(data.curl, CURLINFO_CONTENT_TYPE, &mut content_type) == 0
                    && !content_type.is_null()
                {
                    CStr::from_ptr(content_type)
                        .to_str()
                        .ok()
                        .map(|c| c.to_owned())
                } else {
                    None
                }
            };
            data.sender
                .send(Either::Left(HTTPResponseInfo {
                    http_status: http_status as usize,
                    redirected_to,
                    content_type,
                }))
                .unwrap();
        }
    }
}

unsafe extern "C" fn http_request_execute(
    ptr: *const c_char,
    size: usize,
    nmemb: usize,
    data: *mut c_void,
) -> usize {
    let data = (data as *mut HTTPThreadData).as_mut().unwrap();
    http_send_info(data);
    let buf = std::slice::from_raw_parts(ptr as *const u8, size.checked_mul(nmemb).unwrap());
    if data.sender.send(Either::Right(buf.to_owned())).is_err() {
        return 0;
    }
    nmemb
}

impl HgHTTPConnection {
    fn start_command_request(&mut self, command: &str, args: HgArgs) -> HTTPRequest {
        let args = Iterator::chain(
            args.args.iter(),
            args.extra_args.as_ref().unwrap_or(&&[][..]).iter(),
        )
        .map(|OneHgArg { name, value }| (name, value))
        .collect::<Vec<_>>();

        let httpheader = self
            .get_capability(b"httpheader")
            .and_then(|c| c.to_str().ok())
            .and_then(|s| usize::from_str(s).ok())
            .unwrap_or(0);

        let mut command_url = self.inner.url.clone();
        let mut query_pairs = command_url.query_pairs_mut();
        query_pairs.append_pair("cmd", command);
        let mut headers = Vec::new();

        if httpheader > 0 && !args.is_empty() {
            let mut encoder = form_urlencoded::Serializer::new(String::new());
            for (name, value) in args.iter() {
                encoder.append_pair(name, value);
            }
            let args = encoder.finish();
            let mut args = &args[..];
            let mut num = 1;
            while !args.is_empty() {
                let header_name = format!("X-HgArg-{}", num);
                num += 1;
                let (chunk, remainder) = args.split_at(cmp::min(
                    args.len(),
                    httpheader - header_name.len() - ": ".len(),
                ));
                headers.push((header_name, chunk.to_string()));
                args = remainder;
            }
        } else {
            for (name, value) in args.iter() {
                query_pairs.append_pair(name, value);
            }
        }
        drop(query_pairs);

        let mut request = self.inner.client.request(command_url);
        request.header("Accept", "application/mercurial-0.1");
        for (name, value) in headers {
            request.header(&name, &value);
        }
        request
    }

    fn handle_redirect(&mut self, http_resp: &HTTPResponse) {
        if let Some(url) = http_resp.redirected_to() {
            let mut new_url = url.clone();
            new_url.set_query(None);
            eprintln!("warning: redirecting to {}", new_url.as_str());
            self.inner.url = new_url;
        }
    }
}

impl HgWireConnection for HgHTTPConnection {
    fn simple_command(&mut self, response: &mut strbuf, command: &str, args: HgArgs) {
        let mut http_req = self.start_command_request(command, args);
        if command == "pushkey" {
            http_req.header("Content-Type", "application/mercurial-0.1");
            http_req.post_data(Box::new(Cursor::new(Vec::<u8>::new())));
        }
        let mut http_resp = http_req.execute().unwrap();
        self.handle_redirect(&http_resp);
        copy(&mut http_resp, response).unwrap();
    }

    /* The changegroup, changegroupsubset and getbundle commands return a raw
     *  * zlib stream when called over HTTP. */
    fn changegroup_command(&mut self, out: Box<dyn Write + Send>, command: &str, args: HgArgs) {
        let mut http_req = self.start_command_request(command, args);
        if let Some(media_type) = self
            .get_capability(b"httpmediatype")
            .and_then(|c| c.to_str().ok())
        {
            if media_type.split(',').any(|t| t == "0.2tx") {
                //TODO: Allow to disable individual features via configuration.
                //TODO: Only send compression types the server reported supporting.
                //TODO: Tests!
                http_req.header("X-HgProto-1", "0.1 0.2 comp=zstd,zlib,none,bzip2");
            }
        }
        let mut http_resp = http_req.execute().unwrap();
        self.handle_redirect(&http_resp);
        let mut writer = out;

        let mut reader: Box<dyn Read> = match http_resp.content_type() {
            Some("application/mercurial-0.1") => Box::new(ZlibDecoder::new(http_resp)),
            Some("application/mercurial-0.2") => {
                let comp_len = http_resp.read_u8().unwrap() as u64;
                let mut comp = Vec::new();
                (&mut http_resp)
                    .take(comp_len)
                    .read_to_end(&mut comp)
                    .unwrap();
                match &comp[..] {
                    b"zstd" => Box::new(ZstdDecoder::new(http_resp).unwrap()),
                    b"zlib" => Box::new(ZlibDecoder::new(http_resp)),
                    b"none" => Box::new(http_resp),
                    b"bzip2" => Box::new(BzDecoder::new(http_resp)),
                    comp => die!(
                        "Server responded with unknown compression {}",
                        String::from_utf8_lossy(comp)
                    ),
                }
            }
            Some("application/hg-error") => {
                writer.write_all(b"err\n").unwrap();

                //XXX: Can't easily pass a StderrLock here.
                writer = Box::new(PrefixWriter::new(b"remote: ", stderr()));
                Box::new(http_resp)
            }
            _ => unimplemented!(),
        };
        copy(&mut reader, &mut *writer).unwrap();
    }

    fn push_command(&mut self, response: &mut strbuf, input: File, command: &str, args: HgArgs) {
        let mut http_req = self.start_command_request(command, args);
        http_req.post_data(Box::new(input));
        http_req.header("Content-Type", "application/mercurial-0.1");
        let mut http_resp = http_req.execute().unwrap();
        self.handle_redirect(&http_resp);
        let mut header = [0u8; 4];
        let len = http_resp.read_at_most(&mut header).unwrap();
        let header = &header[..len];
        if header == b"HG20" {
            response.extend_from_slice(header);
            copy(&mut http_resp, response).unwrap();
        } else {
            let stderr = stderr();
            let mut buf = header.to_owned();
            http_resp.read_to_end(&mut buf).unwrap();
            match buf.splitn_exact(b'\n') {
                Some([stdout_, stderr_]) => {
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

impl HgHTTPConnection {
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
    fn capabilities_command(&mut self, mut writer: &mut dyn Write) -> bool {
        let http_req = self.start_command_request("capabilities", args!());
        let mut http_resp = http_req.execute().unwrap();
        self.handle_redirect(&http_resp);
        let mut header = [0u8; 4];
        let len = http_resp.read_at_most(&mut header).unwrap();
        let header = &header[..len];
        match header {
            b"HG10" | b"HG20" => {
                let mut out = unsafe { crate::libc::FdFile::stdout() };
                out.write_all(b"bundle\n").unwrap();
                let mut reader = DecompressBundleReader::new(Cursor::new(header).chain(http_resp));
                copy(&mut reader, &mut out).unwrap();
                false
            }
            _ => {
                writer.write_all(header).unwrap();
                copy(&mut http_resp, &mut writer).unwrap();
                true
            }
        }
    }

    pub fn new(url: &Url) -> Option<Self> {
        let mut conn = HgHTTPConnection {
            capabilities: Vec::new(),
            inner: hg_connection_http {
                url: url.clone(),
                initial_request: true,
                client: HTTPClient::new(),
            },
        };

        let c_url = CString::new(url.to_string()).unwrap();
        unsafe {
            http_init(ptr::null_mut(), c_url.as_ptr(), 0);
        }

        let mut caps = Vec::<u8>::new();
        if !conn.capabilities_command(&mut caps) {
            unsafe {
                conn.finish();
            }
            return None;
        }
        mem::swap(&mut conn.capabilities, &mut split_capabilities(&caps));

        Some(conn)
    }
}
