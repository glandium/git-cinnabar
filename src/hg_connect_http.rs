/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::ToOwned;
use std::cmp;
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::{self, copy, stderr, Cursor, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::raw::{c_char, c_int, c_long};
use std::ptr;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use bstr::{BStr, ByteSlice};
use byteorder::ReadBytesExt;
use bzip2::read::BzDecoder;
use cstr::cstr;
use curl_sys::{
    curl_easy_getinfo, curl_easy_setopt, curl_slist_append, curl_slist_free_all, CURL,
    CURLINFO_CONTENT_TYPE, CURLINFO_EFFECTIVE_URL, CURLINFO_REDIRECT_COUNT, CURLINFO_RESPONSE_CODE,
    CURLOPT_ACCEPT_ENCODING, CURLOPT_FAILONERROR, CURLOPT_FILE, CURLOPT_FOLLOWLOCATION,
    CURLOPT_HTTPGET, CURLOPT_HTTPHEADER, CURLOPT_NOBODY, CURLOPT_POST, CURLOPT_POSTFIELDSIZE_LARGE,
    CURLOPT_READDATA, CURLOPT_READFUNCTION, CURLOPT_URL, CURLOPT_USERAGENT, CURLOPT_WRITEFUNCTION,
};
use either::Either;
use flate2::read::ZlibDecoder;
use itertools::Itertools;
use url::{form_urlencoded, Url};
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::args;
use crate::hg_bundle::{BundleConnection, DecompressBundleReader};
use crate::hg_connect::{
    HgArgs, HgCapabilities, HgConnection, HgConnectionBase, HgWireConnection, OneHgArg,
};
use crate::libgit::{
    credential_fill, curl_errorstr, get_active_slot, http_auth, http_follow_config, run_one_slot,
    slot_results, HTTP_OK, HTTP_REAUTH,
};
use crate::util::{ImmutBString, PrefixWriter, ReadExt, SeekExt, SliceExt, ToBoxed};

use self::git_http_state::{GitHttpStateToken, GIT_HTTP_STATE};

mod git_http_state {
    use std::{ffi::CString, ptr, sync::Mutex};

    use once_cell::sync::Lazy;
    use url::Url;

    use crate::libgit::{http_cleanup, http_init};

    pub struct GitHttpState {
        url: Option<Url>,
        taken: bool,
    }

    pub struct GitHttpStateToken(());

    impl GitHttpState {
        fn new() -> Self {
            GitHttpState {
                url: None,
                taken: false,
            }
        }

        pub fn take(&mut self, url: &Url) -> GitHttpStateToken {
            assert!(!self.taken);
            let mut normalized_url = url.clone();
            let _ = normalized_url.set_password(None);
            normalized_url.set_query(None);
            normalized_url.set_fragment(None);
            match &self.url {
                Some(url) if url == &normalized_url => {}
                _ => {
                    let c_url = CString::new(normalized_url.to_string()).unwrap();
                    unsafe {
                        if self.url.is_some() {
                            http_cleanup();
                        }
                        http_init(ptr::null_mut(), c_url.as_ptr(), 0);
                    }
                    self.url = Some(normalized_url);
                }
            }
            self.taken = true;
            GitHttpStateToken(())
        }

        pub fn clean(&mut self) {
            assert!(!self.taken);
            if self.url.take().is_some() {
                unsafe {
                    http_cleanup();
                }
            }
        }
    }

    pub static GIT_HTTP_STATE: Lazy<Mutex<GitHttpState>> =
        Lazy::new(|| Mutex::new(GitHttpState::new()));

    impl Drop for GitHttpStateToken {
        fn drop(&mut self) {
            let mut state = GIT_HTTP_STATE.lock().unwrap();
            assert!(state.taken);
            state.taken = false;
        }
    }
}
pub struct HgHttpConnection {
    capabilities: HgCapabilities,
    url: Url,
}

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

pub struct HttpRequest {
    url: Url,
    headers: Vec<(String, String)>,
    body: Option<Box<dyn ReadAndSeek + Send>>,
    follow_redirects: bool,
    token: Arc<GitHttpStateToken>,
}

#[derive(Debug)]
struct HttpResponseInfo {
    http_status: usize,
    redirected_to: Option<Url>,
    content_type: Option<String>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct HttpResponse {
    info: HttpResponseInfo,
    thread: Option<JoinHandle<Result<(), (c_int, HttpRequest)>>>,
    cursor: Cursor<ImmutBString>,
    receiver: Option<Receiver<HttpRequestChannelData>>,
    #[derivative(Debug = "ignore")]
    token: Arc<GitHttpStateToken>,
}

type HttpRequestChannelData = Either<HttpResponseInfo, ImmutBString>;

struct HttpThreadData {
    sender: Sender<HttpRequestChannelData>,
    curl: *mut CURL,
    first: bool,
}

impl HttpRequest {
    pub fn new(url: Url) -> Self {
        let token = GIT_HTTP_STATE.lock().unwrap().take(&url);
        HttpRequest {
            url,
            headers: Vec::new(),
            body: None,
            follow_redirects: false,
            token: Arc::new(token),
        }
    }

    pub fn follow_redirects(&mut self, enable: bool) {
        self.follow_redirects = enable;
    }

    fn header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn post_data(&mut self, data: Box<dyn ReadAndSeek + Send>) {
        self.body = Some(data);
    }

    fn execute_once(mut self) -> Result<HttpResponse, (c_int, Self)> {
        let (sender, receiver) = channel::<HttpRequestChannelData>();
        let token = self.token.clone();
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
            let mut data = HttpThreadData {
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
            curl_easy_setopt(slot.curl, CURLOPT_ACCEPT_ENCODING, b"\0");
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
            Ok(Either::Left(info)) if info.http_status >= 100 && info.http_status < 300 => {
                Ok(HttpResponse {
                    info,
                    thread: Some(thread),
                    cursor: Cursor::new(b"".to_boxed()),
                    receiver: Some(receiver),
                    token,
                })
            }
            Ok(Either::Right(_)) => unreachable!(),
            _ => {
                while receiver.recv().is_ok() {}
                drop(receiver);
                thread.join().unwrap()?;
                unreachable!();
            }
        }
    }

    pub fn execute(self) -> Result<HttpResponse, String> {
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
                format!(
                    "unable to access '{}': {}",
                    this.url,
                    CStr::from_ptr(curl_errorstr.as_ptr()).to_bytes().as_bstr()
                )
            })
    }
}

impl Read for HttpResponse {
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

impl Drop for HttpResponse {
    fn drop(&mut self) {
        drop(self.receiver.take());
        if let Some(thread) = self.thread.take() {
            let _result = thread.join().unwrap();
        }
    }
}

impl HttpResponse {
    fn content_type(&self) -> Option<&str> {
        self.info.content_type.as_ref().map(|s| &s[..])
    }

    fn redirected_to(&self) -> Option<&Url> {
        self.info.redirected_to.as_ref()
    }
}

fn http_send_info(data: &mut HttpThreadData) {
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
                        .map(ToOwned::to_owned)
                } else {
                    None
                }
            };
            data.sender
                .send(Either::Left(HttpResponseInfo {
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
    let data = (data as *mut HttpThreadData).as_mut().unwrap();
    http_send_info(data);
    let buf = std::slice::from_raw_parts(ptr as *const u8, size.checked_mul(nmemb).unwrap());
    if data.sender.send(Either::Right(buf.to_boxed())).is_err() {
        return 0;
    }
    nmemb
}

impl HgHttpConnection {
    fn start_command_request(&mut self, command: &str, args: HgArgs) -> HttpRequest {
        let args = Iterator::chain(
            args.args.iter(),
            args.extra_args.as_ref().unwrap_or(&&[][..]).iter(),
        )
        .map(|OneHgArg { name, value }| (name, value))
        .collect_vec();

        let httpheader = self
            .get_capability(b"httpheader")
            .and_then(|c| c.to_str().ok())
            .and_then(|s| usize::from_str(s).ok())
            .unwrap_or(0);

        let mut command_url = self.url.clone();
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

        let mut request = HttpRequest::new(command_url);
        if unsafe { http_follow_config } == http_follow_config::HTTP_FOLLOW_ALWAYS {
            request.follow_redirects(true);
        }

        request.header("Accept", "application/mercurial-0.1");
        for (name, value) in headers {
            request.header(&name, &value);
        }
        request
    }

    fn handle_redirect(&mut self, http_resp: &HttpResponse) {
        if let Some(url) = http_resp.redirected_to() {
            let mut new_url = url.clone();
            new_url.set_query(None);
            eprintln!("warning: redirecting to {}", new_url.as_str());
            self.url = new_url;
        }
    }
}

impl HgWireConnection for HgHttpConnection {
    fn simple_command(&mut self, command: &str, args: HgArgs) -> ImmutBString {
        let mut http_req = self.start_command_request(command, args);
        if command == "pushkey" {
            http_req.header("Content-Type", "application/mercurial-0.1");
            http_req.post_data(Box::new(Cursor::new(Vec::<u8>::new())));
        }
        let mut http_resp = http_req.execute().unwrap();
        self.handle_redirect(&http_resp);
        http_resp.read_all().unwrap()
    }

    /* The changegroup, changegroupsubset and getbundle commands return a raw
     *  * zlib stream when called over HTTP. */
    fn changegroup_command<'a>(
        &'a mut self,
        command: &str,
        args: HgArgs,
    ) -> Result<Box<dyn Read + 'a>, ImmutBString> {
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

        match http_resp.content_type() {
            Some("application/mercurial-0.1") => Ok(Box::new(ZlibDecoder::new(http_resp))),
            Some("application/mercurial-0.2") => {
                let comp_len = http_resp.read_u8().unwrap() as u64;
                let comp = (&mut http_resp).take(comp_len).read_all().unwrap();
                let reader: Box<dyn Read> = match &comp[..] {
                    b"zstd" => Box::new(ZstdDecoder::new(http_resp).unwrap()),
                    b"zlib" => Box::new(ZlibDecoder::new(http_resp)),
                    b"none" => Box::new(http_resp),
                    b"bzip2" => Box::new(BzDecoder::new(http_resp)),
                    comp => die!(
                        "Server responded with unknown compression {}",
                        String::from_utf8_lossy(comp)
                    ),
                };
                Ok(reader)
            }
            Some("application/hg-error") => Err(http_resp.read_all().unwrap()),
            _ => unimplemented!(),
        }
    }

    fn push_command(&mut self, input: File, command: &str, args: HgArgs) -> ImmutBString {
        let mut http_req = self.start_command_request(command, args);
        http_req.post_data(Box::new(input));
        http_req.header("Content-Type", "application/mercurial-0.1");
        let mut http_resp = http_req.execute().unwrap();
        self.handle_redirect(&http_resp);
        let header = (&mut http_resp).take(4).read_all().unwrap();
        if &*header == b"HG20" {
            Cursor::new(header).chain(http_resp).read_all().unwrap()
        } else {
            let stderr = stderr();
            let mut buf = header.to_vec();
            http_resp.read_to_end(&mut buf).unwrap();
            match buf.splitn_exact(b'\n') {
                Some([stdout_, stderr_]) => {
                    let mut writer = PrefixWriter::new("remote: ", stderr.lock());
                    writer.write_all(stderr_).unwrap();
                    stdout_.to_boxed()
                }
                //TODO: better eror handling.
                _ => panic!("Bad output from server"),
            }
        }
    }
}

impl HgConnectionBase for HgHttpConnection {
    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        self.capabilities.get_capability(name)
    }
}

impl Drop for HgHttpConnection {
    fn drop(&mut self) {
        GIT_HTTP_STATE.lock().unwrap().clean();
    }
}

pub struct HttpConnectionHoldingReader<R: Read> {
    reader: R,
    // Not used, but needed to guarantee http_cleanup doesn't happen before
    // HttpResponse is dropped.
    #[allow(unused)]
    conn: HgHttpConnection,
}

impl<R: Read> Read for HttpConnectionHoldingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

unsafe extern "C" fn read_from_read<R: Read>(
    ptr: *mut c_char,
    size: usize,
    nmemb: usize,
    data: *const c_void,
) -> usize {
    let read = (data as *mut R).as_mut().unwrap();
    let buf = std::slice::from_raw_parts_mut(ptr as *mut u8, size.checked_mul(nmemb).unwrap());
    read.read(buf).unwrap()
}

#[allow(clippy::unnecessary_wraps)]
pub fn get_http_connection(url: &Url) -> Option<Box<dyn HgConnection>> {
    let mut conn = HgHttpConnection {
        capabilities: HgCapabilities::default(),
        url: url.clone(),
    };

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
    let mut http_req = conn.start_command_request("capabilities", args!());
    if unsafe { http_follow_config } == http_follow_config::HTTP_FOLLOW_INITIAL {
        http_req.follow_redirects(true);
    }
    let mut http_resp = http_req.execute().unwrap();
    conn.handle_redirect(&http_resp);
    let header = (&mut http_resp).take(4).read_all().unwrap();
    match &*header {
        b"HG10" | b"HG20" => Some(Box::new(BundleConnection::new(
            HttpConnectionHoldingReader {
                reader: DecompressBundleReader::new(Cursor::new(header).chain(http_resp)),
                conn,
            },
        ))),

        _ => {
            let mut caps = Vec::<u8>::new();
            caps.extend_from_slice(&header);
            copy(&mut http_resp, &mut caps).unwrap();
            mem::swap(&mut conn.capabilities, &mut HgCapabilities::new_from(&caps));
            Some(Box::new(Box::new(conn) as Box<dyn HgWireConnection>))
        }
    }
}
