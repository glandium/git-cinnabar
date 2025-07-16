/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::ToOwned;
use std::ffi::{c_void, CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, stderr, Cursor, Read, Write};
use std::os::raw::{c_char, c_int, c_long};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::{cmp, mem, ptr};

use bstr::{BStr, ByteSlice};
use byteorder::ReadBytesExt;
use bzip2::read::BzDecoder;
use cstr::cstr;
use curl_sys::{
    curl_easy_getinfo, curl_easy_setopt, curl_infotype, curl_slist_append, curl_slist_free_all,
    CURL, CURLINFO_CONTENT_TYPE, CURLINFO_EFFECTIVE_URL, CURLINFO_HEADER_IN, CURLINFO_HEADER_OUT,
    CURLINFO_REDIRECT_COUNT, CURLINFO_RESPONSE_CODE, CURLOPT_ACCEPT_ENCODING, CURLOPT_CAINFO,
    CURLOPT_DEBUGDATA, CURLOPT_DEBUGFUNCTION, CURLOPT_FAILONERROR, CURLOPT_FILE,
    CURLOPT_FOLLOWLOCATION, CURLOPT_HTTPGET, CURLOPT_HTTPHEADER, CURLOPT_NOBODY, CURLOPT_POST,
    CURLOPT_POSTFIELDSIZE_LARGE, CURLOPT_READDATA, CURLOPT_READFUNCTION, CURLOPT_URL,
    CURLOPT_USERAGENT, CURLOPT_VERBOSE, CURLOPT_WRITEFUNCTION,
};
use derive_more::Debug;
use either::Either;
use flate2::read::ZlibDecoder;
use itertools::Itertools;
use once_cell::sync::Lazy;
use url::{form_urlencoded, Url};
use zstd::stream::read::Decoder as ZstdDecoder;

use self::git_http_state::{GitHttpStateToken, GIT_HTTP_STATE};
use crate::hg_bundle::BundleConnection;
use crate::hg_connect::{
    args, HgArgs, HgCapabilities, HgConnectionBase, HgRepo, HgWireConnection, HgWired, OneHgArg,
    UnbundleResponse,
};
use crate::libgit::{
    credential_fill, curl_errorstr, die, get_active_slot, http_auth, http_follow_config,
    run_one_slot, slot_results, ssl_cainfo, the_repository, HTTP_OK, HTTP_REAUTH,
};
use crate::logging::{self, LoggingReader, LoggingWriter};
use crate::util::{
    ExactSizeReadRewind, ImmutBString, OsStrExt, PrefixWriter, ReadExt, SliceExt, ToBoxed,
};

pub static CURL_GLOBAL_INIT: OnceLock<()> = OnceLock::new();

mod git_http_state {
    use std::ffi::CString;
    use std::ptr;
    use std::sync::Mutex;

    use url::Url;

    use crate::libgit::{http_cleanup, http_init};

    pub struct GitHttpState {
        url: Option<Url>,
        taken: bool,
    }

    pub struct GitHttpStateToken(());

    impl GitHttpState {
        const fn new() -> Self {
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
                    super::CURL_GLOBAL_INIT.get_or_init(|| {
                        if unsafe { curl_sys::curl_global_init(curl_sys::CURL_GLOBAL_ALL) }
                            != curl_sys::CURLE_OK
                        {
                            crate::die!("curl_global_init failed");
                        }
                    });
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

    pub static GIT_HTTP_STATE: Mutex<GitHttpState> = Mutex::new(GitHttpState::new());

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

enum Body {
    None,
    Simple(Box<dyn ExactSizeReadRewind + Send>),
    Chained(
        std::io::Chain<Box<dyn ExactSizeReadRewind + Send>, Box<dyn ExactSizeReadRewind + Send>>,
    ),
}

impl Body {
    fn new() -> Body {
        Body::None
    }

    fn is_some(&self) -> bool {
        !matches!(self, Body::None)
    }

    fn add(&mut self, r: impl ExactSizeReadRewind + Send + 'static) {
        let current = mem::replace(self, Body::None);
        *self = match current {
            Body::None => Body::Simple(Box::new(r)),
            Body::Simple(first) => Body::Chained(first.chain(Box::new(r))),
            Body::Chained(_) => Body::Chained(
                (Box::new(current) as Box<dyn ExactSizeReadRewind + Send>).chain(Box::new(r)),
            ),
        }
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::None => Ok(0),
            Body::Simple(first) => first.read(buf),
            Body::Chained(chained) => chained.read(buf),
        }
    }
}

impl ExactSizeReadRewind for Body {
    fn len(&self) -> io::Result<u64> {
        match self {
            Body::None => Ok(0),
            Body::Simple(first) => first.len(),
            Body::Chained(chained) => {
                let (first, second) = chained.get_ref();
                Ok(first.len()? + second.len()?)
            }
        }
    }

    fn rewind(&mut self) -> io::Result<()> {
        match self {
            Body::None => Ok(()),
            Body::Simple(first) => first.rewind(),
            Body::Chained(_) => {
                let current = mem::replace(self, Body::None);
                if let Body::Chained(chained) = current {
                    let (mut first, mut second) = chained.into_inner();
                    first.rewind()?;
                    second.rewind()?;
                    *self = Body::Chained(first.chain(second));
                }
                Ok(())
            }
        }
    }
}

#[test]
fn test_exactsize_read_rewind_body() {
    let a = "abcd";
    let b = "efg";
    let c = "hijklm";

    let mut body1 = Body::new();
    body1.add(Cursor::new(a));

    assert_eq!(body1.len().unwrap(), 4);
    assert_eq!(&body1.read_all().unwrap()[..], b"abcd");
    body1.rewind().unwrap();
    assert_eq!(&body1.read_all().unwrap()[..], b"abcd");

    let mut body2 = Body::new();
    body2.add(Cursor::new(a));
    body2.add(Cursor::new(b));

    assert_eq!(body2.len().unwrap(), 7);
    assert_eq!(&body2.read_all().unwrap()[..], b"abcdefg");
    body2.rewind().unwrap();
    assert_eq!(&body2.read_all().unwrap()[..], b"abcdefg");

    let mut body3 = Body::new();
    body3.add(Cursor::new(a));
    body3.add(Cursor::new(b));
    body3.add(Cursor::new(c));

    assert_eq!(body3.len().unwrap(), 13);
    assert_eq!(&body3.read_all().unwrap()[..], b"abcdefghijklm");
    body3.rewind().unwrap();
    assert_eq!(&body3.read_all().unwrap()[..], b"abcdefghijklm");
}

pub struct HttpRequest {
    url: Url,
    headers: Vec<(String, String)>,
    body: Body,
    follow_redirects: bool,
    token: Arc<GitHttpStateToken>,
    log_target: Option<String>,
}

#[derive(Debug)]
struct HttpResponseInfo {
    http_status: usize,
    redirected_to: Option<Url>,
    content_type: Option<String>,
}

#[derive(Debug)]
pub struct HttpResponse {
    info: HttpResponseInfo,
    thread: Option<JoinHandle<Result<(), (c_int, HttpRequest)>>>,
    cursor: Cursor<ImmutBString>,
    receiver: Option<Receiver<HttpRequestChannelData>>,
    #[allow(dead_code)]
    #[debug(skip)]
    token: Arc<GitHttpStateToken>,
}

type HttpRequestChannelData = Either<HttpResponseInfo, ImmutBString>;

struct HttpThreadData {
    sender: Sender<HttpRequestChannelData>,
    curl: *mut CURL,
    first: bool,
    logger: Option<LoggingWriter<'static, std::io::Sink>>,
}

unsafe extern "C" fn trace_log_callback(
    _curl: *const CURL,
    typ: curl_infotype,
    data: *const c_char,
    size: usize,
    context: *mut c_void,
) -> c_int {
    let target = (context as *const c_void as *const String)
        .as_ref()
        .unwrap();
    let direction = match typ {
        CURLINFO_HEADER_IN => logging::Direction::Receive,
        CURLINFO_HEADER_OUT => logging::Direction::Send,
        _ => return 0,
    };
    let data = std::slice::from_raw_parts(data as *const _, size);
    for line in data.lines() {
        trace!(target: target, "{} {}", direction, line.as_bstr());
    }
    0
}

impl HttpRequest {
    pub fn new(url: Url) -> Self {
        let token = GIT_HTTP_STATE.lock().unwrap().take(&url);
        HttpRequest {
            url,
            headers: Vec::new(),
            body: Body::new(),
            follow_redirects: false,
            token: Arc::new(token),
            log_target: None,
        }
    }

    pub fn set_log_target(&mut self, target: String) {
        self.log_target = log_enabled!(target: &target, log::Level::Trace).then_some(target);
    }

    pub fn follow_redirects(&mut self, enable: bool) {
        self.follow_redirects = enable;
    }

    fn header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn post_data(&mut self, data: impl ExactSizeReadRewind + Send + 'static) {
        self.body.add(data);
    }

    #[allow(clippy::result_large_err)]
    fn execute_once(mut self) -> Result<HttpResponse, (c_int, Self)> {
        let (sender, receiver) = channel::<HttpRequestChannelData>();
        let token = Arc::clone(&self.token);
        let thread = thread::Builder::new()
            .name("HTTP".into())
            .spawn(move || unsafe {
                let url = self.url.to_string();
                let url = CString::new(url).unwrap();
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
                    logger: self.log_target.as_ref().map(|log_target| {
                        let mut writer = LoggingWriter::new_hex(
                            log_target.clone(),
                            log::Level::Trace,
                            std::io::sink(),
                        );
                        writer.set_direction(logging::Direction::Receive);
                        writer
                    }),
                };
                curl_easy_setopt(slot.curl, CURLOPT_FILE, &mut data);
                curl_easy_setopt(
                    slot.curl,
                    CURLOPT_WRITEFUNCTION,
                    http_request_execute as *const c_void,
                );
                let mut headers = ptr::null_mut();
                if self.body.is_some() {
                    curl_easy_setopt(slot.curl, CURLOPT_POST, 1);
                    curl_easy_setopt(
                        slot.curl,
                        CURLOPT_POSTFIELDSIZE_LARGE,
                        self.body.len().unwrap(),
                    );
                    /* Ensure we have no state from a previous attempt that failed because
                     * of authentication (401). */
                    self.body.rewind().unwrap();
                    if let Some(log_target) = &self.log_target {
                        let body = mem::replace(&mut self.body, Body::None);
                        let mut reader =
                            LoggingReader::new_hex(log_target.clone(), log::Level::Trace, body);
                        reader.set_direction(logging::Direction::Send);
                        self.body.add(reader);
                    }
                    curl_easy_setopt(slot.curl, CURLOPT_READDATA, &mut self.body);
                    curl_easy_setopt(
                        slot.curl,
                        CURLOPT_READFUNCTION,
                        read_from_read::<Body> as *const c_void,
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
                    let header_line = CString::new(format!("{name}: {value}")).unwrap();
                    headers = curl_slist_append(headers, header_line.as_ptr());
                }
                curl_easy_setopt(slot.curl, CURLOPT_HTTPHEADER, headers);
                curl_easy_setopt(slot.curl, CURLOPT_ACCEPT_ENCODING, b"\0");

                // On old versions of Git for Windows, http.sslcainfo is set
                // and usefully points to the CA certs file, but on recent
                // versions, it is not set and the path is derived from the
                // exec path in the curl dll, but we don't use it, so do that
                // ourselves.
                // See https://github.com/git-for-windows/MINGW-packages/commit/2e8f4580eb4d
                if ssl_cainfo.is_null() && cfg!(windows) {
                    static CA_INFO_PATH: Lazy<PathBuf> = Lazy::new(|| {
                        let base_path = Path::new(
                            &std::env::var_os("GIT_EXEC_PATH")
                                .filter(|p| !p.is_empty())
                                .unwrap_or_else(|| {
                                    let output = std::process::Command::new("git")
                                        .arg("--exec-path")
                                        .stderr(std::process::Stdio::null())
                                        .output()
                                        .unwrap();
                                    assert!(output.status.success());
                                    OsStr::from_bytes(&output.stdout).into()
                                }),
                        )
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .to_path_buf();

                        let bundle_path =
                            |base: &Path| base.join("ssl").join("certs").join("ca-bundle.crt");

                        let path = bundle_path(&base_path);
                        if path.exists() {
                            path
                        } else {
                            bundle_path(&base_path.join("etc"))
                        }
                    });

                    let ca_info_path = CString::new(CA_INFO_PATH.as_os_str().as_bytes()).unwrap();
                    curl_easy_setopt(slot.curl, CURLOPT_CAINFO, ca_info_path.as_ptr());
                }
                if let Some(log_target) = &self.log_target {
                    curl_easy_setopt(slot.curl, CURLOPT_VERBOSE, 1);
                    curl_easy_setopt(
                        slot.curl,
                        CURLOPT_DEBUGFUNCTION,
                        trace_log_callback as *const c_void,
                    );
                    curl_easy_setopt(slot.curl, CURLOPT_DEBUGDATA, log_target as *const String);
                }
                let mut results = slot_results::new();
                let result = run_one_slot(slot, &mut results);
                curl_slist_free_all(headers);
                http_send_info(&mut data);
                if result == HTTP_OK {
                    Ok(())
                } else {
                    Err((result, self))
                }
            })
            .unwrap();

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
                    if let Some(log_target) = &this.log_target {
                        trace!(target: &log_target, "Request required reauthentication");
                    }
                    unsafe { credential_fill(the_repository, ptr::addr_of_mut!(http_auth), 1) };
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
                Err(_) => {
                    drop(self.receiver.take());
                    if let Some(thread) = self.thread.take() {
                        thread.join().unwrap().map_err(|_| {
                            io::Error::other(
                                unsafe { CStr::from_ptr(curl_errorstr.as_ptr()) }.to_string_lossy(),
                            )
                        })?;
                    }
                    Ok(0)
                }
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
            if data.logger.as_ref().map(LoggingWriter::log_target) == Some("raw-wire::capabilities")
            {
                match content_type.as_deref() {
                    Some("application/mercurial-0.1" | "application/mercurial-0.2") => {}
                    _ => {
                        // If the response to the capabilities request is a bundle, log in
                        // a different category.
                        // Ideally we'd log the headers too with the switched logger, but
                        // it's too late for that.
                        trace!(
                            target: "raw-wire::capabilities",
                            "Not a capabilities response; switching to clonebundle.",
                        );
                        if log_enabled!(target: "raw-wire::clonebundle", log::Level::Trace) {
                            let mut writer = LoggingWriter::new_hex(
                                "raw-wire::clonebundle".to_string(),
                                log::Level::Trace,
                                std::io::sink(),
                            );
                            writer.set_direction(logging::Direction::Receive);
                            data.logger = Some(writer);
                        }
                    }
                }
            }
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
    let buf = std::slice::from_raw_parts(ptr as *const _, size.checked_mul(nmemb).unwrap());
    if let Some(logger) = &mut data.logger {
        logger.write_all(buf).unwrap();
    }
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

        let httppostargs = self.get_capability(b"httppostargs").is_some()
            // Versions of mercurial >= 3.8 < 4.4 don't handle httppostargs
            // on commands that are already POST. We check for the `phases`
            // bundle2 capability, which was introduced in mercurial 4.4.
            && ((command != "unbundle" && command != "pushkey")
                || self
                    .get_capability(b"bundle2")
                    .unwrap_or(b"".as_bstr())
                    .split(|x| *x == b'\n')
                    .any(|x| x.starts_with(b"phases=")));

        let mut command_url = self.url.clone();
        let mut query_pairs = command_url.query_pairs_mut();
        query_pairs.append_pair("cmd", command);
        let mut headers = Vec::new();
        let mut body = None;

        if !args.is_empty() && (httppostargs || httpheader > 0) {
            let mut encoder = form_urlencoded::Serializer::new(String::new());
            for (name, value) in args.iter() {
                encoder.append_pair(name, &value.as_string());
            }
            let args = encoder.finish();
            if httppostargs {
                headers.push(("X-HgArgs-Post".to_string(), args.len().to_string()));
                headers.push((
                    "Content-Type".to_string(),
                    "application/mercurial-0.1".to_string(),
                ));
                body = Some(args);
            } else {
                let mut args = &args[..];
                let mut num = 1;
                while !args.is_empty() {
                    let header_name = format!("X-HgArg-{num}");
                    num += 1;
                    let (chunk, remainder) = args.split_at(cmp::min(
                        args.len(),
                        httpheader - header_name.len() - ": ".len(),
                    ));
                    headers.push((header_name, chunk.to_string()));
                    args = remainder;
                }
            }
        } else {
            for (name, value) in args.iter() {
                query_pairs.append_pair(name, &value.as_string());
            }
        }
        drop(query_pairs);

        let mut request = HttpRequest::new(command_url);
        request.set_log_target(format!("raw-wire::{command}"));
        if unsafe { http_follow_config } == http_follow_config::HTTP_FOLLOW_ALWAYS {
            request.follow_redirects(true);
        }

        request.header("Accept", "application/mercurial-0.1");
        for (name, value) in headers {
            request.header(&name, &value);
        }
        if let Some(body) = body {
            request.post_data(Cursor::new(body));
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
            http_req.post_data(Cursor::new(Vec::<u8>::new()));
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

    fn push_command(&mut self, input: File, command: &str, args: HgArgs) -> UnbundleResponse {
        let mut http_req = self.start_command_request(command, args);
        http_req.post_data(input);
        http_req.header("Content-Type", "application/mercurial-0.1");
        let mut http_resp = http_req.execute().unwrap();
        self.handle_redirect(&http_resp);
        let header = (&mut http_resp).take(4).read_all().unwrap();
        if &*header == b"HG20" {
            UnbundleResponse::Bundlev2(Box::new(Cursor::new(header).chain(http_resp)))
        } else {
            let stderr = stderr();
            let mut buf = header.to_vec();
            http_resp.read_to_end(&mut buf).unwrap();
            match buf.splitn_exact(b'\n') {
                Some([stdout_, stderr_]) => {
                    let mut writer = PrefixWriter::new("remote: ", stderr.lock());
                    writer.write_all(stderr_).unwrap();
                    UnbundleResponse::Raw(stdout_.to_boxed())
                }
                //TODO: better eror handling.
                _ => panic!("Bad output from server"),
            }
        }
    }
}

impl HgConnectionBase for HgHttpConnection {
    fn get_url(&self) -> Option<&Url> {
        Some(&self.url)
    }

    fn get_capability(&self, name: &[u8]) -> Option<&BStr> {
        self.capabilities.get_capability(name)
    }

    fn sample_size(&self) -> usize {
        if self.capabilities.get_capability(b"httppostargs").is_some() {
            10000
        } else {
            100
        }
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
    let buf = std::slice::from_raw_parts_mut(ptr as *mut _, size.checked_mul(nmemb).unwrap());
    read.read(buf).unwrap()
}

#[allow(clippy::unnecessary_wraps)]
pub fn get_http_connection(url: &Url) -> Option<Box<dyn HgRepo>> {
    let mut conn = HgHttpConnection {
        capabilities: HgCapabilities::default(),
        url: url.clone(),
    };

    /* The first request we send is a "capabilities" request. This sends to
     * the repo url with a query string "?cmd=capabilities". If the remote
     * url is not actually a repo, but a bundle, the content will start with
     * 'HG10' or 'HG20', which is not something that would appear as the first
     * four characters for the "capabilities" answer.
     * (Note this assumes HTTP servers serving bundles don't care about query
     * strings)
     */
    let mut http_req = conn.start_command_request("capabilities", args!());
    if unsafe { http_follow_config } == http_follow_config::HTTP_FOLLOW_INITIAL {
        http_req.follow_redirects(true);
    }
    let mut http_resp = http_req.execute().unwrap();
    conn.handle_redirect(&http_resp);
    match http_resp.content_type() {
        Some("application/mercurial-0.1" | "application/mercurial-0.2") => {
            let caps = http_resp.read_all().unwrap();
            drop(http_resp);
            conn.capabilities = HgCapabilities::new_from(&caps);
            Some(Box::new(HgWired::new(conn)))
        }
        _ => Some(Box::new(BundleConnection::new(
            HttpConnectionHoldingReader {
                reader: http_resp,
                conn,
            },
        ))),
    }
}
