/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::{self, Debug, Display, Write as _};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use bstr::ByteSlice;
use log::LevelFilter;

use crate::get_config;
use crate::util::{ExactSizeReadRewind, FromBytes, OsStrExt};

pub fn init(start_time: Instant) {
    let logger = CinnabarLogger::new(start_time);
    let max_log_level = logger.max_log_level();
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(max_log_level);
    }
}

#[derive(Debug)]
enum LoggerOutput {
    StdErr,
    File(Mutex<File>),
    FileAndStdErr(Mutex<File>),
}

impl LoggerOutput {
    fn with_stderr(self) -> Self {
        match self {
            LoggerOutput::File(f) => LoggerOutput::FileAndStdErr(f),
            x => x,
        }
    }
}

impl Write for &LoggerOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            LoggerOutput::StdErr => std::io::stderr().write(buf),
            LoggerOutput::File(f) => f.lock().unwrap().write(buf),
            LoggerOutput::FileAndStdErr(f) => {
                match (std::io::stderr().write(buf), f.lock().unwrap().write(buf)) {
                    (Ok(n), Ok(m)) if n == m => Ok(n),
                    (Ok(n), Ok(m)) => Ok(std::cmp::min(n, m)), // Not ideal but better than nothing.
                    (a, b) => b.or(a),
                }
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            LoggerOutput::StdErr => std::io::stderr().flush(),
            LoggerOutput::File(f) => f.lock().unwrap().flush(),
            LoggerOutput::FileAndStdErr(f) => {
                match (std::io::stderr().flush(), f.lock().unwrap().flush()) {
                    (Ok(()), Ok(())) => Ok(()),
                    (a, b) => b.or(a),
                }
            }
        }
    }
}

struct LevelPrinter(log::Level);

impl Display for LevelPrinter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            log::Level::Warn => f.write_str("WARNING"),
            level => Display::fmt(&level, f),
        }
    }
}

struct TargetMap<T: Copy>(HashMap<String, T>);

impl<T: Copy> TargetMap<T> {
    fn new() -> Self {
        TargetMap(HashMap::new())
    }

    fn get(&self, key: &str) -> Option<T> {
        self.0.get(key).copied().or_else(|| {
            key.rsplit_once("::")
                .and_then(|(parent, _)| self.get(parent))
        })
    }

    fn insert(&mut self, key: &str, value: T) -> Option<T> {
        self.0.insert(key.to_string(), value)
    }

    fn values(&self) -> impl Iterator<Item = T> + '_ {
        self.0.values().copied()
    }

    fn iter(&self) -> impl Iterator<Item = (&str, T)> {
        self.0.iter().map(|(k, v)| (&**k, *v))
    }
}

#[test]
fn test_target_map() {
    let mut map = TargetMap::new();
    map.insert("foo", 1);
    map.insert("bar", 2);
    map.insert("foo::qux", 3);
    map.insert("foo::hoge", 0);

    assert_eq!(map.get("foo"), Some(1));
    assert_eq!(map.get("bar"), Some(2));
    assert_eq!(map.get("foo::qux"), Some(3));
    assert_eq!(map.get("foo::hoge"), Some(0));
    assert_eq!(map.get("foo::qux::deep"), map.get("foo::qux"));
    assert_eq!(map.get("foo::hoge::deep"), map.get("foo::hoge"));
    assert_eq!(map.get("foo::baz"), map.get("foo"));
    assert_eq!(map.get("foo::baz::deep"), map.get("foo"));
    assert_eq!(map.get("baz"), None);
    assert_eq!(map.get("baz::fuga"), None);
    assert_eq!(map.get("baz::fuga::deep"), None);
}

impl<T: Copy + Debug> Debug for TargetMap<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

#[derive(Debug)]
struct CinnabarLogger {
    level_by_target: TargetMap<LevelFilter>,
    default_level: LevelFilter,
    output_by_target: TargetMap<usize>,
    outputs: Vec<LoggerOutput>,
    start_time: Instant,
}

impl CinnabarLogger {
    fn new(start_time: Instant) -> Self {
        let mut level_by_target = TargetMap::new();
        let mut output_by_target = TargetMap::new();
        let mut outputs = vec![LoggerOutput::StdErr];
        let mut output_by_path = HashMap::new();
        let mut default_level = LevelFilter::Warn;

        // Initialize logging from the GIT_CINNABAR_LOG environment variable
        // or the cinnabar.log configuration, the former taking precedence.
        if let Some(config) = get_config("log") {
            for item in config.as_bytes().split(|&b| b == b',') {
                let mut iter = item.splitn(2, |&b| b == b'>');
                let assignment = iter.next().unwrap();
                let path = iter.next();
                let mut iter = assignment.rsplitn(2, |&b| b == b':');
                let (target, level) = match (iter.next().unwrap(), iter.next()) {
                    // For cases where we have `foo::bar`
                    (_, Some(b)) if b.ends_with(b":") => (assignment, None),
                    (a, Some(b)) => (b, Some(a)),
                    (a, None) => (a, None),
                };
                let target = match std::str::from_utf8(target) {
                    Ok("*") => "",
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let level = level.and_then(|l| {
                    u8::from_bytes(l)
                        .map(|l| match l {
                            0 => LevelFilter::Off,
                            1 => LevelFilter::Error,
                            2 => LevelFilter::Warn,
                            3 => LevelFilter::Info,
                            4 => LevelFilter::Debug,
                            5.. => LevelFilter::Trace,
                        })
                        .or_else(|_| LevelFilter::from_bytes(l))
                        .ok()
                });
                if let Some(level) = level {
                    if target.is_empty() {
                        default_level = level;
                    } else {
                        level_by_target.insert(target, level);
                    }
                }
                if let Some(path) = path {
                    let path = Path::new(OsStr::from_bytes(path));
                    let index = if let Some(index) = output_by_path.get(path) {
                        Some(*index)
                    } else if let Some(output) = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(path)
                        .ok()
                        .map(|f| LoggerOutput::File(Mutex::new(f)))
                    {
                        let index = if target.is_empty() { 0 } else { outputs.len() };
                        output_by_path.insert(path.to_path_buf(), index);
                        if index == 0 {
                            outputs[0] = output.with_stderr();
                            None
                        } else {
                            outputs.push(output);
                            Some(index)
                        }
                    } else {
                        None
                    };
                    if let Some(index) = index {
                        output_by_target.insert(target, index);
                    }
                }
            }
        }
        CinnabarLogger {
            level_by_target,
            default_level,
            output_by_target,
            outputs,
            start_time,
        }
    }

    fn max_log_level(&self) -> LevelFilter {
        std::cmp::max(
            self.level_by_target
                .values()
                .max()
                .unwrap_or(self.default_level),
            self.default_level,
        )
    }
}

impl log::Log for CinnabarLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let target = metadata.target();
        let level = metadata.level();
        if let Some(target) = target.strip_suffix('*') {
            self.level_by_target
                .iter()
                .filter_map(|(k, v)| k.starts_with(target).then_some(v))
                .any(|lvl| level <= lvl)
        } else {
            level
                <= self
                    .level_by_target
                    .get(target)
                    .unwrap_or(self.default_level)
        }
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let index = self.output_by_target.get(record.target()).unwrap_or(0);
            if let Some(mut output) = self.outputs.get(index) {
                let mut line = vec![b'\r'];
                if record.level() > log::Level::Warn {
                    write!(line, "{:.3} ", self.start_time.elapsed().as_secs_f32()).ok();
                }
                write!(line, "{} ", LevelPrinter(record.level())).ok();
                if record.target() != "root" {
                    write!(line, "[{}] ", record.target()).ok();
                }
                writeln!(line, "{}", record.args()).ok();
                output.write_all(&line).ok();
            }
        }
    }

    fn flush(&self) {
        for mut out in self.outputs.iter() {
            out.flush().ok();
        }
    }
}

pub fn max_log_level(target: &str, min_level: log::Level) -> log::LevelFilter {
    let mut result = log::LevelFilter::Off;
    let mut iter = log::LevelFilter::iter().skip(min_level as usize).peekable();
    loop {
        if let Some(level) = iter.peek() {
            if log_enabled!(target: target, level.to_level().unwrap()) {
                result = iter.next().unwrap();
                continue;
            }
        }
        return result;
    }
}

pub enum Direction {
    Send,
    Receive,
}

impl Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Direction::Send => "=>",
            Direction::Receive => "<=",
        })
    }
}

struct LoggingHelper<'a> {
    target: Cow<'a, str>,
    level: Option<log::Level>,
    hex: Option<u64>,
    direction: Direction,
}

impl<'a> LoggingHelper<'a> {
    fn new(
        target: impl Into<Cow<'a, str>>,
        level: log::Level,
        direction: Direction,
        hex: bool,
    ) -> Self {
        let target = target.into();
        let level = log_enabled!(target: &*target, level).then_some(level);
        let hex = hex.then_some(0);
        LoggingHelper {
            target,
            level,
            hex,
            direction,
        }
    }

    fn log(&mut self, buf: &[u8]) {
        if let Some(level) = self.level {
            if let Some(offset) = &mut self.hex {
                let mut line = String::with_capacity(81);
                if *offset > 0 {
                    log!(target: &*self.target, level, "   --------");
                }
                for ofs in ((*offset - *offset % 16)..*offset + buf.len() as u64).step_by(16) {
                    line.clear();
                    write!(line, "{} {:08x}  ", self.direction, ofs).unwrap();
                    for n in 0..16 {
                        if n == 8 {
                            line.push(' ');
                        }
                        if n < (*offset).saturating_sub(ofs) {
                            line.push_str(".. ");
                        } else if let Some(c) = buf.get(usize::try_from(ofs + n - *offset).unwrap())
                        {
                            write!(line, "{c:02x} ").unwrap();
                        } else {
                            line.push_str("   ");
                        }
                    }
                    line.push_str(" |");
                    for n in 0..16 {
                        if n < (*offset).saturating_sub(ofs) {
                            line.push(' ');
                        } else if let Some(c) = buf.get(usize::try_from(ofs + n - *offset).unwrap())
                        {
                            if *c >= 0x20 && *c < 0x7f {
                                line.push(*c as char);
                            } else {
                                line.push('.');
                            }
                        } else {
                            line.push(' ');
                        }
                    }
                    line.push('|');
                    log!(target: &*self.target, level, "{line}");
                }
                *offset += buf.len() as u64;
            } else {
                log!(target: &*self.target, level, "{} {:?}", self.direction, buf.as_bstr());
            }
        }
    }
}

pub struct LoggingReader<'a, R: Read> {
    log: LoggingHelper<'a>,
    reader: R,
}

impl<'a, R: Read> LoggingReader<'a, R> {
    pub fn new(target: impl Into<Cow<'a, str>>, level: log::Level, r: R) -> Self {
        LoggingReader {
            log: LoggingHelper::new(target, level, Direction::Receive, false),
            reader: r,
        }
    }

    pub fn new_hex(target: impl Into<Cow<'a, str>>, level: log::Level, r: R) -> Self {
        LoggingReader {
            log: LoggingHelper::new(target, level, Direction::Receive, true),
            reader: r,
        }
    }

    pub fn set_direction(&mut self, direction: Direction) {
        self.log.direction = direction;
    }
}

impl<R: Read> Read for LoggingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf).map(|l| {
            self.log.log(&buf[..l]);
            l
        })
    }
}

impl<R: BufRead> BufRead for LoggingReader<'_, R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt);
    }

    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.reader.read_until(byte, buf).map(|l| {
            self.log.log(&buf[buf.len() - l..]);
            l
        })
    }

    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.reader.read_line(buf).map(|l| {
            self.log.log(buf.as_bytes());
            l
        })
    }
}

impl<R: ExactSizeReadRewind> ExactSizeReadRewind for LoggingReader<'_, R> {
    fn len(&self) -> std::io::Result<u64> {
        self.reader.len()
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.reader.rewind()
    }
}

pub struct LoggingWriter<'a, W: Write> {
    log: LoggingHelper<'a>,
    writer: W,
}

impl<'a, W: Write> LoggingWriter<'a, W> {
    pub fn new(target: impl Into<Cow<'a, str>>, level: log::Level, w: W) -> Self {
        LoggingWriter {
            log: LoggingHelper::new(target, level, Direction::Send, false),
            writer: w,
        }
    }

    pub fn new_hex(target: impl Into<Cow<'a, str>>, level: log::Level, w: W) -> Self {
        LoggingWriter {
            log: LoggingHelper::new(target, level, Direction::Send, true),
            writer: w,
        }
    }

    pub fn set_direction(&mut self, direction: Direction) {
        self.log.direction = direction;
    }

    pub fn log_target(&self) -> &str {
        &self.log.target
    }
}

impl<W: Write> Write for LoggingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf).map(|l| {
            self.log.log(&buf[..l]);
            l
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
