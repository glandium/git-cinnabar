/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use bstr::ByteSlice;
use log::LevelFilter;

use crate::get_config;
use crate::util::{FromBytes, OsStrExt};

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            log::Level::Warn => f.write_str("WARNING"),
            level => level.fmt(f),
        }
    }
}

#[derive(Debug)]
struct CinnabarLogger {
    level_by_target: HashMap<String, LevelFilter>,
    default_level: LevelFilter,
    output_by_target: HashMap<String, usize>,
    outputs: Vec<LoggerOutput>,
    start_time: Instant,
}

impl CinnabarLogger {
    fn new(start_time: Instant) -> Self {
        let mut level_by_target = HashMap::new();
        let mut output_by_target = HashMap::new();
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
                let level = level.and_then(|l| u8::from_bytes(l).ok()).map(|l| match l {
                    0 => LevelFilter::Off,
                    1 => LevelFilter::Error,
                    2 => LevelFilter::Warn,
                    3 => LevelFilter::Info,
                    4 => LevelFilter::Debug,
                    5.. => LevelFilter::Trace,
                });
                if let Some(level) = level {
                    if target.is_empty() {
                        default_level = level;
                    } else {
                        level_by_target.insert(target.to_string(), level);
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
                        output_by_target.insert(target.to_string(), index);
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
                .copied()
                .unwrap_or(self.default_level),
            self.default_level,
        )
    }
}

impl log::Log for CinnabarLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level()
            <= self
                .level_by_target
                .get(metadata.target())
                .copied()
                .unwrap_or(self.default_level)
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let index = self
                .output_by_target
                .get(record.target())
                .copied()
                .unwrap_or(0);
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

pub struct LoggingBufReader<'a, R: BufRead> {
    target: &'a str,
    level: log::Level,
    reader: R,
}

impl<'a, R: BufRead> LoggingBufReader<'a, R> {
    pub fn new(target: &'a str, level: log::Level, r: R) -> Self {
        LoggingBufReader {
            target,
            level,
            reader: r,
        }
    }
}

impl<'a, R: BufRead> Read for LoggingBufReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf).map(|l| {
            log!(target: self.target, self.level, "<= {:?}", buf[..l].as_bstr());
            l
        })
    }
}

impl<'a, R: BufRead> BufRead for LoggingBufReader<'a, R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt);
    }

    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.reader.read_until(byte, buf).map(|l| {
            log!(target: self.target, self.level, "<= {:?}", buf[buf.len() - l..].as_bstr());
            l
        })
    }

    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.reader.read_line(buf).map(|l| {
            log!(target: self.target, self.level, "<= {:?}", buf);
            l
        })
    }
}

pub struct LoggingReader<'a, R: Read> {
    target: &'a str,
    level: log::Level,
    reader: R,
}

impl<'a, R: Read> LoggingReader<'a, R> {
    #[allow(dead_code)]
    pub fn new(target: &'a str, level: log::Level, r: R) -> Self {
        LoggingReader {
            target,
            level,
            reader: r,
        }
    }
}

impl<'a, R: Read> Read for LoggingReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf).map(|l| {
            log!(target: self.target, self.level, "<= {:?}", buf[..l].as_bstr());
            l
        })
    }
}

pub struct LoggingWriter<'a, W: Write> {
    target: &'a str,
    level: log::Level,
    writer: W,
}

impl<'a, W: Write> LoggingWriter<'a, W> {
    pub fn new(target: &'a str, level: log::Level, w: W) -> Self {
        LoggingWriter {
            target,
            level,
            writer: w,
        }
    }
}

impl<'a, W: Write> Write for LoggingWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf).map(|l| {
            log!(target: self.target, self.level, "=> {:?}", buf[..l].as_bstr());
            l
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
