/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::{
    iter::Enumerate,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use crate::{check_enabled, Checks};

static PROGRESS_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn progress_enabled() -> bool {
    PROGRESS_ENABLED.load(Ordering::Relaxed)
}

pub fn set_progress(value: bool) {
    PROGRESS_ENABLED.store(value, Ordering::Relaxed);
}

pub trait Progress: Iterator + Sized {
    fn progress<F: Fn(usize) -> String>(self, formatter: F) -> ProgressIter<Self, F>;
}

enum ProgressIterImpl<I: Iterator, F: Fn(usize) -> String> {
    Enabled(ProgressIterEnabled<I, F>),
    Disabled(I),
}

struct ProgressIterEnabled<I: Iterator, F: Fn(usize) -> String> {
    iter: Enumerate<I>,
    formatter: F,
    start: Option<Instant>,
    last_update: Instant,
    count: usize,
}

pub struct ProgressIter<I: Iterator, F: Fn(usize) -> String>(ProgressIterImpl<I, F>);

impl<I: Iterator> Progress for I {
    fn progress<F: Fn(usize) -> String>(self, formatter: F) -> ProgressIter<Self, F> {
        if PROGRESS_ENABLED.load(Ordering::Relaxed) {
            let now = Instant::now();

            let this = ProgressIterEnabled {
                iter: self.enumerate(),
                formatter,
                start: check_enabled(Checks::TIME).then(|| now),
                last_update: now,
                count: 0,
            };
            ProgressIter(ProgressIterImpl::Enabled(this))
        } else {
            ProgressIter(ProgressIterImpl::Disabled(self))
        }
    }
}

impl<I: Iterator, F: Fn(usize) -> String> ProgressIterEnabled<I, F> {
    #[inline]
    fn display(&mut self, now: Instant) {
        let s = (self.formatter)(self.count);
        if let Some(start) = self.start {
            eprint!("\r{} in {:.1}s", s, (now - start).as_secs_f32());
        } else {
            eprint!("\r{}", s);
        }
        self.last_update = now;
    }
}

impl<I: Iterator, F: Fn(usize) -> String> Drop for ProgressIterEnabled<I, F> {
    fn drop(&mut self) {
        if self.count > 0 {
            self.display(Instant::now());
            eprintln!();
        }
    }
}

impl<I: Iterator, F: Fn(usize) -> String> Iterator for ProgressIterEnabled<I, F> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(n, item)| {
            let now = Instant::now();
            self.count = n + 1;
            if (now - self.last_update).as_millis() > 100 {
                self.display(now);
            }
            item
        })
    }
}

impl<I: Iterator, F: Fn(usize) -> String> Iterator for ProgressIter<I, F> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            ProgressIterImpl::Enabled(p) => p.next(),
            ProgressIterImpl::Disabled(i) => i.next(),
        }
    }
}
