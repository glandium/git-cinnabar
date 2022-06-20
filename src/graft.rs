/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{BufRead, Write};
use std::os::raw::{c_int, c_uint};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use bstr::ByteSlice;
use once_cell::sync::Lazy;

use crate::hg_data::{GitAuthorship, HgAuthorship};
use crate::libgit::{
    lookup_replace_commit, object_id, rev_list, strbuf, BlobId, CommitId, RawCommit, TreeId,
};
use crate::oid::{GitObjectId, ObjectId};
use crate::progress::Progress;
use crate::store::{
    store_git_blob, GeneratedGitChangesetMetadata, GitChangesetId, GitChangesetMetadataId,
    HgChangesetId, RawHgChangeset,
};
use crate::util::{FromBytes, ReadExt};

extern "C" {
    static metadata_flags: c_int;

    fn replace_map_size() -> c_uint;
}

fn has_metadata() -> bool {
    unsafe { metadata_flags != 0 }
}

fn grafted() -> bool {
    unsafe { replace_map_size() != 0 }
}

static DID_SOMETHING: AtomicBool = AtomicBool::new(false);

static GRAFT_TREES: Lazy<Mutex<BTreeMap<TreeId, Vec<CommitId>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn do_graft(input: &mut dyn BufRead, mut output: impl Write, args: &[&[u8]]) {
    match args.split_first() {
        Some((&b"init", args)) => do_init(args),
        Some((&b"changeset", args)) => do_changeset(input, output, args),
        Some((&b"finish", &[])) => {
            if grafted() || DID_SOMETHING.load(Ordering::Relaxed) {
                writeln!(output, "ok").unwrap();
            } else {
                writeln!(output, "ko").unwrap();
            }
        }
        Some((cmd, _)) => die!("unknown graft subcommand: {}", cmd.as_bstr()),
        None => die!("graft expects a subcommand"),
    }
}

fn do_init(args: &[&[u8]]) {
    if !args.is_empty() {
        die!("graft init takes no argument");
    }
    let mut args = vec![
        OsStr::new("--full-history"),
        OsStr::new("--exclude=refs/cinnabar/*"),
        OsStr::new("--exclude=refs/notes/cinnabar"),
        OsStr::new("--exclude=refs/original/*"),
        OsStr::new("--all"),
    ];
    if has_metadata() {
        args.push(OsStr::new("--not"));
        args.push(OsStr::new("refs/cinnabar/metadata^"));
    }
    let mut graft_trees = GRAFT_TREES.lock().unwrap();
    for cid in rev_list(&args).progress(|n| format!("Reading {} graft candidates", n)) {
        let c = RawCommit::read(&cid).unwrap();
        let c = c.parse().unwrap();
        let cids_for_tree = graft_trees.entry(c.tree().clone()).or_insert(Vec::new());
        cids_for_tree.push(cid);
    }
}

#[derive(Debug)]
enum GraftError {
    Ambiguous(Box<[CommitId]>),
    NoGraft,
}

fn graft(
    changeset_id: &HgChangesetId,
    raw_changeset: &RawHgChangeset,
    tree: &TreeId,
    parents: &[GitChangesetId],
) -> Result<CommitId, GraftError> {
    let changeset = raw_changeset.parse().unwrap();
    let mut graft_trees = GRAFT_TREES.lock().unwrap();
    let graft_trees_entry = graft_trees.get_mut(tree).ok_or(GraftError::NoGraft)?;
    let candidates = graft_trees_entry
        .iter()
        .map(|c| {
            let raw = RawCommit::read(c).unwrap();
            (c.clone(), raw)
        })
        .collect::<Vec<_>>();
    let candidates = candidates
        .iter()
        .map(|(cid, c)| (cid, c.parse().unwrap()))
        .filter(|(_, c)| {
            if &*HgAuthorship::from(GitAuthorship(c.author())).timestamp != changeset.timestamp() {
                return false;
            }
            if c.parents()
                .iter()
                .zip(parents)
                .all(|(commit_parent, changeset_parent)| {
                    lookup_replace_commit(commit_parent) == lookup_replace_commit(changeset_parent)
                })
            {
                return true;
            }
            // Allow to graft if not already grafted.
            !grafted()
        })
        .collect::<Vec<_>>();
    let mut candidates = candidates.iter().collect::<Vec<_>>();

    if candidates.len() > 1 {
        // Ideally, this should all be tried with fuzziness, and
        // independently of the number of nodes we got, but the
        // following is enough to graft github.com/mozilla/gecko-dev
        // to mozilla-central and related repositories.
        // Try with commits with the same subject line
        let cs_subject = ByteSlice::lines(changeset.body()).next();
        let mut possible_candidates = candidates.clone();
        possible_candidates.retain(|(_, c)| ByteSlice::lines(c.body()).next() == cs_subject);
        if possible_candidates.len() > 1 {
            // Try with commits with the same author ; this is attempted
            // separately from checking timestamps because author may
            // have been munged.
            possible_candidates.retain(|(_, c)| {
                &*HgAuthorship::from(GitAuthorship(c.author())).author == changeset.author()
            });
        }
        if possible_candidates.len() == 1 {
            candidates = possible_candidates;
        }
    }

    // If we still have multiple nodes, check if one of them is one that
    // cinnabar would have created. If it is, we prefer other commits on
    // the premise that it means we've been asked to reclone with a graft.
    // on a repo that was already handled by cinnabar.
    if candidates.len() > 1 {
        candidates.retain(|(_, c)| {
            GeneratedGitChangesetMetadata::generate(c, changeset_id, raw_changeset)
                .unwrap()
                .patch()
                .is_some()
        });
    }

    match candidates.len() {
        1 => {
            let (commit, _) = candidates[0];
            graft_trees_entry.retain(|c| c != *commit);
            Ok((*commit).clone())
        }
        0 => Err(GraftError::NoGraft),
        _ => Err(GraftError::Ambiguous(
            candidates
                .into_iter()
                .map(|(cid, _)| (*cid).clone())
                .collect::<Vec<_>>()
                .into(),
        )),
    }
}

fn do_changeset(mut input: &mut dyn BufRead, mut output: impl Write, args: &[&[u8]]) {
    if args.len() < 3 || args.len() > 5 {
        die!("graft changeset takes between 3 and 5 arguments");
    }
    let node = HgChangesetId::from_bytes(args[0]).unwrap();
    let tree = TreeId::from_bytes(args[1]).unwrap();
    let parents = &args[2..args.len() - 1]
        .iter()
        .map(|p| HgChangesetId::from_bytes(p).unwrap().to_git().unwrap())
        .collect::<Vec<_>>();
    let size = usize::from_bytes(args[args.len() - 1]).unwrap();
    let buf = input.read_exactly(size).unwrap();
    let changeset = RawHgChangeset(buf);

    match graft(&node, &changeset, &tree, parents) {
        Ok(commit) => {
            DID_SOMETHING.store(true, Ordering::Relaxed);
            let metadata = GeneratedGitChangesetMetadata::generate(
                &RawCommit::read(&commit).unwrap().parse().unwrap(),
                &node,
                &changeset,
            )
            .unwrap();
            if !grafted() && metadata.patch().is_some() {
                writeln!(output, "{} transition", commit)
            } else {
                let mut buf = strbuf::new();
                buf.extend_from_slice(&metadata.serialize());
                let mut metadata_oid = object_id::default();
                unsafe {
                    store_git_blob(&buf, &mut metadata_oid);
                }
                let metadata_id = unsafe {
                    GitChangesetMetadataId::from_unchecked(BlobId::from_unchecked(
                        GitObjectId::from(metadata_oid),
                    ))
                };
                writeln!(output, "{} {}", commit, metadata_id)
            }
        }
        Err(GraftError::NoGraft) => writeln!(output, "{} {}", CommitId::null(), CommitId::null()),
        Err(GraftError::Ambiguous(candidates)) => writeln!(
            output,
            "ambiguous {}",
            itertools::join(candidates.iter(), " ")
        ),
    }
    .ok();
}
