/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::BTreeMap;
use std::os::raw::c_uint;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use bstr::ByteSlice;

use crate::cinnabar::GitChangesetId;
use crate::git::{CommitId, RawCommit, TreeId};
use crate::hg::HgChangesetId;
use crate::hg_data::{GitAuthorship, HgAuthorship};
use crate::libgit::{lookup_replace_commit, rev_list};
use crate::progress::Progress;
use crate::store::{has_metadata, GeneratedGitChangesetMetadata, RawHgChangeset, Store};

extern "C" {
    fn replace_map_size() -> c_uint;
    pub fn replace_map_tablesize() -> c_uint;
}

pub fn grafted() -> bool {
    unsafe { replace_map_size() != 0 }
}

static DID_SOMETHING: AtomicBool = AtomicBool::new(false);

static GRAFT_TREES: Mutex<BTreeMap<TreeId, Vec<CommitId>>> = Mutex::new(BTreeMap::new());

pub fn graft_finish() -> Option<bool> {
    if GRAFT_TREES.lock().unwrap().is_empty() {
        None
    } else {
        Some(grafted() || DID_SOMETHING.load(Ordering::Relaxed))
    }
}

pub fn init_graft(store: &Store) {
    let mut args = vec![
        "--full-history",
        "--exclude=refs/cinnabar/*",
        "--exclude=refs/notes/cinnabar",
        "--exclude=refs/original/*",
        "--all",
    ];
    if has_metadata(store) {
        args.push("--not");
        args.push("refs/cinnabar/metadata^");
    }
    let mut graft_trees = GRAFT_TREES.lock().unwrap();
    for cid in rev_list(&args).progress(|n| format!("Reading {} graft candidates", n)) {
        let c = RawCommit::read(cid).unwrap();
        let c = c.parse().unwrap();
        let cids_for_tree = graft_trees.entry(c.tree()).or_default();
        cids_for_tree.push(cid);
    }
}

#[derive(Debug)]
pub enum GraftError {
    Ambiguous(Box<[CommitId]>),
    NoGraft,
}

pub fn graft(
    store: &Store,
    changeset_id: HgChangesetId,
    raw_changeset: &RawHgChangeset,
    tree: TreeId,
    parents: &[GitChangesetId],
) -> Result<Option<CommitId>, GraftError> {
    let mut graft_trees = GRAFT_TREES.lock().unwrap();
    if graft_trees.is_empty() {
        return Ok(None);
    }

    let changeset = raw_changeset.parse().unwrap();
    let graft_trees_entry = graft_trees.get_mut(&tree).ok_or(GraftError::NoGraft)?;
    let candidates = graft_trees_entry
        .iter()
        .map(|&c| {
            let raw = RawCommit::read(c).unwrap();
            (c, raw)
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
                .copied()
                .zip(parents.iter().copied())
                .all(|(commit_parent, changeset_parent)| {
                    lookup_replace_commit(commit_parent)
                        == lookup_replace_commit(changeset_parent.into())
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
            GeneratedGitChangesetMetadata::generate(store, c, changeset_id, raw_changeset)
                .unwrap()
                .patch()
                .is_some()
        });
    }

    match candidates.len() {
        1 => {
            let (commit, _) = candidates[0];
            graft_trees_entry.retain(|c| c != *commit);
            DID_SOMETHING.store(true, Ordering::Relaxed);
            Ok(Some(*(*commit)))
        }
        0 => Err(GraftError::NoGraft),
        _ => Err(GraftError::Ambiguous(
            candidates
                .into_iter()
                .map(|(cid, _)| *(*cid))
                .collect::<Vec<_>>()
                .into(),
        )),
    }
}
