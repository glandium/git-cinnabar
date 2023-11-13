/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cell::RefCell;
use std::cmp;
use std::io::{self, Write};
use std::num::NonZeroUsize;

use either::Either;
use lru::LruCache;

use crate::git::{git_oid_type, CommitId, MalformedTree, TreeId, TreeIsh};
use crate::hg::{HgFileAttr, HgFileId, ManifestEntry};
use crate::libgit::{die, FileMode, RawCommit, RawTree};
use crate::oid::ObjectId;
use crate::tree_util::{Empty, MayRecurse, ParseTree, RecurseAs, TreeIter, WithPath};

git_oid_type!(GitManifestId(CommitId));
git_oid_type!(GitManifestTreeId(TreeId));

impl TreeIsh for GitManifestTreeId {
    type TreeId = GitManifestTreeId;
    fn get_tree_id(self) -> Self::TreeId {
        self
    }
}

impl TreeIsh for GitManifestId {
    type TreeId = GitManifestTreeId;
    fn get_tree_id(self) -> Self::TreeId {
        let commit = RawCommit::read(self.into()).unwrap();
        let commit = commit.parse().unwrap();
        GitManifestTreeId::from_unchecked(commit.tree())
    }
}

#[derive(Clone)]
pub struct GitManifestTree(RawTree);

struct ManifestTreeCache {
    lru_cache: LruCache<GitManifestTreeId, GitManifestTree>,
    queries: usize,
    misses: usize,
}

impl ManifestTreeCache {
    fn new() -> Self {
        ManifestTreeCache {
            lru_cache: LruCache::unbounded(),
            queries: 0,
            misses: 0,
        }
    }

    fn try_get_or_insert<F: FnOnce() -> Result<GitManifestTree, E>, E>(
        &mut self,
        k: GitManifestTreeId,
        f: F,
    ) -> Result<GitManifestTree, E> {
        self.queries += 1;
        let result = self
            .lru_cache
            .try_get_or_insert(k, || {
                self.misses += 1;
                f()
            })
            .map(Clone::clone);
        let queries_limit = cmp::max(100, self.lru_cache.len() / 2);
        if self.queries >= queries_limit {
            let miss_rate = self.misses / (self.queries / 10);
            if (self.lru_cache.cap() == NonZeroUsize::MAX) || miss_rate >= 7 {
                self.lru_cache.resize(
                    NonZeroUsize::new(self.lru_cache.len() + self.lru_cache.len() / 2 + 1).unwrap(),
                );
            }
            debug!(
                target: "manifesttreecache",
                "cap: {}, len: {} ; {} misses in the last {} queries ({:.1}%)",
                self.lru_cache.cap(),
                self.lru_cache.len(),
                self.misses,
                self.queries,
                (self.misses as f64) * 100.0 / (self.queries as f64)
            );
            self.queries = 0;
            self.misses = 0;
        }
        result
    }
}

thread_local! {
    static MANIFEST_TREE_CACHE: RefCell<ManifestTreeCache> = RefCell::new(ManifestTreeCache::new());
}

impl GitManifestTree {
    pub const EMPTY: GitManifestTree = GitManifestTree(RawTree::EMPTY);

    pub fn read(oid: GitManifestTreeId) -> Option<GitManifestTree> {
        MANIFEST_TREE_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .try_get_or_insert(oid, || RawTree::read(oid.into()).map(Self).ok_or(()))
                .ok()
        })
    }

    pub fn read_treeish<T: TreeIsh<TreeId = GitManifestTreeId>>(t: T) -> Option<GitManifestTree> {
        GitManifestTree::read(t.get_tree_id())
    }
}

pub type GitManifestTreeEntry = Either<GitManifestTreeId, ManifestEntry>;

impl MayRecurse for GitManifestTreeEntry {
    fn may_recurse(&self) -> bool {
        self.is_left()
    }
}

impl AsRef<[u8]> for GitManifestTree {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Empty for GitManifestTree {
    fn empty() -> Self {
        GitManifestTree(RawTree::EMPTY)
    }
}

impl ParseTree for GitManifestTree {
    type Inner = GitManifestTreeEntry;
    type Error = MalformedTree;

    fn parse_one_entry(buf: &mut &[u8]) -> Result<WithPath<Self::Inner>, Self::Error> {
        let (path, item) = RawTree::parse_one_entry(buf)?.unzip();
        Ok(WithPath::new(
            &path[1..],
            item.map_left(GitManifestTreeId::from_unchecked)
                .map_right(|entry| ManifestEntry {
                    fid: HgFileId::from_raw_bytes(entry.oid.as_raw_bytes()).unwrap(),
                    attr: {
                        assert_eq!(entry.mode.typ(), FileMode::GITLINK);
                        match entry.mode.perms() {
                            FileMode::RW => HgFileAttr::Regular,
                            FileMode::RWX => HgFileAttr::Executable,
                            FileMode::NONE => HgFileAttr::Symlink,
                            _ => die!("Unexpected file mode"),
                        }
                    },
                }),
        ))
    }

    fn write_one_entry<W: Write>(_entry: &WithPath<Self::Inner>, _w: W) -> io::Result<()> {
        todo!()
    }
}

impl IntoIterator for GitManifestTree {
    type Item = WithPath<GitManifestTreeEntry>;
    type IntoIter = TreeIter<GitManifestTree>;

    fn into_iter(self) -> TreeIter<GitManifestTree> {
        TreeIter::new(self)
    }
}

impl RecurseAs<TreeIter<GitManifestTree>> for GitManifestTreeEntry {
    type NonRecursed = ManifestEntry;

    fn maybe_recurse(self) -> Either<TreeIter<GitManifestTree>, ManifestEntry> {
        self.map_left(|tree_id| GitManifestTree::read(tree_id).unwrap().into_iter())
    }
}
