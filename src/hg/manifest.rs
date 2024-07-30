/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{self, Write};

use bstr::{BStr, ByteSlice};

use super::{HgFileId, HgObjectId};
use crate::libgit::FileMode;
use crate::oid::oid_type;
use crate::store::RawHgManifest;
use crate::tree_util::{MayRecurse, ParseTree, TreeIter, WithPath};
use crate::util::{FromBytes, SliceExt};

oid_type!(HgManifestId(HgObjectId));

/// Information related to a file in a Mercurial manifest
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Object Id of the file.
    pub fid: HgFileId,
    /// File attribute (regular, executable or symbolic link).
    pub attr: HgFileAttr,
}

impl MayRecurse for ManifestEntry {
    fn may_recurse(&self) -> bool {
        false
    }
}

/// File attribute, as recorded in a Mercurial manifest
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HgFileAttr {
    /// Regular file. Corresponds to file mode 0644.
    Regular,
    /// Executable file. Corresponds to file mode 0755.
    Executable,
    /// Symbolic link. Corresponds to file mode 0120000.
    Symlink,
}

impl HgFileAttr {
    /// Returns the file attribute as it appears in raw form in a Mercurial manifest.
    pub fn as_bstr(&self) -> &'static BStr {
        match self {
            HgFileAttr::Regular => b"".as_bstr(),
            HgFileAttr::Executable => b"x".as_bstr(),
            HgFileAttr::Symlink => b"l".as_bstr(),
        }
    }
}

impl FromBytes for HgFileAttr {
    type Err = ();

    fn from_bytes(b: &[u8]) -> Result<Self, Self::Err> {
        match b {
            b"" => Ok(HgFileAttr::Regular),
            b"x" => Ok(HgFileAttr::Executable),
            b"l" => Ok(HgFileAttr::Symlink),
            _ => Err(()),
        }
    }
}

impl TryFrom<FileMode> for HgFileAttr {
    type Error = ();

    fn try_from(mode: FileMode) -> Result<Self, Self::Error> {
        match (mode.typ(), mode.perms()) {
            (FileMode::REGULAR, FileMode::RW) => Ok(HgFileAttr::Regular),
            (FileMode::REGULAR, FileMode::RWX) => Ok(HgFileAttr::Executable),
            (FileMode::SYMLINK, FileMode::NONE) => Ok(HgFileAttr::Symlink),
            _ => Err(()),
        }
    }
}

impl AsRef<[u8]> for RawHgManifest {
    fn as_ref(&self) -> &[u8] {
        (**self).as_ref()
    }
}

/// An error occurred while parsing the manifest.
#[derive(Debug)]
pub struct MalformedManifest;

impl ParseTree for RawHgManifest {
    type Inner = ManifestEntry;
    type Error = MalformedManifest;

    fn parse_one_entry(buf: &mut &[u8]) -> Result<WithPath<Self::Inner>, Self::Error> {
        (|| {
            let [path, remainder] = buf.splitn_exact(b'\0')?;
            let fid = HgFileId::from_bytes(&remainder[..40]).ok()?;
            let [mode, remainder] = remainder[40..].splitn_exact(b'\n')?;
            *buf = remainder;
            Some(WithPath::new(
                path,
                ManifestEntry {
                    fid,
                    attr: HgFileAttr::from_bytes(mode).ok()?,
                },
            ))
        })()
        .ok_or(MalformedManifest)
    }

    fn write_one_entry<W: Write>(entry: &WithPath<Self::Inner>, mut w: W) -> io::Result<()> {
        w.write_all(entry.path())?;
        w.write_all(b"\0")?;
        write!(w, "{}", entry.inner().fid)?;
        w.write_all(entry.inner().attr.as_bstr())?;
        w.write_all(b"\n")?;
        Ok(())
    }
}

impl IntoIterator for RawHgManifest {
    type Item = WithPath<ManifestEntry>;
    type IntoIter = TreeIter<RawHgManifest>;

    fn into_iter(self) -> TreeIter<RawHgManifest> {
        TreeIter::new(self)
    }
}
