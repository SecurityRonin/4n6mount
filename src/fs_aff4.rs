#![forbid(unsafe_code)]
//! AFF4-Logical (`aff4:FileImage`) mount — `aff4` feature.
//!
//! An AFF4-Logical container is a collection of files (not a disk image), so it
//! mounts like AD1: entries are enumerated at open into a synthetic inode tree
//! ([`crate::archive_tree::ArchiveTree`]) and bytes are read on FUSE/Dokan
//! access via [`aff4::LogicalContainer::read_file`]. Read-only; encrypted
//! containers are refused at open (decryption needs a password).
//!
//! AFF4 *disk* images are a different shape — a `Read + Seek` stream whose inner
//! filesystem is mounted via `build_filesystem` (wired in `main.rs`), not here.

use std::path::Path;

use aff4::LogicalContainer;

use crate::archive_tree::ArchiveTree;
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};

/// A read-only view over an AFF4-Logical file collection.
pub struct Aff4ForensicFs {
    container: LogicalContainer,
    tree: ArchiveTree,
}

impl Aff4ForensicFs {
    /// Open an AFF4-Logical container by path. Returns a `NotSupported` error
    /// for encrypted containers (decryption needs a password).
    pub fn open(path: &Path) -> Result<Self, FsError> {
        let container = LogicalContainer::open(path).map_err(map_err)?;
        let mut tree = ArchiveTree::new();
        for (idx, e) in container.files().iter().enumerate() {
            // original_file_name is slash-separated and often prefixed "./".
            // ArchiveTree synthesises any missing parent directories.
            let rel = e.original_file_name.trim_start_matches("./");
            tree.insert(
                rel,
                false,
                e.size,
                FsTimestamp {
                    seconds: 0,
                    nanoseconds: 0,
                },
                Some(idx),
            );
        }
        Ok(Self { container, tree })
    }

    /// Read `len` bytes at `offset` from the file at `ino`. AFF4-Logical has no
    /// positioned read, so the whole file is inflated and the window sliced.
    fn read_range(&mut self, ino: u64, offset: u64, len: usize) -> FsResult<Vec<u8>> {
        let idx = self
            .tree
            .payload_id(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino} is not a readable file")))?;
        // Clone the small entry to release the immutable borrow before the
        // mutable read_file call.
        let entry = self.container.files()[idx].clone();
        let data = self.container.read_file(&entry).map_err(map_err)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len).min(data.len());
        Ok(data[start..end].to_vec())
    }
}

impl ForensicFs for Aff4ForensicFs {
    fn root_ino(&self) -> u64 {
        self.tree.root_ino()
    }
    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        self.tree.read_dir(ino)
    }
    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        self.tree.lookup(parent_ino, name)
    }
    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        self.tree.metadata(ino)
    }
    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let size = self.metadata(ino)?.size;
        self.read_range(ino, 0, size as usize)
    }
    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        self.read_range(ino, offset, len as usize)
    }
    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("aff4: symlinks are not surfaced"))
    }
    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({ "type": "aff4-logical", "entries": self.container.files().len() }))
    }
}

/// Map an `aff4::Aff4Error` onto 4n6mount's `FsError`.
fn map_err(e: aff4::Aff4Error) -> FsError {
    match e {
        aff4::Aff4Error::Io(io) => FsError::Io(io),
        aff4::Aff4Error::Encrypted(m) => FsError::NotSupported(format!("aff4: {m}")),
        aff4::Aff4Error::BadFormat(m) => FsError::Corrupt(format!("aff4: {m}")),
        aff4::Aff4Error::Zip(m) => FsError::Corrupt(format!("aff4: zip: {m}")),
        // Aff4Error is #[non_exhaustive]; surface any future variant loudly.
        other => FsError::Other(format!("aff4: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const DUMMY_MD5: &str = "00000000000000000000000000000000";

    fn write_tmp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    fn resolve(fs: &mut Aff4ForensicFs, path: &str) -> Option<u64> {
        let mut ino = fs.root_ino();
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            ino = fs.lookup(ino, comp.as_bytes()).ok().flatten()?;
        }
        Some(ino)
    }

    #[test]
    fn lists_and_reads_logical_file() {
        let content = b"AFF4-Logical file content spanning a chunk boundary...\n";
        let img = aff4::testutil::test_aff4_logical("dir/dream.txt", content, DUMMY_MD5);
        let f = write_tmp(&img);
        let mut fs = Aff4ForensicFs::open(f.path()).unwrap();

        assert!(!fs.read_dir(fs.root_ino()).unwrap().is_empty());
        let ino = resolve(&mut fs, "dir/dream.txt").expect("dir/dream.txt");
        assert_eq!(fs.metadata(ino).unwrap().size, content.len() as u64);
        assert_eq!(&fs.read_file(ino).unwrap(), content);
    }

    #[test]
    fn range_read_slices_the_file() {
        let content = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let img = aff4::testutil::test_aff4_logical("a.bin", content, DUMMY_MD5);
        let f = write_tmp(&img);
        let mut fs = Aff4ForensicFs::open(f.path()).unwrap();
        let ino = resolve(&mut fs, "a.bin").expect("a.bin");
        assert_eq!(fs.read_file_range(ino, 10, 6).unwrap(), &content[10..16]);
    }

    #[test]
    fn fs_info_reports_aff4_logical() {
        let img = aff4::testutil::test_aff4_logical("x.txt", b"x", DUMMY_MD5);
        let f = write_tmp(&img);
        let fs = Aff4ForensicFs::open(f.path()).unwrap();
        assert_eq!(fs.fs_info().unwrap()["type"], "aff4-logical");
    }
}
