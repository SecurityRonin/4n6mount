#![forbid(unsafe_code)]
//! AD1 (`AccessData` logical image) lazy mount — `ad1` feature.
//!
//! Entries are enumerated at open into a synthetic inode tree
//! ([`crate::archive_tree::ArchiveTree`]); file bytes are read lazily via
//! [`ad1::Ad1Reader::read_at`] on FUSE access, so a large (multi-GiB) image is
//! browsed without full extraction. Read-only; encrypted (ADCRYPT) images are
//! refused at open with a clear error (ciphertext cannot be mounted).

use std::path::Path;

use ad1::Ad1Reader;

use crate::archive_tree::ArchiveTree;
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};

/// A read-only, lazily-decompressing view over an AD1 logical image.
pub struct Ad1ForensicFs {
    reader: Ad1Reader,
    tree: ArchiveTree,
}

impl Ad1ForensicFs {
    /// Open an AD1 image by path (discovers sibling `.ad2…` segments alongside
    /// it). Returns a `NotSupported` error for encrypted (ADCRYPT) images.
    pub fn open(path: &Path) -> Result<Self, FsError> {
        let reader = Ad1Reader::open(path).map_err(map_err)?;
        let mut tree = ArchiveTree::new();
        for (idx, e) in reader.entries().iter().enumerate() {
            // AD1 timestamps are display strings ("YYYYMMDDThhmmss"); browsing
            // doesn't depend on them, so v1 surfaces the epoch rather than
            // parsing. The synthetic tree carries the path, type, and size.
            tree.insert(
                &e.path,
                e.is_dir,
                e.size,
                FsTimestamp {
                    seconds: 0,
                    nanoseconds: 0,
                },
                if e.is_dir { None } else { Some(idx) },
            );
        }
        Ok(Self { reader, tree })
    }

    /// Read `len` bytes at `offset` from the file at `ino`, inflating only the
    /// overlapping zlib chunks. `read_at` may short-read, so loop until filled.
    fn read_range(&self, ino: u64, offset: u64, len: usize) -> FsResult<Vec<u8>> {
        let idx = self
            .tree
            .payload_id(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino} is not a readable file")))?;
        // `read_at` takes `&self`; clone the small entry so the tree's `&mut
        // self` method signatures stay intact.
        let entry = self.reader.entries()[idx].clone();
        let want = (entry.size.saturating_sub(offset) as usize).min(len);
        let mut buf = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            let n = self
                .reader
                .read_at(&entry, offset + filled as u64, &mut buf[filled..])
                .map_err(map_err)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        Ok(buf)
    }
}

impl ForensicFs for Ad1ForensicFs {
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
        Err(not_supported("ad1: symlinks are not surfaced"))
    }
    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({ "type": "ad1", "entries": self.reader.entries().len() }))
    }
}

/// Map an `ad1::Ad1Error` onto 4n6mount's `FsError`.
fn map_err(e: ad1::Ad1Error) -> FsError {
    match e {
        ad1::Ad1Error::Io(io) => FsError::Io(io),
        // ADCRYPT (encrypted) and other unsupported features.
        ad1::Ad1Error::Unsupported(m) => FsError::NotSupported(format!("ad1: {m}")),
        ad1::Ad1Error::NotAd1(m) | ad1::Ad1Error::Malformed(m) => {
            FsError::Corrupt(format!("ad1: {m}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ad1::testfix;

    struct Fixture {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        built: testfix::Built,
    }

    fn write_fixture() -> Fixture {
        let built = testfix::build(testfix::sample_tree());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.ad1");
        std::fs::write(&path, &built.bytes).unwrap();
        Fixture {
            _dir: dir,
            path,
            built,
        }
    }

    /// Walk `lookup` from the root to resolve a POSIX '/'-separated path.
    fn resolve(fs: &mut Ad1ForensicFs, path: &str) -> Option<u64> {
        let mut ino = fs.root_ino();
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            ino = fs.lookup(ino, comp.as_bytes()).ok().flatten()?;
        }
        Some(ino)
    }

    #[test]
    fn root_lists_entries() {
        let fx = write_fixture();
        let mut fs = Ad1ForensicFs::open(&fx.path).unwrap();
        let root = fs.root_ino();
        assert!(!fs.read_dir(root).unwrap().is_empty());
    }

    #[test]
    fn files_read_back_byte_identical() {
        let fx = write_fixture();
        let mut fs = Ad1ForensicFs::open(&fx.path).unwrap();
        let mut checked = 0;
        for e in &fx.built.expected {
            if e.is_dir {
                continue;
            }
            let Some(data) = &e.data else { continue };
            let ino =
                resolve(&mut fs, &e.path).unwrap_or_else(|| panic!("path not found: {}", e.path));
            assert_eq!(fs.metadata(ino).unwrap().size, e.size, "size of {}", e.path);
            assert_eq!(&fs.read_file(ino).unwrap(), data, "content of {}", e.path);
            checked += 1;
        }
        assert!(checked >= 1, "fixture should contain at least one file");
    }

    #[test]
    fn range_read_across_chunk_boundary() {
        let fx = write_fixture();
        let mut fs = Ad1ForensicFs::open(&fx.path).unwrap();
        // The largest file spans multiple zlib chunks; read a window in its
        // middle and compare against testfix's independent ground truth.
        let big = fx
            .built
            .expected
            .iter()
            .filter(|e| !e.is_dir && e.data.is_some())
            .max_by_key(|e| e.size)
            .expect("fixture should contain a file with data");
        let data = big.data.as_ref().unwrap();
        let ino = resolve(&mut fs, &big.path).unwrap();
        let off = (data.len() / 2) as u64;
        let len = 4096u64.min(data.len() as u64 - off);
        let got = fs.read_file_range(ino, off, len).unwrap();
        assert_eq!(
            got,
            &data[off as usize..(off + len) as usize],
            "mid-file range read of {}",
            big.path
        );
    }

    #[test]
    fn fs_info_reports_ad1() {
        let fx = write_fixture();
        let fs = Ad1ForensicFs::open(&fx.path).unwrap();
        assert_eq!(fs.fs_info().unwrap()["type"], "ad1");
    }
}
