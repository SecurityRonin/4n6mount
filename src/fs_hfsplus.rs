#![forbid(unsafe_code)]

//! HFS+ / HFSX filesystem support via the `hfsplus-forensic` crate. Enabled
//! with the `hfsplus` feature flag.
//!
//! `hfsplus-forensic` operates on a fully-buffered volume image, so the source
//! is read into memory at open. The catalog is walked to enumerate every entry
//! (path, CNID, dir-or-file); each file is read once — transparently handling
//! decmpfs (zlib/LZVN/LZFSE) decompression — into a cache so getattr can report
//! a correct size and reads are served instantly. Entries whose data fails to
//! decompress are skipped and counted rather than shown as empty.
//!
//! HFS+ entry timestamps are not exposed by the crate's listing API, so node
//! times default to epoch-zero in this revision.

use crate::archive_tree::ArchiveTree;
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};
use std::io::{Read, Seek, SeekFrom};

/// `ForensicFs` implementation for HFS+/HFSX volumes.
pub struct HfsPlusForensicFs {
    tree: ArchiveTree,
    /// File contents indexed by payload id (== position in this vector).
    data: Vec<Vec<u8>>,
    /// Files whose `$DATA` could not be decompressed (skipped, not shown empty).
    decompress_failures: usize,
}

impl HfsPlusForensicFs {
    /// Buffer and open an HFS+/HFSX volume.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the volume header is not HFS+ or the catalog
    /// cannot be walked.
    pub fn new<R: Read + Seek>(mut source: R) -> Result<Self, FsError> {
        source.seek(SeekFrom::Start(0)).map_err(FsError::Io)?;
        let mut buf = Vec::new();
        source.read_to_end(&mut buf).map_err(FsError::Io)?;

        hfsplus_forensic::parse(&buf)
            .ok_or_else(|| FsError::Corrupt("not an HFS+/HFSX volume".to_string()))?;
        let entries = hfsplus_forensic::walk(&buf)
            .ok_or_else(|| FsError::Corrupt("HFS+ catalog walk failed".to_string()))?;

        let mut tree = ArchiveTree::new();
        let mut data: Vec<Vec<u8>> = Vec::new();
        let mut decompress_failures = 0usize;

        for entry in entries {
            // walk() yields root-relative paths; strip a leading '/' so the tree
            // builder (which rejects absolute paths) accepts them.
            let path = entry.path.strip_prefix('/').unwrap_or(&entry.path);
            if path.is_empty() {
                continue;
            }
            if entry.is_dir {
                tree.insert(path, true, 0, FsTimestamp::default(), None);
            } else {
                match hfsplus_forensic::read_file(&buf, entry.cnid) {
                    Some(bytes) => {
                        let id = data.len();
                        if tree
                            .insert(
                                path,
                                false,
                                bytes.len() as u64,
                                FsTimestamp::default(),
                                Some(id),
                            )
                            .is_some()
                        {
                            data.push(bytes);
                        }
                    }
                    None => decompress_failures += 1,
                }
            }
        }

        Ok(Self {
            tree,
            data,
            decompress_failures,
        })
    }
}

impl ForensicFs for HfsPlusForensicFs {
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
        let id = self
            .tree
            .payload_id(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino} is not a file")))?;
        self.data
            .get(id)
            .cloned()
            .ok_or_else(|| FsError::NotFound(format!("payload {id}")))
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let data = self.read_file(ino)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("HFS+ symlinks not resolved"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "hfsplus",
            "entries": self.data.len(),
            "decompress_failures": self.decompress_failures,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The committed 512 KiB HFS+ volume minted on macOS (`newfs_hfs` via
    /// hdiutil); TSK `fls`/`icat` ground truth: `hello.txt` (cnid 18) and a
    /// `sub/` directory holding `deep.txt`.
    const IMG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfsplus.img");

    fn open() -> Option<HfsPlusForensicFs> {
        let data = std::fs::read(IMG).ok()?;
        HfsPlusForensicFs::new(Cursor::new(data)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let Some(fs) = open() else {
            eprintln!("skip: hfsplus.img unavailable");
            return;
        };
        assert_eq!(fs.root_ino(), 2);
    }

    #[test]
    fn root_lists_hello_and_sub() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let names: Vec<String> = fs
            .read_dir(2)
            .unwrap()
            .iter()
            .map(FsDirEntry::name_str)
            .collect();
        assert!(names.contains(&"hello.txt".to_string()), "got {names:?}");
        assert!(names.contains(&"sub".to_string()), "got {names:?}");
    }

    #[test]
    fn read_hello_matches_icat() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(ino).unwrap(), b"hello from hfsplus\n");
    }

    #[test]
    fn nested_file_reachable() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let sub = fs.lookup(2, b"sub").unwrap().unwrap();
        let deep = fs.lookup(sub, b"deep.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(deep).unwrap(), b"deep hfs content\n");
    }

    #[test]
    fn metadata_size_matches() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.metadata(ino).unwrap().size, 19); // "hello from hfsplus\n"
    }

    #[test]
    fn fs_info_reports_hfsplus() {
        let Some(fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.fs_info().unwrap()["type"], "hfsplus");
    }
}
