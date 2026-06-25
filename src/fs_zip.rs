#![forbid(unsafe_code)]

//! ZIP archive mount support. Enabled with the `zip` feature flag.
//!
//! ZIP has a central directory, so entries are random-access: the tree is built
//! from the directory at open time and each file's bytes are decompressed
//! on demand (avoiding materializing a whole — potentially bomb-sized — archive
//! into memory up front). Directory entries map to [`ArchiveTree`] nodes; each
//! file node's payload id is its central-directory index.
//!
//! ZIP is a read-only archive: no deleted inodes, no journal, no overlay.

use crate::archive_tree::{civil_to_unix, ArchiveTree};
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};
use std::io::{Read, Seek};

/// `ForensicFs` implementation for ZIP archives.
pub struct ZipForensicFs<R: Read + Seek> {
    archive: zip::ZipArchive<R>,
    tree: ArchiveTree,
}

impl<R: Read + Seek> ZipForensicFs<R> {
    /// Open a ZIP archive from a seekable source.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the central directory cannot be read.
    pub fn new(source: R) -> Result<Self, FsError> {
        let mut archive = zip::ZipArchive::new(source)
            .map_err(|e| FsError::Corrupt(format!("not a zip: {e}")))?;
        let mut tree = ArchiveTree::new();
        for i in 0..archive.len() {
            let entry = archive
                .by_index(i)
                .map_err(|e| FsError::Corrupt(format!("zip entry {i}: {e}")))?;
            let name = entry.name().to_string();
            let is_dir = entry.is_dir();
            let size = entry.size();
            let mtime = entry
                .last_modified()
                .map_or_else(FsTimestamp::default, |dt| FsTimestamp {
                    seconds: civil_to_unix(
                        i64::from(dt.year()),
                        i64::from(dt.month()),
                        i64::from(dt.day()),
                        i64::from(dt.hour()),
                        i64::from(dt.minute()),
                        i64::from(dt.second()),
                    ),
                    nanoseconds: 0,
                });
            tree.insert(
                &name,
                is_dir,
                size,
                mtime,
                if is_dir { None } else { Some(i) },
            );
        }
        Ok(Self { archive, tree })
    }
}

impl<R: Read + Seek> ForensicFs for ZipForensicFs<R> {
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
        let idx = self
            .tree
            .payload_id(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino} is not a file")))?;
        let mut entry = self
            .archive
            .by_index(idx)
            .map_err(|e| FsError::Corrupt(format!("zip entry {idx}: {e}")))?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(FsError::Io)?;
        Ok(buf)
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let data = self.read_file(ino)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("symlinks not surfaced for zip archives"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "zip",
            "entries": self.archive.len(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Mint a real `.zip` with the system `zip` tool (independent oracle)
    /// holding `hello.txt` and `sub/deep.txt`. `None` if `zip` is unavailable.
    fn make_zip() -> Option<Vec<u8>> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("4n6zip_{}_{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).ok()?;
        std::fs::write(dir.join("hello.txt"), b"hello zip\n").ok()?;
        std::fs::write(dir.join("sub/deep.txt"), b"deep content\n").ok()?;
        let out = dir.join("test.zip");
        // `zip -r out.zip hello.txt sub` run from inside `dir`.
        let status = std::process::Command::new("zip")
            .current_dir(&dir)
            .arg("-r")
            .arg(&out)
            .args(["hello.txt", "sub"])
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        let bytes = std::fs::read(&out).ok();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    fn open() -> Option<ZipForensicFs<Cursor<Vec<u8>>>> {
        ZipForensicFs::new(Cursor::new(make_zip()?)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let Some(fs) = open() else {
            eprintln!("skip: zip unavailable");
            return;
        };
        assert_eq!(fs.root_ino(), 2);
    }

    #[test]
    fn read_dir_root_lists_entries() {
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
    fn read_file_returns_content() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(ino).unwrap(), b"hello zip\n");
    }

    #[test]
    fn nested_file_reachable() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let sub = fs.lookup(2, b"sub").unwrap().unwrap();
        let deep = fs.lookup(sub, b"deep.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(deep).unwrap(), b"deep content\n");
    }

    #[test]
    fn metadata_size_matches() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.metadata(ino).unwrap().size, 10); // "hello zip\n"
    }

    #[test]
    fn fs_info_reports_zip() {
        let Some(fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.fs_info().unwrap()["type"], "zip");
    }
}
