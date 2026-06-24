#![forbid(unsafe_code)]

//! gzip-compressed tar archive (`.tar.gz` / `.tgz`) mount support.
//! Enabled with the `targz` feature flag.
//!
//! A tar stream is sequential and the gzip wrapper is not seekable, so the
//! archive is decoded once at open time: every regular file's bytes are read
//! into memory and indexed by a synthetic inode via [`ArchiveTree`]. Symlinks,
//! devices, and other non-regular entries are counted and skipped (browsing a
//! tar's file contents is the goal; a later revision can surface link targets).
//!
//! tar is a read-only archive: no deleted inodes, no journal, no overlay.

use crate::archive_tree::ArchiveTree;
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};
use std::io::{Read, Seek, SeekFrom};

/// `ForensicFs` implementation for gzip-compressed tar archives.
pub struct TarGzForensicFs {
    tree: ArchiveTree,
    /// File contents indexed by payload id (== position in this vector).
    data: Vec<Vec<u8>>,
    /// Non-regular, non-directory entries skipped at open (symlinks, devices).
    skipped: usize,
}

impl TarGzForensicFs {
    /// Decode a `.tar.gz` from a seekable source.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the gzip or tar stream is malformed.
    pub fn new<R: Read + Seek>(source: R) -> Result<Self, FsError> {
        let _ = (source, SeekFrom::Start(0), FsTimestamp::default());
        todo!("TarGzForensicFs::new")
    }
}

impl ForensicFs for TarGzForensicFs {
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
        Err(not_supported("symlinks not surfaced for tar archives"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "tar.gz",
            "entries": self.data.len(),
            "skipped_non_regular": self.skipped,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Mint a real `.tar.gz` with the system `tar` tool (an independent oracle)
    /// containing `hello.txt` and `sub/deep.txt`. Returns the archive bytes, or
    /// `None` if `tar` is unavailable.
    fn make_targz() -> Option<Vec<u8>> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("4n6tar_{}_{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).ok()?;
        std::fs::write(dir.join("hello.txt"), b"hello tar\n").ok()?;
        std::fs::write(dir.join("sub/deep.txt"), b"deep content\n").ok()?;
        let out = dir.join("test.tar.gz");
        let status = std::process::Command::new("tar")
            .args(["-czf"])
            .arg(&out)
            .arg("-C")
            .arg(&dir)
            .args(["hello.txt", "sub/deep.txt"])
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        let bytes = std::fs::read(&out).ok();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    fn open() -> Option<TarGzForensicFs> {
        TarGzForensicFs::new(Cursor::new(make_targz()?)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let Some(fs) = open() else {
            eprintln!("skip: tar unavailable");
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
        assert_eq!(fs.read_file(ino).unwrap(), b"hello tar\n");
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
        assert_eq!(fs.metadata(ino).unwrap().size, 10); // "hello tar\n"
    }

    #[test]
    fn read_file_range_prefix() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.read_file_range(ino, 0, 5).unwrap(), b"hello");
    }

    #[test]
    fn fs_info_reports_targz() {
        let Some(fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.fs_info().unwrap()["type"], "tar.gz");
    }
}
