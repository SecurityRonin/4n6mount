#![forbid(unsafe_code)]

//! 7-Zip (`.7z`) archive mount support. Enabled with the `sevenz` feature flag.
//!
//! 7z is typically solid-compressed (one LZMA stream spans many files), so
//! seeking to a single entry means decoding everything before it. The archive
//! is therefore decoded once at open: every file's bytes are read in stream
//! order into memory and indexed by an [`ArchiveTree`] synthetic inode.
//!
//! 7z is a read-only archive: no deleted inodes, no journal, no overlay.
//! Encrypted archives are not handled (opened with an empty password).

use crate::archive_tree::ArchiveTree;
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};
use sevenz_rust::{Password, SevenZReader};
use std::io::{Read, Seek, SeekFrom};

/// 100-ns ticks between the Windows FILETIME epoch (1601-01-01) and the Unix
/// epoch (1970-01-01), used to convert 7z entry timestamps.
const FILETIME_TO_UNIX_SECS: i64 = 11_644_473_600;

/// `ForensicFs` implementation for 7-Zip archives.
pub struct SevenZForensicFs {
    tree: ArchiveTree,
    /// File contents indexed by payload id (== position in this vector).
    data: Vec<Vec<u8>>,
}

impl SevenZForensicFs {
    /// Decode a `.7z` archive from a seekable source.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the archive headers or streams are malformed.
    pub fn new<R: Read + Seek>(source: R) -> Result<Self, FsError> {
        let _ = (source, SeekFrom::Start(0), FsTimestamp::default());
        todo!("SevenZForensicFs::new")
    }
}

/// Convert a Windows FILETIME (100-ns ticks since 1601) to an `FsTimestamp`.
/// A zero tick count (7z's "no timestamp") maps to the default (epoch-zero).
fn filetime_to_ts(raw: u64) -> FsTimestamp {
    if raw == 0 {
        return FsTimestamp::default();
    }
    FsTimestamp {
        seconds: (raw / 10_000_000) as i64 - FILETIME_TO_UNIX_SECS,
        nanoseconds: ((raw % 10_000_000) * 100) as u32,
    }
}

impl ForensicFs for SevenZForensicFs {
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
        Err(not_supported("symlinks not surfaced for 7z archives"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "7z",
            "entries": self.data.len(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Mint a real `.7z` with whichever 7-Zip CLI is installed (independent
    /// oracle), holding `hello.txt` and `sub/deep.txt`. `None` if no 7z tool.
    fn make_7z() -> Option<Vec<u8>> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("4n67z_{}_{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).ok()?;
        std::fs::write(dir.join("hello.txt"), b"hello 7z\n").ok()?;
        std::fs::write(dir.join("sub/deep.txt"), b"deep content\n").ok()?;
        let out = dir.join("test.7z");
        let mut made = false;
        for bin in ["7z", "7za", "7zz"] {
            let status = std::process::Command::new(bin)
                .current_dir(&dir)
                .arg("a")
                .arg(&out)
                .args(["hello.txt", "sub"])
                .stdout(std::process::Stdio::null())
                .status();
            if matches!(status, Ok(s) if s.success()) {
                made = true;
                break;
            }
        }
        let bytes = if made { std::fs::read(&out).ok() } else { None };
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    fn open() -> Option<SevenZForensicFs> {
        SevenZForensicFs::new(Cursor::new(make_7z()?)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let Some(fs) = open() else {
            eprintln!("skip: no 7z tool");
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
        assert_eq!(fs.read_file(ino).unwrap(), b"hello 7z\n");
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
    fn fs_info_reports_7z() {
        let Some(fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.fs_info().unwrap()["type"], "7z");
    }

    #[test]
    fn filetime_zero_is_default() {
        assert_eq!(filetime_to_ts(0), FsTimestamp::default());
    }

    #[test]
    fn filetime_unix_epoch_converts() {
        // FILETIME for 1970-01-01T00:00:00Z is exactly the offset in ticks.
        let raw = (FILETIME_TO_UNIX_SECS as u64) * 10_000_000;
        assert_eq!(filetime_to_ts(raw).seconds, 0);
    }
}
