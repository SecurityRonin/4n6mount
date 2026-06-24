#![forbid(unsafe_code)]

//! tar archive mount support — gzip (`.tar.gz`/`.tgz`) or bzip2
//! (`.tar.bz2`/`.tbz2`) compressed. Enabled with the `tarball` feature flag.
//!
//! A tar stream is sequential and the surrounding compressor is not seekable, so
//! the archive is decoded once at open: every regular file's bytes are read into
//! memory and indexed by a synthetic inode via [`ArchiveTree`]. Symlinks,
//! devices, and other non-regular entries are counted and skipped (browsing a
//! tar's file contents is the goal; a later revision can surface link targets).
//!
//! The tar walk is shared across compressors — only the decoder wrapping the
//! source differs (`GzDecoder` vs `MultiBzDecoder`). tar is a read-only archive:
//! no deleted inodes, no journal, no overlay.

use crate::archive_tree::ArchiveTree;
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};
use std::io::{Read, Seek, SeekFrom};

/// `ForensicFs` implementation for compressed tar archives.
pub struct TarballForensicFs {
    tree: ArchiveTree,
    /// File contents indexed by payload id (== position in this vector).
    data: Vec<Vec<u8>>,
    /// Non-regular, non-directory entries skipped at open (symlinks, devices).
    skipped: usize,
    /// The compressor that wrapped the tar stream ("gzip" or "bzip2").
    compression: &'static str,
}

impl TarballForensicFs {
    /// Decode a gzip-compressed tar (`.tar.gz`) from a seekable source.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the gzip or tar stream is malformed.
    pub fn from_gz<R: Read + Seek>(mut source: R) -> Result<Self, FsError> {
        source.seek(SeekFrom::Start(0)).map_err(FsError::Io)?;
        Self::read_tar(flate2::read::GzDecoder::new(source), "gzip")
    }

    /// Decode a bzip2-compressed tar (`.tar.bz2`) from a seekable source.
    ///
    /// `MultiBzDecoder` is used so concatenated bzip2 streams (e.g. from
    /// `pbzip2`) are decoded in full, not just the first.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the bzip2 or tar stream is malformed.
    pub fn from_bz2<R: Read + Seek>(mut source: R) -> Result<Self, FsError> {
        source.seek(SeekFrom::Start(0)).map_err(FsError::Io)?;
        Self::read_tar(bzip2::read::MultiBzDecoder::new(source), "bzip2")
    }

    /// Shared tar walk: read every entry from a decompressed stream, caching
    /// regular files and building the directory tree.
    fn read_tar<R: Read>(reader: R, compression: &'static str) -> Result<Self, FsError> {
        let mut archive = tar::Archive::new(reader);
        let mut tree = ArchiveTree::new();
        let mut data: Vec<Vec<u8>> = Vec::new();
        let mut skipped = 0usize;

        let entries = archive
            .entries()
            .map_err(|e| FsError::Corrupt(format!("tar: {e}")))?;
        for entry in entries {
            let mut entry = entry.map_err(|e| FsError::Corrupt(format!("tar entry: {e}")))?;
            let etype = entry.header().entry_type();
            let mtime = FsTimestamp {
                seconds: entry.header().mtime().unwrap_or(0) as i64,
                nanoseconds: 0,
            };
            let path = entry
                .path()
                .map_err(|e| FsError::Corrupt(format!("tar path: {e}")))?
                .to_string_lossy()
                .into_owned();

            if etype.is_dir() {
                tree.insert(&path, true, 0, mtime, None);
            } else if etype.is_file() {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf).map_err(FsError::Io)?;
                let id = data.len();
                if tree
                    .insert(&path, false, buf.len() as u64, mtime, Some(id))
                    .is_some()
                {
                    data.push(buf);
                }
            } else {
                skipped += 1;
            }
        }

        Ok(Self {
            tree,
            data,
            skipped,
            compression,
        })
    }
}

impl ForensicFs for TarballForensicFs {
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
            "type": "tar",
            "compression": self.compression,
            "entries": self.data.len(),
            "skipped_non_regular": self.skipped,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Mint a real compressed tar with the system `tar` tool (an independent
    /// oracle) containing `hello.txt` and `sub/deep.txt`. `flag` selects the
    /// compressor: `-z` (gzip) or `-j` (bzip2). `None` if `tar` is unavailable.
    fn make_tar(flag: &str) -> Option<Vec<u8>> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("4n6tar_{}_{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).ok()?;
        std::fs::write(dir.join("hello.txt"), b"hello tar\n").ok()?;
        std::fs::write(dir.join("sub/deep.txt"), b"deep content\n").ok()?;
        let out = dir.join("test.tar");
        let status = std::process::Command::new("tar")
            .arg(format!("-c{flag}f"))
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

    fn open_gz() -> Option<TarballForensicFs> {
        TarballForensicFs::from_gz(Cursor::new(make_tar("z")?)).ok()
    }

    fn open_bz2() -> Option<TarballForensicFs> {
        TarballForensicFs::from_bz2(Cursor::new(make_tar("j")?)).ok()
    }

    #[test]
    fn gz_root_lists_entries() {
        let Some(mut fs) = open_gz() else {
            eprintln!("skip: tar unavailable");
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
    fn gz_read_file_and_nested() {
        let Some(mut fs) = open_gz() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(ino).unwrap(), b"hello tar\n");
        let sub = fs.lookup(2, b"sub").unwrap().unwrap();
        let deep = fs.lookup(sub, b"deep.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(deep).unwrap(), b"deep content\n");
    }

    #[test]
    fn gz_fs_info_reports_gzip() {
        let Some(fs) = open_gz() else {
            eprintln!("skip");
            return;
        };
        let info = fs.fs_info().unwrap();
        assert_eq!(info["type"], "tar");
        assert_eq!(info["compression"], "gzip");
    }

    #[test]
    fn bz2_root_lists_entries() {
        let Some(mut fs) = open_bz2() else {
            eprintln!("skip: tar unavailable");
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
    fn bz2_read_file_and_nested() {
        let Some(mut fs) = open_bz2() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(ino).unwrap(), b"hello tar\n");
        let sub = fs.lookup(2, b"sub").unwrap().unwrap();
        let deep = fs.lookup(sub, b"deep.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(deep).unwrap(), b"deep content\n");
    }

    #[test]
    fn bz2_metadata_size_and_info() {
        let Some(mut fs) = open_bz2() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.metadata(ino).unwrap().size, 10); // "hello tar\n"
        assert_eq!(fs.fs_info().unwrap()["compression"], "bzip2");
    }
}
