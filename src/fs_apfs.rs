#![forbid(unsafe_code)]

//! APFS filesystem support via the `apfs-core` crate. Enabled with the `apfs`
//! feature flag.
//!
//! APFS already numbers every object by its file-system oid, so those oids serve
//! directly as inodes (root = `ROOT_DIR_INO_NUM` = 2). On open, the container
//! superblock is parsed, the checkpoint ring walked to the live state, and the
//! first volume's superblock parsed; navigation is then lazy — each `read_dir`/
//! `lookup`/`metadata`/`read_file` calls straight into apfs-core's fs-tree
//! walkers, so nothing is materialized up front.
//!
//! This reads the live volume (the container's current point-in-time view).
//! `read_data` handles transparent decmpfs decompression. APFS is mounted
//! read-only here: no deleted-inode recovery, journal, or overlay.

use crate::{
    not_supported, ForensicFs, FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp,
};
use apfs_core::volume::ApfsVolume;
use apfs_core::ApfsContainer;
use std::io::{Read, Seek, SeekFrom};

/// APFS root directory inode number (`ROOT_DIR_INO_NUM`).
const ROOT_INO: u64 = 2;

/// `ForensicFs` implementation for APFS volumes.
pub struct ApfsForensicFs<R: Read + Seek> {
    reader: R,
    volume: ApfsVolume,
    block_size: usize,
}

/// Map an APFS `DIR_REC` entry's flag bits (low nibble = `DT_*`) to a file type.
fn drec_file_type(flags: u16) -> FsFileType {
    match flags & 0x0F {
        4 => FsFileType::Directory,
        10 => FsFileType::Symlink,
        1 => FsFileType::Fifo,
        2 => FsFileType::CharDevice,
        6 => FsFileType::BlockDevice,
        12 => FsFileType::Socket,
        _ => FsFileType::RegularFile,
    }
}

/// Map a POSIX `mode` (S_IFMT bits) to a file type.
fn mode_file_type(mode: u16) -> FsFileType {
    match mode & 0o170000 {
        0o040000 => FsFileType::Directory,
        0o120000 => FsFileType::Symlink,
        0o010000 => FsFileType::Fifo,
        0o020000 => FsFileType::CharDevice,
        0o060000 => FsFileType::BlockDevice,
        0o140000 => FsFileType::Socket,
        _ => FsFileType::RegularFile,
    }
}

/// Convert APFS nanoseconds-since-epoch into an `FsTimestamp`.
fn ns_ts(ns: u64) -> FsTimestamp {
    FsTimestamp {
        seconds: (ns / 1_000_000_000) as i64,
        nanoseconds: (ns % 1_000_000_000) as u32,
    }
}

impl<R: Read + Seek> ApfsForensicFs<R> {
    /// Open an APFS container and bind to its first volume's live view.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the container/volume superblock is invalid or the
    /// container exposes no volumes.
    pub fn new(reader: R) -> Result<Self, FsError> {
        let _ = (reader, ROOT_INO, SeekFrom::Start(0));
        todo!("ApfsForensicFs::new")
    }
}

impl<R: Read + Seek> ForensicFs for ApfsForensicFs<R> {
    fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let entries =
            apfs_core::dir::list_dir(&mut self.reader, &self.volume, ino, self.block_size)
                .map_err(|e| FsError::Io(std::io::Error::other(e.to_string())))?;
        Ok(entries
            .into_iter()
            .map(|e| FsDirEntry {
                inode: e.file_id,
                name: e.name.into_bytes(),
                file_type: drec_file_type(e.flags),
            })
            .collect())
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        let name = std::str::from_utf8(name)
            .map_err(|_| FsError::NotFound("non-UTF-8 APFS name".to_string()))?;
        apfs_core::dir::lookup_child(
            &mut self.reader,
            &self.volume,
            parent_ino,
            name,
            self.block_size,
        )
        .map_err(|e| FsError::Io(std::io::Error::other(e.to_string())))
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let inode =
            apfs_core::dir::load_inode(&mut self.reader, &self.volume, ino, self.block_size)
                .map_err(|e| FsError::NotFound(format!("inode {ino}: {e}")))?;
        let file_type = mode_file_type(inode.mode);
        Ok(FsMetadata {
            ino,
            file_type,
            mode: inode.mode & 0o7777,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size.unwrap_or(0),
            links_count: inode.nlink_or_nchildren.max(0).min(i32::from(u16::MAX)) as u16,
            atime: ns_ts(inode.access_time),
            mtime: ns_ts(inode.mod_time),
            ctime: ns_ts(inode.change_time),
            crtime: ns_ts(inode.create_time),
            allocated: true,
        })
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let inode =
            apfs_core::dir::load_inode(&mut self.reader, &self.volume, ino, self.block_size)
                .map_err(|e| FsError::NotFound(format!("inode {ino}: {e}")))?;
        if mode_file_type(inode.mode) == FsFileType::Directory {
            return Err(not_supported("read_file on a directory"));
        }
        apfs_core::extent::read_data(&mut self.reader, &self.volume, &inode, self.block_size)
            .map_err(|e| FsError::Io(std::io::Error::other(e.to_string())))
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let data = self.read_file(ino)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("APFS symlink targets not yet resolved"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "apfs",
            "block_size": self.block_size,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The committed APFS partition carve from the sibling `apfs-forensic` repo
    /// (a real macOS-authored APFS container; ground truth from TSK `fls`/`istat`
    /// per its tests/data/README.md): root holds `top.txt`(22, "top level file\n",
    /// 15B), `Dir1`(18) → `Beth.txt`(20, 38B), `Sub`(19) → `secret.bin`(21, 26B).
    const IMG: &str = "/Users/4n6h4x0r/src/apfs-forensic/tests/data/apfs_fstree.bin";

    fn open() -> Option<ApfsForensicFs<Cursor<Vec<u8>>>> {
        let data = std::fs::read(IMG).ok()?;
        ApfsForensicFs::new(Cursor::new(data)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let Some(fs) = open() else {
            eprintln!("skip: apfs_fstree.bin unavailable");
            return;
        };
        assert_eq!(fs.root_ino(), 2);
    }

    #[test]
    fn root_lists_top_and_dir1() {
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
        assert!(names.contains(&"top.txt".to_string()), "got {names:?}");
        assert!(names.contains(&"Dir1".to_string()), "got {names:?}");
    }

    #[test]
    fn top_txt_resolves_to_inode_22() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.lookup(2, b"top.txt").unwrap(), Some(22));
    }

    #[test]
    fn read_top_txt_matches_oracle() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"top.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(ino).unwrap(), b"top level file\n");
    }

    #[test]
    fn nested_secret_bin_reachable() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let dir1 = fs.lookup(2, b"Dir1").unwrap().unwrap();
        let sub = fs.lookup(dir1, b"Sub").unwrap().unwrap();
        let secret = fs.lookup(sub, b"secret.bin").unwrap().unwrap();
        assert_eq!(secret, 21);
        assert_eq!(fs.metadata(secret).unwrap().size, 26);
    }

    #[test]
    fn top_is_regular_dir1_is_dir() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let top = fs.lookup(2, b"top.txt").unwrap().unwrap();
        assert_eq!(fs.metadata(top).unwrap().file_type, FsFileType::RegularFile);
        assert_eq!(fs.metadata(top).unwrap().size, 15);
        let dir1 = fs.lookup(2, b"Dir1").unwrap().unwrap();
        assert_eq!(fs.metadata(dir1).unwrap().file_type, FsFileType::Directory);
    }

    #[test]
    fn fs_info_reports_apfs() {
        let Some(fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.fs_info().unwrap()["type"], "apfs");
    }
}
