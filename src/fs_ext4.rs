#![forbid(unsafe_code)]

//! ext4 filesystem support via the ext4fs crate.
//! Enabled with the `ext4` feature flag.

use crate::{
    ForensicFs, FsBlockRange, FsDirEntry, FsDeletedInode, FsError, FsEventType, FsFileType,
    FsMetadata, FsRecoveryResult, FsResult, FsTimestamp, FsTimelineEvent, FsTransaction,
};
use ext4fs::Ext4Fs;
use std::io::{Read, Seek};

/// ForensicFs implementation for ext4 filesystems.
pub struct Ext4ForensicFs<R: Read + Seek> {
    fs: Ext4Fs<R>,
}

impl<R: Read + Seek> Ext4ForensicFs<R> {
    pub fn new(source: R) -> Result<Self, FsError> {
        let fs = Ext4Fs::open(source).map_err(map_err)?;
        Ok(Self { fs })
    }
}

impl<R: Read + Seek> ForensicFs for Ext4ForensicFs<R> {
    fn root_ino(&self) -> u64 {
        2 // ext4 root is always inode 2
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let entries = self.fs.read_dir_by_ino(ino).map_err(map_err)?;
        Ok(entries
            .iter()
            .map(|e| FsDirEntry {
                inode: e.inode as u64,
                name: e.name.clone(),
                file_type: map_dir_entry_type(e.file_type),
            })
            .collect())
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        self.fs.lookup_by_ino(parent_ino, name).map_err(map_err)
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let inode = self.fs.inode(ino).map_err(map_err)?;
        let allocated = self.fs.is_inode_allocated(ino).unwrap_or(false);
        Ok(FsMetadata {
            ino,
            file_type: map_file_type(inode.file_type()),
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            links_count: inode.links_count,
            atime: map_ts(&inode.atime),
            mtime: map_ts(&inode.mtime),
            ctime: map_ts(&inode.ctime),
            crtime: map_ts(&inode.crtime),
            allocated,
        })
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        self.fs.read_inode_data(ino).map_err(map_err)
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        self.fs
            .read_inode_data_range(ino, offset, len as usize)
            .map_err(map_err)
    }

    fn read_link(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        self.fs.read_link_by_ino(ino).map_err(map_err)
    }

    fn deleted_inodes(&mut self) -> FsResult<Vec<FsDeletedInode>> {
        let deleted = self.fs.deleted_inodes().map_err(map_err)?;
        Ok(deleted
            .into_iter()
            .map(|d| FsDeletedInode {
                ino: d.ino,
                file_type: map_file_type(d.file_type),
                size: d.size,
                dtime: d.dtime,
                recoverability: d.recoverability,
            })
            .collect())
    }

    fn recover_file(&mut self, ino: u64) -> FsResult<FsRecoveryResult> {
        let r = self.fs.recover_file(ino).map_err(map_err)?;
        let pct = r.recovery_percentage();
        Ok(FsRecoveryResult {
            ino,
            data: r.data,
            expected_size: r.expected_size,
            recovered_bytes: r.recovered_size,
            recovery_percentage: pct,
        })
    }

    fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> {
        let events = self.fs.timeline().map_err(map_err)?;
        Ok(events
            .into_iter()
            .map(|e| FsTimelineEvent {
                timestamp: map_ts(&e.timestamp),
                event_type: match e.event_type {
                    ext4fs::forensic::EventType::Created => FsEventType::Created,
                    ext4fs::forensic::EventType::Modified => FsEventType::Modified,
                    ext4fs::forensic::EventType::Accessed => FsEventType::Accessed,
                    ext4fs::forensic::EventType::Changed => FsEventType::Changed,
                    ext4fs::forensic::EventType::Deleted => FsEventType::Deleted,
                    ext4fs::forensic::EventType::Mounted => FsEventType::Mounted,
                },
                inode: e.inode,
                size: e.size,
                uid: e.uid,
                gid: e.gid,
            })
            .collect())
    }

    fn unallocated_blocks(&mut self) -> FsResult<Vec<FsBlockRange>> {
        let blocks = self.fs.unallocated_blocks().map_err(map_err)?;
        Ok(blocks
            .into_iter()
            .map(|b| FsBlockRange {
                start: b.start,
                length: b.length,
            })
            .collect())
    }

    fn read_unallocated(&mut self, range: &FsBlockRange) -> FsResult<Vec<u8>> {
        let ext4_range = ext4fs::forensic::BlockRange {
            start: range.start,
            length: range.length,
        };
        self.fs.read_unallocated(&ext4_range).map_err(map_err)
    }

    fn journal_transactions(&mut self) -> FsResult<Vec<FsTransaction>> {
        let journal = self.fs.journal().map_err(map_err)?;
        Ok(journal
            .transactions
            .into_iter()
            .map(|t| FsTransaction {
                sequence: t.sequence as u64,
                commit_seconds: t.commit_seconds as u64,
                commit_nanoseconds: t.commit_nanoseconds,
            })
            .collect())
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        let sb = self.fs.superblock();
        Ok(serde_json::json!({
            "filesystem": "ext4",
            "label": sb.label(),
            "uuid": sb.uuid_string(),
            "block_size": sb.block_size,
            "blocks_count": sb.blocks_count,
            "inodes_count": sb.inodes_count,
        }))
    }

    fn block_size(&self) -> u64 {
        self.fs.superblock().block_size as u64
    }
}

// --- Type mapping helpers ---

fn map_err(e: ext4fs::error::Ext4Error) -> FsError {
    FsError::Other(e.to_string())
}

fn map_file_type(ft: ext4fs::ondisk::FileType) -> FsFileType {
    match ft {
        ext4fs::ondisk::FileType::RegularFile => FsFileType::RegularFile,
        ext4fs::ondisk::FileType::Directory => FsFileType::Directory,
        ext4fs::ondisk::FileType::Symlink => FsFileType::Symlink,
        ext4fs::ondisk::FileType::CharDevice => FsFileType::CharDevice,
        ext4fs::ondisk::FileType::BlockDevice => FsFileType::BlockDevice,
        ext4fs::ondisk::FileType::Fifo => FsFileType::Fifo,
        ext4fs::ondisk::FileType::Socket => FsFileType::Socket,
        ext4fs::ondisk::FileType::Unknown => FsFileType::Unknown,
    }
}

fn map_dir_entry_type(dt: ext4fs::ondisk::DirEntryType) -> FsFileType {
    match dt {
        ext4fs::ondisk::DirEntryType::RegularFile => FsFileType::RegularFile,
        ext4fs::ondisk::DirEntryType::Directory => FsFileType::Directory,
        ext4fs::ondisk::DirEntryType::Symlink => FsFileType::Symlink,
        ext4fs::ondisk::DirEntryType::CharDevice => FsFileType::CharDevice,
        ext4fs::ondisk::DirEntryType::BlockDevice => FsFileType::BlockDevice,
        ext4fs::ondisk::DirEntryType::Fifo => FsFileType::Fifo,
        ext4fs::ondisk::DirEntryType::Socket => FsFileType::Socket,
        ext4fs::ondisk::DirEntryType::Unknown => FsFileType::Unknown,
    }
}

fn map_ts(ts: &ext4fs::ondisk::Timestamp) -> FsTimestamp {
    FsTimestamp {
        seconds: ts.seconds,
        nanoseconds: ts.nanoseconds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn open_forensic() -> Option<Ext4ForensicFs<Cursor<Vec<u8>>>> {
        let path = "/Users/4n6h4x0r/src/ext4fs-forensic/tests/data/forensic.img";
        let data = std::fs::read(path).ok()?;
        Ext4ForensicFs::new(Cursor::new(data)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        assert_eq!(fs.root_ino(), 2);
    }

    #[test]
    fn read_dir_root_has_entries() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let entries = fs.read_dir(2).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
        assert!(names.contains(&"hello.txt".to_string()));
    }

    #[test]
    fn lookup_finds_file() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap();
        assert!(ino.is_some());
    }

    #[test]
    fn metadata_root_is_directory() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let meta = fs.metadata(2).unwrap();
        assert_eq!(meta.file_type, FsFileType::Directory);
        assert!(meta.allocated);
    }

    #[test]
    fn read_file_returns_content() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let data = fs.read_file(ino).unwrap();
        assert!(String::from_utf8_lossy(&data).contains("Hello"));
    }

    #[test]
    fn read_file_range_returns_prefix() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let data = fs.read_file_range(ino, 0, 5).unwrap();
        assert_eq!(&data, b"Hello");
    }

    #[test]
    fn read_link_returns_target() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let ino = fs.lookup(2, b"abs-link").unwrap().unwrap();
        let target = fs.read_link(ino).unwrap();
        assert_eq!(String::from_utf8_lossy(&target), "/hello.txt");
    }

    #[test]
    fn deleted_inodes_found() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let deleted = fs.deleted_inodes().unwrap();
        assert!(deleted.len() >= 2);
    }

    #[test]
    fn timeline_has_events() {
        let mut fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let events = fs.timeline().unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn fs_info_is_ext4() {
        let fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        let info = fs.fs_info().unwrap();
        assert_eq!(info["filesystem"], "ext4");
    }

    #[test]
    fn block_size_is_4096() {
        let fs = match open_forensic() {
            Some(f) => f,
            None => {
                eprintln!("skip");
                return;
            }
        };
        assert_eq!(fs.block_size(), 4096);
    }
}
