#![forbid(unsafe_code)]

use crate::{ForensicFs, FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp};
use std::io::{Read, Seek, SeekFrom};

/// A `ForensicFs` that exposes a single raw data source as one file.
/// Used for L01 logical evidence or raw binary data.
pub struct RawForensicFs<R: Read + Seek> {
    source: R,
    size: u64,
    filename: String,
}

impl<R: Read + Seek> RawForensicFs<R> {
    pub fn new(mut source: R, filename: String) -> Result<Self, FsError> {
        let size = source.seek(SeekFrom::End(0)).map_err(FsError::Io)?;
        source.seek(SeekFrom::Start(0)).map_err(FsError::Io)?;
        Ok(Self {
            source,
            size,
            filename,
        })
    }
}

impl<R: Read + Seek> ForensicFs for RawForensicFs<R> {
    fn root_ino(&self) -> u64 {
        1
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        if ino == 1 {
            Ok(vec![
                FsDirEntry {
                    inode: 1,
                    name: b".".to_vec(),
                    file_type: FsFileType::Directory,
                },
                FsDirEntry {
                    inode: 1,
                    name: b"..".to_vec(),
                    file_type: FsFileType::Directory,
                },
                FsDirEntry {
                    inode: 2,
                    name: self.filename.as_bytes().to_vec(),
                    file_type: FsFileType::RegularFile,
                },
            ])
        } else {
            Err(FsError::NotFound(format!("inode {ino}")))
        }
    }

    fn lookup(&mut self, _parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        if name == self.filename.as_bytes() {
            Ok(Some(2))
        } else if name == b"." || name == b".." {
            Ok(Some(1))
        } else {
            Ok(None)
        }
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        match ino {
            1 => Ok(FsMetadata {
                ino: 1,
                file_type: FsFileType::Directory,
                mode: 0o40555,
                uid: 0,
                gid: 0,
                size: 0,
                links_count: 2,
                atime: FsTimestamp::default(),
                mtime: FsTimestamp::default(),
                ctime: FsTimestamp::default(),
                crtime: FsTimestamp::default(),
                allocated: true,
            }),
            2 => Ok(FsMetadata {
                ino: 2,
                file_type: FsFileType::RegularFile,
                mode: 0o100_444,
                uid: 0,
                gid: 0,
                size: self.size,
                links_count: 1,
                atime: FsTimestamp::default(),
                mtime: FsTimestamp::default(),
                ctime: FsTimestamp::default(),
                crtime: FsTimestamp::default(),
                allocated: true,
            }),
            _ => Err(FsError::NotFound(format!("inode {ino}"))),
        }
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        if ino != 2 {
            return Err(FsError::NotFound(format!("inode {ino}")));
        }
        self.source.seek(SeekFrom::Start(0)).map_err(FsError::Io)?;
        let mut data = Vec::with_capacity(self.size as usize);
        self.source.read_to_end(&mut data).map_err(FsError::Io)?;
        Ok(data)
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        if ino != 2 {
            return Err(FsError::NotFound(format!("inode {ino}")));
        }
        self.source
            .seek(SeekFrom::Start(offset))
            .map_err(FsError::Io)?;
        let actual_len = len.min(self.size.saturating_sub(offset)) as usize;
        let mut buf = vec![0u8; actual_len];
        self.source.read_exact(&mut buf).map_err(FsError::Io)?;
        Ok(buf)
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(FsError::NotFound("no symlinks in raw data".to_string()))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "filesystem": "raw",
            "size": self.size,
            "filename": self.filename,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_raw_fs(data: &[u8]) -> RawForensicFs<Cursor<Vec<u8>>> {
        RawForensicFs::new(Cursor::new(data.to_vec()), "evidence.bin".to_string()).unwrap()
    }

    #[test]
    fn root_ino_is_1() {
        let fs = make_raw_fs(b"hello");
        assert_eq!(fs.root_ino(), 1);
    }

    #[test]
    fn read_dir_root_has_file() {
        let mut fs = make_raw_fs(b"hello");
        let entries = fs.read_dir(1).unwrap();
        assert_eq!(entries.len(), 3); // ., .., evidence.bin
        let names: Vec<String> = entries
            .iter()
            .map(super::super::types::FsDirEntry::name_str)
            .collect();
        assert!(names.contains(&"evidence.bin".to_string()));
    }

    #[test]
    fn lookup_file() {
        let mut fs = make_raw_fs(b"hello");
        assert_eq!(fs.lookup(1, b"evidence.bin").unwrap(), Some(2));
        assert_eq!(fs.lookup(1, b"missing").unwrap(), None);
    }

    #[test]
    fn metadata_root() {
        let mut fs = make_raw_fs(b"hello");
        let meta = fs.metadata(1).unwrap();
        assert_eq!(meta.file_type, FsFileType::Directory);
    }

    #[test]
    fn metadata_file() {
        let mut fs = make_raw_fs(b"hello");
        let meta = fs.metadata(2).unwrap();
        assert_eq!(meta.file_type, FsFileType::RegularFile);
        assert_eq!(meta.size, 5);
    }

    #[test]
    fn read_file_content() {
        let mut fs = make_raw_fs(b"hello world");
        let data = fs.read_file(2).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn read_file_range_prefix() {
        let mut fs = make_raw_fs(b"hello world");
        let data = fs.read_file_range(2, 0, 5).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn read_file_range_middle() {
        let mut fs = make_raw_fs(b"hello world");
        let data = fs.read_file_range(2, 6, 5).unwrap();
        assert_eq!(data, b"world");
    }

    #[test]
    fn fs_info_raw() {
        let fs = make_raw_fs(b"data");
        let info = fs.fs_info().unwrap();
        assert_eq!(info["filesystem"], "raw");
        assert_eq!(info["size"], 4);
    }

    #[test]
    fn read_dir_invalid_ino() {
        let mut fs = make_raw_fs(b"data");
        assert!(fs.read_dir(99).is_err());
    }
}
