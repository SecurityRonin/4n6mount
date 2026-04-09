#![forbid(unsafe_code)]

use crate::{ForensicFs, FsDirEntry, FsFileType, FsMetadata, FsTimestamp, FsError, FsResult};
use std::io::{Read, Seek, SeekFrom};

/// A ForensicFs that exposes a single raw data source as one file.
/// Used for L01 logical evidence or raw binary data.
pub struct RawForensicFs<R: Read + Seek> {
    source: R,
    size: u64,
    filename: String,
}

impl<R: Read + Seek> RawForensicFs<R> {
    pub fn new(mut source: R, filename: String) -> Result<Self, FsError> {
        let size = source.seek(SeekFrom::End(0))
            .map_err(|e| FsError::Io(e))?;
        source.seek(SeekFrom::Start(0))
            .map_err(|e| FsError::Io(e))?;
        Ok(Self { source, size, filename })
    }
}

impl<R: Read + Seek> ForensicFs for RawForensicFs<R> {
    fn root_ino(&self) -> u64 { todo!() }

    fn read_dir(&mut self, _ino: u64) -> FsResult<Vec<FsDirEntry>> { todo!() }

    fn lookup(&mut self, _parent_ino: u64, _name: &[u8]) -> FsResult<Option<u64>> { todo!() }

    fn metadata(&mut self, _ino: u64) -> FsResult<FsMetadata> { todo!() }

    fn read_file(&mut self, _ino: u64) -> FsResult<Vec<u8>> { todo!() }

    fn read_file_range(&mut self, _ino: u64, _offset: u64, _len: u64) -> FsResult<Vec<u8>> { todo!() }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> { todo!() }

    fn fs_info(&self) -> FsResult<serde_json::Value> { todo!() }
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
        let names: Vec<String> = entries.iter().map(|e| e.name_str()).collect();
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
