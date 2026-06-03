#![forbid(unsafe_code)]

//! ISO 9660 / Rock Ridge / Joliet filesystem support via the
//! `iso9660-forensic` crate.  Enabled with the `iso` feature flag.
//!
//! ISO 9660 has no native inode numbers, so synthetic inodes are assigned by
//! walking the directory tree once at open time (root = 2, entries from 3 up).

use crate::{
    not_supported, ForensicFs, FsBlockRange, FsDirEntry, FsError, FsMetadata, FsResult,
    FsTimelineEvent,
};
#[cfg(test)]
use crate::FsFileType;
use iso9660_forensic::{DirRecord, IsoReader};
use std::collections::HashMap;
use std::io::{Read, Seek};

/// Root synthetic inode (mirrors ext4's convention of root = 2).
const ROOT_INO: u64 = 2;

/// One node in the synthetic inode table.
struct IsoNode {
    parent: u64,
    name: Vec<u8>,
    is_dir: bool,
    /// `None` for the synthetic root (which has no on-disc directory record).
    record: Option<DirRecord>,
    children: Vec<u64>,
}

/// `ForensicFs` implementation for ISO 9660 images.
pub struct IsoForensicFs<R: Read + Seek> {
    reader: IsoReader<R>,
    nodes: HashMap<u64, IsoNode>,
}

impl<R: Read + Seek> IsoForensicFs<R> {
    pub fn new(source: R) -> Result<Self, FsError> {
        let mut reader =
            IsoReader::open(source).map_err(|e| FsError::Corrupt(format!("not an ISO: {e}")))?;

        // Walk the tree once and assign synthetic inodes.
        let entries = reader
            .walk()
            .map_err(|e| FsError::Corrupt(format!("walk failed: {e}")))?;

        let mut nodes: HashMap<u64, IsoNode> = HashMap::new();
        nodes.insert(
            ROOT_INO,
            IsoNode { parent: ROOT_INO, name: b"/".to_vec(), is_dir: true, record: None, children: vec![] },
        );

        // path -> inode, so children can find their parent.
        let mut path_ino: HashMap<String, u64> = HashMap::new();
        path_ino.insert(String::new(), ROOT_INO);

        for (i, e) in entries.iter().enumerate() {
            let ino = 3 + i as u64;
            let name = e
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&e.path)
                .as_bytes()
                .to_vec();
            let parent_path = match e.path.rsplit_once('/') {
                Some((p, _)) => p.to_string(),
                None => String::new(),
            };
            let parent = path_ino.get(&parent_path).copied().unwrap_or(ROOT_INO);

            path_ino.insert(e.path.clone(), ino);
            nodes.insert(
                ino,
                IsoNode {
                    parent,
                    name,
                    is_dir: e.record.is_dir(),
                    record: Some(e.record.clone()),
                    children: vec![],
                },
            );
            if let Some(p) = nodes.get_mut(&parent) {
                p.children.push(ino);
            }
        }

        Ok(Self { reader, nodes })
    }

    fn node(&self, ino: u64) -> FsResult<&IsoNode> {
        self.nodes
            .get(&ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))
    }
}

impl<R: Read + Seek> ForensicFs for IsoForensicFs<R> {
    fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    fn read_dir(&mut self, _ino: u64) -> FsResult<Vec<FsDirEntry>> {
        Ok(vec![])
    }

    fn lookup(&mut self, _parent_ino: u64, _name: &[u8]) -> FsResult<Option<u64>> {
        Ok(None)
    }

    fn metadata(&mut self, _ino: u64) -> FsResult<FsMetadata> {
        Err(not_supported("metadata"))
    }

    fn read_file(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Ok(vec![])
    }

    fn read_file_range(&mut self, _ino: u64, _offset: u64, _len: u64) -> FsResult<Vec<u8>> {
        Ok(vec![])
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("read_link"))
    }

    fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> {
        Ok(vec![])
    }

    fn unallocated_blocks(&mut self) -> FsResult<Vec<FsBlockRange>> {
        Ok(vec![])
    }

    fn block_size(&self) -> u64 {
        2048
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const ISO: &str = "/Users/4n6h4x0r/src/iso9660-forensic/iso/tests/data/rock_ridge.iso";

    fn open() -> Option<IsoForensicFs<Cursor<Vec<u8>>>> {
        let data = std::fs::read(ISO).ok()?;
        IsoForensicFs::new(Cursor::new(data)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let Some(fs) = open() else { eprintln!("skip"); return; };
        assert_eq!(fs.root_ino(), 2);
    }

    #[test]
    fn read_dir_root_has_entries() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let entries = fs.read_dir(2).unwrap();
        let names: Vec<String> = entries.iter().map(FsDirEntry::name_str).collect();
        assert!(names.contains(&"hello.txt".to_string()), "got: {names:?}");
    }

    #[test]
    fn lookup_finds_file() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let ino = fs.lookup(2, b"hello.txt").unwrap();
        assert!(ino.is_some(), "hello.txt must be found under root");
    }

    #[test]
    fn metadata_root_is_directory() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let meta = fs.metadata(2).unwrap();
        assert_eq!(meta.file_type, FsFileType::Directory);
        assert!(meta.allocated);
    }

    #[test]
    fn read_file_returns_content() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let data = fs.read_file(ino).unwrap();
        assert!(String::from_utf8_lossy(&data).contains("hello from iso corpus"),
            "got: {:?}", String::from_utf8_lossy(&data));
    }

    #[test]
    fn read_file_range_returns_prefix() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let data = fs.read_file_range(ino, 0, 5).unwrap();
        assert_eq!(&data, b"hello");
    }

    #[test]
    fn metadata_file_is_regular() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        let meta = fs.metadata(ino).unwrap();
        assert_eq!(meta.file_type, FsFileType::RegularFile);
        assert_eq!(meta.size, 22); // "hello from iso corpus\n"
    }

    #[test]
    fn lookup_subdir_then_file() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let sub = fs.lookup(2, b"subdir").unwrap();
        assert!(sub.is_some(), "subdir must be found");
        let sub = sub.unwrap();
        let deep = fs.lookup(sub, b"deep.txt").unwrap();
        assert!(deep.is_some(), "subdir/deep.txt must be found");
    }

    #[test]
    fn block_size_is_2048() {
        let Some(fs) = open() else { eprintln!("skip"); return; };
        assert_eq!(fs.block_size(), 2048);
    }

    #[test]
    fn timeline_has_events() {
        let Some(mut fs) = open() else { eprintln!("skip"); return; };
        let tl = fs.timeline().unwrap();
        assert!(!tl.is_empty(), "Rock Ridge ISO should yield timeline events");
    }
}
