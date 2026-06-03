#![forbid(unsafe_code)]

//! ISO 9660 / Rock Ridge / Joliet filesystem support via the
//! `iso9660-forensic` crate.  Enabled with the `iso` feature flag.
//!
//! ISO 9660 has no native inode numbers, so synthetic inodes are assigned by
//! walking the directory tree once at open time (root = 2, entries from 3 up).
//! ISO is a read-only optical format: there are no deleted inodes, no journal,
//! and no writable overlay.

use crate::{
    not_supported, ForensicFs, FsBlockRange, FsDirEntry, FsError, FsEventType, FsFileType,
    FsMetadata, FsResult, FsTimelineEvent, FsTimestamp,
};
use iso9660_forensic::{rock_ridge, DirRecord, IsoReader};
use std::collections::HashMap;
use std::io::{Read, Seek};

/// Root synthetic inode (mirrors ext4's convention of root = 2).
const ROOT_INO: u64 = 2;

/// One node in the synthetic inode table.
struct IsoNode {
    #[allow(dead_code)]
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

        let entries = reader
            .walk()
            .map_err(|e| FsError::Corrupt(format!("walk failed: {e}")))?;

        let mut nodes: HashMap<u64, IsoNode> = HashMap::new();
        nodes.insert(
            ROOT_INO,
            IsoNode { parent: ROOT_INO, name: b"/".to_vec(), is_dir: true, record: None, children: vec![] },
        );

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

    /// Classify a node into a filesystem file type.
    fn file_type_of(node: &IsoNode) -> FsFileType {
        if node.is_dir {
            return FsFileType::Directory;
        }
        if let Some(rec) = &node.record {
            if rock_ridge::symlink_target(&rec.system_use).is_some() {
                return FsFileType::Symlink;
            }
        }
        FsFileType::RegularFile
    }
}

impl<R: Read + Seek> ForensicFs for IsoForensicFs<R> {
    fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let node = self.node(ino)?;
        let mut out = Vec::with_capacity(node.children.len());
        for &child in &node.children {
            if let Some(c) = self.nodes.get(&child) {
                out.push(FsDirEntry {
                    inode: child,
                    name: c.name.clone(),
                    file_type: Self::file_type_of(c),
                });
            }
        }
        Ok(out)
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        let node = self.node(parent_ino)?;
        for &child in &node.children {
            if let Some(c) = self.nodes.get(&child) {
                if c.name == name {
                    return Ok(Some(child));
                }
            }
        }
        Ok(None)
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let node = self.node(ino)?;
        let file_type = Self::file_type_of(node);
        let size = node.record.as_ref().map_or(0, |r| u64::from(r.size));

        // Rock Ridge POSIX attributes, if present.
        let px = node
            .record
            .as_ref()
            .and_then(|r| rock_ridge::posix_attrs(&r.system_use));
        let (mode, uid, gid, nlink) = match px {
            Some(p) => (
                (p.mode & 0o7777) as u16,
                p.uid,
                p.gid,
                p.nlink.min(u32::from(u16::MAX)) as u16,
            ),
            None => {
                let m = if node.is_dir { 0o555 } else { 0o444 };
                (m, 0, 0, 1)
            }
        };

        // Rock Ridge timestamps (short form), if present.
        let tf = node
            .record
            .as_ref()
            .and_then(|r| rock_ridge::timestamps(&r.system_use));
        let mtime = tf.as_ref().and_then(|t| t.modify).map(short_ts_to_unix).unwrap_or_default();
        let atime = tf.as_ref().and_then(|t| t.access).map(short_ts_to_unix).unwrap_or(mtime);
        let ctime = tf.as_ref().and_then(|t| t.attributes).map(short_ts_to_unix).unwrap_or(mtime);
        let crtime = tf.as_ref().and_then(|t| t.creation).map(short_ts_to_unix).unwrap_or(mtime);

        Ok(FsMetadata {
            ino,
            file_type,
            mode,
            uid,
            gid,
            size,
            links_count: nlink,
            atime,
            mtime,
            ctime,
            crtime,
            allocated: true,
        })
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let record = self
            .node(ino)?
            .record
            .clone()
            .ok_or_else(|| FsError::NotFound(format!("inode {ino} has no data")))?;
        if record.is_dir() {
            return Err(not_supported("read_file on a directory"));
        }
        self.reader
            .read_file_entry(&record)
            .map_err(|e| FsError::Io(std::io::Error::other(e.to_string())))
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let data = self.read_file(ino)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn read_link(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let record = self
            .node(ino)?
            .record
            .clone()
            .ok_or_else(|| not_supported("read_link on root"))?;
        rock_ridge::symlink_target(&record.system_use)
            .map(String::into_bytes)
            .ok_or_else(|| not_supported("not a symlink"))
    }

    fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> {
        let tl = self
            .reader
            .timeline()
            .map_err(|e| FsError::Io(std::io::Error::other(e.to_string())))?;
        // Build a path -> inode map for cross-referencing.
        let mut path_ino: HashMap<&[u8], u64> = HashMap::new();
        for (ino, node) in &self.nodes {
            path_ino.insert(node.name.as_slice(), *ino);
        }
        let mut out = Vec::new();
        for e in tl {
            let ts = e.modify_ts.map(short_ts_to_unix).unwrap_or_default();
            let base = e.path.rsplit('/').next().unwrap_or(&e.path).as_bytes();
            let ino = path_ino.get(base).copied().unwrap_or(0);
            out.push(FsTimelineEvent {
                timestamp: ts,
                event_type: FsEventType::Modified,
                inode: ino,
                size: u64::from(e.size),
                uid: 0,
                gid: 0,
            });
        }
        Ok(out)
    }

    fn unallocated_blocks(&mut self) -> FsResult<Vec<FsBlockRange>> {
        let gaps = self
            .reader
            .audit_sector_gaps()
            .map_err(|e| FsError::Io(std::io::Error::other(e.to_string())))?;
        Ok(gaps
            .into_iter()
            .filter(|g| g.nonzero)
            .map(|g| FsBlockRange { start: u64::from(g.lba), length: 1 })
            .collect())
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "iso9660",
            "volume_label": self.reader.volume_label(),
            "system_id": self.reader.system_id(),
            "application_id": self.reader.application_id(),
            "data_preparer": self.reader.data_preparer_id(),
            "volume_space_size": self.reader.volume_space_size(),
            "rock_ridge": self.reader.has_rock_ridge(),
            "joliet": self.reader.has_joliet(),
            "udf": self.reader.has_udf(),
            "sessions": self.reader.session_count(),
        }))
    }

    fn block_size(&self) -> u64 {
        2048
    }
}

/// Convert a 7-byte Rock Ridge short timestamp to a Unix `FsTimestamp`.
///
/// Layout: `[year-1900, month, day, hour, min, sec, tz_offset_15min(i8)]`.
fn short_ts_to_unix(t: [u8; 7]) -> FsTimestamp {
    let year = 1900_i64 + i64::from(t[0]);
    let secs = civil_to_unix(year, i64::from(t[1]), i64::from(t[2]),
        i64::from(t[3]), i64::from(t[4]), i64::from(t[5]));
    // tz offset is signed, in 15-minute units; local = utc + offset.
    let tz = i64::from(t[6] as i8) * 15 * 60;
    FsTimestamp { seconds: secs - tz, nanoseconds: 0 }
}

/// Days/seconds from the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn civil_to_unix(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hh * 3_600 + mm * 60 + ss
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

    #[test]
    fn fs_info_reports_iso() {
        let Some(fs) = open() else { eprintln!("skip"); return; };
        let info = fs.fs_info().unwrap();
        assert_eq!(info["type"], "iso9660");
        assert_eq!(info["rock_ridge"], true);
    }

    #[test]
    fn civil_to_unix_epoch() {
        // 1970-01-01T00:00:00 -> 0
        assert_eq!(civil_to_unix(1970, 1, 1, 0, 0, 0), 0);
        // 2000-01-01T00:00:00 -> 946684800
        assert_eq!(civil_to_unix(2000, 1, 1, 0, 0, 0), 946_684_800);
    }
}
