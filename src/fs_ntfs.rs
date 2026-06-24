#![forbid(unsafe_code)]

//! NTFS filesystem support via the `ntfs-core` crate. Enabled with the `ntfs`
//! feature flag.
//!
//! NTFS already numbers every file by its `$MFT` record, so those record
//! numbers serve directly as inodes (root = record 5, the `.` directory, per
//! the NTFS on-disk layout). The directory tree is walked once at open from the
//! root: each entry's record is read to classify it (a directory carries an
//! `$INDEX_ROOT`, so `directory_entries` succeeds; a file does not), and the
//! full path is cached so file reads can go through `ntfs-core`'s path-based
//! `read_file` (which transparently handles fragmented/compressed `$DATA`).
//!
//! DOS (8.3) short-name index entries are dropped so each file appears once
//! under its long name.

use crate::{
    not_supported, ForensicFs, FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp,
};
use ntfs_core::fs::NtfsFs;
use ntfs_core::time::Filetime;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};

/// Root inode: `$MFT` record 5 is the root directory in NTFS.
const ROOT_INO: u64 = 5;

/// Upper bound on tree nodes built at open, so a hostile/huge MFT cannot make
/// the walk run away. Real volumes have far fewer reachable entries than this.
const MAX_NODES: usize = 5_000_000;

/// One node in the cached directory tree.
struct NtfsNode {
    name: Vec<u8>,
    is_dir: bool,
    size: u64,
    atime: FsTimestamp,
    mtime: FsTimestamp,
    ctime: FsTimestamp,
    crtime: FsTimestamp,
    /// Root-relative `/`-joined path, used for `ntfs-core`'s path-based reads.
    path: String,
    children: Vec<u64>,
}

/// `ForensicFs` implementation for NTFS volumes.
pub struct NtfsForensicFs<R: Read + Seek> {
    fs: NtfsFs<R>,
    nodes: HashMap<u64, NtfsNode>,
    /// (parent inode, child name) -> child inode, for `lookup`.
    index: HashMap<(u64, Vec<u8>), u64>,
}

fn ts(ft: Filetime) -> FsTimestamp {
    if ft.is_zero() {
        return FsTimestamp::default();
    }
    FsTimestamp {
        seconds: ft.to_unix_seconds(),
        nanoseconds: (ft.to_unix_nanos().rem_euclid(1_000_000_000)) as u32,
    }
}

impl<R: Read + Seek> NtfsForensicFs<R> {
    /// Open an NTFS volume and walk its directory tree.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the boot sector or `$MFT` cannot be parsed.
    pub fn new(source: R) -> Result<Self, FsError> {
        let mut fs =
            NtfsFs::open(source).map_err(|e| FsError::Corrupt(format!("not NTFS: {e}")))?;

        let mut nodes: HashMap<u64, NtfsNode> = HashMap::new();
        nodes.insert(
            ROOT_INO,
            NtfsNode {
                name: b"/".to_vec(),
                is_dir: true,
                size: 0,
                atime: FsTimestamp::default(),
                mtime: FsTimestamp::default(),
                ctime: FsTimestamp::default(),
                crtime: FsTimestamp::default(),
                path: String::new(),
                children: vec![],
            },
        );
        let mut index: HashMap<(u64, Vec<u8>), u64> = HashMap::new();

        // Iterative DFS from the root directory. `visited` guards against
        // revisiting a directory (cycles / hardlinked dirs); files reachable via
        // multiple parents share one inode (the MFT record number) by design.
        let mut visited: HashSet<u64> = HashSet::new();
        visited.insert(ROOT_INO);
        let mut stack = vec![ROOT_INO];

        while let Some(rec) = stack.pop() {
            if nodes.len() >= MAX_NODES {
                break;
            }
            let Ok(record) = fs.read_record(rec) else {
                continue;
            };
            let Ok(entries) = fs.directory_entries(&record) else {
                continue; // not a directory after all
            };
            let parent_path = nodes.get(&rec).map(|n| n.path.clone()).unwrap_or_default();

            for entry in entries {
                let Some(fnm) = entry.file_name else { continue };
                // Drop DOS 8.3 short names so each file appears once.
                if fnm.is_dos_namespace() {
                    continue;
                }
                if fnm.name == "." || fnm.name == ".." {
                    continue;
                }
                let child = entry.file_reference.record_number;
                if child == rec {
                    continue;
                }

                // Classify by reading the child's record: a directory carries an
                // $INDEX_ROOT, so directory_entries succeeds.
                let Ok(child_record) = fs.read_record(child) else {
                    continue;
                };
                let is_dir = fs.directory_entries(&child_record).is_ok();

                let name_bytes = fnm.name.clone().into_bytes();
                let path = if parent_path.is_empty() {
                    fnm.name.clone()
                } else {
                    format!("{parent_path}/{}", fnm.name)
                };

                nodes.entry(child).or_insert_with(|| NtfsNode {
                    name: name_bytes.clone(),
                    is_dir,
                    size: fnm.real_size,
                    atime: ts(fnm.accessed),
                    mtime: ts(fnm.modified),
                    ctime: ts(fnm.mft_modified),
                    crtime: ts(fnm.created),
                    path,
                    children: vec![],
                });

                // Link under the parent once (a record can be index-listed twice).
                let key = (rec, name_bytes);
                if !index.contains_key(&key) {
                    index.insert(key, child);
                    if let Some(p) = nodes.get_mut(&rec) {
                        p.children.push(child);
                    }
                }

                if is_dir && visited.insert(child) {
                    stack.push(child);
                }
            }
        }

        Ok(Self { fs, nodes, index })
    }

    fn node(&self, ino: u64) -> FsResult<&NtfsNode> {
        self.nodes
            .get(&ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))
    }
}

impl<R: Read + Seek> ForensicFs for NtfsForensicFs<R> {
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
                    file_type: if c.is_dir {
                        FsFileType::Directory
                    } else {
                        FsFileType::RegularFile
                    },
                });
            }
        }
        Ok(out)
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        self.node(parent_ino)?;
        Ok(self.index.get(&(parent_ino, name.to_vec())).copied())
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let node = self.node(ino)?;
        let (file_type, mode) = if node.is_dir {
            (FsFileType::Directory, 0o40555)
        } else {
            (FsFileType::RegularFile, 0o100_444)
        };
        Ok(FsMetadata {
            ino,
            file_type,
            mode,
            uid: 0,
            gid: 0,
            size: node.size,
            links_count: 1,
            atime: node.atime,
            mtime: node.mtime,
            ctime: node.ctime,
            crtime: node.crtime,
            allocated: true,
        })
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let node = self.node(ino)?;
        if node.is_dir {
            return Err(not_supported("read_file on a directory"));
        }
        let path = node.path.clone();
        self.fs
            .read_file(&path)
            .map_err(|e| FsError::Io(std::io::Error::other(e.to_string())))
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let data = self.read_file(ino)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("NTFS reparse points not resolved"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "ntfs",
            "entries": self.nodes.len(),
            "cluster_size": self.fs.boot().cluster_size(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Extract the real NTFS volume `partition.dd` from the committed
    /// `SampleTinyNtfsVolume.zip` in the sibling `ntfs-forensic` repo (a real
    /// Windows-authored NTFS volume — the ground truth below comes from TSK
    /// `fls`/`icat`). `None` if the corpus or `unzip` is unavailable.
    fn load_ntfs() -> Option<Vec<u8>> {
        let zip = "/Users/4n6h4x0r/src/ntfs-forensic/tests/data/SampleTinyNtfsVolume.zip";
        let out = std::process::Command::new("unzip")
            .args(["-p", zip, "SampleTinyNtfsVolume/partition.dd"])
            .output()
            .ok()?;
        if !out.status.success() || out.stdout.is_empty() {
            return None;
        }
        Some(out.stdout)
    }

    fn open() -> Option<NtfsForensicFs<Cursor<Vec<u8>>>> {
        NtfsForensicFs::new(Cursor::new(load_ntfs()?)).ok()
    }

    #[test]
    fn root_ino_is_5() {
        let Some(fs) = open() else {
            eprintln!("skip: ntfs corpus unavailable");
            return;
        };
        assert_eq!(fs.root_ino(), 5);
    }

    #[test]
    fn root_lists_user_files() {
        // TSK fls: root holds file1.txt .. file8.txt and $RECYCLE.BIN.
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let names: Vec<String> = fs
            .read_dir(5)
            .unwrap()
            .iter()
            .map(FsDirEntry::name_str)
            .collect();
        for f in ["file1.txt", "file2.txt", "file8.txt"] {
            assert!(names.contains(&f.to_string()), "missing {f}, got {names:?}");
        }
        assert!(names.contains(&"$RECYCLE.BIN".to_string()), "got {names:?}");
    }

    #[test]
    fn file1_resolves_to_record_37() {
        // TSK fls: file1.txt is MFT record 37.
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.lookup(5, b"file1.txt").unwrap(), Some(37));
    }

    #[test]
    fn file1_content_matches_icat() {
        // TSK `icat partition.dd 37` begins with this resident text.
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(5, b"file1.txt").unwrap().unwrap();
        let data = fs.read_file(ino).unwrap();
        assert!(
            data.starts_with(b"Just some bogus text to be kept resident in $MFT."),
            "got: {:?}",
            String::from_utf8_lossy(&data[..data.len().min(60)])
        );
    }

    #[test]
    fn file1_is_regular_recycle_is_dir() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let f = fs.lookup(5, b"file1.txt").unwrap().unwrap();
        assert_eq!(fs.metadata(f).unwrap().file_type, FsFileType::RegularFile);
        let r = fs.lookup(5, b"$RECYCLE.BIN").unwrap().unwrap();
        assert_eq!(fs.metadata(r).unwrap().file_type, FsFileType::Directory);
    }

    #[test]
    fn fs_info_reports_ntfs() {
        let Some(fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.fs_info().unwrap()["type"], "ntfs");
    }
}
