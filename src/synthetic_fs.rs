//! A synthetic, read-only [`ForensicFs`] over a **flat entry list** — the mount
//! adapter for containers the forensic-vfs engine cannot surface as a browsable
//! tree:
//!
//! * **archive containers** (zip / 7z / tar / tar.gz / tar.bz2) via
//!   [`archive_core::Archive`], and
//! * **logical containers** (FTK AD1 / AFF4-Logical / DAR) via
//!   [`disk_forensic::logical`].
//!
//! The engine's `Vfs::open_all` treats an archive's members as *nested-evidence*
//! candidates (looking for a disk image inside), never as files to browse, so a
//! file-bearing archive resolves to `fs: None` — or, worse, is claimed by the
//! AFF4 decoder (both are Zip-framed) and errors. Both container families expose
//! the same shape — a `[(path, is_dir, size)]` list plus a `read(index)` — so one
//! adapter serves both. The caller ([`crate::engine_fs::open_image_all`]) tries
//! logical and archive only when the engine yields nothing, so a real disk image
//! (including a *physical* AFF4) is never mis-claimed here.

use crate::{
    not_supported, ForensicFs, FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp,
};
use std::collections::HashMap;
use std::io;
use std::path::Path;

/// Root inode. The FUSE/Dokan layer pins the mount root to inode 1.
const ROOT_INO: u64 = 1;
const EPOCH: FsTimestamp = FsTimestamp {
    seconds: 0,
    nanoseconds: 0,
};

/// Reads one entry's bytes by its source index (`Archive::read` /
/// `LogicalImage::read_file`). `FnMut` because both readers take `&mut self`.
type ReadFn = Box<dyn FnMut(usize) -> io::Result<Vec<u8>> + Send>;

/// One node in the synthetic tree. Directories carry `children`; files carry the
/// source `entry` index handed back to the read callback.
struct Node {
    is_dir: bool,
    size: u64,
    entry: Option<usize>,
    /// child ino keyed by name (directories only)
    children: HashMap<Vec<u8>, u64>,
}

/// A read-only filesystem materialized from a flat entry list.
pub struct SyntheticFs {
    /// `ino == index + 1`; `nodes[0]` is the root (ino 1).
    nodes: Vec<Node>,
    read: ReadFn,
    /// Keeps a peeled-image temp file alive for the mount's lifetime; dropped
    /// (and unlinked) only when the filesystem is.
    _tmp: Option<tempfile::TempPath>,
}

impl SyntheticFs {
    /// Build the tree from `(path, is_dir, size, entry_index)` tuples. Paths are
    /// `/`-separated; a leading `./`, empty, or `.` component is skipped, and
    /// intermediate directories are created on demand (archives often omit
    /// explicit directory entries). A directory always wins over a same-named
    /// file placeholder.
    fn build(entries: impl IntoIterator<Item = (String, bool, u64, usize)>, read: ReadFn) -> Self {
        let mut nodes = vec![Node {
            is_dir: true,
            size: 0,
            entry: None,
            children: HashMap::new(),
        }];
        for (path, is_dir, size, entry) in entries {
            let comps: Vec<&str> = path
                .split('/')
                .map(str::trim)
                .filter(|c| !c.is_empty() && *c != ".")
                .collect();
            if comps.is_empty() {
                continue;
            }
            let mut parent = 0usize; // root index
            for (i, comp) in comps.iter().enumerate() {
                let last = i + 1 == comps.len();
                let key = comp.as_bytes().to_vec();
                if let Some(&child_ino) = nodes[parent].children.get(&key) {
                    parent = (child_ino - 1) as usize;
                    continue;
                }
                let leaf_file = last && !is_dir;
                nodes.push(Node {
                    is_dir: !leaf_file,
                    size: if leaf_file { size } else { 0 },
                    entry: if leaf_file { Some(entry) } else { None },
                    children: HashMap::new(),
                });
                let ino = nodes.len() as u64; // 1-based
                nodes[parent].children.insert(key, ino);
                parent = (ino - 1) as usize;
            }
        }
        SyntheticFs {
            nodes,
            read,
            _tmp: None,
        }
    }

    /// Attach a peeled-image temp file so it outlives the mount (set at
    /// construction, mirroring `EngineFs`/`MultiPartitionFs`).
    pub(crate) fn with_tmp(self, tmp: Option<tempfile::TempPath>) -> Self {
        Self { _tmp: tmp, ..self }
    }

    fn node(&self, ino: u64) -> FsResult<&Node> {
        ino.checked_sub(1)
            .and_then(|i| self.nodes.get(i as usize))
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))
    }
}

impl ForensicFs for SyntheticFs {
    fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let node = self.node(ino)?;
        if !node.is_dir {
            return Err(FsError::Other(format!("not a directory: inode {ino}")));
        }
        let mut out = Vec::with_capacity(node.children.len());
        for (name, &child) in &node.children {
            let file_type = if self.nodes[(child - 1) as usize].is_dir {
                FsFileType::Directory
            } else {
                FsFileType::RegularFile
            };
            out.push(FsDirEntry {
                inode: child,
                name: name.clone(),
                file_type,
            });
        }
        Ok(out)
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        Ok(self.node(parent_ino)?.children.get(name).copied())
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let node = self.node(ino)?;
        Ok(FsMetadata {
            ino,
            file_type: if node.is_dir {
                FsFileType::Directory
            } else {
                FsFileType::RegularFile
            },
            mode: if node.is_dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            size: node.size,
            links_count: 1,
            atime: EPOCH,
            mtime: EPOCH,
            ctime: EPOCH,
            crtime: EPOCH,
            allocated: true,
        })
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let entry = {
            let node = self.node(ino)?;
            if node.is_dir {
                return Err(FsError::Other(format!("is a directory: inode {ino}")));
            }
            node.entry
                .ok_or_else(|| FsError::NotFound(format!("no source entry for inode {ino}")))?
        };
        (self.read)(entry).map_err(FsError::Io)
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let all = self.read_file(ino)?;
        let start = (offset as usize).min(all.len());
        let end = start.saturating_add(len as usize).min(all.len());
        Ok(all[start..end].to_vec())
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("read_link"))
    }
}

/// Try to mount `path` as a **logical** container (AD1 / AFF4-Logical / DAR).
/// `Ok(None)` when it is not a logical container (a physical disk, incl. a
/// physical AFF4, is rejected as `NotLogical` and left to the engine).
pub(crate) fn try_open_logical(path: &Path) -> io::Result<Option<SyntheticFs>> {
    use disk_forensic::logical::{self, LogicalError};
    match logical::open(path) {
        Ok(mut img) => {
            let entries: Vec<(String, bool, u64, usize)> = img
                .entries()
                .iter()
                .enumerate()
                .map(|(i, e)| (e.path.clone(), e.is_dir, e.size, i))
                .collect();
            let read: ReadFn = Box::new(move |i| {
                img.read_file(i)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
            });
            Ok(Some(SyntheticFs::build(entries, read)))
        }
        Err(LogicalError::NotLogical(..)) => Ok(None),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// Try to mount `path` as an **archive** container (zip / 7z / tar / tar.gz /
/// tar.bz2). `Ok(None)` when it is not an archive.
pub(crate) fn try_open_archive(path: &Path) -> io::Result<Option<SyntheticFs>> {
    let data = std::fs::read(path)?;
    let name = path.file_name().and_then(|n| n.to_str());
    match archive_core::Archive::open(&data, name) {
        Ok(Some(mut arc)) => {
            let entries: Vec<(String, bool, u64, usize)> = arc
                .entries()
                .iter()
                .enumerate()
                .map(|(i, e)| (e.name.clone(), e.is_dir, e.size, i))
                .collect();
            let read: ReadFn = Box::new(move |i| {
                arc.read(i)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
            });
            Ok(Some(SyntheticFs::build(entries, read)))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}
