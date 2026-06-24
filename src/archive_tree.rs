#![forbid(unsafe_code)]

//! Shared synthetic-inode directory tree for archive formats (zip, tar, 7z).
//!
//! Archives list a flat set of `path` entries; this builds the directory
//! hierarchy those paths imply, assigning synthetic inode numbers (root = 2,
//! mirroring the ext4/ISO convention) and auto-creating intermediate
//! directories that the archive did not list explicitly.
//!
//! Each leaf file carries an opaque `payload_id` — an index the concrete
//! format module uses to fetch the file's bytes from its backend (a zip entry
//! index, or a slot in an extracted-data vector). The tree itself never holds
//! file contents.

use crate::{FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp};
use std::collections::HashMap;

/// Root synthetic inode (mirrors ext4/ISO: root = 2).
pub const ROOT_INO: u64 = 2;

/// One node in the synthetic tree.
struct Node {
    name: Vec<u8>,
    is_dir: bool,
    size: u64,
    mtime: FsTimestamp,
    /// Backend payload handle for leaf files; `None` for directories.
    payload_id: Option<usize>,
    children: Vec<u64>,
}

/// A directory tree built from archive entry paths.
pub struct ArchiveTree {
    nodes: HashMap<u64, Node>,
    /// Map from a parent inode + child name to the child's inode, for fast
    /// path-component resolution while building and for `lookup`.
    index: HashMap<(u64, Vec<u8>), u64>,
    next_ino: u64,
}

impl Default for ArchiveTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveTree {
    /// Create an empty tree containing only the root directory.
    pub fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            ROOT_INO,
            Node {
                name: b"/".to_vec(),
                is_dir: true,
                size: 0,
                mtime: FsTimestamp::default(),
                payload_id: None,
                children: vec![],
            },
        );
        Self {
            nodes,
            index: HashMap::new(),
            next_ino: ROOT_INO + 1,
        }
    }

    /// Insert a file (or explicit directory) at `path`, creating any missing
    /// intermediate directories. Returns the leaf inode, or `None` if the path
    /// is unsafe (absolute, empty, or contains a `..` component) and was
    /// skipped.
    pub fn insert(
        &mut self,
        path: &str,
        is_dir: bool,
        size: u64,
        mtime: FsTimestamp,
        payload_id: Option<usize>,
    ) -> Option<u64> {
        let components = sanitize_path(path)?;
        if components.is_empty() {
            return None;
        }
        let last = components.len() - 1;
        let mut parent = ROOT_INO;
        for (i, comp) in components.iter().enumerate() {
            let leaf = i == last;
            let key = (parent, comp.clone());
            if let Some(&existing) = self.index.get(&key) {
                // A path may re-list an intermediate directory; reuse it. A leaf
                // colliding with an existing node keeps the first (archives can
                // carry duplicate names; the tree shows one).
                parent = existing;
                continue;
            }
            let ino = self.next_ino;
            self.next_ino += 1;
            let node = Node {
                name: comp.clone(),
                is_dir: if leaf { is_dir } else { true },
                size: if leaf && !is_dir { size } else { 0 },
                mtime: if leaf { mtime } else { FsTimestamp::default() },
                payload_id: if leaf && !is_dir { payload_id } else { None },
                children: vec![],
            };
            self.nodes.insert(ino, node);
            self.index.insert(key, ino);
            if let Some(p) = self.nodes.get_mut(&parent) {
                p.children.push(ino);
            }
            parent = ino;
        }
        Some(parent)
    }

    /// The root inode.
    pub fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    /// The backend payload handle for a leaf file, if any.
    pub fn payload_id(&self, ino: u64) -> Option<usize> {
        self.nodes.get(&ino).and_then(|n| n.payload_id)
    }

    /// List a directory's children.
    pub fn read_dir(&self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
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

    /// Look up a child by name within a directory.
    pub fn lookup(&self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        // Validate the parent exists so a lookup on a bogus inode errors rather
        // than silently returning "not found".
        self.node(parent_ino)?;
        Ok(self.index.get(&(parent_ino, name.to_vec())).copied())
    }

    /// Metadata for an inode.
    pub fn metadata(&self, ino: u64) -> FsResult<FsMetadata> {
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
            atime: node.mtime,
            mtime: node.mtime,
            ctime: node.mtime,
            crtime: node.mtime,
            allocated: true,
        })
    }

    fn node(&self, ino: u64) -> FsResult<&Node> {
        self.nodes
            .get(&ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))
    }

    /// Number of nodes (including the root), for diagnostics.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree holds only the root.
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }
}

/// Split an archive entry path into safe components, or `None` if the path is
/// absolute, empty, or escapes its root via a `..` component (zip-slip / tar
/// traversal). `.` and empty components are dropped; a trailing slash collapses.
fn sanitize_path(path: &str) -> Option<Vec<Vec<u8>>> {
    if path.starts_with('/') {
        return None;
    }
    let mut out = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => continue,
            ".." => return None,
            c => out.push(c.as_bytes().to_vec()),
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Seconds from the Unix epoch for a civil UTC date (Howard Hinnant's
/// algorithm). Shared by archive formats whose entry timestamps are broken-down
/// calendar fields (e.g. ZIP's MS-DOS date, 7z's component date).
pub(crate) fn civil_to_unix(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> i64 {
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

    fn ts() -> FsTimestamp {
        FsTimestamp {
            seconds: 1_700_000_000,
            nanoseconds: 0,
        }
    }

    #[test]
    fn new_tree_has_only_root() {
        let t = ArchiveTree::new();
        assert_eq!(t.root_ino(), ROOT_INO);
        assert!(t.is_empty());
        assert_eq!(
            t.metadata(ROOT_INO).unwrap().file_type,
            FsFileType::Directory
        );
    }

    #[test]
    fn insert_file_at_root() {
        let mut t = ArchiveTree::new();
        let ino = t.insert("hello.txt", false, 11, ts(), Some(0)).unwrap();
        assert_eq!(t.lookup(ROOT_INO, b"hello.txt").unwrap(), Some(ino));
        let meta = t.metadata(ino).unwrap();
        assert_eq!(meta.file_type, FsFileType::RegularFile);
        assert_eq!(meta.size, 11);
        assert_eq!(t.payload_id(ino), Some(0));
    }

    #[test]
    fn insert_creates_intermediate_dirs() {
        let mut t = ArchiveTree::new();
        let ino = t.insert("a/b/c.txt", false, 3, ts(), Some(0)).unwrap();
        let a = t.lookup(ROOT_INO, b"a").unwrap().expect("a created");
        assert_eq!(t.metadata(a).unwrap().file_type, FsFileType::Directory);
        let b = t.lookup(a, b"b").unwrap().expect("b created");
        let c = t.lookup(b, b"c.txt").unwrap().expect("c.txt created");
        assert_eq!(c, ino);
    }

    #[test]
    fn read_dir_lists_children() {
        let mut t = ArchiveTree::new();
        t.insert("x.txt", false, 1, ts(), Some(0)).unwrap();
        t.insert("y.txt", false, 1, ts(), Some(1)).unwrap();
        let names: Vec<String> = t
            .read_dir(ROOT_INO)
            .unwrap()
            .iter()
            .map(FsDirEntry::name_str)
            .collect();
        assert!(names.contains(&"x.txt".to_string()));
        assert!(names.contains(&"y.txt".to_string()));
    }

    #[test]
    fn explicit_dir_entry_is_directory() {
        let mut t = ArchiveTree::new();
        t.insert("subdir/", true, 0, ts(), None).unwrap();
        let d = t.lookup(ROOT_INO, b"subdir").unwrap().expect("subdir");
        assert_eq!(t.metadata(d).unwrap().file_type, FsFileType::Directory);
    }

    #[test]
    fn duplicate_intermediate_dir_is_shared() {
        let mut t = ArchiveTree::new();
        t.insert("a/b.txt", false, 1, ts(), Some(0)).unwrap();
        t.insert("a/c.txt", false, 1, ts(), Some(1)).unwrap();
        let a = t.lookup(ROOT_INO, b"a").unwrap().unwrap();
        let kids = t.read_dir(a).unwrap();
        assert_eq!(kids.len(), 2, "a/ holds exactly b.txt and c.txt");
    }

    #[test]
    fn unsafe_paths_are_skipped() {
        let mut t = ArchiveTree::new();
        assert_eq!(t.insert("../escape", false, 1, ts(), Some(0)), None);
        assert_eq!(t.insert("/abs", false, 1, ts(), Some(0)), None);
        assert_eq!(t.insert("", false, 1, ts(), Some(0)), None);
        assert_eq!(t.insert("a/../b", false, 1, ts(), Some(0)), None);
    }

    #[test]
    fn leading_dot_slash_normalized() {
        let mut t = ArchiveTree::new();
        let ino = t.insert("./file.txt", false, 1, ts(), Some(0)).unwrap();
        assert_eq!(t.lookup(ROOT_INO, b"file.txt").unwrap(), Some(ino));
    }

    #[test]
    fn metadata_missing_inode_errs() {
        let t = ArchiveTree::new();
        assert!(t.metadata(9999).is_err());
    }
}
