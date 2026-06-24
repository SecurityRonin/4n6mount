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
        let _ = (
            ROOT_INO,
            FsFileType::Directory,
            FsError::NotFound(String::new()),
        );
        todo!("ArchiveTree::new")
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
        let _ = (path, is_dir, size, mtime, payload_id);
        todo!("ArchiveTree::insert")
    }

    /// The root inode.
    pub fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    /// The backend payload handle for a leaf file, if any.
    pub fn payload_id(&self, ino: u64) -> Option<usize> {
        let _ = ino;
        todo!("ArchiveTree::payload_id")
    }

    /// List a directory's children.
    pub fn read_dir(&self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let _ = ino;
        todo!("ArchiveTree::read_dir")
    }

    /// Look up a child by name within a directory.
    pub fn lookup(&self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        let _ = (parent_ino, name);
        todo!("ArchiveTree::lookup")
    }

    /// Metadata for an inode.
    pub fn metadata(&self, ino: u64) -> FsResult<FsMetadata> {
        let _ = ino;
        todo!("ArchiveTree::metadata")
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
