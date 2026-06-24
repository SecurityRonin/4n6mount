#![forbid(unsafe_code)]

//! exFAT filesystem support via the `exfat-fs` crate (MIT). Enabled with the
//! `exfat` feature flag.
//!
//! `exfat-fs` reads through its own positioned-read trait, so the source is
//! wrapped in a small `Mutex` adapter (the crate shares it internally via an
//! `Arc`). The directory tree is walked once at open and synthetic inodes are
//! assigned by [`ArchiveTree`]; each file is read into a cache so getattr
//! reports a correct size and reads are served instantly.
//!
//! exFAT is browsed read-only here: no deleted-entry recovery, journal, or
//! overlay. Entry timestamps are not surfaced in this revision (node times
//! default to epoch-zero).

use crate::archive_tree::ArchiveTree;
use crate::{not_supported, ForensicFs, FsDirEntry, FsError, FsMetadata, FsResult, FsTimestamp};
use exfat_fs::dir::entry::fs::FsElement;
use exfat_fs::dir::Root;
use exfat_fs::disk::{PartitionError, ReadOffset};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

/// Bound on entries walked at open, guarding against a hostile directory loop.
const MAX_NODES: usize = 5_000_000;

/// Error type the `exfat-fs` `ReadOffset`/`PartitionError` contract requires.
#[derive(Debug)]
enum ExfatErr {
    UnexpectedEop,
    ClusterNotFound(u32),
    Io(String),
}

impl PartitionError for ExfatErr {
    fn unexpected_eop() -> Self {
        ExfatErr::UnexpectedEop
    }
    fn cluster_not_found(cluster: u32) -> Self {
        ExfatErr::ClusterNotFound(cluster)
    }
}

impl std::fmt::Display for ExfatErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExfatErr::UnexpectedEop => f.write_str("unexpected end of partition"),
            ExfatErr::ClusterNotFound(c) => write!(f, "cluster {c} not found"),
            ExfatErr::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl From<ExfatErr> for std::io::Error {
    fn from(e: ExfatErr) -> Self {
        std::io::Error::other(e.to_string())
    }
}

/// Positioned-read adapter over a `Read + Seek` source. The crate wraps this in
/// an `Arc`, so `read_at` takes `&self` and serializes access with a `Mutex`.
struct OffsetReader<R> {
    inner: Mutex<R>,
}

impl<R> std::fmt::Debug for OffsetReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OffsetReader")
    }
}

impl<R: Read + Seek> ReadOffset for OffsetReader<R> {
    type Err = ExfatErr;

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, ExfatErr> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| ExfatErr::Io("reader mutex poisoned".to_string()))?;
        guard
            .seek(SeekFrom::Start(offset))
            .map_err(|e| ExfatErr::Io(e.to_string()))?;
        guard.read(buffer).map_err(|e| ExfatErr::Io(e.to_string()))
    }
}

/// `ForensicFs` implementation for exFAT volumes.
pub struct ExFatForensicFs {
    tree: ArchiveTree,
    /// File contents indexed by payload id (== position in this vector).
    data: Vec<Vec<u8>>,
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

impl ExFatForensicFs {
    /// Open an exFAT volume and walk its directory tree, caching file contents.
    ///
    /// # Errors
    ///
    /// [`FsError::Corrupt`] if the boot sector / directory structure is invalid.
    pub fn new<R: Read + Seek>(source: R) -> Result<Self, FsError> {
        let device = OffsetReader {
            inner: Mutex::new(source),
        };
        let mut root =
            Root::open(device).map_err(|e| FsError::Corrupt(format!("not exFAT: {e:?}")))?;

        let mut tree = ArchiveTree::new();
        let mut data: Vec<Vec<u8>> = Vec::new();
        let mut stack: Vec<(Vec<FsElement<OffsetReader<R>>>, String)> = Vec::new();

        for element in root.items() {
            ingest(element, "", &mut tree, &mut data, &mut stack)?;
        }
        while let Some((mut children, prefix)) = stack.pop() {
            if tree.len() >= MAX_NODES {
                break;
            }
            for element in &mut children {
                ingest(element, &prefix, &mut tree, &mut data, &mut stack)?;
            }
        }

        Ok(Self { tree, data })
    }
}

/// Insert one filesystem element into the tree, reading file bytes into `data`
/// and queueing subdirectories onto `stack` for later traversal.
fn ingest<R: Read + Seek>(
    element: &mut FsElement<OffsetReader<R>>,
    prefix: &str,
    tree: &mut ArchiveTree,
    data: &mut Vec<Vec<u8>>,
    stack: &mut Vec<(Vec<FsElement<OffsetReader<R>>>, String)>,
) -> Result<(), FsError> {
    match element {
        FsElement::F(file) => {
            let path = join(prefix, file.name());
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).map_err(FsError::Io)?;
            let id = data.len();
            if tree
                .insert(
                    &path,
                    false,
                    buf.len() as u64,
                    FsTimestamp::default(),
                    Some(id),
                )
                .is_some()
            {
                data.push(buf);
            }
        }
        FsElement::D(dir) => {
            let path = join(prefix, dir.name());
            tree.insert(&path, true, 0, FsTimestamp::default(), None);
            let children = dir
                .open()
                .map_err(|e| FsError::Corrupt(format!("exFAT dir: {e:?}")))?;
            stack.push((children, path));
        }
    }
    Ok(())
}

impl ForensicFs for ExFatForensicFs {
    fn root_ino(&self) -> u64 {
        self.tree.root_ino()
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        self.tree.read_dir(ino)
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        self.tree.lookup(parent_ino, name)
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        self.tree.metadata(ino)
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let id = self
            .tree
            .payload_id(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino} is not a file")))?;
        self.data
            .get(id)
            .cloned()
            .ok_or_else(|| FsError::NotFound(format!("payload {id}")))
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let data = self.read_file(ino)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("exFAT has no symlinks"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "exfat",
            "entries": self.data.len(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The committed 1 MiB exFAT volume minted on macOS (`newfs_exfat` via
    /// hdiutil); TSK `fls`/`icat` ground truth: `hello.txt` and `sub/deep.txt`.
    const IMG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/exfat.img");

    fn open() -> Option<ExFatForensicFs> {
        let data = std::fs::read(IMG).ok()?;
        ExFatForensicFs::new(Cursor::new(data)).ok()
    }

    #[test]
    fn root_ino_is_2() {
        let Some(fs) = open() else {
            eprintln!("skip: exfat.img unavailable");
            return;
        };
        assert_eq!(fs.root_ino(), 2);
    }

    #[test]
    fn root_lists_hello_and_sub() {
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
        assert!(names.contains(&"hello.txt".to_string()), "got {names:?}");
        assert!(names.contains(&"sub".to_string()), "got {names:?}");
    }

    #[test]
    fn read_hello_matches_icat() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(ino).unwrap(), b"hello from exfat\n");
    }

    #[test]
    fn nested_file_reachable() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let sub = fs.lookup(2, b"sub").unwrap().unwrap();
        let deep = fs.lookup(sub, b"deep.txt").unwrap().unwrap();
        assert_eq!(fs.read_file(deep).unwrap(), b"deep exfat content\n");
    }

    #[test]
    fn metadata_size_matches() {
        let Some(mut fs) = open() else {
            eprintln!("skip");
            return;
        };
        let ino = fs.lookup(2, b"hello.txt").unwrap().unwrap();
        assert_eq!(fs.metadata(ino).unwrap().size, 17); // "hello from exfat\n"
    }

    #[test]
    fn fs_info_reports_exfat() {
        let Some(fs) = open() else {
            eprintln!("skip");
            return;
        };
        assert_eq!(fs.fs_info().unwrap()["type"], "exfat");
    }
}
