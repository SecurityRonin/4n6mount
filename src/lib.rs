#![forbid(unsafe_code)]

pub mod detect;
pub mod filter;
pub mod fusefs;
pub mod inode_map;
pub mod session;
pub mod types;

#[cfg(unix)]
pub mod fuse_unix;
pub mod fuse_windows;

#[cfg(feature = "ext4")]
pub mod fs_ext4;

#[cfg(feature = "iso")]
pub mod fs_iso;

pub mod fs_raw;

pub use types::*;

use std::io;
use std::path::Path;

/// Mount options for the FUSE filesystem.
///
/// Platform-agnostic configuration consumed by both the Unix (fuser)
/// and Windows (`WinFSP`) mount backends.
pub struct MountOptions {
    pub read_only: bool,
    pub daemon: bool,
    pub fs_name: String,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            daemon: false,
            fs_name: "4n6mount".to_string(),
        }
    }
}

/// The core trait that filesystem crates implement.
///
/// Provides both standard filesystem access (required methods) and
/// forensic operations (optional, with sensible defaults).
pub trait ForensicFs {
    // --- Core filesystem ops (required) ---

    /// The root directory inode number for this filesystem.
    fn root_ino(&self) -> u64;

    /// List directory entries for the given inode.
    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>>;

    /// Look up a name in a directory, returning the child inode if found.
    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>>;

    /// Get file/directory metadata for an inode.
    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata>;

    /// Read the entire contents of a file.
    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>>;

    /// Read a range of bytes from a file.
    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>>;

    /// Read the target of a symbolic link.
    fn read_link(&mut self, ino: u64) -> FsResult<Vec<u8>>;

    // --- Forensic ops (optional) ---

    /// List deleted inodes.
    fn deleted_inodes(&mut self) -> FsResult<Vec<FsDeletedInode>> {
        Ok(vec![])
    }

    /// Attempt to recover a deleted file by inode number.
    fn recover_file(&mut self, _ino: u64) -> FsResult<FsRecoveryResult> {
        Err(not_supported("recover_file"))
    }

    /// Generate a forensic timeline of all filesystem events.
    fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> {
        Ok(vec![])
    }

    /// Get all unallocated block ranges.
    fn unallocated_blocks(&mut self) -> FsResult<Vec<FsBlockRange>> {
        Ok(vec![])
    }

    /// Read raw data from an unallocated block range.
    fn read_unallocated(&mut self, _range: &FsBlockRange) -> FsResult<Vec<u8>> {
        Err(not_supported("read_unallocated"))
    }

    /// List journal transactions.
    fn journal_transactions(&mut self) -> FsResult<Vec<FsTransaction>> {
        Ok(vec![])
    }

    /// Get filesystem-specific info as JSON (superblock, volume label, etc.).
    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }

    /// The block size of this filesystem.
    fn block_size(&self) -> u64 {
        4096
    }
}

/// Mount a forensic filesystem via FUSE (or `WinFSP` on Windows).
///
/// This is the main entry point for consumers.  Pass a `ForensicFs`
/// implementation and a `MountOptions`, and this dispatches to the
/// correct platform backend.
///
/// On Unix the mount is handled by `fuser`.  On Windows it will be
/// handled by `winfsp-wrs` (currently a stub that returns
/// `Unsupported`).
pub fn mount(
    fs: Box<dyn ForensicFs + Send>,
    mountpoint: &Path,
    session: Option<session::Session>,
    options: &MountOptions,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        fuse_unix::mount_unix(fs, mountpoint, session, options)
    }
    #[cfg(windows)]
    {
        fuse_windows::mount_windows(fs, mountpoint, session, options)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (fs, mountpoint, session, options);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no FUSE support on this platform",
        ))
    }
}
