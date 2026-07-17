#![forbid(unsafe_code)]

//! The filesystem-agnostic value types the FUSE/Dokan mount layer speaks.
//!
//! These are 4n6mount's own FUSE-facing vocabulary — a small, `u64`-inode,
//! serde-friendly model that the mount callbacks (`getattr`/`readdir`/`read`/…)
//! consume directly. A concrete backend (the memory VFS, or the disk-image
//! [`EngineFs`](crate::EngineFs) adapter over `forensic-vfs`) converts its native
//! representation into these types via the [`ForensicFs`](crate::ForensicFs)
//! trait.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Filesystem-agnostic file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsFileType {
    RegularFile,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown,
}

/// Filesystem-agnostic timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FsTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// Filesystem-agnostic file metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsMetadata {
    pub ino: u64,
    pub file_type: FsFileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links_count: u16,
    pub atime: FsTimestamp,
    pub mtime: FsTimestamp,
    pub ctime: FsTimestamp,
    pub crtime: FsTimestamp,
    pub allocated: bool,
}

/// Filesystem-agnostic directory entry.
#[derive(Debug, Clone)]
pub struct FsDirEntry {
    pub inode: u64,
    pub name: Vec<u8>,
    pub file_type: FsFileType,
}

impl FsDirEntry {
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).to_string()
    }
}

/// Deleted inode information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDeletedInode {
    pub ino: u64,
    pub file_type: FsFileType,
    pub size: u64,
    pub dtime: u32,
    pub recoverability: f64,
}

/// Result of attempting to recover a deleted file.
#[derive(Debug, Clone)]
pub struct FsRecoveryResult {
    pub ino: u64,
    pub data: Vec<u8>,
    pub expected_size: u64,
    pub recovered_bytes: u64,
    pub recovery_percentage: f64,
}

/// A timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsTimelineEvent {
    pub timestamp: FsTimestamp,
    pub event_type: FsEventType,
    pub inode: u64,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
}

/// Type of filesystem event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsEventType {
    Created,
    Modified,
    Accessed,
    Changed,
    Deleted,
    Mounted,
}

/// A contiguous range of blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsBlockRange {
    pub start: u64,
    pub length: u64,
}

/// A journal transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsTransaction {
    pub sequence: u64,
    pub commit_seconds: u64,
    pub commit_nanoseconds: u32,
}

/// Error type for `ForensicFs` operations.
#[derive(Debug)]
pub enum FsError {
    Io(std::io::Error),
    NotSupported(String),
    NotFound(String),
    Corrupt(String),
    Other(String),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::NotSupported(msg) => write!(f, "not supported: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::Corrupt(msg) => write!(f, "corrupt: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convenience alias.
pub type FsResult<T> = std::result::Result<T, FsError>;

/// Helper to create a "not supported" error.
pub fn not_supported(op: &str) -> FsError {
    FsError::NotSupported(op.to_string())
}

/// Helper to create a "not found" error.
pub fn not_found(what: &str) -> FsError {
    FsError::NotFound(what.to_string())
}
