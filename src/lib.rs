#![forbid(unsafe_code)]

pub mod detect;
pub mod types;
pub mod inode_map;
pub mod session;
pub mod filter;
pub mod fusefs;

pub use types::*;

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

/// Mount a forensic filesystem via FUSE.
///
/// This is the main entry point for consumers. Pass a `ForensicFs` implementation
/// and mount options, and this handles the FUSE lifecycle.
///
/// When `daemon` is false (default), this blocks until the filesystem is unmounted.
/// When `daemon` is true, the FUSE event loop runs in a background thread and this
/// function returns immediately. The mount stays alive until the process exits or
/// the filesystem is unmounted externally (`umount`).
pub fn mount(
    fs: Box<dyn ForensicFs + Send>,
    mountpoint: &str,
    session_dir: Option<&str>,
    resume: bool,
    _filter_dbs: &[String],
    daemon: bool,
) -> std::io::Result<()> {
    let session_mgr = session_dir.map(|dir| {
        let session_path = std::path::Path::new(dir);
        if resume {
            session::Session::resume(session_path, std::path::Path::new(""))
                .expect("cannot resume session")
        } else {
            session::Session::create(session_path, std::path::Path::new(""))
                .expect("cannot create session")
        }
    });

    let fuse_fs = fusefs::ForensicFuseFs::new(fs, session_mgr);

    let mut options = vec![
        fuser::MountOption::FSName("4n6mount".to_string()),
    ];
    if session_dir.is_none() {
        options.push(fuser::MountOption::RO);
    }

    if daemon {
        // Background mode: spawn FUSE in a thread, write PID, wait for signal
        let _session = fuser::spawn_mount2(fuse_fs, mountpoint, &options)?;
        eprintln!("4n6mount: mounted at {mountpoint} (daemon mode, PID {})", std::process::id());
        // Block on signal — the mount stays alive until the process is killed
        // or the filesystem is unmounted externally
        loop {
            std::thread::park();
        }
    } else {
        fuser::mount2(fuse_fs, mountpoint, &options)
    }
}
