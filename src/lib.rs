#![forbid(unsafe_code)]

pub mod detect;
pub mod filter;
#[cfg(unix)]
pub mod fusefs;
pub mod inode_map;
pub mod session;
pub mod win_map;

#[cfg(unix)]
pub mod fuse_unix;
#[cfg(windows)]
pub mod fuse_windows;

#[cfg(feature = "memory")]
pub mod mem;

// 4n6mount owns its FUSE-facing filesystem contract: the `ForensicFs` trait and
// its `Fs*` value types (implemented by both the memory VFS and the disk-image
// `EngineFs` adapter over `forensic-vfs`). The engine now speaks a different,
// inode-enum `FileSystem` trait; `EngineFs` bridges it into this one.
pub mod engine_fs;
pub mod types;

pub use engine_fs::{open_image, EngineFs};
pub use types::*;

use std::io;
use std::path::Path;

/// One mounted, browsable forensic filesystem, in 4n6mount's own `u64`-inode
/// vocabulary. A backend (the memory VFS, or [`EngineFs`] over a disk image)
/// converts its native model into these calls; the FUSE/Dokan mount layer
/// consumes them directly.
///
/// The core navigation ops are required. The forensic ops have default impls so
/// a backend that cannot honor one degrades cleanly (an empty list, or a loud
/// `NotSupported` for the byte-producing ones).
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

    /// List deleted/orphan nodes with recovered identity — a readable inode,
    /// the recovered name, parent inode, record id, and MACB times — so the
    /// mount can render each in place (or route it to `$Orphans`) and read its
    /// bytes via [`read_file`](Self::read_file). Default empty: a backend opts
    /// in once it can recover the rich identity (e.g. NTFS `$FILE_NAME` + the
    /// MFT reference). It never fabricates an entry.
    fn deleted_nodes(&mut self) -> FsResult<Vec<FsDeletedNode>> {
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

/// How the FUSE mount renders a [`ForensicFs`].
///
/// `DiskOverlay` is the disk-image presentation: the mount root lists the
/// `ro/ rw/ deleted/ …` virtual directories and the filesystem tree lives under
/// `ro/`. `Raw` renders the `ForensicFs` tree directly at the mount root with no
/// overlay — used for read-only memory mounts (and any provider that owns its
/// own top level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MountLayout {
    /// Disk-image overlay: `ro/`, `rw/`, `deleted/`, … virtual directories.
    #[default]
    DiskOverlay,
    /// The `ForensicFs` tree rendered directly at the root, read-only.
    Raw,
}

/// How the `deleted/` view surfaces recovered deleted files.
///
/// A deleted file is placed **in-place** (under its recovered parent, at its
/// real name) when its parent is known and no live sibling holds the name;
/// otherwise it is routed to a synthetic `$Orphans` bucket (ADR 0008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum DeletedMode {
    /// Newest deleted instance per (parent, name) rendered in-place; older
    /// same-name instances routed to `$Orphans`. The default.
    #[default]
    Latest,
    /// Every deleted instance rendered under `$Orphans`, disambiguated by
    /// recovered mtime and record id.
    All,
    /// Do not surface deleted files at all.
    Off,
}

/// Mount options for the FUSE filesystem.
///
/// Platform-agnostic configuration consumed by both the Unix (fuser)
/// and Windows (Dokan) mount backends.
pub struct MountOptions {
    pub read_only: bool,
    pub daemon: bool,
    pub fs_name: String,
    pub layout: MountLayout,
    /// How the `deleted/` view is populated.
    pub deleted_mode: DeletedMode,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            daemon: false,
            fs_name: "4n6mount".to_string(),
            layout: MountLayout::DiskOverlay,
            deleted_mode: DeletedMode::default(),
        }
    }
}

/// Open a memory dump and build a [`MemoryFs`] over it, bootstrapping the
/// analysis context (OS, DTB/CR3, kernel list-heads) via `memf-session`.
///
/// `symbols` is an optional ISF/PDB path. A header-bearing Windows crash dump
/// bootstraps with an empty resolver; raw `.mem` and Linux dumps need symbols.
///
/// Fails LOUD on a bootstrap failure (bad dump, undetectable OS, missing
/// symbols) rather than mounting an empty tree — the memory mount is meaningless
/// without a valid context.
///
/// # Errors
///
/// Propagates dump-open, symbol-load, and analysis-bootstrap failures as
/// `InvalidData`.
#[cfg(feature = "memory")]
pub fn build_memory_fs(
    image: &Path,
    symbols: Option<&Path>,
) -> io::Result<Box<dyn ForensicFs + Send>> {
    let bad = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);

    let provider = memf_format::open_dump(image)
        .map_err(|e| bad(format!("cannot open memory dump {}: {e}", image.display())))?;

    // Load symbols if given; otherwise an empty resolver (sufficient for a
    // crash dump whose header carries CR3 + list-heads).
    let resolver: Box<dyn memf_symbols::SymbolResolver> = match symbols {
        Some(p) => Box::new(
            memf_symbols::isf::IsfResolver::from_path(p)
                .map_err(|e| bad(format!("cannot load symbols {}: {e}", p.display())))?,
        ),
        None => Box::new(
            memf_symbols::isf::IsfResolver::from_value(&serde_json::json!({}))
                .map_err(|e| bad(format!("empty symbol resolver: {e}")))?,
        ),
    };

    let metadata = provider.metadata();
    let ctx = memf_session::build_analysis_context(
        metadata.as_ref(),
        resolver.as_ref(),
        provider.as_ref(),
    )
    .map_err(|e| bad(format!("memory analysis bootstrap failed: {e}")))?;

    Ok(Box::new(mem::memoryfs::MemoryFs::new(
        provider, ctx, resolver,
    )))
}

/// Mount a forensic filesystem via FUSE (or Dokan on Windows).
///
/// This is the main entry point for consumers.  Pass a `ForensicFs`
/// implementation and a `MountOptions`, and this dispatches to the
/// correct platform backend.
///
/// On Unix the mount is handled by `fuser`.  On Windows it is handled
/// by Dokan (the MIT `dokan` crate).
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

#[cfg(all(test, feature = "memory"))]
mod memory_tests {
    use super::*;

    /// build_memory_fs bootstraps a synthetic Windows crash dump (header carries
    /// CR3 + machine type, so no symbols are required) and renders sys/os-info.
    #[test]
    fn build_memory_fs_bootstraps_crashdump() {
        use memf_format::test_builders::CrashDumpBuilder;
        let bytes = CrashDumpBuilder::new().cr3(0x1ab000).build();

        let dir = std::env::temp_dir().join(format!("4n6mem_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("crash.dmp");
        std::fs::write(&path, &bytes).unwrap();

        let mut fs = build_memory_fs(&path, None).expect("crash dump must bootstrap");
        // Root is the Raw memory tree: sys/ present, os-info.txt renders the OS.
        let sys = fs
            .lookup(mem::inode::ROOT_INO, b"sys")
            .unwrap()
            .expect("sys");
        let oi = fs
            .lookup(sys, b"os-info.txt")
            .unwrap()
            .expect("os-info.txt");
        let text = String::from_utf8(fs.read_file(oi).unwrap()).unwrap();
        assert!(text.contains("OS: Windows"), "got: {text}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
