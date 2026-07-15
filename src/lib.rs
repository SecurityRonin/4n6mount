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

// The `ForensicFs` trait, the shared Fs* types, and every FS/archive backend now
// live in `forensic-vfs-engine`. Re-export them so `crate::ForensicFs` and the
// `crate::Fs*` types still resolve for the FUSE/session/memory adapters here.
pub use forensic_vfs_engine::{
    not_found, not_supported, ForensicFs, FsBlockRange, FsDeletedInode, FsDirEntry, FsError,
    FsEventType, FsFileType, FsMetadata, FsRecoveryResult, FsResult, FsTimelineEvent, FsTimestamp,
    FsTransaction,
};

use std::io;
use std::path::Path;

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

/// Mount options for the FUSE filesystem.
///
/// Platform-agnostic configuration consumed by both the Unix (fuser)
/// and Windows (Dokan) mount backends.
pub struct MountOptions {
    pub read_only: bool,
    pub daemon: bool,
    pub fs_name: String,
    pub layout: MountLayout,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            daemon: false,
            fs_name: "4n6mount".to_string(),
            layout: MountLayout::DiskOverlay,
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
