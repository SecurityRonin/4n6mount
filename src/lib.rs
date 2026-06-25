#![forbid(unsafe_code)]

pub mod archive_tree;
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

#[cfg(feature = "tarball")]
pub mod fs_tar;

#[cfg(feature = "zip")]
pub mod fs_zip;

#[cfg(feature = "sevenz")]
pub mod fs_sevenz;

#[cfg(feature = "ntfs")]
pub mod fs_ntfs;

#[cfg(feature = "hfsplus")]
pub mod fs_hfsplus;

#[cfg(feature = "exfat")]
pub mod fs_exfat;

#[cfg(feature = "apfs")]
pub mod fs_apfs;

#[cfg(feature = "memory")]
pub mod mem;

pub mod fs_raw;

pub use types::*;

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
/// and Windows (`WinFSP`) mount backends.
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

/// Construct a [`ForensicFs`] from a seekable byte source and a detected type.
///
/// This is the single dispatch point shared by the CLI's outer mount path and
/// its container (EWF/VMDK) inner-filesystem path, so a new format is wired in
/// exactly once. `name` is used only to label the single file of a raw
/// (`FsType::Unknown`) mount.
///
/// Archives (`zip`/`7z`/`tar.gz`) and filesystems (`ext4`/`ntfs`/`exfat`/
/// `hfsplus`/`iso`/`apfs`) all build from the same `Read + Seek` reader.
/// Container types (`Ewf`/`Vmdk`) are opened by the caller, not here.
///
/// # Errors
///
/// Returns the parse error (as `InvalidData`) if the source does not match the
/// claimed type, or `Unsupported` for APFS / a feature that was not compiled in.
pub fn build_filesystem<R: io::Read + io::Seek + Send + 'static>(
    reader: R,
    fs_type: detect::FsType,
    name: &str,
) -> io::Result<Box<dyn ForensicFs + Send>> {
    use detect::FsType;
    let bad = |e: FsError| io::Error::new(io::ErrorKind::InvalidData, e.to_string());
    match fs_type {
        #[cfg(feature = "ext4")]
        FsType::Ext4 => Ok(Box::new(fs_ext4::Ext4ForensicFs::new(reader).map_err(bad)?)),
        #[cfg(feature = "iso")]
        FsType::Iso => Ok(Box::new(fs_iso::IsoForensicFs::new(reader).map_err(bad)?)),
        #[cfg(feature = "ntfs")]
        FsType::Ntfs => Ok(Box::new(fs_ntfs::NtfsForensicFs::new(reader).map_err(bad)?)),
        #[cfg(feature = "hfsplus")]
        FsType::Hfsplus => Ok(Box::new(
            fs_hfsplus::HfsPlusForensicFs::new(reader).map_err(bad)?,
        )),
        #[cfg(feature = "exfat")]
        FsType::ExFat => Ok(Box::new(
            fs_exfat::ExFatForensicFs::new(reader).map_err(bad)?,
        )),
        #[cfg(feature = "tarball")]
        FsType::TarGz => Ok(Box::new(
            fs_tar::TarballForensicFs::from_gz(reader).map_err(bad)?,
        )),
        #[cfg(feature = "tarball")]
        FsType::TarBz2 => Ok(Box::new(
            fs_tar::TarballForensicFs::from_bz2(reader).map_err(bad)?,
        )),
        #[cfg(feature = "zip")]
        FsType::Zip => Ok(Box::new(fs_zip::ZipForensicFs::new(reader).map_err(bad)?)),
        #[cfg(feature = "sevenz")]
        FsType::SevenZ => Ok(Box::new(
            fs_sevenz::SevenZForensicFs::new(reader).map_err(bad)?,
        )),
        FsType::Unknown => Ok(Box::new(
            fs_raw::RawForensicFs::new(reader, name.to_string()).map_err(bad)?,
        )),
        #[cfg(feature = "apfs")]
        FsType::Apfs => Ok(Box::new(fs_apfs::ApfsForensicFs::new(reader).map_err(bad)?)),
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "filesystem '{other}' cannot be built here \
                 (a container type, or its feature was not compiled in)"
            ),
        )),
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
    let _ = (image, symbols);
    todo!("build_memory_fs")
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

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn apfs_garbage_errors_loud_not_silent() {
        // A non-APFS source must fail loud (InvalidData), never silently mount empty.
        match build_filesystem(Cursor::new(vec![0u8; 64]), detect::FsType::Apfs, "x") {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("garbage must error, not mount"),
        }
    }

    #[cfg(feature = "apfs")]
    #[test]
    fn apfs_dispatches_to_module() {
        let img = "/Users/4n6h4x0r/src/apfs-forensic/tests/data/apfs_fstree.bin";
        let Ok(data) = std::fs::read(img) else {
            eprintln!("skip: apfs_fstree.bin unavailable");
            return;
        };
        let fs = build_filesystem(Cursor::new(data), detect::FsType::Apfs, "x").unwrap();
        assert_eq!(fs.fs_info().unwrap()["type"], "apfs");
    }

    #[test]
    fn unknown_builds_raw() {
        let fs = build_filesystem(
            Cursor::new(b"hello".to_vec()),
            detect::FsType::Unknown,
            "evidence.bin",
        )
        .unwrap();
        assert_eq!(fs.fs_info().unwrap()["filesystem"], "raw");
    }

    #[cfg(feature = "hfsplus")]
    #[test]
    fn hfsplus_dispatches_to_module() {
        let img = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfsplus.img");
        let Ok(data) = std::fs::read(img) else {
            eprintln!("skip: hfsplus.img unavailable");
            return;
        };
        let fs = build_filesystem(Cursor::new(data), detect::FsType::Hfsplus, "x").unwrap();
        assert_eq!(fs.fs_info().unwrap()["type"], "hfsplus");
    }

    #[cfg(feature = "exfat")]
    #[test]
    fn exfat_dispatches_to_module() {
        let img = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/exfat.img");
        let Ok(data) = std::fs::read(img) else {
            eprintln!("skip: exfat.img unavailable");
            return;
        };
        let fs = build_filesystem(Cursor::new(data), detect::FsType::ExFat, "x").unwrap();
        assert_eq!(fs.fs_info().unwrap()["type"], "exfat");
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
        let sys = fs.lookup(mem::inode::ROOT_INO, b"sys").unwrap().expect("sys");
        let oi = fs.lookup(sys, b"os-info.txt").unwrap().expect("os-info.txt");
        let text = String::from_utf8(fs.read_file(oi).unwrap()).unwrap();
        assert!(text.contains("OS: Windows"), "got: {text}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
