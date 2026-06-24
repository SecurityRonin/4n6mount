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

/// Construct a [`ForensicFs`] from a seekable byte source and a detected type.
///
/// This is the single dispatch point shared by the CLI's outer mount path and
/// its container (EWF/VMDK) inner-filesystem path, so a new format is wired in
/// exactly once. `name` is used only to label the single file of a raw
/// (`FsType::Unknown`) mount.
///
/// Archives (`zip`/`7z`/`tar.gz`) and filesystems (`ext4`/`ntfs`/`exfat`/
/// `hfsplus`/`iso`) all build from the same `Read + Seek` reader. `FsType::Apfs`
/// is detected but returns an explicit unsupported error (the `apfs-core`
/// parser is an unimplemented skeleton). Container types (`Ewf`/`Vmdk`) are
/// opened by the caller, not here.
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
        FsType::TarGz => Ok(Box::new(fs_tar::TarballForensicFs::from_gz(reader).map_err(bad)?)),
        #[cfg(feature = "tarball")]
        FsType::TarBz2 => Ok(Box::new(fs_tar::TarballForensicFs::from_bz2(reader).map_err(bad)?)),
        #[cfg(feature = "zip")]
        FsType::Zip => Ok(Box::new(fs_zip::ZipForensicFs::new(reader).map_err(bad)?)),
        #[cfg(feature = "sevenz")]
        FsType::SevenZ => Ok(Box::new(
            fs_sevenz::SevenZForensicFs::new(reader).map_err(bad)?,
        )),
        FsType::Unknown => Ok(Box::new(
            fs_raw::RawForensicFs::new(reader, name.to_string()).map_err(bad)?,
        )),
        FsType::Apfs => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "APFS detected but not yet supported: the apfs-core parser is an \
             unimplemented skeleton (container/catalog parsing is a work in progress)",
        )),
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "filesystem '{other}' cannot be built here \
                 (a container type, or its feature was not compiled in)"
            ),
        )),
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

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn apfs_is_unsupported_not_silent() {
        // APFS must fail loud, never silently mount empty.
        match build_filesystem(Cursor::new(vec![0u8; 64]), detect::FsType::Apfs, "x") {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("APFS must error, not mount"),
        }
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
