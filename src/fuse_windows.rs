#![forbid(unsafe_code)]

//! Windows mount backend via WinFsp (the `winfsp` crate, WinFsp 2.x).
//!
//! Maps the platform-agnostic [`ForensicFs`] tree onto WinFsp's
//! [`FileSystemContext`] trait, presenting the filesystem **read-only** at the
//! mount point. WinFsp addresses files by path (`\dir\file`), so each callback
//! resolves a path to a `ForensicFs` inode by walking `lookup` from the root;
//! the inode is the WinFsp file context.
//!
//! This is the read-only MVP: it surfaces the `ForensicFs` tree directly (the
//! `ro/`/`rw/`/`deleted/` overlay parity of the Unix backend is future work).
//! Writes are rejected — the trait's mutating methods keep their default
//! `STATUS_INVALID_DEVICE_REQUEST`, so the mount cannot modify evidence.

use std::sync::Mutex;

use widestring::U16CStr;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::winfsp_init_or_die;
use winfsp::FspError;

use crate::session::Session;
use crate::{ForensicFs, FsFileType, FsMetadata, FsTimestamp, MountOptions};

/// `STATUS_OBJECT_NAME_NOT_FOUND` — the file/path does not exist.
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
/// `STATUS_IO_DEVICE_ERROR` — an underlying read/parse failed.
const STATUS_IO_DEVICE_ERROR: i32 = 0xC000_0185u32 as i32;

/// 100-ns intervals between the Windows FILETIME epoch (1601) and Unix (1970).
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;

fn not_found() -> FspError {
    FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND)
}

fn io_error() -> FspError {
    FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR)
}

/// Convert a Unix `FsTimestamp` to a Windows FILETIME (100-ns since 1601).
fn to_filetime(ts: FsTimestamp) -> u64 {
    if ts.seconds <= 0 {
        return 0;
    }
    (ts.seconds as u64 + FILETIME_UNIX_OFFSET) * 10_000_000 + u64::from(ts.nanoseconds) / 100
}

/// Windows file attributes for a `ForensicFs` file type.
fn attributes(ft: FsFileType) -> FILE_FLAGS_AND_ATTRIBUTES {
    match ft {
        FsFileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        _ => FILE_ATTRIBUTE_NORMAL,
    }
}

/// A read-only WinFsp view over a `ForensicFs`.
pub struct WinForensicFs {
    fs: Mutex<Box<dyn ForensicFs + Send>>,
    root_ino: u64,
}

impl WinForensicFs {
    fn new(fs: Box<dyn ForensicFs + Send>) -> Self {
        let root_ino = fs.root_ino();
        Self {
            fs: Mutex::new(fs),
            root_ino,
        }
    }

    /// Resolve a WinFsp path (`\a\b`) to a `ForensicFs` inode by walking
    /// `lookup` from the root. Returns `None` if any component is missing.
    fn resolve(&self, path: &U16CStr) -> Option<u64> {
        let path = path.to_string_lossy();
        let mut ino = self.root_ino;
        let mut fs = self.fs.lock().ok()?;
        for comp in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
            ino = fs.lookup(ino, comp.as_bytes()).ok().flatten()?;
        }
        Some(ino)
    }

    /// Populate a WinFsp `FileInfo` from `ForensicFs` metadata.
    fn fill(&self, ino: u64, fi: &mut FileInfo) -> Result<(), FspError> {
        let meta: FsMetadata = {
            let mut fs = self.fs.lock().map_err(|_| io_error())?;
            fs.metadata(ino).map_err(|_| not_found())?
        };
        fi.file_attributes = attributes(meta.file_type);
        fi.file_size = meta.size;
        // Round allocation up to a 4 KiB cluster, mirroring a real volume.
        fi.allocation_size = meta.size.div_ceil(4096) * 4096;
        fi.creation_time = to_filetime(meta.crtime);
        fi.last_access_time = to_filetime(meta.atime);
        fi.last_write_time = to_filetime(meta.mtime);
        fi.change_time = to_filetime(meta.ctime);
        fi.index_number = ino;
        Ok(())
    }
}

/// WinFsp per-handle file context: the resolved inode plus a directory buffer.
/// WinFsp's model fills the buffer once (the initial, marker-less `read_directory`
/// call) and re-reads it for subsequent paginated calls.
pub struct WinFile {
    ino: u64,
    dir_buffer: DirBuffer,
}

impl FileSystemContext for WinForensicFs {
    type FileContext = WinFile;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [std::ffi::c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity, FspError> {
        let ino = self.resolve(file_name).ok_or_else(not_found)?;
        let meta = {
            let mut fs = self.fs.lock().map_err(|_| io_error())?;
            fs.metadata(ino).map_err(|_| not_found())?
        };
        Ok(FileSecurity {
            reparse: false,
            // No ACLs are surfaced (persistent_acls is off); the descriptor is empty.
            sz_security_descriptor: 0,
            attributes: attributes(meta.file_type),
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext, FspError> {
        let ino = self.resolve(file_name).ok_or_else(not_found)?;
        self.fill(ino, file_info.as_mut())?;
        Ok(WinFile {
            ino,
            dir_buffer: DirBuffer::default(),
        })
    }

    fn close(&self, _context: Self::FileContext) {}

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        self.fill(context.ino, file_info)
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<u32, FspError> {
        let data = {
            let mut fs = self.fs.lock().map_err(|_| io_error())?;
            fs.read_file_range(context.ino, offset, buffer.len() as u64)
                .map_err(|_| io_error())?
        };
        let n = data.len().min(buffer.len());
        buffer[..n].copy_from_slice(&data[..n]);
        Ok(n as u32)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32, FspError> {
        // Populate the per-handle directory buffer once (on the initial,
        // marker-less call — `acquire(reset, _)` returns Ok only when a fill is
        // needed); WinFsp re-reads the buffer for subsequent paginated calls.
        if let Ok(lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let mut entries: Vec<(String, u64)> = {
                let mut fs = self.fs.lock().map_err(|_| io_error())?;
                fs.read_dir(context.ino)
                    .map_err(|_| io_error())?
                    .into_iter()
                    .filter(|e| e.name != b"." && e.name != b"..")
                    .map(|e| (String::from_utf8_lossy(&e.name).into_owned(), e.inode))
                    .collect()
            };
            // Stable order for deterministic, resumable listing.
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, ino) in entries {
                let mut dir_info: DirInfo<255> = DirInfo::new();
                if self.fill(ino, dir_info.file_info_mut()).is_err() {
                    continue;
                }
                dir_info.set_name(name.as_str())?;
                lock.write(&mut dir_info)?;
            }
        }
        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn get_volume_info(&self, out: &mut VolumeInfo) -> Result<(), FspError> {
        // Size is informational for a read-only forensic view; report no free
        // space (the volume cannot be written).
        out.total_size = 0;
        out.free_size = 0;
        Ok(())
    }
}

/// Mount a `ForensicFs` via WinFsp at `mountpoint` (a drive letter `X:` or a
/// directory). Read-only; `session` is unused (no rw overlay on Windows yet).
pub fn mount_windows(
    fs: Box<dyn ForensicFs + Send>,
    mountpoint: &std::path::Path,
    _session: Option<Session>,
    options: &MountOptions,
) -> std::io::Result<()> {
    let _init = winfsp_init_or_die();

    let mut volume_params = VolumeParams::new();
    volume_params
        .sector_size(4096)
        .sectors_per_allocation_unit(1)
        .case_sensitive_search(true)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(false)
        .filesystem_name(&options.fs_name);

    let context = WinForensicFs::new(fs);
    let mut host = FileSystemHost::new(volume_params, context)
        .map_err(|e| std::io::Error::other(format!("WinFsp host: {e:?}")))?;
    host.mount(mountpoint.as_os_str())
        .map_err(|e| std::io::Error::other(format!("WinFsp mount: {e:?}")))?;
    host.start()
        .map_err(|e| std::io::Error::other(format!("WinFsp start: {e:?}")))?;

    // Block while WinFsp serves on its own threads, until the process is signalled.
    std::thread::park();
    Ok(())
}
