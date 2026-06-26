#![forbid(unsafe_code)]

//! Windows mount backend via Dokan (the MIT-licensed `dokan` crate, Dokany 2.x).
//!
//! Maps the platform-agnostic [`ForensicFs`] tree onto Dokan's
//! [`FileSystemHandler`] trait, presenting the filesystem **read-only** at the
//! mount point. The volume is mounted with [`MountFlags::WRITE_PROTECT`], so the
//! Dokan kernel driver rejects writes before they ever reach this code — the
//! mount cannot modify evidence. Dokan addresses files by path (`\dir\file`),
//! so each callback resolves a path to a `ForensicFs` inode by walking
//! [`ForensicFs::lookup`] from the root; the inode is the per-handle file
//! context.
//!
//! This module is the thin FFI shell (a Humble Object): every testable decision
//! — path splitting, attribute and timestamp mapping — lives in the
//! cross-platform [`crate::win_map`] module and is unit-tested there. The shell
//! is validated end-to-end by the Dokan mount-smoke test.
//!
//! This is the read-only MVP: it surfaces the `ForensicFs` tree directly (the
//! `ro/`/`rw/`/`deleted/` overlay parity of the Unix backend is future work).

use std::sync::Mutex;

use dokan::{
    init, shutdown, CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler, FileSystemMounter,
    FillDataError, FillDataResult, FindData, MountFlags, MountOptions as DokanMountOptions,
    OperationInfo, OperationResult, VolumeInfo, IO_SECURITY_CONTEXT,
};
use widestring::{U16CStr, U16CString};

use crate::session::Session;
use crate::win_map::{path_components, to_system_time, windows_attributes};
use crate::{ForensicFs, FsFileType, FsMetadata, MountOptions};

// NTSTATUS codes returned to Dokan (NTSTATUS is a plain i32). Defined locally to
// avoid pulling in a Windows binding crate for three constants.
/// `STATUS_OBJECT_NAME_NOT_FOUND` — the file/path does not exist.
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
/// `STATUS_INVALID_DEVICE_REQUEST` — an underlying read/parse/lock failed.
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;
/// `STATUS_BUFFER_OVERFLOW` — the directory fill buffer is full.
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;

// Volume flags advertised in `get_volume_information`. `FILE_READ_ONLY_VOLUME`
// is added automatically by Dokan because the volume uses `WRITE_PROTECT`.
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;

fn lock_failed() -> i32 {
    STATUS_INVALID_DEVICE_REQUEST
}

/// A read-only Dokan view over a `ForensicFs`.
pub struct DokanForensicFs {
    fs: Mutex<Box<dyn ForensicFs + Send>>,
    root_ino: u64,
    label: U16CString,
}

impl DokanForensicFs {
    fn new(fs: Box<dyn ForensicFs + Send>, label: &str) -> Self {
        let root_ino = fs.root_ino();
        Self {
            fs: Mutex::new(fs),
            root_ino,
            label: U16CString::from_str(label).unwrap_or_default(),
        }
    }

    /// Resolve a Dokan path (`\a\b`) to a `ForensicFs` inode by walking
    /// `lookup` from the root. Returns `None` if any component is missing.
    fn resolve(&self, path: &U16CStr) -> Option<u64> {
        let path = path.to_string_lossy();
        let mut ino = self.root_ino;
        let mut fs = self.fs.lock().ok()?;
        for comp in path_components(&path) {
            ino = fs.lookup(ino, comp.as_bytes()).ok().flatten()?;
        }
        Some(ino)
    }

    fn metadata(&self, ino: u64) -> OperationResult<FsMetadata> {
        let mut fs = self.fs.lock().map_err(|_| lock_failed())?;
        fs.metadata(ino).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)
    }
}

/// Build a Dokan `FileInfo` from `ForensicFs` metadata.
fn file_info(meta: &FsMetadata, ino: u64) -> FileInfo {
    FileInfo {
        attributes: windows_attributes(meta.file_type),
        creation_time: to_system_time(meta.crtime),
        last_access_time: to_system_time(meta.atime),
        last_write_time: to_system_time(meta.mtime),
        file_size: meta.size,
        number_of_links: u32::from(meta.links_count).max(1),
        file_index: ino,
    }
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for DokanForensicFs {
    /// The per-handle context is the resolved inode.
    type Context = u64;

    #[allow(clippy::too_many_arguments)]
    fn create_file(
        &'h self,
        file_name: &U16CStr,
        _security_context: &IO_SECURITY_CONTEXT,
        _desired_access: u32,
        _file_attributes: u32,
        _share_access: u32,
        _create_disposition: u32,
        _create_options: u32,
        _info: &mut OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        let ino = self
            .resolve(file_name)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let meta = self.metadata(ino)?;
        Ok(CreateFileInfo {
            context: ino,
            is_dir: matches!(meta.file_type, FsFileType::Directory),
            new_file_created: false,
        })
    }

    fn close_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) {
    }

    fn read_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        let data = {
            let mut fs = self.fs.lock().map_err(|_| lock_failed())?;
            fs.read_file_range(*context, offset.max(0) as u64, buffer.len() as u64)
                .map_err(|_| STATUS_INVALID_DEVICE_REQUEST)?
        };
        let n = data.len().min(buffer.len());
        buffer[..n].copy_from_slice(&data[..n]);
        Ok(n as u32)
    }

    fn get_file_information(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<FileInfo> {
        let meta = self.metadata(*context)?;
        Ok(file_info(&meta, *context))
    }

    fn find_files(
        &'h self,
        _file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        let mut entries = {
            let mut fs = self.fs.lock().map_err(|_| lock_failed())?;
            fs.read_dir(*context)
                .map_err(|_| STATUS_INVALID_DEVICE_REQUEST)?
        };
        // Stable order for a deterministic listing.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for e in entries {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            let Ok(meta) = self.metadata(e.inode) else {
                continue;
            };
            let Ok(name) = U16CString::from_str(String::from_utf8_lossy(&e.name)) else {
                continue;
            };
            let find = FindData {
                attributes: windows_attributes(meta.file_type),
                creation_time: to_system_time(meta.crtime),
                last_access_time: to_system_time(meta.atime),
                last_write_time: to_system_time(meta.mtime),
                file_size: meta.size,
                file_name: name,
            };
            match fill_find_data(&find) {
                Ok(()) => {}
                // A single over-long name shouldn't make the whole dir unreadable.
                Err(FillDataError::NameTooLong) => continue,
                Err(FillDataError::BufferFull) => return Err(STATUS_BUFFER_OVERFLOW),
            }
        }
        Ok(())
    }

    fn get_disk_free_space(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        // Read-only forensic view: the volume cannot be written, so report no
        // free space.
        Ok(DiskSpaceInfo {
            byte_count: 0,
            free_byte_count: 0,
            available_byte_count: 0,
        })
    }

    fn get_volume_information(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<VolumeInfo> {
        Ok(VolumeInfo {
            name: self.label.clone(),
            serial_number: 0,
            max_component_length: 255,
            fs_flags: FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK,
            // Windows gates feature availability on the FS name; "NTFS" is the
            // safe, well-known choice (custom names interact poorly with UAC).
            fs_name: U16CString::from_str("NTFS").unwrap_or_default(),
        })
    }
}

/// Mount a `ForensicFs` via Dokan at `mountpoint` (a drive letter `X:` or a
/// directory on an NTFS volume). Read-only; `session` is unused (no rw overlay
/// on Windows yet). Blocks until the volume is unmounted.
pub fn mount_windows(
    fs: Box<dyn ForensicFs + Send>,
    mountpoint: &std::path::Path,
    _session: Option<Session>,
    options: &MountOptions,
) -> std::io::Result<()> {
    let mount_point = U16CString::from_os_str(mountpoint.as_os_str())
        .map_err(|e| std::io::Error::other(format!("invalid mount point: {e}")))?;

    let handler = DokanForensicFs::new(fs, &options.fs_name);

    let dokan_options = DokanMountOptions {
        flags: MountFlags::WRITE_PROTECT,
        ..Default::default()
    };

    init();
    let mut mounter = FileSystemMounter::new(&handler, &mount_point, &dokan_options);
    let file_system = mounter
        .mount()
        .map_err(|e| std::io::Error::other(format!("Dokan mount: {e}")))?;
    eprintln!("4n6mount: mounted at {} (Dokan)", mountpoint.display());

    // `FileSystem`'s Drop blocks until the volume is unmounted (e.g. via
    // `dokanctl /u <mountpoint>`); holding it keeps the mount alive.
    drop(file_system);
    shutdown();
    Ok(())
}
