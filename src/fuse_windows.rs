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
//! `ro/`/`rw/`/`$Orphans/` overlay parity of the Unix backend is future work).
//!
//! ## Recovered-deleted marking (ADR-0008 v2)
//!
//! The Windows counterpart to the Unix `user.4n6.*` xattr channel is the NTFS
//! Alternate Data Stream: a recovered deleted/orphan entry exposes
//! `<name>:4n6.status` and `<name>:4n6.macb`, surfaced by [`find_streams`] and
//! read back through [`read_file`]. Both render from [`crate::marking`], the
//! single cross-platform source of truth — so the bytes a Windows tool reads
//! from `Get-Item -Stream 4n6.status` are identical to what a Unix tool reads
//! from `getfattr -n user.4n6.status`. A live file exposes only its unnamed
//! `::$DATA` stream, never a `4n6.*` marker.
//!
//! [`find_streams`]: DokanForensicFs::find_streams
//! [`read_file`]: DokanForensicFs::read_file
//!
//! **Runner-verification pending.** Dokan is Windows-only, so this channel is
//! compiled (`cargo check --target x86_64-pc-windows-msvc`) but not exercised by
//! the macOS/Linux CI `cargo test`; a Windows runner is required to confirm the
//! ADS surfaces end-to-end. The marking *values* are fully unit-tested on every
//! platform via [`crate::marking`]. One residual gap this shell shares with the
//! Unix parity work: it does not yet inject the recovered-deleted entries into
//! the visible tree (the `find_files` in-place render), so the ADS marks an
//! entry only once that deleted-rendering unification lands — the plumbing here
//! is ready for it.

use std::collections::HashMap;
use std::sync::Mutex;

use dokan::{
    init, shutdown, CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler, FileSystemMounter,
    FillDataError, FillDataResult, FindData, FindStreamData, MountFlags,
    MountOptions as DokanMountOptions, OperationInfo, OperationResult, VolumeInfo,
    IO_SECURITY_CONTEXT,
};
use widestring::{U16CStr, U16CString};

use crate::marking::{self, Mark, MarkStream};
use crate::session::Session;
use crate::win_map::{path_components, split_path_stream, to_system_time, windows_attributes};
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

/// The per-handle context: the resolved inode plus, for an Alternate Data
/// Stream open (`\file:4n6.status`), which marking stream the handle addresses.
/// `stream == None` is the ordinary unnamed `::$DATA` data stream.
#[derive(Debug, Clone, Copy)]
pub struct FileCtx {
    ino: u64,
    stream: Option<MarkStream>,
}

/// A read-only Dokan view over a `ForensicFs`.
pub struct DokanForensicFs {
    fs: Mutex<Box<dyn ForensicFs + Send>>,
    root_ino: u64,
    label: U16CString,
    /// `ino -> Mark` for every recovered deleted/orphan node, built once at
    /// mount time from [`ForensicFs::deleted_nodes`]. Drives the ADS marking:
    /// an inode in this map exposes the `4n6.*` streams, everything else does
    /// not.
    marks: HashMap<u64, Mark>,
}

impl DokanForensicFs {
    fn new(mut fs: Box<dyn ForensicFs + Send>, label: &str) -> Self {
        let root_ino = fs.root_ino();
        // Snapshot the recovered-deleted marks before the reader is locked away
        // behind the mutex. A backend without deleted-recovery yields none, so
        // no entry is ever marked (the honesty gate — never a fabricated mark).
        let marks = fs
            .deleted_nodes()
            .map(|nodes| nodes.iter().map(|n| (n.ino, Mark::from_node(n))).collect())
            .unwrap_or_default();
        Self {
            fs: Mutex::new(fs),
            root_ino,
            label: U16CString::from_str(label).unwrap_or_default(),
            marks,
        }
    }

    /// Resolve a Dokan file path (`\a\b`, no ADS suffix) to a `ForensicFs`
    /// inode by walking `lookup` from the root. Returns `None` if any component
    /// is missing.
    fn resolve(&self, path: &str) -> Option<u64> {
        let mut ino = self.root_ino;
        let mut fs = self.fs.lock().ok()?;
        for comp in path_components(path) {
            ino = fs.lookup(ino, comp.as_bytes()).ok().flatten()?;
        }
        Some(ino)
    }

    fn metadata(&self, ino: u64) -> OperationResult<FsMetadata> {
        let mut fs = self.fs.lock().map_err(|_| lock_failed())?;
        fs.metadata(ino).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)
    }

    /// The recovered-deleted marking for an inode, or `None` for a live entry.
    fn mark(&self, ino: u64) -> Option<Mark> {
        self.marks.get(&ino).copied()
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

/// Report one NTFS stream to Dokan's `find_streams` fill callback, mapping the
/// fill errors to NTSTATUS exactly as `find_files` does: an unrenderable or
/// over-long name is skipped (not fatal), a full buffer is a hard overflow.
fn fill_stream(
    fill: &mut impl FnMut(&FindStreamData) -> FillDataResult,
    name: &str,
    size: i64,
) -> OperationResult<()> {
    let Ok(name) = U16CString::from_str(name) else {
        return Ok(());
    };
    match fill(&FindStreamData { size, name }) {
        Ok(()) | Err(FillDataError::NameTooLong) => Ok(()),
        Err(FillDataError::BufferFull) => Err(STATUS_BUFFER_OVERFLOW),
    }
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for DokanForensicFs {
    /// The per-handle context is the resolved inode plus an optional marking
    /// stream (for an ADS open like `\file:4n6.status`).
    type Context = FileCtx;

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
        let path = file_name.to_string_lossy();
        let (file_path, stream_name) = split_path_stream(&path);
        let ino = self
            .resolve(file_path)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let meta = self.metadata(ino)?;
        // A named ADS is valid only when it is one of our `4n6.*` markers AND
        // the entry is a recovered-deleted/orphan entry; anything else is "no
        // such stream". A live file therefore has no openable marking stream.
        let stream = match stream_name {
            None => None,
            Some(name) => Some(
                MarkStream::from_base(name)
                    .filter(|_| self.mark(ino).is_some())
                    .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?,
            ),
        };
        Ok(CreateFileInfo {
            context: FileCtx { ino, stream },
            // An ADS handle addresses a data stream, never a directory.
            is_dir: stream.is_none() && matches!(meta.file_type, FsFileType::Directory),
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
        // A marking-stream handle serves the in-memory `4n6.*` bytes (the exact
        // schema render), not the file's data.
        if let Some(stream) = context.stream {
            let mark = self.mark(context.ino).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            let bytes = marking::ads_stream_value(&mark, stream);
            let start = (offset.max(0) as usize).min(bytes.len());
            let n = (bytes.len() - start).min(buffer.len());
            buffer[..n].copy_from_slice(&bytes[start..start + n]);
            return Ok(n as u32);
        }
        let data = {
            let mut fs = self.fs.lock().map_err(|_| lock_failed())?;
            fs.read_file_range(context.ino, offset.max(0) as u64, buffer.len() as u64)
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
        let meta = self.metadata(context.ino)?;
        Ok(file_info(&meta, context.ino))
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
            fs.read_dir(context.ino)
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

    /// Enumerate a file's NTFS data streams. Every file reports its unnamed
    /// `::$DATA` stream; a recovered deleted/orphan entry additionally reports
    /// the marking streams `:4n6.status:$DATA` and `:4n6.macb:$DATA` (ADR-0008
    /// v2, the Windows counterpart to the Unix `user.4n6.*` xattrs). A live
    /// file reports only `::$DATA`. Directories have no data stream.
    fn find_streams(
        &'h self,
        _file_name: &U16CStr,
        mut fill_find_stream_data: impl FnMut(&FindStreamData) -> FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        let meta = self.metadata(context.ino)?;
        if matches!(meta.file_type, FsFileType::Directory) {
            return Ok(());
        }
        // The unnamed data stream, present on every file.
        fill_stream(&mut fill_find_stream_data, "::$DATA", meta.size as i64)?;
        // The out-of-band marking streams, only on a recovered-deleted entry.
        if let Some(mark) = self.mark(context.ino) {
            for stream in marking::ADS_STREAMS {
                let bytes = marking::ads_stream_value(&mark, stream);
                fill_stream(
                    &mut fill_find_stream_data,
                    &stream.ads_full_name(),
                    bytes.len() as i64,
                )?;
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
