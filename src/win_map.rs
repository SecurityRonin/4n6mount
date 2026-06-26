//! Pure mapping helpers from the platform-agnostic `ForensicFs` model onto
//! Windows filesystem semantics (path components, file attributes, timestamps).
//!
//! This module is **cross-platform on purpose**: the Windows mount backend
//! (`fuse_windows`, `#[cfg(windows)]`) is a thin Humble-Object shell over
//! Dokan's FFI callbacks, so every testable decision lives here where the
//! Linux/macOS `cargo test` job can exercise it. The attribute constants are
//! the documented Windows ABI values ([MS-FSCC] §2.6 / `WinNT.h`), so they are
//! defined once here and reused by the shell rather than pulled from a
//! Windows-only binding crate.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::{FsFileType, FsTimestamp};

/// `FILE_ATTRIBUTE_READONLY` — the file is read-only.
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
/// `FILE_ATTRIBUTE_DIRECTORY` — the handle identifies a directory.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_NORMAL` — no other attributes are set (valid only alone).
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Windows file-attribute bits for a `ForensicFs` file type.
///
/// Directories carry `FILE_ATTRIBUTE_DIRECTORY`; everything else is reported as
/// a normal file. The mount is presented read-only at the volume level
/// (`MountFlags::WRITE_PROTECT`), so a per-file read-only bit is redundant and
/// is not set here.
pub fn windows_attributes(ft: FsFileType) -> u32 {
    unimplemented!()
}

/// Convert a Unix `FsTimestamp` to a `SystemTime` (Dokan converts it to a
/// Windows `FILETIME` internally).
///
/// Non-positive seconds (missing/zero timestamps) map to the Unix epoch.
pub fn to_system_time(ts: FsTimestamp) -> SystemTime {
    unimplemented!()
}

/// Split a Windows path (`\dir\file`, also tolerating `/`) into its non-empty
/// components, for walking `ForensicFs::lookup` from the root.
pub fn path_components(path: &str) -> Vec<&str> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_maps_to_directory_attribute() {
        assert_eq!(
            windows_attributes(FsFileType::Directory),
            FILE_ATTRIBUTE_DIRECTORY
        );
    }

    #[test]
    fn non_directory_types_map_to_normal() {
        for ft in [
            FsFileType::RegularFile,
            FsFileType::Symlink,
            FsFileType::CharDevice,
            FsFileType::BlockDevice,
            FsFileType::Fifo,
            FsFileType::Socket,
            FsFileType::Unknown,
        ] {
            assert_eq!(windows_attributes(ft), FILE_ATTRIBUTE_NORMAL);
        }
    }

    #[test]
    fn zero_and_negative_timestamps_map_to_epoch() {
        assert_eq!(
            to_system_time(FsTimestamp {
                seconds: 0,
                nanoseconds: 0
            }),
            UNIX_EPOCH
        );
        assert_eq!(
            to_system_time(FsTimestamp {
                seconds: -5,
                nanoseconds: 123
            }),
            UNIX_EPOCH
        );
    }

    #[test]
    fn positive_timestamp_offsets_from_epoch() {
        assert_eq!(
            to_system_time(FsTimestamp {
                seconds: 1,
                nanoseconds: 500_000_000
            }),
            UNIX_EPOCH + Duration::new(1, 500_000_000)
        );
    }

    #[test]
    fn path_components_splits_on_both_separators_and_drops_empties() {
        assert_eq!(path_components(r"\dir\file.txt"), vec!["dir", "file.txt"]);
        assert_eq!(path_components("/a//b/"), vec!["a", "b"]);
    }

    #[test]
    fn root_and_empty_paths_have_no_components() {
        assert!(path_components("").is_empty());
        assert!(path_components(r"\").is_empty());
    }
}
