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

use crate::{FsFileType, FsTimestamp};

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
    match ft {
        FsFileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        _ => FILE_ATTRIBUTE_NORMAL,
    }
}

/// Convert a Unix `FsTimestamp` to a `SystemTime` (Dokan converts it to a
/// Windows `FILETIME` internally).
///
/// Non-positive seconds (missing/zero timestamps) map to the Unix epoch.
pub fn to_system_time(ts: FsTimestamp) -> SystemTime {
    if ts.seconds <= 0 {
        return UNIX_EPOCH;
    }
    UNIX_EPOCH + Duration::new(ts.seconds as u64, ts.nanoseconds)
}

/// Split a Windows path (`\dir\file`, also tolerating `/`) into its non-empty
/// components, for walking `ForensicFs::lookup` from the root.
pub fn path_components(path: &str) -> Vec<&str> {
    path.split(['\\', '/']).filter(|c| !c.is_empty()).collect()
}

/// Split a Dokan path into its file part and an optional NTFS Alternate Data
/// Stream name, so a `create_file` on `\dir\file:4n6.status` resolves `\dir\file`
/// and remembers the `4n6.status` stream.
///
/// An ADS suffix (`:name`) is only ever on the **final** path component, and `:`
/// is illegal in a normal Windows filename, so the split is unambiguous. The
/// `:$DATA` stream-type suffix is stripped, and the unnamed main stream — no
/// suffix, or the explicit `::$DATA` — yields `None`.
pub fn split_path_stream(path: &str) -> (&str, Option<&str>) {
    todo!()
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

    #[test]
    fn split_path_stream_plain_path_has_no_stream() {
        assert_eq!(
            split_path_stream(r"\dir\file.txt"),
            (r"\dir\file.txt", None)
        );
        assert_eq!(split_path_stream(r"\"), (r"\", None));
        assert_eq!(split_path_stream(""), ("", None));
    }

    #[test]
    fn split_path_stream_extracts_named_ads() {
        assert_eq!(
            split_path_stream(r"\dir\file.txt:4n6.status"),
            (r"\dir\file.txt", Some("4n6.status"))
        );
        assert_eq!(
            split_path_stream(r"\file:4n6.macb"),
            (r"\file", Some("4n6.macb"))
        );
    }

    #[test]
    fn split_path_stream_strips_data_type_suffix() {
        assert_eq!(
            split_path_stream(r"\file:4n6.status:$DATA"),
            (r"\file", Some("4n6.status"))
        );
    }

    #[test]
    fn split_path_stream_unnamed_main_stream_is_none() {
        // The explicit unnamed data stream `::$DATA` is the main stream, not an
        // ADS — it must not be mistaken for a named stream.
        assert_eq!(split_path_stream(r"\file::$DATA"), (r"\file", None));
    }

    #[test]
    fn split_path_stream_only_splits_the_final_component() {
        // A `:` can appear only in the last component; a directory drive-letter
        // form is left intact by the caller's path model (leading `\`).
        assert_eq!(
            split_path_stream(r"\a\b\c:4n6.status"),
            (r"\a\b\c", Some("4n6.status"))
        );
    }
}
