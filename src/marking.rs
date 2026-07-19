//! Platform-agnostic recovered-deleted marking schema (ADR-0008 v2).
//!
//! The single source of truth for the *values* a recovered deleted/orphan entry
//! advertises out-of-band: its `status` (`deleted` / `orphan`) and the four
//! recovered MACB times in ISO-8601 UTC. One logical schema, two physical
//! channels — both render **from here**, so they can never drift:
//!
//! - **Unix** (macFUSE / Linux): extended attributes `user.4n6.status` +
//!   `user.4n6.macb.{modified,accessed,changed,born}` — see
//!   [`crate::fusefs`]'s `getxattr` / `listxattr`.
//! - **Windows** (Dokan): NTFS Alternate Data Streams `<name>:4n6.status` and
//!   `<name>:4n6.macb`, surfaced by `find_streams` — see
//!   [`crate::fuse_windows`].
//!
//! The Unix channel splits the four MACB times across four xattrs; the Windows
//! channel carries all four in one `:4n6.macb` stream as a JSON object. The
//! *values* (the status word and each ISO-8601 time) are identical byte-for-byte
//! between the channels — that identity is the parity guarantee this module
//! exists to enforce, and it is asserted in the tests below.

use crate::{FsAllocation, FsDeletedNode};

/// The four recovered MACB times as Unix seconds, in canonical `M A C B` order.
///
/// `modified` ← mtime, `accessed` ← atime, `changed` ← ctime, `born` ← crtime —
/// the same mapping the Unix `deleted/` cache applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Macb {
    pub modified: i64,
    pub accessed: i64,
    pub changed: i64,
    pub born: i64,
}

/// The out-of-band marking on one recovered deleted/orphan entry: its allocation
/// state plus the recovered MACB times. Both physical channels render from this.
#[derive(Debug, Clone, Copy)]
pub struct Mark {
    pub allocation: FsAllocation,
    pub macb: Macb,
}

impl Mark {
    /// Build a [`Mark`] from a recovered [`FsDeletedNode`], applying the
    /// canonical MACB mapping (mtime→modified, atime→accessed, ctime→changed,
    /// crtime→born).
    pub fn from_node(node: &FsDeletedNode) -> Self {
        Self {
            allocation: node.allocation,
            macb: Macb {
                modified: node.mtime.seconds,
                accessed: node.atime.seconds,
                changed: node.ctime.seconds,
                born: node.crtime.seconds,
            },
        }
    }
}

/// The five Unix xattr names on a recovered-deleted entry, in listing order.
pub const UNIX_XATTR_NAMES: [&str; 5] = [
    "user.4n6.status",
    "user.4n6.macb.modified",
    "user.4n6.macb.accessed",
    "user.4n6.macb.changed",
    "user.4n6.macb.born",
];

/// One NTFS Alternate Data Stream carrying part of the marking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkStream {
    /// `<name>:4n6.status` — the `deleted` / `orphan` word.
    Status,
    /// `<name>:4n6.macb` — the four MACB times as a JSON object.
    Macb,
}

/// The two marking ADS streams a recovered-deleted entry exposes, in order.
pub const ADS_STREAMS: [MarkStream; 2] = [MarkStream::Status, MarkStream::Macb];

impl MarkStream {
    /// The bare NTFS stream name (no `:` delimiters, no `:$DATA` type suffix).
    pub fn base(self) -> &'static str {
        match self {
            MarkStream::Status => "4n6.status",
            MarkStream::Macb => "4n6.macb",
        }
    }

    /// Parse a bare NTFS stream name into a marking stream, or `None` when it is
    /// not one of ours (so a foreign ADS is never misread as a 4n6 marker).
    pub fn from_base(base: &str) -> Option<Self> {
        match base {
            "4n6.status" => Some(MarkStream::Status),
            "4n6.macb" => Some(MarkStream::Macb),
            _ => None,
        }
    }

    /// The full NTFS stream name Dokan reports for this stream, e.g.
    /// `:4n6.status:$DATA`.
    pub fn ads_full_name(self) -> String {
        format!(":{}:$DATA", self.base())
    }
}

/// The status word for an allocation state: `deleted` or `orphan`.
pub fn status_str(allocation: FsAllocation) -> &'static str {
    match allocation {
        FsAllocation::Deleted => "deleted",
        FsAllocation::Orphan => "orphan",
    }
}

/// Format Unix seconds as ISO-8601 UTC `YYYY-MM-DDTHH:MM:SSZ` — the marking
/// *value* form (colons are legal inside a value, unlike a filename).
#[allow(clippy::many_single_char_names)] // conventional date-field names
pub fn iso8601_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mon, d) = civil_from_days(days);
    format!("{y:04}-{mon:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Value of one Unix xattr on a marked entry, or `None` when `name` is outside
/// the schema (the getxattr shell then replies `ENODATA`).
pub fn unix_xattr_value(mark: &Mark, name: &str) -> Option<Vec<u8>> {
    let v = match name {
        "user.4n6.status" => status_str(mark.allocation).to_string(),
        "user.4n6.macb.modified" => iso8601_utc(mark.macb.modified),
        "user.4n6.macb.accessed" => iso8601_utc(mark.macb.accessed),
        "user.4n6.macb.changed" => iso8601_utc(mark.macb.changed),
        "user.4n6.macb.born" => iso8601_utc(mark.macb.born),
        _ => return None,
    };
    Some(v.into_bytes())
}

/// Bytes of one marking ADS stream on a marked entry. The `Status` stream is the
/// status word; the `Macb` stream is a JSON object of the four ISO-8601 times.
pub fn ads_stream_value(mark: &Mark, stream: MarkStream) -> Vec<u8> {
    match stream {
        MarkStream::Status => status_str(mark.allocation).as_bytes().to_vec(),
        MarkStream::Macb => {
            let obj = serde_json::json!({
                "modified": iso8601_utc(mark.macb.modified),
                "accessed": iso8601_utc(mark.macb.accessed),
                "changed": iso8601_utc(mark.macb.changed),
                "born": iso8601_utc(mark.macb.born),
            });
            serde_json::to_vec(&obj).unwrap_or_default()
        }
    }
}

/// Days since the Unix epoch → (year, month, day). Howard Hinnant's
/// `civil_from_days` (public domain), valid across the whole i64 range.
#[allow(clippy::many_single_char_names)] // canonical algorithm's variable names
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsFileType, FsTimestamp};

    fn ts(secs: i64) -> FsTimestamp {
        FsTimestamp {
            seconds: secs,
            nanoseconds: 0,
        }
    }

    fn sample_mark(allocation: FsAllocation) -> Mark {
        Mark {
            allocation,
            macb: Macb {
                modified: 1_700_000_000,
                accessed: 1_700_000_100,
                changed: 1_700_000_200,
                born: 1_700_000_300,
            },
        }
    }

    #[test]
    fn status_str_maps_allocation() {
        assert_eq!(status_str(FsAllocation::Deleted), "deleted");
        assert_eq!(status_str(FsAllocation::Orphan), "orphan");
    }

    #[test]
    fn iso8601_utc_renders_zulu() {
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_utc(200), "1970-01-01T00:03:20Z");
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn unix_xattr_names_are_the_schema() {
        assert_eq!(
            UNIX_XATTR_NAMES,
            [
                "user.4n6.status",
                "user.4n6.macb.modified",
                "user.4n6.macb.accessed",
                "user.4n6.macb.changed",
                "user.4n6.macb.born",
            ]
        );
    }

    #[test]
    fn unix_xattr_value_status_and_macb() {
        let d = sample_mark(FsAllocation::Deleted);
        let o = sample_mark(FsAllocation::Orphan);
        assert_eq!(
            unix_xattr_value(&d, "user.4n6.status").as_deref(),
            Some(&b"deleted"[..])
        );
        assert_eq!(
            unix_xattr_value(&o, "user.4n6.status").as_deref(),
            Some(&b"orphan"[..])
        );
        assert_eq!(
            unix_xattr_value(&d, "user.4n6.macb.modified").as_deref(),
            Some(iso8601_utc(1_700_000_000).as_bytes())
        );
        assert_eq!(
            unix_xattr_value(&d, "user.4n6.macb.born").as_deref(),
            Some(iso8601_utc(1_700_000_300).as_bytes())
        );
        // A name outside the schema yields None.
        assert!(unix_xattr_value(&d, "user.4n6.nope").is_none());
        assert!(unix_xattr_value(&d, "user.other").is_none());
    }

    #[test]
    fn ads_stream_base_names_and_full_names() {
        assert_eq!(MarkStream::Status.base(), "4n6.status");
        assert_eq!(MarkStream::Macb.base(), "4n6.macb");
        assert_eq!(MarkStream::Status.ads_full_name(), ":4n6.status:$DATA");
        assert_eq!(MarkStream::Macb.ads_full_name(), ":4n6.macb:$DATA");
        assert_eq!(ADS_STREAMS, [MarkStream::Status, MarkStream::Macb]);
    }

    #[test]
    fn ads_from_base_recognizes_only_ours() {
        assert_eq!(
            MarkStream::from_base("4n6.status"),
            Some(MarkStream::Status)
        );
        assert_eq!(MarkStream::from_base("4n6.macb"), Some(MarkStream::Macb));
        assert_eq!(MarkStream::from_base("Zone.Identifier"), None);
        assert_eq!(MarkStream::from_base(""), None);
    }

    #[test]
    fn ads_status_stream_is_the_status_word() {
        let d = sample_mark(FsAllocation::Deleted);
        let o = sample_mark(FsAllocation::Orphan);
        assert_eq!(ads_stream_value(&d, MarkStream::Status), b"deleted");
        assert_eq!(ads_stream_value(&o, MarkStream::Status), b"orphan");
    }

    #[test]
    fn ads_macb_stream_is_json_of_the_four_iso_times() {
        let d = sample_mark(FsAllocation::Deleted);
        let bytes = ads_stream_value(&d, MarkStream::Macb);
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(v["modified"], iso8601_utc(1_700_000_000));
        assert_eq!(v["accessed"], iso8601_utc(1_700_000_100));
        assert_eq!(v["changed"], iso8601_utc(1_700_000_200));
        assert_eq!(v["born"], iso8601_utc(1_700_000_300));
    }

    /// The parity contract: the *value* the Unix xattr channel emits for the
    /// status is byte-identical to the Windows ADS status stream, and each MACB
    /// time is identical across the two channels. Same logical schema, two
    /// physical channels.
    #[test]
    fn unix_and_windows_channels_agree_on_values() {
        let d = sample_mark(FsAllocation::Deleted);
        // Status parity.
        assert_eq!(
            unix_xattr_value(&d, "user.4n6.status").unwrap(),
            ads_stream_value(&d, MarkStream::Status)
        );
        // MACB-time parity: the Unix per-field xattr equals the matching field
        // in the Windows combined JSON stream.
        let macb_json: serde_json::Value =
            serde_json::from_slice(&ads_stream_value(&d, MarkStream::Macb)).unwrap();
        for (xattr, field) in [
            ("user.4n6.macb.modified", "modified"),
            ("user.4n6.macb.accessed", "accessed"),
            ("user.4n6.macb.changed", "changed"),
            ("user.4n6.macb.born", "born"),
        ] {
            let unix = String::from_utf8(unix_xattr_value(&d, xattr).unwrap()).unwrap();
            assert_eq!(unix, macb_json[field].as_str().unwrap());
        }
    }

    #[test]
    fn from_node_applies_the_macb_mapping() {
        let node = FsDeletedNode {
            ino: 42,
            name: b"notes.txt".to_vec(),
            parent_ino: Some(5),
            size: 12,
            file_type: FsFileType::RegularFile,
            allocation: FsAllocation::Deleted,
            record_id: 12345,
            atime: ts(200),
            mtime: ts(100),
            ctime: ts(300),
            crtime: ts(400),
        };
        let mark = Mark::from_node(&node);
        assert_eq!(mark.allocation, FsAllocation::Deleted);
        assert_eq!(mark.macb.modified, 100); // mtime
        assert_eq!(mark.macb.accessed, 200); // atime
        assert_eq!(mark.macb.changed, 300); // ctime
        assert_eq!(mark.macb.born, 400); // crtime
    }
}
