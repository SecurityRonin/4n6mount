#![forbid(unsafe_code)]

use std::io::{self, Read, Seek, SeekFrom};

/// Detected filesystem type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Ext4,
    Ntfs,
    ExFat,
    Ewf,
    Unknown,
}

impl std::fmt::Display for FsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsType::Ext4 => write!(f, "ext4"),
            FsType::Ntfs => write!(f, "ntfs"),
            FsType::ExFat => write!(f, "exfat"),
            FsType::Ewf => write!(f, "ewf"),
            FsType::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for FsType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ext4" => Ok(FsType::Ext4),
            "ntfs" => Ok(FsType::Ntfs),
            "exfat" => Ok(FsType::ExFat),
            "ewf" | "e01" => Ok(FsType::Ewf),
            _ => Err(format!("unknown filesystem type: {s}")),
        }
    }
}

/// Auto-detect filesystem type from a Read+Seek source.
///
/// Checks magic numbers for ext4, NTFS, and exFAT. Returns `FsType::Unknown`
/// if no known signature matches. The seek position is reset to 0 after detection.
pub fn detect_filesystem<R: Read + Seek>(source: &mut R) -> io::Result<FsType> {
    // Seek to start
    source.seek(SeekFrom::Start(0))?;

    // Read enough bytes for all checks (need at least 1082 for ext4)
    let mut buf = vec![0u8; 1082];
    let bytes_read = read_fill(source, &mut buf);

    // Reset seek position to start
    source.seek(SeekFrom::Start(0))?;

    // Check NTFS: "NTFS" at byte 3
    if bytes_read >= 7 && &buf[3..7] == b"NTFS" {
        return Ok(FsType::Ntfs);
    }

    // Check exFAT: "EXFAT" at byte 3
    if bytes_read >= 8 && &buf[3..8] == b"EXFAT" {
        return Ok(FsType::ExFat);
    }

    // Check ext4: magic 0xEF53 at byte 1080 (little-endian)
    if bytes_read >= 1082 {
        let magic = u16::from_le_bytes([buf[1080], buf[1081]]);
        if magic == 0xEF53 {
            return Ok(FsType::Ext4);
        }
    }

    Ok(FsType::Unknown)
}

/// Read as many bytes as possible into `buf`, returning total bytes read.
fn read_fill<R: Read>(source: &mut R, buf: &mut [u8]) -> usize {
    let mut total = 0;
    while total < buf.len() {
        match source.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_ext4_image() -> Vec<u8> {
        // ext4 magic 0xEF53 is at byte offset 1080 (0x438) within the superblock
        // Superblock starts at byte 1024
        let mut data = vec![0u8; 2048];
        data[1080] = 0x53; // low byte of 0xEF53
        data[1081] = 0xEF; // high byte (little-endian)
        data
    }

    fn make_ntfs_image() -> Vec<u8> {
        // NTFS: "NTFS    " (with spaces) at byte offset 3
        let mut data = vec![0u8; 512];
        data[3..7].copy_from_slice(b"NTFS");
        data
    }

    fn make_exfat_image() -> Vec<u8> {
        // exFAT: "EXFAT   " at byte offset 3
        let mut data = vec![0u8; 512];
        data[3..8].copy_from_slice(b"EXFAT");
        data
    }

    #[test]
    fn detect_ext4() {
        let data = make_ext4_image();
        let mut cursor = Cursor::new(data);
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::Ext4);
    }

    #[test]
    fn detect_ntfs() {
        let data = make_ntfs_image();
        let mut cursor = Cursor::new(data);
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::Ntfs);
    }

    #[test]
    fn detect_exfat() {
        let data = make_exfat_image();
        let mut cursor = Cursor::new(data);
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::ExFat);
    }

    #[test]
    fn detect_unknown() {
        let data = vec![0u8; 2048];
        let mut cursor = Cursor::new(data);
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::Unknown);
    }

    #[test]
    fn detect_too_short() {
        let data = vec![0u8; 10];
        let mut cursor = Cursor::new(data);
        // Should not panic, should return Unknown or an error
        let result = detect_filesystem(&mut cursor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FsType::Unknown);
    }

    #[test]
    fn detect_real_ext4_image() {
        let path = "/Users/4n6h4x0r/src/ext4fs-forensic/tests/data/forensic.img";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => { eprintln!("skip: forensic.img not found"); return; }
        };
        let mut cursor = Cursor::new(data);
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::Ext4);
    }

    #[test]
    fn fstype_from_str() {
        assert_eq!("ext4".parse::<FsType>().unwrap(), FsType::Ext4);
        assert_eq!("NTFS".parse::<FsType>().unwrap(), FsType::Ntfs);
        assert_eq!("ExFat".parse::<FsType>().unwrap(), FsType::ExFat);
        assert!("btrfs".parse::<FsType>().is_err());
    }

    #[test]
    fn fstype_display() {
        assert_eq!(FsType::Ext4.to_string(), "ext4");
        assert_eq!(FsType::Ntfs.to_string(), "ntfs");
        assert_eq!(FsType::ExFat.to_string(), "exfat");
        assert_eq!(FsType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn detect_ewf_image() {
        // EWF signature: EVF\x09\x0d\x0a\xff\x00
        let mut data = vec![0u8; 2048];
        data[0..8].copy_from_slice(&[0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00]);
        let mut cursor = Cursor::new(data);
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::Ewf);
    }

    #[test]
    fn fstype_ewf_display() {
        assert_eq!(FsType::Ewf.to_string(), "ewf");
    }

    #[test]
    fn fstype_ewf_from_str() {
        assert_eq!("ewf".parse::<FsType>().unwrap(), FsType::Ewf);
        assert_eq!("e01".parse::<FsType>().unwrap(), FsType::Ewf);
    }

    #[test]
    fn detect_resets_seek_position() {
        let data = make_ext4_image();
        let mut cursor = Cursor::new(data);
        cursor.seek(SeekFrom::Start(500)).unwrap();
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::Ext4);
        // Seek position should be reset to 0 after detection
        assert_eq!(cursor.stream_position().unwrap(), 0);
    }
}
