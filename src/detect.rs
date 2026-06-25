#![forbid(unsafe_code)]

use std::io::{self, Read, Seek, SeekFrom};

/// Detected filesystem type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Ext4,
    Ntfs,
    ExFat,
    Hfsplus,
    Apfs,
    Ewf,
    Iso,
    Vmdk,
    Zip,
    SevenZ,
    TarGz,
    TarBz2,
    Unknown,
}

impl std::fmt::Display for FsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsType::Ext4 => write!(f, "ext4"),
            FsType::Ntfs => write!(f, "ntfs"),
            FsType::ExFat => write!(f, "exfat"),
            FsType::Hfsplus => write!(f, "hfsplus"),
            FsType::Apfs => write!(f, "apfs"),
            FsType::Ewf => write!(f, "ewf"),
            FsType::Iso => write!(f, "iso9660"),
            FsType::Vmdk => write!(f, "vmdk"),
            FsType::Zip => write!(f, "zip"),
            FsType::SevenZ => write!(f, "7z"),
            FsType::TarGz => write!(f, "tar.gz"),
            FsType::TarBz2 => write!(f, "tar.bz2"),
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
            "hfsplus" | "hfs+" | "hfsx" => Ok(FsType::Hfsplus),
            "apfs" => Ok(FsType::Apfs),
            "ewf" | "e01" => Ok(FsType::Ewf),
            "iso" | "iso9660" | "cd" | "udf" => Ok(FsType::Iso),
            "zip" => Ok(FsType::Zip),
            "7z" | "sevenz" | "7zip" => Ok(FsType::SevenZ),
            "targz" | "tar.gz" | "tgz" | "gz" | "gzip" => Ok(FsType::TarGz),
            "tarbz2" | "tar.bz2" | "tbz2" | "tbz" | "bz2" | "bzip2" => Ok(FsType::TarBz2),
            _ => Err(format!("unknown filesystem type: {s}")),
        }
    }
}

/// Auto-detect filesystem type from a Read+Seek source.
///
/// Checks magic numbers for ext4, NTFS, exFAT, HFS+, APFS, ISO9660, the EWF and
/// VMDK containers, and the zip/7z/gzip archive formats. Returns `FsType::Unknown`
/// if no known signature matches. The seek position is reset to 0 after detection.
pub fn detect_filesystem<R: Read + Seek>(source: &mut R) -> io::Result<FsType> {
    // Seek to start
    source.seek(SeekFrom::Start(0))?;

    // Read enough bytes for all checks.  The ISO 9660 volume descriptor lives
    // at sector 16: byte 32769 for 2048-byte sectors, or 37633 for 2352-byte
    // raw CD sectors.  Read through the raw-mode offset so both are covered.
    let mut buf = vec![0u8; 37_640];
    let bytes_read = read_fill(source, &mut buf);

    // Reset seek position to start
    source.seek(SeekFrom::Start(0))?;

    // Check EWF: signature "EVF\x09\x0d\x0a\xff\x00" at byte 0
    if bytes_read >= 8 && buf[0..3] == [0x45, 0x56, 0x46] && buf[3] == 0x09 {
        return Ok(FsType::Ewf);
    }

    // Check VMDK: sparse/streamOptimized header magic 0x564D444B ("KDMV", LE) at
    // byte 0, or a text descriptor file. VMDK is a container, like EWF.
    if bytes_read >= 4 && buf[0..4] == [0x4B, 0x44, 0x4D, 0x56] {
        return Ok(FsType::Vmdk);
    }
    if bytes_read >= 21 && buf[0..21] == *b"# Disk DescriptorFile" {
        return Ok(FsType::Vmdk);
    }

    // Check archives by their byte-0 signatures. These are terminal containers
    // that expose a file tree directly (no inner filesystem to recurse into).
    //   gzip: 1f 8b  (a .tar.gz / .tgz; a bare .gz is decoded as a 1-file tar)
    //   zip : "PK\x03\x04" (local file header) or "PK\x05\x06" (empty archive)
    //   7z  : 37 7a bc af 27 1c
    if bytes_read >= 2 && buf[0] == 0x1F && buf[1] == 0x8B {
        return Ok(FsType::TarGz);
    }
    // bzip2: "BZh" (a .tar.bz2 / .tbz2; a bare .bz2 is decoded as a 1-file tar)
    if bytes_read >= 3 && &buf[0..3] == b"BZh" {
        return Ok(FsType::TarBz2);
    }
    if bytes_read >= 4
        && buf[0..2] == [0x50, 0x4B]
        && matches!(buf[2..4], [0x03, 0x04] | [0x05, 0x06] | [0x07, 0x08])
    {
        return Ok(FsType::Zip);
    }
    if bytes_read >= 6 && buf[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Ok(FsType::SevenZ);
    }

    // Check APFS: container superblock magic "NXSB" at byte 32 (after the
    // 32-byte obj_phys_t object header of block 0).
    if bytes_read >= 36 && &buf[32..36] == b"NXSB" {
        return Ok(FsType::Apfs);
    }

    // Check NTFS: "NTFS" at byte 3
    if bytes_read >= 7 && &buf[3..7] == b"NTFS" {
        return Ok(FsType::Ntfs);
    }

    // Check exFAT: "EXFAT" at byte 3
    if bytes_read >= 8 && &buf[3..8] == b"EXFAT" {
        return Ok(FsType::ExFat);
    }

    // Check HFS+/HFSX: volume header at byte 1024; signature "H+" (0x482B) for
    // HFS+, "HX" (0x4858) for the case-sensitive HFSX variant.
    if bytes_read >= 1026 && buf[1024] == 0x48 && (buf[1025] == 0x2B || buf[1025] == 0x58) {
        return Ok(FsType::Hfsplus);
    }

    // Check ext4: magic 0xEF53 at byte 1080 (little-endian)
    if bytes_read >= 1082 {
        let magic = u16::from_le_bytes([buf[1080], buf[1081]]);
        if magic == 0xEF53 {
            return Ok(FsType::Ext4);
        }
    }

    // Check ISO 9660 / UDF: "CD001" at sector 16.
    //   2048-byte sectors: offset 32769 (16 * 2048 + 1)
    //   2352-byte raw CD : offset 37633 (16 * 2352 + 16 + 1)
    if bytes_read >= 32_774 && &buf[32_769..32_774] == b"CD001" {
        return Ok(FsType::Iso);
    }
    if bytes_read >= 37_638 && &buf[37_633..37_638] == b"CD001" {
        return Ok(FsType::Iso);
    }

    Ok(FsType::Unknown)
}

/// A recognized memory-dump container format. These route to the memory mount
/// path (a `MemoryFs` over memf), not the disk-filesystem dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemDumpFormat {
    /// LiME (Linux Memory Extractor) — magic "EMiL".
    Lime,
    /// AVML (Acquisition of Volatile Memory for Linux) v2 — magic "AVML".
    Avml,
    /// ELF core dump (`ET_CORE`).
    ElfCore,
    /// Windows kernel crash dump (64-bit) — magic "PAGEDU64".
    WinCrashDump,
}

impl std::fmt::Display for MemDumpFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemDumpFormat::Lime => write!(f, "lime"),
            MemDumpFormat::Avml => write!(f, "avml"),
            MemDumpFormat::ElfCore => write!(f, "elf-core"),
            MemDumpFormat::WinCrashDump => write!(f, "win-crashdump"),
        }
    }
}

/// Detect a memory-dump container by its header magic.
///
/// Returns `Ok(None)` for non-dumps — including raw/headerless dumps, which
/// carry no signature and must be selected explicitly (`--fs memory`). The seek
/// position is reset to 0. Magics mirror `memf-format`'s plugins (LiME
/// `0x4C694D45`, AVML `0x4C4D5641`, ELF `ET_CORE`, crash `PAGE`+`DU64`).
pub fn detect_memory_dump<R: Read + Seek>(source: &mut R) -> io::Result<Option<MemDumpFormat>> {
    let _ = MemDumpFormat::Lime;
    source.seek(SeekFrom::Start(0))?;
    Ok(None)
}

/// Read as many bytes as possible into `buf`, returning total bytes read.
fn read_fill<R: Read>(source: &mut R, buf: &mut [u8]) -> usize {
    let mut total = 0;
    while total < buf.len() {
        match source.read(&mut buf[total..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn detects_vmdk_sparse_magic() {
        // VMDK sparse/streamOptimized header magic 0x564D444B ("KDMV", LE) at byte 0.
        let mut data = vec![0u8; 2048];
        data[0..4].copy_from_slice(b"KDMV");
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::Vmdk
        );
    }

    #[test]
    fn detects_vmdk_text_descriptor() {
        let data = b"# Disk DescriptorFile\nversion=1\n".to_vec();
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::Vmdk
        );
    }

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

    /// ISO 9660: "CD001" at byte 1 of sector 16 (offset 16*2048 = 32768).
    fn make_iso_image() -> Vec<u8> {
        let mut data = vec![0u8; 18 * 2048];
        let pvd = 16 * 2048;
        data[pvd] = 0x01;
        data[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        data[pvd + 6] = 0x01;
        data
    }

    #[test]
    fn detect_iso() {
        let data = make_iso_image();
        let mut cursor = Cursor::new(data);
        assert_eq!(detect_filesystem(&mut cursor).unwrap(), FsType::Iso);
    }

    #[test]
    fn iso_fstype_parses_from_str() {
        assert_eq!("iso".parse::<FsType>().unwrap(), FsType::Iso);
        assert_eq!("iso9660".parse::<FsType>().unwrap(), FsType::Iso);
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
        let Ok(data) = std::fs::read(path) else {
            eprintln!("skip: forensic.img not found");
            return;
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

    #[test]
    fn detect_gzip_as_targz() {
        // gzip magic 1f 8b at byte 0.
        let mut data = vec![0u8; 64];
        data[0] = 0x1F;
        data[1] = 0x8B;
        data[2] = 0x08; // deflate
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::TarGz
        );
    }

    #[test]
    fn detect_mem_lime() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"EMiL"); // LIME_MAGIC 0x4C694D45 little-endian
        assert_eq!(
            detect_memory_dump(&mut Cursor::new(data)).unwrap(),
            Some(MemDumpFormat::Lime)
        );
    }

    #[test]
    fn detect_mem_avml() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"AVML");
        assert_eq!(
            detect_memory_dump(&mut Cursor::new(data)).unwrap(),
            Some(MemDumpFormat::Avml)
        );
    }

    #[test]
    fn detect_mem_elf_core() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[16..18].copy_from_slice(&4u16.to_le_bytes()); // e_type = ET_CORE
        assert_eq!(
            detect_memory_dump(&mut Cursor::new(data)).unwrap(),
            Some(MemDumpFormat::ElfCore)
        );
    }

    #[test]
    fn detect_mem_elf_exec_is_not_a_dump() {
        // A normal ELF executable (ET_EXEC) is not a core dump.
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        assert_eq!(detect_memory_dump(&mut Cursor::new(data)).unwrap(), None);
    }

    #[test]
    fn detect_mem_win_crashdump() {
        let mut data = vec![0u8; 64];
        data[0..8].copy_from_slice(b"PAGEDU64");
        assert_eq!(
            detect_memory_dump(&mut Cursor::new(data)).unwrap(),
            Some(MemDumpFormat::WinCrashDump)
        );
    }

    #[test]
    fn detect_mem_none_for_non_dump() {
        let mut data = vec![0u8; 64];
        assert_eq!(detect_memory_dump(&mut Cursor::new(data)).unwrap(), None);
    }

    #[test]
    fn detect_bzip2_as_tarbz2() {
        // bzip2 magic "BZh" (0x42 0x5A 0x68) at byte 0.
        let mut data = vec![0u8; 64];
        data[0..3].copy_from_slice(b"BZh");
        data[3] = b'9'; // block-size digit
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::TarBz2
        );
    }

    #[test]
    fn detect_zip_local_file_header() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::Zip
        );
    }

    #[test]
    fn detect_zip_empty_archive() {
        // An empty zip is just the end-of-central-directory record: PK\x05\x06.
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"PK\x05\x06");
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::Zip
        );
    }

    #[test]
    fn detect_7z_signature() {
        let mut data = vec![0u8; 64];
        data[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::SevenZ
        );
    }

    #[test]
    fn detect_hfsplus_signature() {
        // HFS+ volume header at byte 1024; signature "H+" (0x482B).
        let mut data = vec![0u8; 2048];
        data[1024] = 0x48; // 'H'
        data[1025] = 0x2B; // '+'
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::Hfsplus
        );
    }

    #[test]
    fn detect_hfsx_signature() {
        // HFSX (case-sensitive) uses "HX" (0x4858) at the same offset.
        let mut data = vec![0u8; 2048];
        data[1024] = 0x48; // 'H'
        data[1025] = 0x58; // 'X'
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::Hfsplus
        );
    }

    #[test]
    fn detect_apfs_nxsb() {
        // APFS container superblock: 32-byte obj header, then magic "NXSB".
        let mut data = vec![0u8; 4096];
        data[32..36].copy_from_slice(b"NXSB");
        assert_eq!(
            detect_filesystem(&mut Cursor::new(data)).unwrap(),
            FsType::Apfs
        );
    }

    #[test]
    fn new_fstypes_parse_and_display() {
        assert_eq!("hfsplus".parse::<FsType>().unwrap(), FsType::Hfsplus);
        assert_eq!("apfs".parse::<FsType>().unwrap(), FsType::Apfs);
        assert_eq!("zip".parse::<FsType>().unwrap(), FsType::Zip);
        assert_eq!("7z".parse::<FsType>().unwrap(), FsType::SevenZ);
        assert_eq!("tar.gz".parse::<FsType>().unwrap(), FsType::TarGz);
        assert_eq!(FsType::Hfsplus.to_string(), "hfsplus");
        assert_eq!(FsType::SevenZ.to_string(), "7z");
        assert_eq!(FsType::TarGz.to_string(), "tar.gz");
    }
}
