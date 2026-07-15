#![forbid(unsafe_code)]

use std::io::{self, Read, Seek, SeekFrom};

/// A recognized memory-dump container format. These route to the memory mount
/// path (a `MemoryFs` over memf), not the engine's disk/logical `open()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemDumpFormat {
    /// `LiME` (Linux Memory Extractor) — magic `EMiL`.
    Lime,
    /// AVML (Acquisition of Volatile Memory for Linux) v2 — magic `AVML`.
    Avml,
    /// ELF core dump (`ET_CORE`).
    ElfCore,
    /// Windows kernel crash dump (64-bit) — magic `PAGEDU64`.
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
/// position is reset to 0. Magics mirror `memf-format`'s plugins (`LiME`
/// `0x4C694D45`, AVML `0x4C4D5641`, ELF `ET_CORE`, crash `PAGE` + `DU64`).
pub fn detect_memory_dump<R: Read + Seek>(source: &mut R) -> io::Result<Option<MemDumpFormat>> {
    source.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 18];
    let n = read_fill(source, &mut buf);
    source.seek(SeekFrom::Start(0))?;

    // LiME header: magic 0x4C694D45 ("EMiL" little-endian) at byte 0.
    if n >= 4 && &buf[0..4] == b"EMiL" {
        return Ok(Some(MemDumpFormat::Lime));
    }
    // AVML v2: magic 0x4C4D5641 ("AVML" little-endian) at byte 0.
    if n >= 4 && &buf[0..4] == b"AVML" {
        return Ok(Some(MemDumpFormat::Avml));
    }
    // Windows kernel crash dump (64-bit): "PAGE" + "DU64" = "PAGEDU64" at byte 0.
    if n >= 8 && &buf[0..8] == b"PAGEDU64" {
        return Ok(Some(MemDumpFormat::WinCrashDump));
    }
    // ELF core dump: ELF magic at byte 0 and e_type == ET_CORE (4) at byte 16.
    if n >= 18 && buf[0..4] == [0x7F, b'E', b'L', b'F'] {
        let e_type = u16::from_le_bytes([buf[16], buf[17]]);
        if e_type == 4 {
            return Ok(Some(MemDumpFormat::ElfCore));
        }
    }
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
        let data = vec![0u8; 64];
        assert_eq!(detect_memory_dump(&mut Cursor::new(data)).unwrap(), None);
    }
}
