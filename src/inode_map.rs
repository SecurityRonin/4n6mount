#![forbid(unsafe_code)]

/// FUSE inode number constants for virtual directories.
pub const FUSE_ROOT_INO: u64 = 1;
pub const FUSE_RO_INO: u64 = 2;
pub const FUSE_RW_INO: u64 = 3;
pub const FUSE_DELETED_INO: u64 = 4;
pub const FUSE_JOURNAL_INO: u64 = 5;
pub const FUSE_METADATA_INO: u64 = 6;
pub const FUSE_UNALLOCATED_INO: u64 = 7;
pub const FUSE_SESSION_INO: u64 = 8;
pub const FUSE_EVIDENCE_INO: u64 = 9;

/// Offset added to real ext4 inodes when exposing them under ro/.
const RO_INODE_OFFSET: u64 = 1_000;
/// Offset for rw/ overlay inodes.
const RW_INODE_OFFSET: u64 = 10_000_000;
/// Offset for deleted/ virtual file inodes.
const DELETED_INODE_OFFSET: u64 = 20_000_000;
/// Offset for metadata/ virtual file inodes.
const METADATA_INODE_OFFSET: u64 = 30_000_000;
/// Offset for journal/ virtual file inodes.
const JOURNAL_INODE_OFFSET: u64 = 40_000_000;
/// Offset for evidence/ filtered view inodes.
const EVIDENCE_INODE_OFFSET: u64 = 50_000_000;
/// Offset for unallocated/ virtual file inodes.
const UNALLOCATED_INODE_OFFSET: u64 = 60_000_000;

/// Which virtual namespace a FUSE inode belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeNamespace {
    /// Virtual root or top-level directory
    Virtual(u64),
    /// Real ext4 inode under ro/
    Ro(u64),
    /// Overlay inode under rw/
    Rw(u64),
    /// Deleted file virtual inode
    Deleted(u64),
    /// Metadata virtual file
    Metadata(u64),
    /// Journal virtual file
    Journal(u64),
    /// Evidence filtered view inode
    Evidence(u64),
    /// Unallocated block range
    Unallocated(u64),
}

/// Convert a FUSE inode number to its namespace and real inode.
pub fn decode_fuse_ino(ino: u64) -> InodeNamespace {
    if ino <= FUSE_EVIDENCE_INO {
        InodeNamespace::Virtual(ino)
    } else if ino >= UNALLOCATED_INODE_OFFSET {
        InodeNamespace::Unallocated(ino - UNALLOCATED_INODE_OFFSET)
    } else if ino >= EVIDENCE_INODE_OFFSET {
        InodeNamespace::Evidence(ino - EVIDENCE_INODE_OFFSET)
    } else if ino >= JOURNAL_INODE_OFFSET {
        InodeNamespace::Journal(ino - JOURNAL_INODE_OFFSET)
    } else if ino >= METADATA_INODE_OFFSET {
        InodeNamespace::Metadata(ino - METADATA_INODE_OFFSET)
    } else if ino >= DELETED_INODE_OFFSET {
        InodeNamespace::Deleted(ino - DELETED_INODE_OFFSET)
    } else if ino >= RW_INODE_OFFSET {
        InodeNamespace::Rw(ino - RW_INODE_OFFSET)
    } else {
        InodeNamespace::Ro(ino - RO_INODE_OFFSET)
    }
}

/// Encode a real ext4 inode for the ro/ namespace.
pub fn ro_ino(ext4_ino: u64) -> u64 {
    ext4_ino + RO_INODE_OFFSET
}

/// Encode an overlay inode for the rw/ namespace.
pub fn rw_ino(ext4_ino: u64) -> u64 {
    ext4_ino + RW_INODE_OFFSET
}

/// Encode a deleted inode for the deleted/ namespace.
pub fn deleted_ino(ext4_ino: u64) -> u64 {
    ext4_ino + DELETED_INODE_OFFSET
}

/// Encode a metadata virtual inode.
pub fn metadata_ino(id: u64) -> u64 {
    id + METADATA_INODE_OFFSET
}

/// Encode a journal virtual inode.
pub fn journal_ino(seq: u64) -> u64 {
    seq + JOURNAL_INODE_OFFSET
}

/// Encode an evidence filtered view inode.
pub fn evidence_ino(ext4_ino: u64) -> u64 {
    ext4_ino + EVIDENCE_INODE_OFFSET
}

/// Encode an unallocated range virtual inode.
pub fn unallocated_ino(id: u64) -> u64 {
    id + UNALLOCATED_INODE_OFFSET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ro_inode() {
        let ext4_ino = 42;
        let fuse = ro_ino(ext4_ino);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Ro(ext4_ino));
    }

    #[test]
    fn roundtrip_rw_inode() {
        let ext4_ino = 42;
        let fuse = rw_ino(ext4_ino);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Rw(ext4_ino));
    }

    #[test]
    fn roundtrip_deleted_inode() {
        let ext4_ino = 21;
        let fuse = deleted_ino(ext4_ino);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Deleted(ext4_ino));
    }

    #[test]
    fn virtual_root() {
        assert_eq!(decode_fuse_ino(FUSE_ROOT_INO), InodeNamespace::Virtual(1));
    }

    #[test]
    fn virtual_dirs() {
        assert_eq!(decode_fuse_ino(FUSE_RO_INO), InodeNamespace::Virtual(2));
        assert_eq!(decode_fuse_ino(FUSE_RW_INO), InodeNamespace::Virtual(3));
        assert_eq!(decode_fuse_ino(FUSE_DELETED_INO), InodeNamespace::Virtual(4));
    }

    #[test]
    fn roundtrip_metadata_inode() {
        let id = 1;
        let fuse = metadata_ino(id);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Metadata(id));
    }

    #[test]
    fn roundtrip_journal_inode() {
        let seq = 42;
        let fuse = journal_ino(seq);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Journal(seq));
    }

    #[test]
    fn roundtrip_unallocated_inode() {
        let id = 7;
        let fuse = unallocated_ino(id);
        assert_eq!(decode_fuse_ino(fuse), InodeNamespace::Unallocated(id));
    }

    #[test]
    fn namespaces_do_not_overlap() {
        // Verify that max realistic ext4 inode in ro/ doesn't collide with rw/
        let max_ro = ro_ino(9_000_000);
        let min_rw = rw_ino(0);
        assert!(max_ro < min_rw);
    }
}
