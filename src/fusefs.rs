#![forbid(unsafe_code)]

use crate::inode_map::*;
use crate::session::Session;
use crate::types::*;
use crate::ForensicFs;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, Request, TimeOrNow,
};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

/// Virtual directory names at the FUSE root.
const VIRTUAL_DIRS: &[(u64, &str)] = &[
    (FUSE_RO_INO, "ro"),
    (FUSE_RW_INO, "rw"),
    (FUSE_DELETED_INO, "deleted"),
    (FUSE_JOURNAL_INO, "journal"),
    (FUSE_METADATA_INO, "metadata"),
    (FUSE_UNALLOCATED_INO, "unallocated"),
    (FUSE_SESSION_INO, "session"),
];

/// Cached entry for a deleted file visible in the `deleted/` virtual directory.
struct DeletedEntry {
    fs_ino: u64,
    name: String,
    size: u64,
    data: Vec<u8>,
}

/// Cached entry for a journal transaction visible in the `journal/` virtual directory.
struct JournalTxnEntry {
    sequence: u64,
    name: String,
}

/// Cached metadata files for the `metadata/` virtual directory.
struct MetadataCache {
    superblock_json: Vec<u8>,
    timeline_jsonl: Vec<u8>,
}

/// Cached entry for an unallocated block range visible in the `unallocated/` virtual directory.
struct UnallocatedEntry {
    #[allow(dead_code)]
    range_id: u64,
    name: String,
    start: u64,
    length: u64,
}

pub struct ForensicFuseFs {
    fs: RefCell<Box<dyn ForensicFs>>,
    session: RefCell<Option<Session>>,
    /// Counter for allocating new overlay inode numbers (for created files).
    overlay_ino_counter: RefCell<u64>,
    /// The root inode number reported by the underlying filesystem.
    root_ino: u64,
    /// Lazy-loaded cache for the deleted/ virtual directory.
    deleted_cache: RefCell<Option<Vec<DeletedEntry>>>,
    /// Lazy-loaded cache for the journal/ virtual directory.
    journal_cache: RefCell<Option<Vec<JournalTxnEntry>>>,
    /// Lazy-loaded cache for the metadata/ virtual directory.
    metadata_cache: RefCell<Option<MetadataCache>>,
    /// Lazy-loaded cache for the unallocated/ virtual directory.
    unallocated_cache: RefCell<Option<Vec<UnallocatedEntry>>>,
}

impl ForensicFuseFs {
    pub fn new(fs: Box<dyn ForensicFs>, session: Option<Session>) -> Self {
        let root_ino = fs.root_ino();
        Self {
            fs: RefCell::new(fs),
            session: RefCell::new(session),
            overlay_ino_counter: RefCell::new(1),
            root_ino,
            deleted_cache: RefCell::new(None),
            journal_cache: RefCell::new(None),
            metadata_cache: RefCell::new(None),
            unallocated_cache: RefCell::new(None),
        }
    }

    /// Check if a session is available (rw/ operations require one).
    fn has_session(&self) -> bool {
        self.session.borrow().is_some()
    }

    /// Get the overlay file ID for a modified inode.
    fn modified_overlay_id(fs_ino: u64) -> String {
        format!("ino_{fs_ino}")
    }

    /// Allocate a new overlay inode number for created files.
    fn alloc_overlay_ino(&self) -> u64 {
        let mut counter = self.overlay_ino_counter.borrow_mut();
        let ino = *counter;
        *counter += 1;
        ino
    }

    /// Get the overlay file ID for a newly created file.
    fn created_overlay_id(counter: u64) -> String {
        format!("new_{counter}")
    }

    /// Build a FileAttr for an overlay-created file.
    fn overlay_created_attr(fuse_ino: u64, size: u64, is_dir: bool) -> FileAttr {
        let kind = if is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        FileAttr {
            ino: fuse_ino,
            size,
            blocks: size.div_ceil(512),
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind,
            perm: if is_dir { 0o755 } else { 0o644 },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Resolve rw/ parent inode to underlying fs parent inode.
    fn rw_parent_to_fs(&self, parent: u64) -> Option<u64> {
        match parent {
            FUSE_RW_INO => Some(self.root_ino),
            _ => match decode_fuse_ino(parent) {
                InodeNamespace::Rw(ino) => Some(ino),
                _ => None,
            },
        }
    }

    /// Check if an inode is in the whiteout (deleted) list.
    fn is_whiteout(&self, fs_ino: u64) -> bool {
        let session = self.session.borrow();
        match session.as_ref() {
            Some(s) => s.overlay.deleted.contains(&fs_ino),
            None => false,
        }
    }

    /// Ensure the deleted/ cache is populated.
    fn ensure_deleted_cache(&self) {
        if self.deleted_cache.borrow().is_some() {
            return;
        }
        let mut fs = self.fs.borrow_mut();
        let deleted_inodes = fs.deleted_inodes().unwrap_or_default();
        let mut entries = Vec::new();
        for di in &deleted_inodes {
            let name = format!("{}_unknown", di.ino);
            let result = fs.recover_file(di.ino);
            let (size, data) = match result {
                Ok(r) => (r.data.len() as u64, r.data),
                Err(_) => (0, Vec::new()),
            };
            entries.push(DeletedEntry {
                fs_ino: di.ino,
                name,
                size,
                data,
            });
        }
        *self.deleted_cache.borrow_mut() = Some(entries);
    }

    /// Ensure the journal/ cache is populated.
    fn ensure_journal_cache(&self) {
        if self.journal_cache.borrow().is_some() {
            return;
        }
        let mut fs = self.fs.borrow_mut();
        let entries = match fs.journal_transactions() {
            Ok(txns) => txns
                .iter()
                .map(|txn| JournalTxnEntry {
                    sequence: txn.sequence,
                    name: format!("txn_{}", txn.sequence),
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        *self.journal_cache.borrow_mut() = Some(entries);
    }

    /// Ensure the metadata/ cache is populated.
    fn ensure_metadata_cache(&self) {
        if self.metadata_cache.borrow().is_some() {
            return;
        }
        let fs = self.fs.borrow();

        // Build superblock.json from fs_info()
        let superblock_json = match fs.fs_info() {
            Ok(info) => serde_json::to_string_pretty(&info)
                .unwrap_or_default()
                .into_bytes(),
            Err(_) => b"{}".to_vec(),
        };
        drop(fs);

        // Build timeline.jsonl
        let mut fs = self.fs.borrow_mut();
        let timeline_jsonl = match fs.timeline() {
            Ok(events) => {
                let mut buf = Vec::new();
                for event in &events {
                    let event_type = match event.event_type {
                        FsEventType::Created => "Created",
                        FsEventType::Modified => "Modified",
                        FsEventType::Accessed => "Accessed",
                        FsEventType::Changed => "Changed",
                        FsEventType::Deleted => "Deleted",
                        FsEventType::Mounted => "Mounted",
                    };
                    let line = serde_json::json!({
                        "timestamp_secs": event.timestamp.seconds,
                        "timestamp_nsecs": event.timestamp.nanoseconds,
                        "event_type": event_type,
                        "inode": event.inode,
                        "size": event.size,
                        "uid": event.uid,
                        "gid": event.gid,
                    });
                    let line_str = serde_json::to_string(&line).unwrap_or_default();
                    buf.extend_from_slice(line_str.as_bytes());
                    buf.push(b'\n');
                }
                buf
            }
            Err(_) => Vec::new(),
        };

        *self.metadata_cache.borrow_mut() = Some(MetadataCache {
            superblock_json,
            timeline_jsonl,
        });
    }

    /// Ensure the unallocated/ cache is populated.
    fn ensure_unallocated_cache(&self) {
        if self.unallocated_cache.borrow().is_some() {
            return;
        }
        let mut fs = self.fs.borrow_mut();
        let entries = match fs.unallocated_blocks() {
            Ok(ranges) => ranges
                .iter()
                .enumerate()
                .map(|(i, r)| UnallocatedEntry {
                    range_id: i as u64,
                    name: format!("blocks_{}-{}.raw", r.start, r.start + r.length),
                    start: r.start,
                    length: r.length,
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        *self.unallocated_cache.borrow_mut() = Some(entries);
    }

    /// Find a created overlay entry by parent_ino and name.
    fn find_created_by_name(&self, parent_ino: u64, name: &[u8]) -> Option<(String, u64, bool)> {
        let session = self.session.borrow();
        let session = session.as_ref()?;
        let name_str = std::str::from_utf8(name).ok()?;
        for (id, entry) in &session.overlay.created {
            if entry.parent_ino == parent_ino && entry.name == name_str {
                let counter: u64 = id.strip_prefix("new_").and_then(|s| s.parse().ok())?;
                return Some((id.clone(), counter, false));
            }
        }
        for (id, entry) in &session.overlay.dirs {
            if entry.parent_ino == parent_ino && entry.name == name_str {
                let counter: u64 = id.strip_prefix("new_").and_then(|s| s.parse().ok())?;
                return Some((id.clone(), counter, true));
            }
        }
        None
    }
}

/// Convert a `FsTimestamp` to `SystemTime`.
fn ts_to_systime(t: &FsTimestamp) -> SystemTime {
    if t.seconds >= 0 {
        UNIX_EPOCH + Duration::new(t.seconds as u64, t.nanoseconds)
    } else {
        UNIX_EPOCH
    }
}

/// Build a `FileAttr` from an `FsMetadata`.
fn fs_to_attr(fuse_ino: u64, meta: &FsMetadata) -> FileAttr {
    let kind = match meta.file_type {
        FsFileType::RegularFile => FileType::RegularFile,
        FsFileType::Directory => FileType::Directory,
        FsFileType::Symlink => FileType::Symlink,
        FsFileType::CharDevice => FileType::CharDevice,
        FsFileType::BlockDevice => FileType::BlockDevice,
        FsFileType::Fifo => FileType::NamedPipe,
        FsFileType::Socket => FileType::Socket,
        FsFileType::Unknown => FileType::RegularFile,
    };

    FileAttr {
        ino: fuse_ino,
        size: meta.size,
        blocks: meta.size.div_ceil(512),
        atime: ts_to_systime(&meta.atime),
        mtime: ts_to_systime(&meta.mtime),
        ctime: ts_to_systime(&meta.ctime),
        crtime: ts_to_systime(&meta.crtime),
        kind,
        perm: meta.mode & 0o7777,
        nlink: meta.links_count as u32,
        uid: meta.uid,
        gid: meta.gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Build a synthetic `FileAttr` for a virtual directory.
fn virtual_dir_attr(ino: u64) -> FileAttr {
    FileAttr {
        ino,
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o555,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Build a synthetic `FileAttr` for a virtual read-only regular file.
fn virtual_file_attr(ino: u64, size: u64) -> FileAttr {
    FileAttr {
        ino,
        size,
        blocks: size.div_ceil(512),
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o444,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Convert an `FsFileType` to a fuser `FileType`.
fn fs_file_type_to_fuse(t: FsFileType) -> FileType {
    match t {
        FsFileType::RegularFile => FileType::RegularFile,
        FsFileType::Directory => FileType::Directory,
        FsFileType::Symlink => FileType::Symlink,
        FsFileType::CharDevice => FileType::CharDevice,
        FsFileType::BlockDevice => FileType::BlockDevice,
        FsFileType::Fifo => FileType::NamedPipe,
        FsFileType::Socket => FileType::Socket,
        FsFileType::Unknown => FileType::RegularFile,
    }
}

impl Filesystem for ForensicFuseFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_bytes = name.as_encoded_bytes();

        // Virtual root: resolve virtual directory names.
        if parent == FUSE_ROOT_INO {
            for &(ino, dir_name) in VIRTUAL_DIRS {
                if name_bytes == dir_name.as_bytes() {
                    let attr = if ino == FUSE_RW_INO && self.has_session() {
                        let mut a = virtual_dir_attr(ino);
                        a.perm = 0o755;
                        a
                    } else {
                        virtual_dir_attr(ino)
                    };
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
            }
            reply.error(libc::ENOENT);
            return;
        }

        // deleted/ namespace lookup.
        if parent == FUSE_DELETED_INO {
            self.ensure_deleted_cache();
            let cache = self.deleted_cache.borrow();
            if let Some(entries) = cache.as_ref() {
                for entry in entries {
                    if name_bytes == entry.name.as_bytes() {
                        let fuse_ino = deleted_ino(entry.fs_ino);
                        let attr = virtual_file_attr(fuse_ino, entry.size);
                        reply.entry(&TTL, &attr, 0);
                        return;
                    }
                }
            }
            reply.error(libc::ENOENT);
            return;
        }

        // journal/ namespace lookup.
        if parent == FUSE_JOURNAL_INO {
            self.ensure_journal_cache();
            let cache = self.journal_cache.borrow();
            if let Some(entries) = cache.as_ref() {
                for entry in entries {
                    if name_bytes == entry.name.as_bytes() {
                        let fuse_ino = journal_ino(entry.sequence);
                        let attr = virtual_dir_attr(fuse_ino);
                        reply.entry(&TTL, &attr, 0);
                        return;
                    }
                }
            }
            reply.error(libc::ENOENT);
            return;
        }

        // metadata/ namespace lookup.
        if parent == FUSE_METADATA_INO {
            self.ensure_metadata_cache();
            let cache = self.metadata_cache.borrow();
            if let Some(mc) = cache.as_ref() {
                if name_bytes == b"superblock.json" {
                    let fuse_ino = metadata_ino(1);
                    let attr = virtual_file_attr(fuse_ino, mc.superblock_json.len() as u64);
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
                if name_bytes == b"timeline.jsonl" {
                    let fuse_ino = metadata_ino(2);
                    let attr = virtual_file_attr(fuse_ino, mc.timeline_jsonl.len() as u64);
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
            }
            reply.error(libc::ENOENT);
            return;
        }

        // unallocated/ namespace lookup.
        if parent == FUSE_UNALLOCATED_INO {
            self.ensure_unallocated_cache();
            let cache = self.unallocated_cache.borrow();
            if let Some(entries) = cache.as_ref() {
                for (i, entry) in entries.iter().enumerate() {
                    if name_bytes == entry.name.as_bytes() {
                        let fuse_ino = unallocated_ino(i as u64);
                        let block_size = self.fs.borrow().block_size();
                        let size = entry.length * block_size;
                        let attr = virtual_file_attr(fuse_ino, size);
                        reply.entry(&TTL, &attr, 0);
                        return;
                    }
                }
            }
            reply.error(libc::ENOENT);
            return;
        }

        // session/ namespace lookup.
        if parent == FUSE_SESSION_INO {
            if name_bytes == b"status.json" && self.has_session() {
                let session = self.session.borrow();
                let s = session.as_ref().unwrap();
                let status = serde_json::json!({
                    "image_path": s.metadata.image_path,
                    "image_sha256": s.metadata.image_sha256,
                    "created": s.metadata.created,
                });
                let data = serde_json::to_string_pretty(&status)
                    .unwrap_or_default()
                    .into_bytes();
                let fuse_ino = metadata_ino(100);
                let attr = virtual_file_attr(fuse_ino, data.len() as u64);
                reply.entry(&TTL, &attr, 0);
                return;
            }
            reply.error(libc::ENOENT);
            return;
        }

        // rw/ namespace lookup.
        if let Some(fs_parent) = self.rw_parent_to_fs(parent) {
            // Check overlay created files first.
            if let Some((id, counter, is_dir)) = self.find_created_by_name(fs_parent, name_bytes)
            {
                let session = self.session.borrow();
                let session = session.as_ref().unwrap();
                let entry = if is_dir {
                    session.overlay.dirs.get(&id)
                } else {
                    session.overlay.created.get(&id)
                };
                if let Some(entry) = entry {
                    let fuse_ino = rw_ino(counter + 9_000_000);
                    let attr = Self::overlay_created_attr(fuse_ino, entry.size, is_dir);
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
            }

            // Check if name is a modified file.
            {
                let mut fs = self.fs.borrow_mut();
                match fs.lookup(fs_parent, name_bytes) {
                    Ok(Some(child_ino)) => {
                        // Check whiteout.
                        if self.is_whiteout(child_ino) {
                            reply.error(libc::ENOENT);
                            return;
                        }

                        // Check if modified in overlay.
                        let session = self.session.borrow();
                        let overlay_id = Self::modified_overlay_id(child_ino);
                        if let Some(s) = session.as_ref() {
                            if s.overlay.modified.contains_key(&child_ino) {
                                match fs.metadata(child_ino) {
                                    Ok(meta) => {
                                        let fuse_ino = rw_ino(child_ino);
                                        let mut attr = fs_to_attr(fuse_ino, &meta);
                                        if let Ok(data) = s.read_overlay_file(&overlay_id) {
                                            attr.size = data.len() as u64;
                                            attr.blocks = attr.size.div_ceil(512);
                                        }
                                        reply.entry(&TTL, &attr, 0);
                                        return;
                                    }
                                    Err(_) => {
                                        reply.error(libc::EIO);
                                        return;
                                    }
                                }
                            }
                        }

                        // Not modified, return attrs under rw/ namespace.
                        match fs.metadata(child_ino) {
                            Ok(meta) => {
                                let fuse_ino = rw_ino(child_ino);
                                reply.entry(&TTL, &fs_to_attr(fuse_ino, &meta), 0);
                            }
                            Err(_) => reply.error(libc::EIO),
                        }
                        return;
                    }
                    Ok(None) => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        }

        // ro/ namespace: the ro/ virtual dir itself maps to the fs root inode.
        let fs_parent = match parent {
            FUSE_RO_INO => self.root_ino,
            _ => match decode_fuse_ino(parent) {
                InodeNamespace::Ro(ino) => ino,
                _ => {
                    reply.error(libc::ENOENT);
                    return;
                }
            },
        };

        let mut fs = self.fs.borrow_mut();
        match fs.lookup(fs_parent, name_bytes) {
            Ok(Some(child_ino)) => match fs.metadata(child_ino) {
                Ok(meta) => {
                    let fuse_ino = ro_ino(child_ino);
                    reply.entry(&TTL, &fs_to_attr(fuse_ino, &meta), 0);
                }
                Err(_) => reply.error(libc::EIO),
            },
            Ok(None) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        // Virtual root.
        if ino == FUSE_ROOT_INO {
            reply.attr(&TTL, &virtual_dir_attr(FUSE_ROOT_INO));
            return;
        }

        // Virtual top-level directories.
        if (FUSE_RO_INO..=FUSE_SESSION_INO).contains(&ino) {
            let mut attr = virtual_dir_attr(ino);
            if ino == FUSE_RW_INO && self.has_session() {
                attr.perm = 0o755;
            }
            reply.attr(&TTL, &attr);
            return;
        }

        match decode_fuse_ino(ino) {
            InodeNamespace::Deleted(fs_ino) => {
                self.ensure_deleted_cache();
                let cache = self.deleted_cache.borrow();
                if let Some(entries) = cache.as_ref() {
                    if let Some(entry) = entries.iter().find(|e| e.fs_ino == fs_ino) {
                        reply.attr(&TTL, &virtual_file_attr(ino, entry.size));
                        return;
                    }
                }
                reply.error(libc::ENOENT);
            }
            InodeNamespace::Metadata(id) => {
                self.ensure_metadata_cache();
                let cache = self.metadata_cache.borrow();
                if let Some(mc) = cache.as_ref() {
                    match id {
                        1 => {
                            reply.attr(&TTL, &virtual_file_attr(ino, mc.superblock_json.len() as u64));
                        }
                        2 => {
                            reply.attr(&TTL, &virtual_file_attr(ino, mc.timeline_jsonl.len() as u64));
                        }
                        100 => {
                            // session/status.json
                            if self.has_session() {
                                let session = self.session.borrow();
                                let s = session.as_ref().unwrap();
                                let status = serde_json::json!({
                                    "image_path": s.metadata.image_path,
                                    "image_sha256": s.metadata.image_sha256,
                                    "created": s.metadata.created,
                                });
                                let data = serde_json::to_string_pretty(&status)
                                    .unwrap_or_default();
                                reply.attr(&TTL, &virtual_file_attr(ino, data.len() as u64));
                            } else {
                                reply.error(libc::ENOENT);
                            }
                        }
                        _ => reply.error(libc::ENOENT),
                    }
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            InodeNamespace::Journal(seq) => {
                self.ensure_journal_cache();
                let cache = self.journal_cache.borrow();
                if let Some(entries) = cache.as_ref() {
                    if entries.iter().any(|e| e.sequence == seq) {
                        reply.attr(&TTL, &virtual_dir_attr(ino));
                    } else {
                        reply.error(libc::ENOENT);
                    }
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            InodeNamespace::Unallocated(range_id) => {
                self.ensure_unallocated_cache();
                let cache = self.unallocated_cache.borrow();
                if let Some(entries) = cache.as_ref() {
                    if let Some(entry) = entries.get(range_id as usize) {
                        let block_size = self.fs.borrow().block_size();
                        let size = entry.length * block_size;
                        reply.attr(&TTL, &virtual_file_attr(ino, size));
                    } else {
                        reply.error(libc::ENOENT);
                    }
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            InodeNamespace::Ro(fs_ino) => {
                let mut fs = self.fs.borrow_mut();
                match fs.metadata(fs_ino) {
                    Ok(meta) => reply.attr(&TTL, &fs_to_attr(ino, &meta)),
                    Err(_) => reply.error(libc::EIO),
                }
            }
            InodeNamespace::Rw(rw_id) => {
                // Check if this is a created overlay file (counter + 9_000_000).
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let session = self.session.borrow();
                    if let Some(s) = session.as_ref() {
                        if let Some(entry) = s.overlay.created.get(&created_id) {
                            let attr =
                                Self::overlay_created_attr(ino, entry.size, false);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                        if let Some(entry) = s.overlay.dirs.get(&created_id) {
                            let attr =
                                Self::overlay_created_attr(ino, entry.size, true);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                    }
                    reply.error(libc::ENOENT);
                    return;
                }

                // This is an fs inode viewed through rw/.
                let fs_ino = rw_id;
                let mut fs = self.fs.borrow_mut();
                match fs.metadata(fs_ino) {
                    Ok(meta) => {
                        let mut attr = fs_to_attr(ino, &meta);
                        // If modified, update size from overlay.
                        let session = self.session.borrow();
                        if let Some(s) = session.as_ref() {
                            let overlay_id = Self::modified_overlay_id(fs_ino);
                            if s.overlay.modified.contains_key(&fs_ino) {
                                if let Ok(data) = s.read_overlay_file(&overlay_id) {
                                    attr.size = data.len() as u64;
                                    attr.blocks = attr.size.div_ceil(512);
                                }
                            }
                        }
                        reply.attr(&TTL, &attr);
                    }
                    Err(_) => reply.error(libc::EIO),
                }
            }
            _ => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let offset = offset as usize;

        // Virtual root directory.
        if ino == FUSE_ROOT_INO {
            let entries: Vec<(u64, FileType, &str)> = vec![
                (FUSE_ROOT_INO, FileType::Directory, "."),
                (FUSE_ROOT_INO, FileType::Directory, ".."),
                (FUSE_RO_INO, FileType::Directory, "ro"),
                (FUSE_RW_INO, FileType::Directory, "rw"),
                (FUSE_DELETED_INO, FileType::Directory, "deleted"),
                (FUSE_JOURNAL_INO, FileType::Directory, "journal"),
                (FUSE_METADATA_INO, FileType::Directory, "metadata"),
                (FUSE_UNALLOCATED_INO, FileType::Directory, "unallocated"),
                (FUSE_SESSION_INO, FileType::Directory, "session"),
            ];
            for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // rw/ namespace readdir.
        if let Some(fs_dir_ino) = match ino {
            FUSE_RW_INO => Some(self.root_ino),
            _ => match decode_fuse_ino(ino) {
                InodeNamespace::Rw(rw_id) if rw_id < 9_000_000 => Some(rw_id),
                _ => None,
            },
        } {
            let mut fs = self.fs.borrow_mut();
            match fs.read_dir(fs_dir_ino) {
                Ok(entries) => {
                    let session = self.session.borrow();
                    let mut fuse_entries: Vec<(u64, FileType, String)> = Vec::new();

                    for e in &entries {
                        let name = e.name_str();
                        let child_ino = e.inode;

                        // Filter out whiteouts.
                        if let Some(s) = session.as_ref() {
                            if name != "." && name != ".." && s.overlay.deleted.contains(&child_ino)
                            {
                                continue;
                            }
                        }

                        let fuse_ino = if name == "." || name == ".." {
                            if fs_dir_ino == self.root_ino && name == "." {
                                FUSE_RW_INO
                            } else if fs_dir_ino == self.root_ino && name == ".." {
                                FUSE_ROOT_INO
                            } else {
                                rw_ino(child_ino)
                            }
                        } else {
                            rw_ino(child_ino)
                        };
                        let kind = fs_file_type_to_fuse(e.file_type);
                        fuse_entries.push((fuse_ino, kind, name));
                    }

                    // Add overlay created entries for this directory.
                    if let Some(s) = session.as_ref() {
                        for (id, entry) in &s.overlay.created {
                            if entry.parent_ino == fs_dir_ino {
                                if let Some(counter) =
                                    id.strip_prefix("new_").and_then(|s| s.parse::<u64>().ok())
                                {
                                    let fuse_ino = rw_ino(counter + 9_000_000);
                                    fuse_entries.push((
                                        fuse_ino,
                                        FileType::RegularFile,
                                        entry.name.clone(),
                                    ));
                                }
                            }
                        }
                        for (id, entry) in &s.overlay.dirs {
                            if entry.parent_ino == fs_dir_ino {
                                if let Some(counter) =
                                    id.strip_prefix("new_").and_then(|s| s.parse::<u64>().ok())
                                {
                                    let fuse_ino = rw_ino(counter + 9_000_000);
                                    fuse_entries.push((
                                        fuse_ino,
                                        FileType::Directory,
                                        entry.name.clone(),
                                    ));
                                }
                            }
                        }
                    }

                    for (i, (entry_ino, kind, name)) in
                        fuse_entries.iter().enumerate().skip(offset)
                    {
                        if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                            break;
                        }
                    }
                    reply.ok();
                }
                Err(_) => reply.error(libc::EIO),
            }
            return;
        }

        // deleted/ readdir
        if ino == FUSE_DELETED_INO {
            self.ensure_deleted_cache();
            let cache = self.deleted_cache.borrow();
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (FUSE_DELETED_INO, FileType::Directory, ".".to_string()),
                (FUSE_ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            if let Some(cached) = cache.as_ref() {
                for entry in cached {
                    entries.push((
                        deleted_ino(entry.fs_ino),
                        FileType::RegularFile,
                        entry.name.clone(),
                    ));
                }
            }
            for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // journal/ readdir
        if ino == FUSE_JOURNAL_INO {
            self.ensure_journal_cache();
            let cache = self.journal_cache.borrow();
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (FUSE_JOURNAL_INO, FileType::Directory, ".".to_string()),
                (FUSE_ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            if let Some(cached) = cache.as_ref() {
                for entry in cached {
                    entries.push((
                        journal_ino(entry.sequence),
                        FileType::Directory,
                        entry.name.clone(),
                    ));
                }
            }
            for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // journal/txn_N/ readdir (empty directory for now)
        if let InodeNamespace::Journal(_seq) = decode_fuse_ino(ino) {
            if offset == 0 {
                let _ = reply.add(ino, 1, FileType::Directory, ".");
                let _ = reply.add(FUSE_JOURNAL_INO, 2, FileType::Directory, "..");
            }
            reply.ok();
            return;
        }

        // metadata/ readdir
        if ino == FUSE_METADATA_INO {
            self.ensure_metadata_cache();
            let cache = self.metadata_cache.borrow();
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (FUSE_METADATA_INO, FileType::Directory, ".".to_string()),
                (FUSE_ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            if cache.is_some() {
                entries.push((
                    metadata_ino(1),
                    FileType::RegularFile,
                    "superblock.json".to_string(),
                ));
                entries.push((
                    metadata_ino(2),
                    FileType::RegularFile,
                    "timeline.jsonl".to_string(),
                ));
            }
            for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // unallocated/ readdir
        if ino == FUSE_UNALLOCATED_INO {
            self.ensure_unallocated_cache();
            let cache = self.unallocated_cache.borrow();
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (FUSE_UNALLOCATED_INO, FileType::Directory, ".".to_string()),
                (FUSE_ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            if let Some(cached) = cache.as_ref() {
                for (i, entry) in cached.iter().enumerate() {
                    entries.push((
                        unallocated_ino(i as u64),
                        FileType::RegularFile,
                        entry.name.clone(),
                    ));
                }
            }
            for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // session/ readdir
        if ino == FUSE_SESSION_INO {
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (FUSE_SESSION_INO, FileType::Directory, ".".to_string()),
                (FUSE_ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            if self.has_session() {
                entries.push((
                    metadata_ino(100),
                    FileType::RegularFile,
                    "status.json".to_string(),
                ));
            }
            for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // Determine the fs inode for this directory.
        let fs_dir_ino = match ino {
            FUSE_RO_INO => self.root_ino,
            _ => match decode_fuse_ino(ino) {
                InodeNamespace::Ro(fs_ino) => fs_ino,
                _ => {
                    reply.error(libc::ENOENT);
                    return;
                }
            },
        };

        let mut fs = self.fs.borrow_mut();
        match fs.read_dir(fs_dir_ino) {
            Ok(entries) => {
                let root_ino = self.root_ino;
                let fuse_entries: Vec<(u64, FileType, String)> = entries
                    .iter()
                    .map(|e| {
                        let name = e.name_str();
                        let fuse_ino = if name == "." || name == ".." {
                            if fs_dir_ino == root_ino && name == "." {
                                FUSE_RO_INO
                            } else if fs_dir_ino == root_ino && name == ".." {
                                FUSE_ROOT_INO
                            } else {
                                ro_ino(e.inode)
                            }
                        } else {
                            ro_ino(e.inode)
                        };
                        let kind = fs_file_type_to_fuse(e.file_type);
                        (fuse_ino, kind, name)
                    })
                    .collect();

                for (i, (entry_ino, kind, name)) in fuse_entries.iter().enumerate().skip(offset) {
                    if reply.add(*entry_ino, (i + 1) as i64, *kind, name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        match decode_fuse_ino(ino) {
            InodeNamespace::Deleted(fs_ino) => {
                self.ensure_deleted_cache();
                let cache = self.deleted_cache.borrow();
                if let Some(entries) = cache.as_ref() {
                    if let Some(entry) = entries.iter().find(|e| e.fs_ino == fs_ino) {
                        let off = offset as usize;
                        if off >= entry.data.len() {
                            reply.data(&[]);
                        } else {
                            let end = (off + size as usize).min(entry.data.len());
                            reply.data(&entry.data[off..end]);
                        }
                        return;
                    }
                }
                reply.error(libc::ENOENT);
            }
            InodeNamespace::Metadata(id) => {
                self.ensure_metadata_cache();
                let data = match id {
                    1 => {
                        let cache = self.metadata_cache.borrow();
                        cache.as_ref().map(|mc| mc.superblock_json.clone())
                    }
                    2 => {
                        let cache = self.metadata_cache.borrow();
                        cache.as_ref().map(|mc| mc.timeline_jsonl.clone())
                    }
                    100 => {
                        // session/status.json
                        let session = self.session.borrow();
                        session.as_ref().map(|s| {
                            let status = serde_json::json!({
                                "image_path": s.metadata.image_path,
                                "image_sha256": s.metadata.image_sha256,
                                "created": s.metadata.created,
                            });
                            serde_json::to_string_pretty(&status)
                                .unwrap_or_default()
                                .into_bytes()
                        })
                    }
                    _ => None,
                };
                match data {
                    Some(buf) => {
                        let off = offset as usize;
                        if off >= buf.len() {
                            reply.data(&[]);
                        } else {
                            let end = (off + size as usize).min(buf.len());
                            reply.data(&buf[off..end]);
                        }
                    }
                    None => reply.error(libc::ENOENT),
                }
            }
            InodeNamespace::Unallocated(range_id) => {
                self.ensure_unallocated_cache();
                let range_info = {
                    let cache = self.unallocated_cache.borrow();
                    cache.as_ref().and_then(|entries| {
                        entries.get(range_id as usize).map(|e| FsBlockRange {
                            start: e.start,
                            length: e.length,
                        })
                    })
                };
                match range_info {
                    Some(range) => {
                        let mut fs = self.fs.borrow_mut();
                        match fs.read_unallocated(&range) {
                            Ok(data) => {
                                let off = offset as usize;
                                if off >= data.len() {
                                    reply.data(&[]);
                                } else {
                                    let end = (off + size as usize).min(data.len());
                                    reply.data(&data[off..end]);
                                }
                            }
                            Err(_) => reply.error(libc::EIO),
                        }
                    }
                    None => reply.error(libc::ENOENT),
                }
            }
            InodeNamespace::Ro(fs_ino) => {
                let mut fs = self.fs.borrow_mut();
                match fs.read_file_range(fs_ino, offset as u64, size as u64) {
                    Ok(data) => reply.data(&data),
                    Err(_) => reply.error(libc::EIO),
                }
            }
            InodeNamespace::Rw(rw_id) => {
                // Check if this is a created overlay file.
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let session = self.session.borrow();
                    if let Some(s) = session.as_ref() {
                        if s.overlay.created.contains_key(&created_id)
                            || s.overlay.dirs.contains_key(&created_id)
                        {
                            match s.read_overlay_file(&created_id) {
                                Ok(data) => {
                                    let off = offset as usize;
                                    let end = (off + size as usize).min(data.len());
                                    if off >= data.len() {
                                        reply.data(&[]);
                                    } else {
                                        reply.data(&data[off..end]);
                                    }
                                    return;
                                }
                                Err(_) => {
                                    reply.error(libc::EIO);
                                    return;
                                }
                            }
                        }
                    }
                    reply.error(libc::ENOENT);
                    return;
                }

                // fs inode under rw/.
                let fs_ino = rw_id;
                // Check if modified in overlay.
                let session = self.session.borrow();
                if let Some(s) = session.as_ref() {
                    let overlay_id = Self::modified_overlay_id(fs_ino);
                    if s.overlay.modified.contains_key(&fs_ino) {
                        match s.read_overlay_file(&overlay_id) {
                            Ok(data) => {
                                let off = offset as usize;
                                let end = (off + size as usize).min(data.len());
                                if off >= data.len() {
                                    reply.data(&[]);
                                } else {
                                    reply.data(&data[off..end]);
                                }
                                return;
                            }
                            Err(_) => {
                                reply.error(libc::EIO);
                                return;
                            }
                        }
                    }
                }
                drop(session);

                // Fall back to underlying fs.
                let mut fs = self.fs.borrow_mut();
                match fs.read_file_range(fs_ino, offset as u64, size as u64) {
                    Ok(data) => reply.data(&data),
                    Err(_) => reply.error(libc::EIO),
                }
            }
            _ => {
                reply.error(libc::ENOENT);
            }
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let fs_ino = match decode_fuse_ino(ino) {
            InodeNamespace::Ro(fs_ino) => fs_ino,
            InodeNamespace::Rw(rw_id) if rw_id < 9_000_000 => rw_id,
            _ => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut fs = self.fs.borrow_mut();
        match fs.read_link(fs_ino) {
            Ok(target) => reply.data(&target),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        match decode_fuse_ino(ino) {
            InodeNamespace::Rw(rw_id) => {
                // Created overlay file.
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let mut session = self.session.borrow_mut();
                    let s = session.as_mut().unwrap();

                    let is_known = s.overlay.created.contains_key(&created_id)
                        || s.overlay.dirs.contains_key(&created_id);
                    if !is_known {
                        reply.error(libc::ENOENT);
                        return;
                    }

                    let mut buf = s.read_overlay_file(&created_id).unwrap_or_default();
                    let off = offset as usize;
                    let end = off + data.len();
                    if end > buf.len() {
                        buf.resize(end, 0);
                    }
                    buf[off..end].copy_from_slice(data);

                    if s.write_overlay_file(&created_id, &buf).is_err() {
                        reply.error(libc::EIO);
                        return;
                    }

                    if let Some(entry) = s.overlay.created.get_mut(&created_id) {
                        entry.size = buf.len() as u64;
                    }
                    if let Some(entry) = s.overlay.dirs.get_mut(&created_id) {
                        entry.size = buf.len() as u64;
                    }

                    if s.save().is_err() {
                        reply.error(libc::EIO);
                        return;
                    }

                    reply.written(data.len() as u32);
                    return;
                }

                // Existing fs inode under rw/ — COW on first write.
                let fs_ino = rw_id;
                let overlay_id = Self::modified_overlay_id(fs_ino);

                let mut session = self.session.borrow_mut();
                let s = session.as_mut().unwrap();

                if !s.overlay.modified.contains_key(&fs_ino) {
                    let mut fs = self.fs.borrow_mut();
                    let original = match fs.read_file(fs_ino) {
                        Ok(d) => d,
                        Err(_) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    };
                    if s.write_overlay_file(&overlay_id, &original).is_err() {
                        reply.error(libc::EIO);
                        return;
                    }
                    s.overlay
                        .modified
                        .insert(fs_ino, overlay_id.clone());
                }

                let mut buf = s.read_overlay_file(&overlay_id).unwrap_or_default();
                let off = offset as usize;
                let end = off + data.len();
                if end > buf.len() {
                    buf.resize(end, 0);
                }
                buf[off..end].copy_from_slice(data);

                if s.write_overlay_file(&overlay_id, &buf).is_err() {
                    reply.error(libc::EIO);
                    return;
                }

                if s.save().is_err() {
                    reply.error(libc::EIO);
                    return;
                }

                reply.written(data.len() as u32);
            }
            _ => reply.error(libc::EROFS),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        let fs_parent = match self.rw_parent_to_fs(parent) {
            Some(ino) => ino,
            None => {
                reply.error(libc::EROFS);
                return;
            }
        };

        let name_str = match name.to_str() {
            Some(s) => s.to_string(),
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let counter = self.alloc_overlay_ino();
        let created_id = Self::created_overlay_id(counter);
        let fuse_ino = rw_ino(counter + 9_000_000);

        let mut session = self.session.borrow_mut();
        let s = session.as_mut().unwrap();

        if s.write_overlay_file(&created_id, &[]).is_err() {
            reply.error(libc::EIO);
            return;
        }

        s.overlay.created.insert(
            created_id,
            crate::session::OverlayEntry {
                parent_ino: fs_parent,
                name: name_str,
                size: 0,
            },
        );

        if s.save().is_err() {
            reply.error(libc::EIO);
            return;
        }

        let attr = Self::overlay_created_attr(fuse_ino, 0, false);
        reply.created(&TTL, &attr, 0, 0, 0);
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        let fs_parent = match self.rw_parent_to_fs(parent) {
            Some(ino) => ino,
            None => {
                reply.error(libc::EROFS);
                return;
            }
        };

        let name_str = match name.to_str() {
            Some(s) => s.to_string(),
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let counter = self.alloc_overlay_ino();
        let created_id = Self::created_overlay_id(counter);
        let fuse_ino = rw_ino(counter + 9_000_000);

        let mut session = self.session.borrow_mut();
        let s = session.as_mut().unwrap();

        s.overlay.dirs.insert(
            created_id,
            crate::session::OverlayEntry {
                parent_ino: fs_parent,
                name: name_str,
                size: 0,
            },
        );

        if s.save().is_err() {
            reply.error(libc::EIO);
            return;
        }

        let attr = Self::overlay_created_attr(fuse_ino, 0, true);
        reply.entry(&TTL, &attr, 0);
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if !self.has_session() {
            reply.error(libc::EROFS);
            return;
        }

        let fs_parent = match self.rw_parent_to_fs(parent) {
            Some(ino) => ino,
            None => {
                reply.error(libc::EROFS);
                return;
            }
        };

        let name_bytes = name.as_encoded_bytes();

        // Check if it's a created overlay file first.
        if let Some((id, _counter, _is_dir)) = self.find_created_by_name(fs_parent, name_bytes) {
            let mut session = self.session.borrow_mut();
            let s = session.as_mut().unwrap();
            s.overlay.created.remove(&id);
            s.overlay.dirs.remove(&id);
            let _ = std::fs::remove_file(s.overlay_file_path(&id));
            if s.save().is_err() {
                reply.error(libc::EIO);
                return;
            }
            reply.ok();
            return;
        }

        // Look up the fs inode and add whiteout.
        let mut fs = self.fs.borrow_mut();
        match fs.lookup(fs_parent, name_bytes) {
            Ok(Some(child_ino)) => {
                let mut session = self.session.borrow_mut();
                let s = session.as_mut().unwrap();
                if !s.overlay.deleted.contains(&child_ino) {
                    s.overlay.deleted.push(child_ino);
                }
                if s.save().is_err() {
                    reply.error(libc::EIO);
                    return;
                }
                reply.ok();
            }
            Ok(None) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.unlink(_req, parent, name, reply);
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        match decode_fuse_ino(ino) {
            InodeNamespace::Rw(rw_id) => {
                if !self.has_session() {
                    reply.error(libc::EROFS);
                    return;
                }

                // Handle truncate (size change).
                if let Some(new_size) = size {
                    // Created overlay file.
                    if rw_id >= 9_000_000 {
                        let counter = rw_id - 9_000_000;
                        let created_id = Self::created_overlay_id(counter);
                        let mut session = self.session.borrow_mut();
                        let s = session.as_mut().unwrap();

                        let mut buf = s.read_overlay_file(&created_id).unwrap_or_default();
                        buf.resize(new_size as usize, 0);
                        if s.write_overlay_file(&created_id, &buf).is_err() {
                            reply.error(libc::EIO);
                            return;
                        }

                        if let Some(entry) = s.overlay.created.get_mut(&created_id) {
                            entry.size = new_size;
                        }
                        if let Some(entry) = s.overlay.dirs.get_mut(&created_id) {
                            entry.size = new_size;
                        }
                        if s.save().is_err() {
                            reply.error(libc::EIO);
                            return;
                        }

                        let attr = Self::overlay_created_attr(ino, new_size, false);
                        reply.attr(&TTL, &attr);
                        return;
                    }

                    // Existing fs inode — COW then truncate.
                    let fs_ino = rw_id;
                    let overlay_id = Self::modified_overlay_id(fs_ino);

                    let mut session = self.session.borrow_mut();
                    let s = session.as_mut().unwrap();

                    if !s.overlay.modified.contains_key(&fs_ino) {
                        let mut fs = self.fs.borrow_mut();
                        let original = match fs.read_file(fs_ino) {
                            Ok(d) => d,
                            Err(_) => {
                                reply.error(libc::EIO);
                                return;
                            }
                        };
                        if s.write_overlay_file(&overlay_id, &original).is_err() {
                            reply.error(libc::EIO);
                            return;
                        }
                        s.overlay.modified.insert(fs_ino, overlay_id.clone());
                    }

                    let mut buf = s.read_overlay_file(&overlay_id).unwrap_or_default();
                    buf.resize(new_size as usize, 0);
                    if s.write_overlay_file(&overlay_id, &buf).is_err() {
                        reply.error(libc::EIO);
                        return;
                    }
                    if s.save().is_err() {
                        reply.error(libc::EIO);
                        return;
                    }

                    // Return updated attrs.
                    let mut fs = self.fs.borrow_mut();
                    match fs.metadata(fs_ino) {
                        Ok(meta) => {
                            let mut attr = fs_to_attr(ino, &meta);
                            attr.size = new_size;
                            attr.blocks = new_size.div_ceil(512);
                            reply.attr(&TTL, &attr);
                        }
                        Err(_) => reply.error(libc::EIO),
                    }
                    return;
                }

                // No size change — just return current attrs.
                if rw_id >= 9_000_000 {
                    let counter = rw_id - 9_000_000;
                    let created_id = Self::created_overlay_id(counter);
                    let session = self.session.borrow();
                    if let Some(s) = session.as_ref() {
                        if let Some(entry) = s.overlay.created.get(&created_id) {
                            let attr = Self::overlay_created_attr(ino, entry.size, false);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                        if let Some(entry) = s.overlay.dirs.get(&created_id) {
                            let attr = Self::overlay_created_attr(ino, entry.size, true);
                            reply.attr(&TTL, &attr);
                            return;
                        }
                    }
                    reply.error(libc::ENOENT);
                } else {
                    let fs_ino = rw_id;
                    let mut fs = self.fs.borrow_mut();
                    match fs.metadata(fs_ino) {
                        Ok(meta) => {
                            let mut attr = fs_to_attr(ino, &meta);
                            let session = self.session.borrow();
                            if let Some(s) = session.as_ref() {
                                let overlay_id = Self::modified_overlay_id(fs_ino);
                                if s.overlay.modified.contains_key(&fs_ino) {
                                    if let Ok(data) = s.read_overlay_file(&overlay_id) {
                                        attr.size = data.len() as u64;
                                        attr.blocks = attr.size.div_ceil(512);
                                    }
                                }
                            }
                            reply.attr(&TTL, &attr);
                        }
                        Err(_) => reply.error(libc::EIO),
                    }
                }
            }
            // For non-rw inodes, setattr is not supported.
            _ => reply.error(libc::EROFS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuser::FileType;
    use std::time::{Duration, UNIX_EPOCH};

    // -----------------------------------------------------------------------
    // virtual_dir_attr
    // -----------------------------------------------------------------------

    #[test]
    fn virtual_dir_attr_is_directory() {
        let attr = virtual_dir_attr(1);
        assert_eq!(attr.ino, 1);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o555);
        assert_eq!(attr.nlink, 2);
        assert_eq!(attr.size, 0);
        assert_eq!(attr.blocks, 0);
        assert_eq!(attr.uid, 0);
        assert_eq!(attr.gid, 0);
        assert_eq!(attr.blksize, 4096);
        assert_eq!(attr.atime, UNIX_EPOCH);
        assert_eq!(attr.mtime, UNIX_EPOCH);
        assert_eq!(attr.ctime, UNIX_EPOCH);
        assert_eq!(attr.crtime, UNIX_EPOCH);
    }

    #[test]
    fn virtual_dir_attr_preserves_ino() {
        for ino in [1, 42, FUSE_ROOT_INO, FUSE_DELETED_INO, 999_999] {
            assert_eq!(virtual_dir_attr(ino).ino, ino);
        }
    }

    // -----------------------------------------------------------------------
    // virtual_file_attr
    // -----------------------------------------------------------------------

    #[test]
    fn virtual_file_attr_regular() {
        let attr = virtual_file_attr(100, 4096);
        assert_eq!(attr.ino, 100);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o444);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.blocks, 8); // 4096 / 512
    }

    #[test]
    fn virtual_file_attr_zero_size() {
        let attr = virtual_file_attr(1, 0);
        assert_eq!(attr.size, 0);
        assert_eq!(attr.blocks, 0);
    }

    #[test]
    fn virtual_file_attr_non_512_aligned() {
        // 1000 bytes -> ceil(1000/512) = 2 blocks
        let attr = virtual_file_attr(1, 1000);
        assert_eq!(attr.blocks, 2);
    }

    // -----------------------------------------------------------------------
    // ts_to_systime
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_conversion_positive() {
        let ts = FsTimestamp {
            seconds: 1_700_000_000,
            nanoseconds: 500_000_000,
        };
        let st = ts_to_systime(&ts);
        let dur = st.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), 1_700_000_000);
        assert_eq!(dur.subsec_nanos(), 500_000_000);
    }

    #[test]
    fn timestamp_zero() {
        let ts = FsTimestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        let st = ts_to_systime(&ts);
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn timestamp_negative_clamps_to_epoch() {
        let ts = FsTimestamp {
            seconds: -1,
            nanoseconds: 0,
        };
        let st = ts_to_systime(&ts);
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn timestamp_negative_large_clamps_to_epoch() {
        let ts = FsTimestamp {
            seconds: -1_000_000,
            nanoseconds: 999_999_999,
        };
        let st = ts_to_systime(&ts);
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn timestamp_epoch_plus_one_second() {
        let ts = FsTimestamp {
            seconds: 1,
            nanoseconds: 0,
        };
        let st = ts_to_systime(&ts);
        assert_eq!(st, UNIX_EPOCH + Duration::from_secs(1));
    }

    // -----------------------------------------------------------------------
    // fs_file_type_to_fuse
    // -----------------------------------------------------------------------

    #[test]
    fn file_type_mapping_regular() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::RegularFile),
            FileType::RegularFile
        );
    }

    #[test]
    fn file_type_mapping_directory() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::Directory),
            FileType::Directory
        );
    }

    #[test]
    fn file_type_mapping_symlink() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::Symlink),
            FileType::Symlink
        );
    }

    #[test]
    fn file_type_mapping_chardev() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::CharDevice),
            FileType::CharDevice
        );
    }

    #[test]
    fn file_type_mapping_blockdev() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::BlockDevice),
            FileType::BlockDevice
        );
    }

    #[test]
    fn file_type_mapping_fifo() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::Fifo),
            FileType::NamedPipe
        );
    }

    #[test]
    fn file_type_mapping_socket() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::Socket),
            FileType::Socket
        );
    }

    #[test]
    fn file_type_mapping_unknown() {
        assert_eq!(
            fs_file_type_to_fuse(FsFileType::Unknown),
            FileType::RegularFile
        );
    }

    // -----------------------------------------------------------------------
    // fs_to_attr
    // -----------------------------------------------------------------------

    #[test]
    fn fs_to_attr_regular_file() {
        let meta = FsMetadata {
            ino: 42,
            file_type: FsFileType::RegularFile,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 100,
            links_count: 1,
            atime: FsTimestamp { seconds: 1_700_000_000, nanoseconds: 0 },
            mtime: FsTimestamp { seconds: 1_700_000_000, nanoseconds: 0 },
            ctime: FsTimestamp { seconds: 1_700_000_000, nanoseconds: 0 },
            crtime: FsTimestamp { seconds: 1_700_000_000, nanoseconds: 0 },
            allocated: true,
        };
        let attr = fs_to_attr(1012, &meta);
        assert_eq!(attr.ino, 1012);
        assert_eq!(attr.size, 100);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
    }

    #[test]
    fn fs_to_attr_directory() {
        let meta = FsMetadata {
            ino: 2,
            file_type: FsFileType::Directory,
            mode: 0o40755,
            uid: 0,
            gid: 0,
            size: 4096,
            links_count: 3,
            atime: FsTimestamp::default(),
            mtime: FsTimestamp::default(),
            ctime: FsTimestamp::default(),
            crtime: FsTimestamp::default(),
            allocated: true,
        };
        let attr = fs_to_attr(2000, &meta);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.nlink, 3);
        assert_eq!(attr.perm, 0o755);
    }

    #[test]
    fn fs_to_attr_symlink() {
        let meta = FsMetadata {
            ino: 10,
            file_type: FsFileType::Symlink,
            mode: 0o120777,
            uid: 0,
            gid: 0,
            size: 11,
            links_count: 1,
            atime: FsTimestamp::default(),
            mtime: FsTimestamp::default(),
            ctime: FsTimestamp::default(),
            crtime: FsTimestamp::default(),
            allocated: true,
        };
        let attr = fs_to_attr(3000, &meta);
        assert_eq!(attr.kind, FileType::Symlink);
        assert_eq!(attr.perm, 0o777);
    }

    #[test]
    fn fs_to_attr_blocks_calculation() {
        let meta = FsMetadata {
            ino: 42,
            file_type: FsFileType::RegularFile,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: 1000,
            links_count: 1,
            atime: FsTimestamp::default(),
            mtime: FsTimestamp::default(),
            ctime: FsTimestamp::default(),
            crtime: FsTimestamp::default(),
            allocated: true,
        };
        let attr = fs_to_attr(42, &meta);
        assert_eq!(attr.size, 1000);
        assert_eq!(attr.blocks, 2);
    }

    #[test]
    fn fs_to_attr_blksize_always_4096() {
        let meta = FsMetadata {
            ino: 1,
            file_type: FsFileType::RegularFile,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 1,
            atime: FsTimestamp::default(),
            mtime: FsTimestamp::default(),
            ctime: FsTimestamp::default(),
            crtime: FsTimestamp::default(),
            allocated: true,
        };
        let attr = fs_to_attr(1, &meta);
        assert_eq!(attr.blksize, 4096);
    }

    // -----------------------------------------------------------------------
    // ForensicFuseFs::overlay_created_attr
    // -----------------------------------------------------------------------

    #[test]
    fn overlay_created_attr_regular_file() {
        let attr = ForensicFuseFs::overlay_created_attr(999, 512, false);
        assert_eq!(attr.ino, 999);
        assert_eq!(attr.size, 512);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.blocks, 1);
    }

    #[test]
    fn overlay_created_attr_directory() {
        let attr = ForensicFuseFs::overlay_created_attr(888, 0, true);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
    }

    // -----------------------------------------------------------------------
    // ForensicFuseFs helper methods (static/associated)
    // -----------------------------------------------------------------------

    #[test]
    fn modified_overlay_id_format() {
        assert_eq!(ForensicFuseFs::modified_overlay_id(42), "ino_42");
        assert_eq!(ForensicFuseFs::modified_overlay_id(0), "ino_0");
        assert_eq!(
            ForensicFuseFs::modified_overlay_id(9_999_999),
            "ino_9999999"
        );
    }

    #[test]
    fn created_overlay_id_format() {
        assert_eq!(ForensicFuseFs::created_overlay_id(1), "new_1");
        assert_eq!(ForensicFuseFs::created_overlay_id(0), "new_0");
    }

    // -----------------------------------------------------------------------
    // VIRTUAL_DIRS constant
    // -----------------------------------------------------------------------

    #[test]
    fn virtual_dirs_has_expected_entries() {
        assert_eq!(VIRTUAL_DIRS.len(), 7);
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "ro"));
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "rw"));
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "deleted"));
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "journal"));
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "metadata"));
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "unallocated"));
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "session"));
    }

    #[test]
    fn virtual_dirs_ino_matches_constants() {
        for &(ino, name) in VIRTUAL_DIRS {
            match name {
                "ro" => assert_eq!(ino, FUSE_RO_INO),
                "rw" => assert_eq!(ino, FUSE_RW_INO),
                "deleted" => assert_eq!(ino, FUSE_DELETED_INO),
                "journal" => assert_eq!(ino, FUSE_JOURNAL_INO),
                "metadata" => assert_eq!(ino, FUSE_METADATA_INO),
                "unallocated" => assert_eq!(ino, FUSE_UNALLOCATED_INO),
                "session" => assert_eq!(ino, FUSE_SESSION_INO),
                _ => panic!("unexpected virtual dir: {name}"),
            }
        }
    }
}
