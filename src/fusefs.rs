#![forbid(unsafe_code)]

use crate::inode_map::{
    decode_fuse_ino, deleted_ino, journal_ino, metadata_ino, ro_ino, rw_ino, unallocated_ino,
    InodeNamespace, FUSE_JOURNAL_INO, FUSE_METADATA_INO, FUSE_ORPHANS_INO, FUSE_ROOT_INO,
    FUSE_RO_INO, FUSE_RW_INO, FUSE_SESSION_INO, FUSE_UNALLOCATED_INO,
};
use crate::session::Session;
use crate::ForensicFs;
use crate::{
    DeletedMode, FsAllocation, FsBlockRange, FsEventType, FsFileType, FsMetadata, FsTimestamp,
};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyWrite, ReplyXattr, Request, TimeOrNow,
};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

/// Fixed virtual directory names at the FUSE root. `$Orphans/` is appended
/// dynamically by [`root_dir_listing`] only when recovered orphan entries
/// exist; the old flat `deleted/` directory is gone (recovered deletes now
/// render in-place — ADR 0008 v2).
const VIRTUAL_DIRS: &[(u64, &str)] = &[
    (FUSE_RO_INO, "ro"),
    (FUSE_RW_INO, "rw"),
    (FUSE_JOURNAL_INO, "journal"),
    (FUSE_METADATA_INO, "metadata"),
    (FUSE_UNALLOCATED_INO, "unallocated"),
    (FUSE_SESSION_INO, "session"),
];

/// Root-level directory listing: the fixed [`VIRTUAL_DIRS`] plus the top-level
/// synthetic `$Orphans/` when unplaceable recovered entries exist (ADR 0008
/// v2). Pure, so the root readdir/lookup shells share one decision.
fn root_dir_listing(has_orphans: bool) -> Vec<(u64, &'static str)> {
    let mut v: Vec<(u64, &'static str)> = VIRTUAL_DIRS.to_vec();
    if has_orphans {
        v.push((FUSE_ORPHANS_INO, "$Orphans"));
    }
    v
}

/// Whether any recovered entry is routed to `$Orphans` (true orphan, live-name
/// collision, or an older same-name delete).
fn cache_has_orphans(entries: &[DeletedEntry]) -> bool {
    entries.iter().any(|e| e.orphan)
}

/// Recovered MACB times carried with a deleted entry (timeline + export).
#[derive(Default, Clone, Copy)]
struct DeletedMacb {
    modified: FsTimestamp,
    accessed: FsTimestamp,
    changed: FsTimestamp,
    born: FsTimestamp,
}

/// Cached entry for a recovered deleted file visible under `deleted/`.
///
/// The name is the **real** recovered name when placed in-place, or the
/// disambiguated `<name>@<ts>Z~<id>` form under `$Orphans` — never the old
/// fabricated `<ino>_unknown`. `readable == false` marks content the backend
/// could not recover, surfaced as an explicit read error rather than a
/// fabricated 0-byte success.
struct DeletedEntry {
    /// Readable backend inode (reads the recovered bytes).
    fs_ino: u64,
    /// Display name (real, or disambiguated under `$Orphans`).
    name: String,
    /// The recovered real name (empty when the FS destroyed it on delete).
    real_name: String,
    size: u64,
    data: Vec<u8>,
    readable: bool,
    /// True when routed to `$Orphans`; false when placed in-place.
    orphan: bool,
    /// Recovered parent inode (None for a true orphan).
    parent_ino: Option<u64>,
    /// Metadata record id (MFT entry / inode) — the stable disambiguator.
    record_id: u64,
    allocation: FsAllocation,
    macb: DeletedMacb,
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
    fs: RefCell<Box<dyn ForensicFs + Send>>,
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
    /// How the root is rendered: disk overlay (`ro/ rw/ …`) or raw tree.
    layout: crate::MountLayout,
    /// How the `deleted/` view is populated (latest / all / off).
    deleted_mode: DeletedMode,
}

impl ForensicFuseFs {
    pub fn new(
        fs: Box<dyn ForensicFs + Send>,
        session: Option<Session>,
        layout: crate::MountLayout,
        deleted_mode: DeletedMode,
    ) -> Self {
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
            layout,
            deleted_mode,
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

    /// Build a `FileAttr` for an overlay-created file.
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

    /// Ensure the deleted/ cache is populated from the backend's rich
    /// `deleted_nodes()` — real names, in-place vs `$Orphans` placement, and
    /// `--deleted` gating. No fabrication: an unreadable node is marked, never
    /// rendered as a 0-byte success, and names are never `<ino>_unknown`.
    fn ensure_deleted_cache(&self) {
        if self.deleted_cache.borrow().is_some() {
            return;
        }
        // `off`: a successful, empty enumeration (honest "not requested"), not a
        // populated cache.
        if self.deleted_mode == DeletedMode::Off {
            *self.deleted_cache.borrow_mut() = Some(Vec::new());
            return;
        }

        let mut fs = self.fs.borrow_mut();
        let nodes = fs.deleted_nodes().unwrap_or_default();

        // Per node: does a *live* sibling already hold this name under the
        // recovered parent? A collision forces the entry to `$Orphans`.
        let plans: Vec<DeletedPlan> = nodes
            .iter()
            .map(|n| {
                let has_live_collision = match n.parent_ino {
                    Some(p) if !n.name.is_empty() => fs.lookup(p, &n.name).ok().flatten().is_some(),
                    _ => false,
                };
                DeletedPlan {
                    ino: n.ino,
                    real_name: String::from_utf8_lossy(&n.name).into_owned(),
                    parent_ino: n.parent_ino,
                    mtime_secs: n.mtime.seconds,
                    record_id: n.record_id,
                    has_live_collision,
                    allocation: n.allocation,
                }
            })
            .collect();

        let placed = plan_deleted(&plans, self.deleted_mode);

        let mut entries = Vec::with_capacity(placed.len());
        for p in placed {
            let node = nodes.iter().find(|n| n.ino == p.ino);
            let (meta_size, macb) = node.map_or((0, DeletedMacb::default()), |n| {
                (
                    n.size,
                    DeletedMacb {
                        modified: n.mtime,
                        accessed: n.atime,
                        changed: n.ctime,
                        born: n.crtime,
                    },
                )
            });
            // Content: recover the bytes; a failure is MARKED (readable=false),
            // never fabricated into a 0-byte success. Size falls back to the
            // recovered metadata size so an unreadable entry still shows a size.
            let (data, readable) = match fs.read_file(p.ino) {
                Ok(d) => (d, true),
                Err(_) => (Vec::new(), false),
            };
            let size = if readable {
                data.len() as u64
            } else {
                meta_size
            };
            entries.push(DeletedEntry {
                fs_ino: p.ino,
                name: p.display_name,
                real_name: p.real_name,
                size,
                data,
                readable,
                orphan: p.orphan,
                parent_ino: p.parent_ino,
                record_id: p.record_id,
                allocation: p.allocation,
                macb,
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

        // Build timeline.jsonl: filesystem events first, then one row per
        // recovered deleted instance (grep a path/name = every version of it).
        let mut timeline_jsonl = {
            let mut fs = self.fs.borrow_mut();
            match fs.timeline() {
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
            }
        };

        // Deleted-instance rows derived from the same deleted_nodes() data — one
        // per instance, so every version of a same-named deleted file appears.
        self.ensure_deleted_cache();
        if let Some(entries) = self.deleted_cache.borrow().as_ref() {
            for e in entries {
                timeline_jsonl.extend_from_slice(deleted_timeline_row(e).as_bytes());
                timeline_jsonl.push(b'\n');
            }
        }

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

    /// Find a created overlay entry by `parent_ino` and name.
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

    /// Resolve a name to an in-place recovered-deleted child of `parent_fs_ino`,
    /// returning `(deleted-namespace fuse inode, size)` when a non-orphan entry
    /// under that parent carries exactly that real name (ADR 0008 v2). Ensures
    /// the deleted cache first, so callers must not hold a borrow of `self.fs`.
    fn lookup_deleted_in_place(&self, parent_fs_ino: u64, name: &[u8]) -> Option<(u64, u64)> {
        self.ensure_deleted_cache();
        let cache = self.deleted_cache.borrow();
        cache.as_ref()?.iter().find_map(|e| {
            (!e.orphan && e.parent_ino == Some(parent_fs_ino) && e.name.as_bytes() == name)
                .then_some((deleted_ino(e.fs_ino), e.size))
        })
    }

    /// Whether the recovered-deleted cache holds any `$Orphans` entry, so the
    /// root shells know to surface the top-level `$Orphans/` directory.
    fn cache_orphans_present(&self) -> bool {
        self.ensure_deleted_cache();
        self.deleted_cache
            .borrow()
            .as_ref()
            .is_some_and(|e| cache_has_orphans(e))
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
        FsFileType::RegularFile | FsFileType::Unknown => FileType::RegularFile,
        FsFileType::Directory => FileType::Directory,
        FsFileType::Symlink => FileType::Symlink,
        FsFileType::CharDevice => FileType::CharDevice,
        FsFileType::BlockDevice => FileType::BlockDevice,
        FsFileType::Fifo => FileType::NamedPipe,
        FsFileType::Socket => FileType::Socket,
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
        nlink: u32::from(meta.links_count),
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
        FsFileType::RegularFile | FsFileType::Unknown => FileType::RegularFile,
        FsFileType::Directory => FileType::Directory,
        FsFileType::Symlink => FileType::Symlink,
        FsFileType::CharDevice => FileType::CharDevice,
        FsFileType::BlockDevice => FileType::BlockDevice,
        FsFileType::Fifo => FileType::NamedPipe,
        FsFileType::Socket => FileType::Socket,
    }
}

/// The entries shown at the FUSE mount root, per [`MountLayout`].
///
/// `DiskOverlay` lists the virtual directories (`ro/`, `rw/`, `deleted/`, …);
/// `Raw` lists the underlying [`ForensicFs`] root's children directly (encoded
/// into the `ro/` inode namespace so the existing sub-tree callbacks serve
/// them), with no overlay directories. Returns `(fuse_ino, name, file_type)`;
/// `.`/`..` are added by the caller.
fn root_children(
    layout: crate::MountLayout,
    fs: &mut dyn ForensicFs,
    root_ino: u64,
    has_orphans: bool,
) -> crate::FsResult<Vec<(u64, Vec<u8>, FileType)>> {
    match layout {
        crate::MountLayout::DiskOverlay => Ok(root_dir_listing(has_orphans)
            .into_iter()
            .map(|(ino, name)| (ino, name.as_bytes().to_vec(), FileType::Directory))
            .collect()),
        crate::MountLayout::Raw => {
            let mut out = Vec::new();
            for e in fs.read_dir(root_ino)? {
                if e.name == b"." || e.name == b".." {
                    continue;
                }
                // Encode into the ro/ namespace so the existing sub-tree
                // callbacks (Ro decode) serve everything below the root.
                out.push((ro_ino(e.inode), e.name, fs_file_type_to_fuse(e.file_type)));
            }
            Ok(out)
        }
    }
}

/// One recovered deleted node as input to the placement planner.
struct DeletedPlan {
    ino: u64,
    real_name: String,
    parent_ino: Option<u64>,
    mtime_secs: i64,
    record_id: u64,
    has_live_collision: bool,
    allocation: FsAllocation,
}

/// Planner output: where a recovered node renders and under what name.
struct PlacedDeleted {
    ino: u64,
    display_name: String,
    real_name: String,
    orphan: bool,
    parent_ino: Option<u64>,
    record_id: u64,
    allocation: FsAllocation,
}

/// Decide in-place vs `$Orphans` placement and the display name for each
/// recovered deleted node, per ADR 0008 and the `--deleted` mode. Pure and
/// deterministic (no filesystem access), so it is unit-tested directly:
///
/// - `Off`   → nothing.
/// - `All`   → every instance under `$Orphans`, disambiguated.
/// - `Latest`→ the newest instance of each (parent, name) group renders
///   in-place (real name) when its parent is known, its name survived, its
///   allocation is `Deleted`, and no live sibling holds the name; every other
///   instance (older duplicates, collisions, true orphans) goes to `$Orphans`.
fn plan_deleted(plans: &[DeletedPlan], mode: DeletedMode) -> Vec<PlacedDeleted> {
    match mode {
        DeletedMode::Off => Vec::new(),
        DeletedMode::All => plans.iter().map(orphan_placed).collect(),
        DeletedMode::Latest => {
            use std::collections::{HashMap, HashSet};
            // Winner of each (parent, name) group = the in-place candidate.
            let mut winner: HashMap<(u64, &str), usize> = HashMap::new();
            for (i, p) in plans.iter().enumerate() {
                if !eligible_in_place(p) {
                    continue;
                }
                let key = (p.parent_ino.unwrap_or_default(), p.real_name.as_str());
                match winner.get(&key) {
                    Some(&j) if !outranks(p, &plans[j]) => {}
                    _ => {
                        winner.insert(key, i);
                    }
                }
            }
            let winners: HashSet<usize> = winner.into_values().collect();
            plans
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    if winners.contains(&i) {
                        PlacedDeleted {
                            ino: p.ino,
                            display_name: p.real_name.clone(),
                            real_name: p.real_name.clone(),
                            orphan: false,
                            parent_ino: p.parent_ino,
                            record_id: p.record_id,
                            allocation: p.allocation,
                        }
                    } else {
                        orphan_placed(p)
                    }
                })
                .collect()
        }
    }
}

/// A node may render in place only if it is a named, parented, `Deleted`
/// record whose name is free in the live directory.
fn eligible_in_place(p: &DeletedPlan) -> bool {
    p.allocation == FsAllocation::Deleted
        && p.parent_ino.is_some()
        && !p.real_name.is_empty()
        && !p.has_live_collision
}

/// `a` outranks `b` for the in-place slot: newest mtime, ties to highest id.
fn outranks(a: &DeletedPlan, b: &DeletedPlan) -> bool {
    (a.mtime_secs, a.record_id) > (b.mtime_secs, b.record_id)
}

fn orphan_placed(p: &DeletedPlan) -> PlacedDeleted {
    PlacedDeleted {
        ino: p.ino,
        display_name: orphan_name(&p.real_name, p.mtime_secs, p.record_id),
        real_name: p.real_name.clone(),
        orphan: true,
        parent_ino: p.parent_ino,
        record_id: p.record_id,
        allocation: p.allocation,
    }
}

/// `$Orphans` disambiguated name `<name>@<ts>Z~<id>` (the `Z` is appended by
/// [`filename_safe_utc`]), degrading to `record-<id>[@<ts>Z]` when no name
/// survived. The id is always present — it is the uniqueness guarantee.
fn orphan_name(real_name: &str, mtime_secs: i64, record_id: u64) -> String {
    let ts = (mtime_secs > 0).then(|| filename_safe_utc(mtime_secs));
    match (real_name.is_empty(), ts) {
        (false, Some(ts)) => format!("{real_name}@{ts}~{record_id}"),
        (false, None) => format!("{real_name}~{record_id}"),
        (true, Some(ts)) => format!("record-{record_id}@{ts}"),
        (true, None) => format!("record-{record_id}"),
    }
}

/// Format Unix seconds as a filename-safe UTC string `YYYY-MM-DDTHH-MM-SSZ`.
/// Colons become hyphens because `:` is illegal in Windows filenames, so this
/// timestamp can appear in any path the mount emits (ADR 0008).
#[allow(clippy::many_single_char_names)] // conventional date-field names (y/m/d/h/s)
fn filename_safe_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mon, d) = crate::marking::civil_from_days(days);
    format!("{y:04}-{mon:02}-{d:02}T{h:02}-{m:02}-{s:02}Z")
}

/// One `timeline.jsonl` row for a recovered deleted instance. Emitting one row
/// per instance makes the timeline an all-versions event list: grep a name or
/// path and every deleted version of it appears. `placement` marks in-place vs
/// `$Orphans`; `status` says whether the content was recoverable.
fn deleted_timeline_row(e: &DeletedEntry) -> String {
    // v2 rendering: orphans live under the top-level `$Orphans/`; in-place
    // entries render at their real name in the main tree (full parent path is
    // not reconstructed here — the record id + parent_ino carry identity).
    let path = if e.orphan {
        format!("$Orphans/{}", e.name)
    } else {
        e.real_name.clone()
    };
    let allocation = crate::marking::status_str(e.allocation);
    let row = serde_json::json!({
        "path": path,
        "name": e.real_name,
        "parent_ino": e.parent_ino,
        "macb": {
            "modified": e.macb.modified.seconds,
            "accessed": e.macb.accessed.seconds,
            "changed": e.macb.changed.seconds,
            "born": e.macb.born.seconds,
        },
        "record_id": e.record_id,
        "allocation": allocation,
        "status": if e.readable { "recovered" } else { "unreadable" },
        "placement": if e.orphan { "orphan" } else { "in-place" },
    });
    serde_json::to_string(&row).unwrap_or_default()
}

/// In-place recovered-deleted children of a live directory: the non-orphan
/// entries whose recovered parent is `parent_fs_ino`, returned as
/// `(deleted-namespace fuse inode, real name)`. The main-tree readdir/lookup
/// inject these beside the live siblings so a recovered deleted file appears at
/// its real path under its real name — no `deleted/` subtree, no name
/// decoration (ADR 0008 v2). The `deleted_ino` encoding keeps content served
/// from the recovered-bytes cache via the existing `Deleted` namespace.
fn deleted_in_place_children(entries: &[DeletedEntry], parent_fs_ino: u64) -> Vec<(u64, String)> {
    entries
        .iter()
        .filter(|e| !e.orphan && e.parent_ino == Some(parent_fs_ino))
        .map(|e| (deleted_ino(e.fs_ino), e.name.clone()))
        .collect()
}

/// A [`crate::marking::Mark`] for a cached deleted entry — the adapter from this
/// module's `DeletedEntry` onto the platform-agnostic marking schema, so the
/// Unix xattr channel renders the exact same values the Windows ADS channel does.
fn entry_mark(entry: &DeletedEntry) -> crate::marking::Mark {
    crate::marking::Mark {
        allocation: entry.allocation,
        macb: crate::marking::Macb {
            modified: entry.macb.modified.seconds,
            accessed: entry.macb.accessed.seconds,
            changed: entry.macb.changed.seconds,
            born: entry.macb.born.seconds,
        },
    }
}

/// The out-of-band marking schema exposed on a recovered-deleted entry (ADR
/// 0008 v2): the deleted/orphan status plus the recovered MACB times. Live
/// files carry none of these — the xattr channel is the mount's red-X. The names
/// and values are owned by [`crate::marking`], the single source of truth.
fn deleted_xattr_names() -> &'static [&'static str] {
    &crate::marking::UNIX_XATTR_NAMES
}

/// Value of one xattr on a recovered-deleted entry, or `None` when the name is
/// not part of the schema (the getxattr shell then replies `ENODATA`).
/// `user.4n6.status` is `deleted`|`orphan`; the `macb.*` values are ISO-8601
/// UTC. This is a metadata-only channel — the recovered content is untouched.
fn deleted_xattr_value(entry: &DeletedEntry, name: &str) -> Option<Vec<u8>> {
    crate::marking::unix_xattr_value(&entry_mark(entry), name)
}

/// Copy-up base bytes for an in-place recovered-deleted entry: its recovered
/// content, when readable. `None` when the entry is unknown or its content
/// could not be recovered — a write then fails loud rather than fabricating an
/// empty file. The recovered base in the cache stays untouched; the write lands
/// on the COW overlay, exactly like a live file (ADR 0008 v2).
fn deleted_cow_base(entries: &[DeletedEntry], fs_ino: u64) -> Option<Vec<u8>> {
    entries
        .iter()
        .find(|e| e.fs_ino == fs_ino && e.readable)
        .map(|e| e.data.clone())
}

impl Filesystem for ForensicFuseFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_bytes = name.as_encoded_bytes();

        // Virtual root (disk overlay): resolve virtual directory names. In Raw
        // layout the root maps straight to the ForensicFs root (handled below).
        if parent == FUSE_ROOT_INO && self.layout == crate::MountLayout::DiskOverlay {
            for (ino, dir_name) in root_dir_listing(self.cache_orphans_present()) {
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

        // $Orphans/ namespace lookup (top-level, ADR 0008 v2): the unplaceable
        // recovered entries, disambiguated by mtime + record id.
        if parent == FUSE_ORPHANS_INO {
            self.ensure_deleted_cache();
            let cache = self.deleted_cache.borrow();
            if let Some(entries) = cache.as_ref() {
                for entry in entries.iter().filter(|e| e.orphan) {
                    if name_bytes == entry.name.as_bytes() {
                        let fuse_ino = deleted_ino(entry.fs_ino);
                        reply.entry(&TTL, &virtual_file_attr(fuse_ino, entry.size), 0);
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
            // ADR 0008 v2: an in-place recovered deleted child resolves at its
            // real name. Precomputed before any fs borrow below.
            let deleted_hit = self.lookup_deleted_in_place(fs_parent, name_bytes);

            // Check overlay created files first.
            if let Some((id, counter, is_dir)) = self.find_created_by_name(fs_parent, name_bytes) {
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
                                if let Ok(meta) = fs.metadata(child_ino) {
                                    let fuse_ino = rw_ino(child_ino);
                                    let mut attr = fs_to_attr(fuse_ino, &meta);
                                    if let Ok(data) = s.read_overlay_file(&overlay_id) {
                                        attr.size = data.len() as u64;
                                        attr.blocks = attr.size.div_ceil(512);
                                    }
                                    reply.entry(&TTL, &attr, 0);
                                    return;
                                }
                                reply.error(libc::EIO);
                                return;
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
                        if let Some((fino, size)) = deleted_hit {
                            reply.entry(&TTL, &virtual_file_attr(fino, size), 0);
                            return;
                        }
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

        // ro/ namespace: the ro/ virtual dir maps to the fs root inode. In Raw
        // layout the FUSE root itself maps to the fs root (no ro/ wrapper).
        let fs_parent = match parent {
            FUSE_RO_INO => self.root_ino,
            FUSE_ROOT_INO if self.layout == crate::MountLayout::Raw => self.root_ino,
            _ => {
                if let InodeNamespace::Ro(ino) = decode_fuse_ino(parent) {
                    ino
                } else {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // In-place recovered deleted child (checked before the fs borrow).
        let deleted_hit = self.lookup_deleted_in_place(fs_parent, name_bytes);

        let mut fs = self.fs.borrow_mut();
        match fs.lookup(fs_parent, name_bytes) {
            Ok(Some(child_ino)) => match fs.metadata(child_ino) {
                Ok(meta) => {
                    let fuse_ino = ro_ino(child_ino);
                    reply.entry(&TTL, &fs_to_attr(fuse_ino, &meta), 0);
                }
                Err(_) => reply.error(libc::EIO),
            },
            Ok(None) => {
                if let Some((fino, size)) = deleted_hit {
                    reply.entry(&TTL, &virtual_file_attr(fino, size), 0);
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        // Virtual root.
        if ino == FUSE_ROOT_INO {
            reply.attr(&TTL, &virtual_dir_attr(FUSE_ROOT_INO));
            return;
        }

        // Virtual top-level directories (incl. the top-level `$Orphans/`).
        if (FUSE_RO_INO..=FUSE_SESSION_INO).contains(&ino) || ino == FUSE_ORPHANS_INO {
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
                        // A copied-up delete reports its overlay size (ADR 0008
                        // v2 COW); otherwise the recovered size.
                        let mut size = entry.size;
                        let session = self.session.borrow();
                        if let Some(s) = session.as_ref() {
                            if s.overlay.modified.contains_key(&fs_ino) {
                                let overlay_id = Self::modified_overlay_id(fs_ino);
                                if let Ok(d) = s.read_overlay_file(&overlay_id) {
                                    size = d.len() as u64;
                                }
                            }
                        }
                        reply.attr(&TTL, &virtual_file_attr(ino, size));
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
                            reply.attr(
                                &TTL,
                                &virtual_file_attr(ino, mc.superblock_json.len() as u64),
                            );
                        }
                        2 => {
                            reply.attr(
                                &TTL,
                                &virtual_file_attr(ino, mc.timeline_jsonl.len() as u64),
                            );
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
                                let data =
                                    serde_json::to_string_pretty(&status).unwrap_or_default();
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

    /// Read one extended attribute. Only recovered-deleted/orphan entries carry
    /// the `user.4n6.*` marking (ADR 0008 v2); live files and virtual nodes have
    /// none, so they reply `ENODATA`. Follows the FUSE size-probe protocol:
    /// `size == 0` returns the value length; otherwise the bytes (or `ERANGE`).
    fn getxattr(&mut self, _req: &Request, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
        let value = if let InodeNamespace::Deleted(fs_ino) = decode_fuse_ino(ino) {
            self.ensure_deleted_cache();
            let cache = self.deleted_cache.borrow();
            let attr_name = name.to_str();
            cache.as_ref().and_then(|entries| {
                let n = attr_name?;
                let e = entries.iter().find(|e| e.fs_ino == fs_ino)?;
                deleted_xattr_value(e, n)
            })
        } else {
            None
        };
        match value {
            Some(v) => {
                if size == 0 {
                    reply.size(v.len() as u32);
                } else if (v.len() as u32) <= size {
                    reply.data(&v);
                } else {
                    reply.error(libc::ERANGE);
                }
            }
            None => reply.error(libc::ENODATA),
        }
    }

    /// List the extended attribute names on an entry. Recovered-deleted/orphan
    /// entries expose the `user.4n6.*` marking schema; everything else lists
    /// nothing. Names are NUL-separated per the FUSE `listxattr` contract.
    fn listxattr(&mut self, _req: &Request, ino: u64, size: u32, reply: ReplyXattr) {
        let mut buf: Vec<u8> = Vec::new();
        if let InodeNamespace::Deleted(fs_ino) = decode_fuse_ino(ino) {
            self.ensure_deleted_cache();
            let cache = self.deleted_cache.borrow();
            let present = cache
                .as_ref()
                .is_some_and(|entries| entries.iter().any(|e| e.fs_ino == fs_ino));
            if present {
                for n in deleted_xattr_names() {
                    buf.extend_from_slice(n.as_bytes());
                    buf.push(0);
                }
            }
        }
        if size == 0 {
            reply.size(buf.len() as u32);
        } else if (buf.len() as u32) <= size {
            reply.data(&buf);
        } else {
            reply.error(libc::ERANGE);
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

        // Root directory: virtual dirs (DiskOverlay) or the ForensicFs tree
        // directly (Raw) — both via the tested root_children() decision.
        if ino == FUSE_ROOT_INO {
            let has_orphans = self.cache_orphans_present();
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (FUSE_ROOT_INO, FileType::Directory, ".".to_string()),
                (FUSE_ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            {
                let mut fs = self.fs.borrow_mut();
                let Ok(children) =
                    root_children(self.layout, &mut **fs, self.root_ino, has_orphans)
                else {
                    reply.error(libc::EIO);
                    return;
                };
                for (fino, name, kind) in children {
                    entries.push((fino, kind, String::from_utf8_lossy(&name).into_owned()));
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

        // rw/ namespace readdir.
        if let Some(fs_dir_ino) = match ino {
            FUSE_RW_INO => Some(self.root_ino),
            _ => match decode_fuse_ino(ino) {
                InodeNamespace::Rw(rw_id) if rw_id < 9_000_000 => Some(rw_id),
                _ => None,
            },
        } {
            // ADR 0008 v2: recovered deleted children render in-place beside the
            // live siblings. Computed before borrowing fs (ensure_deleted_cache
            // takes its own fs borrow).
            self.ensure_deleted_cache();
            let injected: Vec<(u64, FileType, String)> = {
                let cache = self.deleted_cache.borrow();
                cache.as_ref().map_or_else(Vec::new, |c| {
                    deleted_in_place_children(c, fs_dir_ino)
                        .into_iter()
                        .map(|(dino, name)| (dino, FileType::RegularFile, name))
                        .collect()
                })
            };
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

                    // Recovered deleted children, in-place at their real name.
                    fuse_entries.extend(injected);

                    for (i, (entry_ino, kind, name)) in fuse_entries.iter().enumerate().skip(offset)
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

        // $Orphans/ readdir (top-level, ADR 0008 v2): the unplaceable recovered
        // entries (true orphans, live-name collisions, older same-name
        // deletes), disambiguated by mtime + record id.
        if ino == FUSE_ORPHANS_INO {
            self.ensure_deleted_cache();
            let cache = self.deleted_cache.borrow();
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (FUSE_ORPHANS_INO, FileType::Directory, ".".to_string()),
                (FUSE_ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            if let Some(cached) = cache.as_ref() {
                for entry in cached.iter().filter(|e| e.orphan) {
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
            _ => {
                if let InodeNamespace::Ro(fs_ino) = decode_fuse_ino(ino) {
                    fs_ino
                } else {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // ADR 0008 v2: recovered deleted children also render in-place in the
        // read-only view of the main tree.
        self.ensure_deleted_cache();
        let injected: Vec<(u64, FileType, String)> = {
            let cache = self.deleted_cache.borrow();
            cache.as_ref().map_or_else(Vec::new, |c| {
                deleted_in_place_children(c, fs_dir_ino)
                    .into_iter()
                    .map(|(dino, name)| (dino, FileType::RegularFile, name))
                    .collect()
            })
        };

        let mut fs = self.fs.borrow_mut();
        match fs.read_dir(fs_dir_ino) {
            Ok(entries) => {
                let root_ino = self.root_ino;
                let mut fuse_entries: Vec<(u64, FileType, String)> = entries
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

                fuse_entries.extend(injected);

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
                // A copied-up recovered-deleted file reads from the overlay
                // (ADR 0008 v2 COW); otherwise from the recovered-bytes cache.
                {
                    let session = self.session.borrow();
                    if let Some(s) = session.as_ref() {
                        if s.overlay.modified.contains_key(&fs_ino) {
                            let overlay_id = Self::modified_overlay_id(fs_ino);
                            if let Ok(d) = s.read_overlay_file(&overlay_id) {
                                let off = offset as usize;
                                if off >= d.len() {
                                    reply.data(&[]);
                                } else {
                                    let end = (off + size as usize).min(d.len());
                                    reply.data(&d[off..end]);
                                }
                                return;
                            }
                        }
                    }
                }
                self.ensure_deleted_cache();
                let cache = self.deleted_cache.borrow();
                if let Some(entries) = cache.as_ref() {
                    if let Some(entry) = entries.iter().find(|e| e.fs_ino == fs_ino) {
                        // Unreadable recovered content is a loud read error, not
                        // a fabricated 0-byte success.
                        if !entry.readable {
                            reply.error(libc::EIO);
                            return;
                        }
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
                match fs.read_file_range(fs_ino, offset as u64, u64::from(size)) {
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
                            if let Ok(data) = s.read_overlay_file(&created_id) {
                                let off = offset as usize;
                                let end = (off + size as usize).min(data.len());
                                if off >= data.len() {
                                    reply.data(&[]);
                                } else {
                                    reply.data(&data[off..end]);
                                }
                                return;
                            }
                            reply.error(libc::EIO);
                            return;
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
                        if let Ok(data) = s.read_overlay_file(&overlay_id) {
                            let off = offset as usize;
                            let end = (off + size as usize).min(data.len());
                            if off >= data.len() {
                                reply.data(&[]);
                            } else {
                                reply.data(&data[off..end]);
                            }
                            return;
                        }
                        reply.error(libc::EIO);
                        return;
                    }
                }
                drop(session);

                // Fall back to underlying fs.
                let mut fs = self.fs.borrow_mut();
                match fs.read_file_range(fs_ino, offset as u64, u64::from(size)) {
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
                    let Ok(original) = fs.read_file(fs_ino) else {
                        reply.error(libc::EIO);
                        return;
                    };
                    if s.write_overlay_file(&overlay_id, &original).is_err() {
                        reply.error(libc::EIO);
                        return;
                    }
                    s.overlay.modified.insert(fs_ino, overlay_id.clone());
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
            // ADR 0008 v2: an in-place recovered-deleted file is COW-writable
            // like a live file. First write copies up its recovered bytes onto
            // the overlay (keyed by fs inode); the recovered base is untouched.
            InodeNamespace::Deleted(fs_ino) => {
                self.ensure_deleted_cache();
                let overlay_id = Self::modified_overlay_id(fs_ino);
                let mut session = self.session.borrow_mut();
                let s = session.as_mut().unwrap();

                if !s.overlay.modified.contains_key(&fs_ino) {
                    let base = {
                        let cache = self.deleted_cache.borrow();
                        cache.as_ref().and_then(|e| deleted_cow_base(e, fs_ino))
                    };
                    // Unreadable recovered content cannot be copied up — fail
                    // loud, never fabricate an empty base.
                    let Some(base) = base else {
                        reply.error(libc::EIO);
                        return;
                    };
                    if s.write_overlay_file(&overlay_id, &base).is_err() {
                        reply.error(libc::EIO);
                        return;
                    }
                    s.overlay.modified.insert(fs_ino, overlay_id.clone());
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

        let Some(fs_parent) = self.rw_parent_to_fs(parent) else {
            reply.error(libc::EROFS);
            return;
        };

        let Some(name_s) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let name_str = name_s.to_string();

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

        let Some(fs_parent) = self.rw_parent_to_fs(parent) else {
            reply.error(libc::EROFS);
            return;
        };

        let Some(name_s) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let name_str = name_s.to_string();

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

        let Some(fs_parent) = self.rw_parent_to_fs(parent) else {
            reply.error(libc::EROFS);
            return;
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

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.unlink(req, parent, name, reply);
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
                        let Ok(original) = fs.read_file(fs_ino) else {
                            reply.error(libc::EIO);
                            return;
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
    use crate::{FsDeletedInode, FsDirEntry, FsError, FsRecoveryResult, FsResult, FsTimelineEvent};
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
        for ino in [1, 42, FUSE_ROOT_INO, FUSE_ORPHANS_INO, 999_999] {
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
        assert_eq!(fs_file_type_to_fuse(FsFileType::Symlink), FileType::Symlink);
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
        assert_eq!(fs_file_type_to_fuse(FsFileType::Fifo), FileType::NamedPipe);
    }

    #[test]
    fn file_type_mapping_socket() {
        assert_eq!(fs_file_type_to_fuse(FsFileType::Socket), FileType::Socket);
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
            mode: 0o100_644,
            uid: 1000,
            gid: 1000,
            size: 100,
            links_count: 1,
            atime: FsTimestamp {
                seconds: 1_700_000_000,
                nanoseconds: 0,
            },
            mtime: FsTimestamp {
                seconds: 1_700_000_000,
                nanoseconds: 0,
            },
            ctime: FsTimestamp {
                seconds: 1_700_000_000,
                nanoseconds: 0,
            },
            crtime: FsTimestamp {
                seconds: 1_700_000_000,
                nanoseconds: 0,
            },
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
            mode: 0o120_777,
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
            mode: 0o100_644,
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
            mode: 0o100_644,
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
    // root_children — MountLayout decision (Humble Object)
    // -----------------------------------------------------------------------

    fn root_child_names(layout: crate::MountLayout) -> Vec<String> {
        let mut fs = MockForensicFs;
        let root = fs.root_ino();
        root_children(layout, &mut fs, root, false)
            .unwrap()
            .iter()
            .map(|(_, n, _)| String::from_utf8_lossy(n).to_string())
            .collect()
    }

    #[test]
    fn root_children_raw_lists_fs_tree_without_overlay() {
        let names = root_child_names(crate::MountLayout::Raw);
        assert!(names.contains(&"hello.txt".to_string()), "got {names:?}");
        assert!(names.contains(&"subdir".to_string()), "got {names:?}");
        assert!(
            !names
                .iter()
                .any(|n| n == "rw" || n == "deleted" || n == "ro"),
            "Raw root must have no overlay dirs: {names:?}"
        );
    }

    #[test]
    fn root_children_diskoverlay_lists_virtual_dirs() {
        let names = root_child_names(crate::MountLayout::DiskOverlay);
        for d in ["ro", "rw", "journal", "metadata", "unallocated", "session"] {
            assert!(names.contains(&d.to_string()), "missing {d}: {names:?}");
        }
        // The flat deleted/ directory is gone in v2 (in-place rendering).
        assert!(!names.contains(&"deleted".to_string()), "got {names:?}");
    }

    #[test]
    fn root_children_diskoverlay_appends_orphans_when_present() {
        let mut fs = MockForensicFs;
        let root = fs.root_ino();
        let with: Vec<String> = root_children(crate::MountLayout::DiskOverlay, &mut fs, root, true)
            .unwrap()
            .iter()
            .map(|(_, n, _)| String::from_utf8_lossy(n).to_string())
            .collect();
        assert!(with.contains(&"$Orphans".to_string()), "got {with:?}");
    }

    // -----------------------------------------------------------------------
    // VIRTUAL_DIRS constant
    // -----------------------------------------------------------------------

    #[test]
    fn virtual_dirs_has_expected_entries() {
        // v2: the flat deleted/ dir is gone; six fixed virtual dirs remain.
        assert_eq!(VIRTUAL_DIRS.len(), 6);
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "ro"));
        assert!(VIRTUAL_DIRS.iter().any(|(_, name)| *name == "rw"));
        assert!(!VIRTUAL_DIRS.iter().any(|(_, name)| *name == "deleted"));
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
                "journal" => assert_eq!(ino, FUSE_JOURNAL_INO),
                "metadata" => assert_eq!(ino, FUSE_METADATA_INO),
                "unallocated" => assert_eq!(ino, FUSE_UNALLOCATED_INO),
                "session" => assert_eq!(ino, FUSE_SESSION_INO),
                _ => panic!("unexpected virtual dir: {name}"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // MockForensicFs + FUSE dispatch tests
    // -----------------------------------------------------------------------

    struct MockForensicFs;

    impl crate::ForensicFs for MockForensicFs {
        fn root_ino(&self) -> u64 {
            2
        }

        fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
            match ino {
                2 => Ok(vec![
                    FsDirEntry {
                        inode: 2,
                        name: b".".to_vec(),
                        file_type: FsFileType::Directory,
                    },
                    FsDirEntry {
                        inode: 2,
                        name: b"..".to_vec(),
                        file_type: FsFileType::Directory,
                    },
                    FsDirEntry {
                        inode: 10,
                        name: b"hello.txt".to_vec(),
                        file_type: FsFileType::RegularFile,
                    },
                    FsDirEntry {
                        inode: 11,
                        name: b"subdir".to_vec(),
                        file_type: FsFileType::Directory,
                    },
                ]),
                11 => Ok(vec![
                    FsDirEntry {
                        inode: 11,
                        name: b".".to_vec(),
                        file_type: FsFileType::Directory,
                    },
                    FsDirEntry {
                        inode: 2,
                        name: b"..".to_vec(),
                        file_type: FsFileType::Directory,
                    },
                    FsDirEntry {
                        inode: 12,
                        name: b"nested.txt".to_vec(),
                        file_type: FsFileType::RegularFile,
                    },
                ]),
                _ => Err(FsError::NotFound(format!("inode {ino}"))),
            }
        }

        fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
            let entries = self.read_dir(parent_ino)?;
            Ok(entries.iter().find(|e| e.name == name).map(|e| e.inode))
        }

        fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
            let (file_type, size) = match ino {
                2 | 11 => (FsFileType::Directory, 4096),
                10 => (FsFileType::RegularFile, 12),
                12 => (FsFileType::RegularFile, 11),
                _ => return Err(FsError::NotFound(format!("inode {ino}"))),
            };
            Ok(FsMetadata {
                ino,
                file_type,
                mode: if file_type == FsFileType::Directory {
                    0o40755
                } else {
                    0o100_644
                },
                uid: 1000,
                gid: 1000,
                size: size as u64,
                links_count: if file_type == FsFileType::Directory {
                    2
                } else {
                    1
                },
                atime: FsTimestamp {
                    seconds: 1_700_000_000,
                    nanoseconds: 0,
                },
                mtime: FsTimestamp {
                    seconds: 1_700_000_000,
                    nanoseconds: 0,
                },
                ctime: FsTimestamp {
                    seconds: 1_700_000_000,
                    nanoseconds: 0,
                },
                crtime: FsTimestamp {
                    seconds: 1_699_000_000,
                    nanoseconds: 0,
                },
                allocated: true,
            })
        }

        fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
            match ino {
                10 => Ok(b"Hello, mock!".to_vec()),
                12 => Ok(b"Nested file".to_vec()),
                // Deleted nodes whose content is recoverable.
                100..=103 => Ok(vec![0xAB; 100]),
                // 104 (gone.txt) deliberately unreadable — falls through to Err.
                _ => Err(FsError::NotFound(format!("inode {ino}"))),
            }
        }

        fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
            let data = self.read_file(ino)?;
            let start = (offset as usize).min(data.len());
            let end = (start + len as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }

        fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
            Err(FsError::NotFound("no symlinks in mock".to_string()))
        }

        fn deleted_inodes(&mut self) -> FsResult<Vec<FsDeletedInode>> {
            Ok(vec![FsDeletedInode {
                ino: 99,
                file_type: FsFileType::RegularFile,
                size: 100,
                dtime: 1_700_001_000,
                recoverability: 0.75,
            }])
        }

        fn deleted_nodes(&mut self) -> FsResult<Vec<crate::FsDeletedNode>> {
            let mk = |ino: u64,
                      name: &[u8],
                      parent: Option<u64>,
                      mtime: i64,
                      record_id: u64,
                      allocation: crate::FsAllocation| {
                crate::FsDeletedNode {
                    ino,
                    name: name.to_vec(),
                    parent_ino: parent,
                    size: 100,
                    file_type: FsFileType::RegularFile,
                    allocation,
                    record_id,
                    atime: FsTimestamp::default(),
                    mtime: FsTimestamp {
                        seconds: mtime,
                        nanoseconds: 0,
                    },
                    ctime: FsTimestamp::default(),
                    crtime: FsTimestamp::default(),
                }
            };
            Ok(vec![
                // Two same-name deletes under the live root (ino 2): newest wins
                // the in-place slot, the older is a same-name orphan.
                mk(
                    100,
                    b"report.txt",
                    Some(2),
                    200,
                    100,
                    crate::FsAllocation::Deleted,
                ),
                mk(
                    101,
                    b"report.txt",
                    Some(2),
                    100,
                    101,
                    crate::FsAllocation::Deleted,
                ),
                // Collides with the live hello.txt (ino 10) -> $Orphans.
                mk(
                    102,
                    b"hello.txt",
                    Some(2),
                    300,
                    102,
                    crate::FsAllocation::Deleted,
                ),
                // Nameless true orphan (no parent) -> $Orphans.
                mk(103, b"", None, 150, 103, crate::FsAllocation::Orphan),
                // In-place candidate whose content is unreadable (ino 104 errors
                // in read_file) -> honest unreadable marker, never a 0-byte fake.
                mk(
                    104,
                    b"gone.txt",
                    Some(2),
                    250,
                    104,
                    crate::FsAllocation::Deleted,
                ),
            ])
        }

        fn recover_file(&mut self, ino: u64) -> FsResult<FsRecoveryResult> {
            match ino {
                99 => Ok(FsRecoveryResult {
                    ino: 99,
                    data: vec![0xDE; 100],
                    expected_size: 100,
                    recovered_bytes: 100,
                    recovery_percentage: 1.0,
                }),
                _ => Err(FsError::NotFound(format!("inode {ino}"))),
            }
        }

        fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> {
            Ok(vec![FsTimelineEvent {
                timestamp: FsTimestamp {
                    seconds: 1_700_000_000,
                    nanoseconds: 0,
                },
                event_type: FsEventType::Created,
                inode: 10,
                size: 12,
                uid: 1000,
                gid: 1000,
            }])
        }

        fn fs_info(&self) -> FsResult<serde_json::Value> {
            Ok(serde_json::json!({ "filesystem": "mock", "block_size": 4096 }))
        }

        fn block_size(&self) -> u64 {
            4096
        }
    }

    fn make_mock_fuse() -> ForensicFuseFs {
        ForensicFuseFs::new(
            Box::new(MockForensicFs),
            None,
            crate::MountLayout::DiskOverlay,
            crate::DeletedMode::Latest,
        )
    }

    #[test]
    fn mock_ensure_deleted_cache() {
        let fuse = make_mock_fuse();
        assert!(fuse.deleted_cache.borrow().is_none());
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        let entries = cache.as_ref().expect("cache should be populated");
        // Five recovered nodes from the mock, real names — never fabricated.
        assert_eq!(entries.len(), 5);
        assert!(entries
            .iter()
            .any(|e| e.fs_ino == 100 && e.name == "report.txt"));
    }

    #[test]
    fn mock_ensure_metadata_cache() {
        let fuse = make_mock_fuse();
        assert!(fuse.metadata_cache.borrow().is_none());
        fuse.ensure_metadata_cache();
        let cache = fuse.metadata_cache.borrow();
        let mc = cache.as_ref().expect("cache should be populated");
        let sb_str = String::from_utf8_lossy(&mc.superblock_json);
        assert!(
            sb_str.contains("mock"),
            "superblock_json should contain 'mock': {sb_str}"
        );
        assert!(
            !mc.timeline_jsonl.is_empty(),
            "timeline_jsonl should not be empty"
        );
    }

    #[test]
    fn mock_root_ino_stored() {
        let fuse = make_mock_fuse();
        assert_eq!(fuse.root_ino, 2);
    }

    #[test]
    fn mock_has_session_false() {
        let fuse = make_mock_fuse();
        assert!(!fuse.has_session());
    }

    #[test]
    fn mock_read_file_through_fs() {
        let fuse = make_mock_fuse();
        let mut fs = fuse.fs.borrow_mut();
        let data = fs.read_file(10).expect("read_file(10) should succeed");
        assert_eq!(data, b"Hello, mock!");
    }

    #[test]
    fn mock_read_file_range_through_fs() {
        let fuse = make_mock_fuse();
        let mut fs = fuse.fs.borrow_mut();
        let data = fs
            .read_file_range(10, 0, 5)
            .expect("read_file_range should succeed");
        assert_eq!(data, b"Hello");
    }

    #[test]
    fn mock_lookup_through_fs() {
        let fuse = make_mock_fuse();
        let mut fs = fuse.fs.borrow_mut();
        let result = fs.lookup(2, b"hello.txt").expect("lookup should succeed");
        assert_eq!(result, Some(10));
    }

    #[test]
    fn mock_metadata_through_fs() {
        let fuse = make_mock_fuse();
        let mut fs = fuse.fs.borrow_mut();
        let meta = fs.metadata(10).expect("metadata(10) should succeed");
        assert_eq!(meta.file_type, FsFileType::RegularFile);
        assert_eq!(meta.size, 12);
        assert_eq!(meta.ino, 10);
    }

    #[test]
    fn mock_fs_to_attr() {
        let fuse = make_mock_fuse();
        let meta = {
            let mut fs = fuse.fs.borrow_mut();
            fs.metadata(10).expect("metadata(10) should succeed")
        };
        let attr = fs_to_attr(ro_ino(10), &meta);
        assert_eq!(attr.ino, ro_ino(10));
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.size, 12);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.blksize, 4096);
        let expected_atime = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(attr.atime, expected_atime);
        let expected_crtime = UNIX_EPOCH + Duration::from_secs(1_699_000_000);
        assert_eq!(attr.crtime, expected_crtime);
    }

    #[test]
    fn mock_timeline_through_fs() {
        let fuse = make_mock_fuse();
        let mut fs = fuse.fs.borrow_mut();
        let events = fs.timeline().expect("timeline should succeed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, FsEventType::Created);
        assert_eq!(events[0].inode, 10);
        assert_eq!(events[0].size, 12);
    }

    #[test]
    fn mock_ensure_journal_cache_empty() {
        let fuse = make_mock_fuse();
        assert!(fuse.journal_cache.borrow().is_none());
        fuse.ensure_journal_cache();
        let cache = fuse.journal_cache.borrow();
        let entries = cache.as_ref().expect("cache should be populated");
        assert!(
            entries.is_empty(),
            "mock has no journal_transactions override, should be empty"
        );
    }

    // -----------------------------------------------------------------------
    // Deleted-node placement (Task 2): real names, in-place vs $Orphans, gating
    // -----------------------------------------------------------------------

    fn make_mock_fuse_mode(mode: crate::DeletedMode) -> ForensicFuseFs {
        ForensicFuseFs::new(
            Box::new(MockForensicFs),
            None,
            crate::MountLayout::DiskOverlay,
            mode,
        )
    }

    #[test]
    fn filename_safe_utc_has_no_colons() {
        // 1_700_000_000 == 2023-11-14T22:13:20Z -> colons become hyphens.
        assert_eq!(filename_safe_utc(1_700_000_000), "2023-11-14T22-13-20Z");
    }

    #[test]
    fn deleted_cache_latest_places_newest_in_place() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Latest);
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        let entries = cache.as_ref().expect("cache populated");
        let by = |ino: u64| {
            entries
                .iter()
                .find(|e| e.fs_ino == ino)
                .unwrap_or_else(|| panic!("no cache entry for ino {ino}"))
        };
        // Newest report.txt renders in-place under its real name.
        let a = by(100);
        assert_eq!(a.name, "report.txt");
        assert!(!a.orphan);
        // Older same-name delete -> $Orphans, disambiguated `<name>@<ts>Z~<id>`.
        let b = by(101);
        assert!(b.orphan);
        assert!(b.name.starts_with("report.txt@"), "got {}", b.name);
        assert!(b.name.ends_with("~101"), "got {}", b.name);
        // Live-name collision -> $Orphans.
        assert!(by(102).orphan);
        // Nameless true orphan -> $Orphans.
        assert!(by(103).orphan);
        // In-place but unreadable content -> honest marker, not a 0-byte fake.
        let g = by(104);
        assert_eq!(g.name, "gone.txt");
        assert!(!g.orphan);
        assert!(!g.readable);
    }

    #[test]
    fn deleted_cache_off_is_empty() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Off);
        fuse.ensure_deleted_cache();
        assert!(fuse
            .deleted_cache
            .borrow()
            .as_ref()
            .expect("cache populated")
            .is_empty());
    }

    #[test]
    fn deleted_cache_all_routes_everything_to_orphans() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::All);
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        let entries = cache.as_ref().expect("cache populated");
        assert_eq!(entries.len(), 5);
        assert!(
            entries.iter().all(|e| e.orphan),
            "All -> every instance orphan"
        );
        let a = entries.iter().find(|e| e.fs_ino == 100).unwrap();
        assert!(a.name.starts_with("report.txt@"), "got {}", a.name);
    }

    #[test]
    fn deleted_cache_never_fabricates_unknown_names() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Latest);
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        for e in cache.as_ref().expect("cache populated") {
            assert!(!e.name.ends_with("_unknown"), "fabricated: {}", e.name);
        }
    }

    #[test]
    fn timeline_jsonl_carries_every_deleted_instance() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Latest);
        fuse.ensure_metadata_cache();
        let cache = fuse.metadata_cache.borrow();
        let mc = cache.as_ref().expect("metadata cache populated");
        let text = String::from_utf8_lossy(&mc.timeline_jsonl);
        // A deleted-instance row is any JSONL line carrying a `placement` field.
        let rows: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v.get("placement").is_some())
            .collect();
        // One row per deleted instance (all 5 mock nodes).
        assert_eq!(rows.len(), 5, "one row per deleted instance");
        // Every version of a same-named deleted file (grep by name).
        let report: Vec<_> = rows.iter().filter(|r| r["name"] == "report.txt").collect();
        assert_eq!(report.len(), 2, "both report.txt instances present");
        assert!(report.iter().any(|r| r["placement"] == "in-place"));
        assert!(report.iter().any(|r| r["placement"] == "orphan"));
        // Required fields present on a row.
        let r = &rows[0];
        for f in ["path", "name", "record_id", "allocation", "status", "macb"] {
            assert!(r.get(f).is_some(), "row missing {f}: {r}");
        }
        assert!(r["macb"].get("modified").is_some());
        // Unreadable content surfaced honestly in the status.
        assert!(rows
            .iter()
            .any(|r| r["name"] == "gone.txt" && r["status"] == "unreadable"));
    }

    // -----------------------------------------------------------------------
    // ADR 0008 v2 (a): in-place recovered-deleted entries render in the main
    // navigable tree at their recovered parent, under their real name.
    // -----------------------------------------------------------------------

    #[test]
    fn in_place_children_injected_under_parent() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Latest);
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        let entries = cache.as_ref().expect("cache populated");
        let kids = deleted_in_place_children(entries, 2);
        // report.txt (ino 100, newest) and gone.txt (ino 104) are the in-place
        // deletes under the live root (parent ino 2); orphans are excluded.
        let names: Vec<&str> = kids.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"report.txt"), "got {names:?}");
        assert!(names.contains(&"gone.txt"), "got {names:?}");
        assert_eq!(
            kids.len(),
            2,
            "only the two in-place deletes under parent 2"
        );
        // Real recovered name — no `(deleted)` decoration.
        assert!(
            !names.iter().any(|n| n.contains("(deleted)")),
            "got {names:?}"
        );
        // Child inode is the deleted-namespace encoding, so getattr/read resolve it.
        assert!(kids.iter().any(|(ino, _)| *ino == deleted_ino(100)));
        // A directory with no recovered deleted children gets nothing injected.
        assert!(deleted_in_place_children(entries, 11).is_empty());
        // Orphans never inject in-place (ino 101/102/103 are routed to $Orphans).
        assert!(!kids.iter().any(|(ino, _)| *ino == deleted_ino(101)));
    }

    // -----------------------------------------------------------------------
    // ADR 0008 v2 (b): `$Orphans/` is a top-level synthetic directory (not a
    // `deleted/` subtree), shown only when unplaceable entries exist.
    // -----------------------------------------------------------------------

    #[test]
    fn orphans_dir_is_top_level_only_when_present() {
        use crate::inode_map::FUSE_ORPHANS_INO;
        // With orphans present, `$Orphans` joins the root listing; the flat
        // `deleted/` directory is gone.
        let with = root_dir_listing(true);
        assert!(
            with.iter()
                .any(|&(ino, n)| ino == FUSE_ORPHANS_INO && n == "$Orphans"),
            "root should list $Orphans when orphans exist: {with:?}"
        );
        assert!(
            !with.iter().any(|&(_, n)| n == "deleted"),
            "the flat deleted/ dir is removed in v2: {with:?}"
        );
        // Stable virtual dirs stay.
        for want in ["ro", "rw", "metadata", "session"] {
            assert!(
                with.iter().any(|&(_, n)| n == want),
                "missing {want}: {with:?}"
            );
        }
        // No orphans -> no $Orphans at the root.
        let without = root_dir_listing(false);
        assert!(
            !without.iter().any(|&(_, n)| n == "$Orphans"),
            "no $Orphans without orphan entries: {without:?}"
        );
    }

    #[test]
    fn cache_has_orphans_reflects_placement() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Latest);
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        let entries = cache.as_ref().expect("cache populated");
        // Mock routes 101/102/103 to $Orphans.
        assert!(cache_has_orphans(entries));
        assert!(!cache_has_orphans(&[]));
    }

    // -----------------------------------------------------------------------
    // ADR 0008 v2 (c): the deleted status + recovered MACB times ride an
    // out-of-band xattr channel (user.4n6.*), never a name/mode decoration.
    // -----------------------------------------------------------------------

    #[test]
    fn deleted_xattr_names_are_the_marking_schema() {
        let names = deleted_xattr_names();
        for want in [
            "user.4n6.status",
            "user.4n6.macb.modified",
            "user.4n6.macb.accessed",
            "user.4n6.macb.changed",
            "user.4n6.macb.born",
        ] {
            assert!(names.contains(&want), "missing {want}: {names:?}");
        }
        assert_eq!(names.len(), 5);
    }

    #[test]
    fn deleted_xattr_value_status_and_macb() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Latest);
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        let entries = cache.as_ref().expect("cache populated");
        let by = |ino: u64| entries.iter().find(|e| e.fs_ino == ino).unwrap();

        // In-place Deleted entry (ino 100) -> status "deleted".
        let a = by(100);
        assert_eq!(
            deleted_xattr_value(a, "user.4n6.status").as_deref(),
            Some(b"deleted".as_ref())
        );
        // Recovered mtime surfaces as ISO-8601 UTC (mock mtime seconds = 200).
        assert_eq!(
            deleted_xattr_value(a, "user.4n6.macb.modified").as_deref(),
            Some(b"1970-01-01T00:03:20Z".as_ref())
        );
        // True orphan (ino 103) -> status "orphan".
        assert_eq!(
            deleted_xattr_value(by(103), "user.4n6.status").as_deref(),
            Some(b"orphan".as_ref())
        );
        // Unknown attribute -> None (getxattr replies ENODATA).
        assert!(deleted_xattr_value(a, "user.4n6.nope").is_none());
    }

    // -----------------------------------------------------------------------
    // ADR 0008 v2 (d): recovered-deleted entries are COW-writable like live
    // files — a write copies up the recovered bytes, leaving the base untouched.
    // -----------------------------------------------------------------------

    #[test]
    fn deleted_cow_base_yields_recovered_bytes() {
        let fuse = make_mock_fuse_mode(crate::DeletedMode::Latest);
        fuse.ensure_deleted_cache();
        let cache = fuse.deleted_cache.borrow();
        let entries = cache.as_ref().expect("cache populated");

        // A readable in-place delete (ino 100) copies up from its recovered
        // bytes — the write path is not forced read-only.
        let base = deleted_cow_base(entries, 100).expect("readable -> copy-up base");
        assert_eq!(base, vec![0xAB; 100]);

        // An unreadable recovered entry (ino 104, gone.txt) has no base to copy
        // up — the write must fail loud, never fabricate an empty file.
        assert!(deleted_cow_base(entries, 104).is_none());

        // Unknown inode -> no base.
        assert!(deleted_cow_base(entries, 999).is_none());
    }
}
