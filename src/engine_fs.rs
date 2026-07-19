#![forbid(unsafe_code)]

//! The disk-image [`ForensicFs`] backend: an adapter over the `forensic-vfs`
//! engine's read-only [`FileSystem`] contract.
//!
//! The FUSE/Dokan mount layer speaks 4n6mount's own `u64`-inode
//! [`ForensicFs`](crate::ForensicFs) vocabulary; the engine speaks
//! `forensic_vfs::FileId` (a per-filesystem identity *enum*) and streams owned
//! iterators. [`EngineFs`] bridges the two: it keeps a bidirectional
//! `FileId <-> u64` map (a dense allocator, so the huge inode space collapses to
//! small FUSE inodes) and converts [`FsMeta`](forensic_vfs::FsMeta) into the
//! mount layer's [`FsMetadata`](crate::FsMetadata).
//!
//! Some forensic surfaces of the old backends have **no** equivalent on the
//! engine's inode-addressed `FileSystem` trait — deleted-file *recovery*,
//! event *timelines*, and journal *transactions*. Those degrade loud (an
//! explicit `NotSupported` error, never a fabricated success); see each gate's
//! `TODO(engine)`.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use forensic_vfs::{
    Allocation, DynFs, FileId, MacbTimes, NodeKind, StreamId, TimeStamp, TimeZonePolicy, VfsError,
};
use forensic_vfs_engine::Vfs;

use crate::{
    not_supported, ForensicFs, FsAllocation, FsBlockRange, FsDeletedInode, FsDeletedNode,
    FsDirEntry, FsError, FsFileType, FsMetadata, FsRecoveryResult, FsResult, FsTimelineEvent,
    FsTimestamp, FsTransaction,
};

/// Cap on deleted/unallocated enumeration — a bomb guard against a hostile
/// filesystem streaming an unbounded node/run list into a mount cache.
const ENUM_CAP: usize = 100_000;

/// A disk-image filesystem mounted through the engine.
///
/// `_tmp` keeps a peeled-and-spilled inner image (e.g. from `evidence.dd.gz`)
/// alive for exactly the mount's lifetime: `fs` is declared first so its open
/// file handle drops *before* the temp file is unlinked (correct on Windows).
pub struct EngineFs {
    fs: DynFs,
    /// `FileId -> FUSE inode` and its inverse, plus the next dense id.
    fwd: HashMap<FileId, u64>,
    rev: HashMap<u64, FileId>,
    next: u64,
    root_u64: u64,
    /// A peeled inner image spilled to a temp file, removed when this drops.
    _tmp: Option<tempfile::TempPath>,
}

impl EngineFs {
    /// Wrap a mounted engine filesystem. `tmp` is the temp file backing a peeled
    /// image, if any — kept alive (and auto-removed) for the mount's lifetime.
    fn new(fs: DynFs, tmp: Option<tempfile::TempPath>) -> Self {
        let root = fs.root();
        let mut this = Self {
            fs,
            fwd: HashMap::new(),
            rev: HashMap::new(),
            // Start above the reserved virtual inodes (1..=9 in `inode_map`); the
            // encoded `ro_ino`/`rw_ino` then never collide with them.
            next: 10,
            root_u64: 0,
            _tmp: tmp,
        };
        this.root_u64 = this.assign(root);
        this
    }

    /// Map a `FileId` to a stable dense FUSE inode, allocating on first sight.
    fn assign(&mut self, id: FileId) -> u64 {
        if let Some(&ino) = self.fwd.get(&id) {
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.fwd.insert(id, ino);
        self.rev.insert(ino, id);
        ino
    }

    /// Resolve a FUSE inode back to its `FileId`, or a loud not-found.
    fn file_id(&self, ino: u64) -> FsResult<FileId> {
        self.rev
            .get(&ino)
            .copied()
            .ok_or_else(|| FsError::NotFound(format!("unknown inode {ino}")))
    }
}

/// Map a `forensic-vfs` error into the mount layer's error, preserving the text.
fn vfs_err(e: VfsError) -> FsError {
    FsError::Other(e.to_string())
}

/// Map the engine's node kind to the mount layer's file type.
fn node_kind(k: NodeKind) -> FsFileType {
    match k {
        NodeKind::File => FsFileType::RegularFile,
        NodeKind::Dir => FsFileType::Directory,
        NodeKind::Symlink => FsFileType::Symlink,
        NodeKind::Device => FsFileType::CharDevice,
        // `NodeKind::Other` plus any future `#[non_exhaustive]` variant map to
        // Unknown rather than fabricating a specific type.
        _ => FsFileType::Unknown,
    }
}

/// Convert an engine timestamp (nanoseconds since the Unix epoch) into the
/// seconds/nanoseconds split the mount layer uses. `None` becomes the zero time.
fn ts(t: Option<TimeStamp>) -> FsTimestamp {
    match t {
        Some(t) => FsTimestamp {
            seconds: (t.unix_nanos.div_euclid(1_000_000_000)) as i64,
            nanoseconds: (t.unix_nanos.rem_euclid(1_000_000_000)) as u32,
        },
        None => FsTimestamp::default(),
    }
}

/// Assemble the mount layer's metadata from an engine `FsMeta`.
fn to_metadata(ino: u64, meta: &forensic_vfs::FsMeta, times: &MacbTimes) -> FsMetadata {
    let file_type = node_kind(meta.kind);
    // The engine exposes a Unix mode only where the filesystem records one
    // (ext/APFS); NTFS/FAT return `None`, so synthesize a sensible default that
    // still carries the type bits `fs_to_attr` masks for `perm`.
    let mode = meta.mode.map_or_else(
        || match file_type {
            FsFileType::Directory => 0o040_755,
            FsFileType::Symlink => 0o120_777,
            _ => 0o100_644,
        },
        |m| (m & 0xFFFF) as u16,
    );
    FsMetadata {
        ino,
        file_type,
        mode,
        uid: meta.uid.unwrap_or(0),
        gid: meta.gid.unwrap_or(0),
        size: meta.size,
        links_count: meta.nlink.min(u32::from(u16::MAX)) as u16,
        atime: ts(times.accessed),
        mtime: ts(times.modified),
        ctime: ts(times.changed),
        crtime: ts(times.born),
        allocated: matches!(meta.allocated, Allocation::Allocated),
    }
}

impl ForensicFs for EngineFs {
    fn root_ino(&self) -> u64 {
        self.root_u64
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let id = self.file_id(ino)?;
        let stream = self.fs.read_dir(id).map_err(vfs_err)?;
        let mut out = Vec::new();
        for entry in stream {
            let entry = entry.map_err(vfs_err)?;
            let child = self.assign(entry.id);
            out.push(FsDirEntry {
                inode: child,
                name: entry.name,
                file_type: node_kind(entry.kind),
            });
        }
        Ok(out)
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        let parent = self.file_id(parent_ino)?;
        match self.fs.lookup(parent, name).map_err(vfs_err)? {
            Some(id) => Ok(Some(self.assign(id))),
            None => Ok(None),
        }
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let id = self.file_id(ino)?;
        let meta = self.fs.meta(id).map_err(vfs_err)?;
        Ok(to_metadata(ino, &meta, &meta.times))
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let id = self.file_id(ino)?;
        let size = self.fs.meta(id).map_err(vfs_err)?.size;
        self.read_file_range(ino, 0, size)
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let id = self.file_id(ino)?;
        let mut buf = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = self
                .fs
                .read_at(
                    id,
                    StreamId::Default,
                    offset + filled as u64,
                    &mut buf[filled..],
                )
                .map_err(vfs_err)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        Ok(buf)
    }

    fn read_link(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let id = self.file_id(ino)?;
        self.fs.read_link(id, 4096).map_err(vfs_err)
    }

    fn deleted_inodes(&mut self) -> FsResult<Vec<FsDeletedInode>> {
        let stream = self.fs.deleted().map_err(vfs_err)?;
        let mut out = Vec::new();
        for meta in stream.take(ENUM_CAP) {
            let meta = meta.map_err(vfs_err)?;
            out.push(FsDeletedInode {
                ino: meta.ino,
                file_type: node_kind(meta.kind),
                size: meta.size,
                dtime: 0,
                recoverability: 0.0,
            });
        }
        Ok(out)
    }

    fn deleted_nodes(&mut self) -> FsResult<Vec<FsDeletedNode>> {
        // The engine's rich deleted surface: each node carries a readable
        // `FileId` (→ a dense FUSE inode here, usable with `read_file`), the
        // recovered name, and the parent `FileId` (→ inode), so the mount can
        // place it in-place or route it to `$Orphans`. Bomb-guarded by
        // `ENUM_CAP`. The stream is owned, so allocating inodes as we go is safe.
        let stream = self.fs.deleted_nodes().map_err(vfs_err)?;
        let mut out = Vec::new();
        for node in stream.take(ENUM_CAP) {
            let node = node.map_err(vfs_err)?;
            let ino = self.assign(node.id);
            let parent_ino = node.parent.map(|p| self.assign(p));
            let meta = &node.meta;
            let allocation = match meta.allocated {
                Allocation::Orphan => FsAllocation::Orphan,
                // `Deleted` and any future/`Allocated` variant render as a
                // deleted record (a recovered node is unlinked by definition).
                _ => FsAllocation::Deleted,
            };
            out.push(FsDeletedNode {
                ino,
                name: node.name.clone(),
                parent_ino,
                size: meta.size,
                file_type: node_kind(meta.kind),
                allocation,
                record_id: meta.ino,
                atime: ts(meta.times.accessed),
                mtime: ts(meta.times.modified),
                ctime: ts(meta.times.changed),
                crtime: ts(meta.times.born),
            });
        }
        Ok(out)
    }

    fn recover_file(&mut self, ino: u64) -> FsResult<FsRecoveryResult> {
        // TODO(engine): re-wire when FileSystem exposes recovery. `deleted()`
        // yields metadata for deleted nodes but no `FileId` to read their bytes,
        // so recovery has no home on the current trait — degrade loud.
        let _ = ino;
        Err(not_supported(
            "recover_file (the forensic-vfs FileSystem trait has no deleted-content read path)",
        ))
    }

    fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> {
        // TODO(engine): re-wire when FileSystem exposes a timeline surface.
        Err(not_supported(
            "timeline (the forensic-vfs FileSystem trait has no event-timeline surface)",
        ))
    }

    fn unallocated_blocks(&mut self) -> FsResult<Vec<FsBlockRange>> {
        let bs = self.block_size().max(1);
        let stream = self.fs.unallocated().map_err(vfs_err)?;
        let mut out = Vec::new();
        for run in stream.take(ENUM_CAP) {
            let run = run.map_err(vfs_err)?;
            out.push(FsBlockRange {
                start: run.run.image_offset,
                // Report the length in blocks so the FUSE size (length * block
                // size) reflects the real byte extent.
                length: (run.run.len / bs).max(1),
            });
        }
        Ok(out)
    }

    fn read_unallocated(&mut self, _range: &FsBlockRange) -> FsResult<Vec<u8>> {
        // TODO(engine): re-wire when FileSystem (or the engine) exposes a raw
        // image byte-reader. The inode-addressed trait cannot read an arbitrary
        // image offset, so the unallocated *ranges* are listable but their bytes
        // are not readable through it — degrade loud rather than fabricate.
        Err(not_supported(
            "read_unallocated (the forensic-vfs FileSystem trait has no raw-image byte reader)",
        ))
    }

    fn journal_transactions(&mut self) -> FsResult<Vec<FsTransaction>> {
        // TODO(engine): re-wire when FileSystem exposes journal transactions.
        Err(not_supported(
            "journal_transactions (the forensic-vfs FileSystem trait has no journal surface)",
        ))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        let sizes = self.fs.sector_sizes();
        let zone = match self.fs.timestamp_zone() {
            TimeZonePolicy::Utc => "utc".to_string(),
            TimeZonePolicy::LocalUnknown => "local-unknown".to_string(),
            TimeZonePolicy::Local { minutes_east } => format!("local+{minutes_east}m"),
            _ => "unknown".to_string(),
        };
        Ok(serde_json::json!({
            "filesystem": self.fs.kind().as_str(),
            "logical_sector_size": sizes.logical,
            "physical_sector_size": sizes.physical,
            "cluster_or_block_size": sizes.cluster_or_block,
            "timestamp_zone": zone,
        }))
    }

    fn block_size(&self) -> u64 {
        let bs = self.fs.sector_sizes().cluster_or_block;
        if bs == 0 {
            4096
        } else {
            u64::from(bs)
        }
    }
}

/// Open a disk-image evidence file as a mountable [`ForensicFs`].
///
/// Transparently peels an OUTER compression wrapper (`evidence.dd.gz` -> `dd`)
/// via `archive-core` — but only when the content magic AND the file extension
/// agree, so a raw disk with coincidental magic still opens as raw — then hands
/// the (inner or original) image to the engine's partition-aware `Vfs::open`.
///
/// # Errors
/// Fails loud on a peel decode error, an engine open/decode error, or when the
/// engine detects no filesystem in the evidence (`InvalidData`).
pub fn open_image(path: &Path) -> io::Result<Box<dyn ForensicFs + Send>> {
    if let Some(tmp) = try_peel_to_tmp(path)? {
        let fs = mount_engine(tmp.path())?;
        return Ok(Box::new(EngineFs::new(fs, Some(tmp.into_temp_path()))));
    }
    let fs = mount_engine(path)?;
    Ok(Box::new(EngineFs::new(fs, None)))
}

/// Attempt to peel one outer compression wrapper, spilling the inner image to a
/// temp file. Returns `None` when `path` is not a compression wrapper (so the
/// caller opens it directly), and an error only when a genuinely-named wrapper
/// fails to decode. Mirrors `disk_forensic::container::try_peel`.
fn try_peel_to_tmp(path: &Path) -> io::Result<Option<tempfile::NamedTempFile>> {
    use std::io::{Read, Write};

    let name = path.file_name().and_then(|n| n.to_str());
    // Sniff the head only — never slurp a large non-wrapper image. Only
    // compression wrappers are peeled here; the sniff/decode/guard policy (incl.
    // the coincidental-magic guard) lives once in archive_core::peel_archive.
    let mut head = [0u8; 16];
    let read = {
        let mut file = std::fs::File::open(path)?;
        file.read(&mut head)?
    };
    if !archive_core::sniff(name, &head[..read]).is_compression_wrapper() {
        return Ok(None);
    }
    let data = std::fs::read(path)?;
    match archive_core::peel_archive(&data, name, &archive_core::Limits::default()) {
        Ok(archive_core::Peel::Inner(inner)) => {
            let mut tmp = tempfile::Builder::new().suffix(".img").tempfile()?;
            tmp.write_all(&inner)?;
            tmp.flush()?;
            Ok(Some(tmp))
        }
        Ok(archive_core::Peel::NotPacked) => Ok(None),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("archive peel failed: {e}"),
        )),
    }
}

/// Run the engine's partition-aware open on `path` and require a filesystem.
fn mount_engine(path: &Path) -> io::Result<DynFs> {
    let evidence = Vfs::new()
        .open(path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    evidence.fs.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "no filesystem detected in {} (unsupported container/volume/filesystem, or empty image)",
                path.display()
            ),
        )
    })
}
