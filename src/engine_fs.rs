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
use std::path::{Path, PathBuf};

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

    /// The mounted filesystem's kind as a short lowercase tag (e.g. `"ntfs"`,
    /// `"fat"`) — used to label a partition in a [`MultiPartitionFs`].
    #[must_use]
    pub fn fs_kind_str(&self) -> &'static str {
        self.fs.kind().as_str()
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

/// Open a disk-image evidence file, surfacing **every** partition as a mountable
/// [`ForensicFs`].
///
/// [`open_image`] mounts only the first filesystem the engine finds; on a Windows
/// GPT disk that is the tiny FAT EFI System Partition, so the NTFS Windows volume
/// is unreachable. This opens all partitions via `Vfs::open_all`:
///
/// * **One** filesystem (a single-partition disk, a bare volume) is returned
///   directly, mounted at the root — behavior and inode scheme identical to
///   [`open_image`], so single-filesystem images are unchanged.
/// * **Several** filesystems are multiplexed under a synthetic root as `p1`,
///   `p2`, … subdirectories (labelled with the filesystem kind, e.g. `p2-ntfs`)
///   by a [`MultiPartitionFs`].
///
/// Transparently peels an OUTER compression wrapper first (as [`open_image`]),
/// keeping the spilled temp image alive for the mount's lifetime.
///
/// # Errors
/// Fails loud on a peel decode error, an engine open/decode error, or when no
/// partition carries a detectable filesystem (`InvalidData`).
pub fn open_image_all(path: &Path) -> io::Result<Box<dyn ForensicFs + Send>> {
    // Peel an outer compression wrapper; the spilled temp file must outlive
    // whatever we return, so it is threaded through to the mounted backend.
    let (image, tmp): (PathBuf, Option<tempfile::TempPath>) = match try_peel_to_tmp(path)? {
        Some(nt) => (nt.path().to_path_buf(), Some(nt.into_temp_path())),
        None => (path.to_path_buf(), None),
    };

    let evidences = Vfs::new()
        .open_all(&image)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut fss: Vec<DynFs> = evidences.into_iter().filter_map(|e| e.fs).collect();

    if fss.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "no filesystem detected in {} (unsupported container/volume/filesystem, or empty image)",
                image.display()
            ),
        ));
    }

    // A single filesystem mounts at the root — unchanged UX for single-fs images.
    if fss.len() == 1 {
        let fs = fss
            .pop()
            .unwrap_or_else(|| unreachable!("len checked == 1"));
        return Ok(Box::new(EngineFs::new(fs, tmp)));
    }

    // Multiple filesystems: multiplex them under a synthetic root as p1..pN.
    let mut parts = Vec::with_capacity(fss.len());
    let mut labels = Vec::with_capacity(fss.len());
    for (i, fs) in fss.into_iter().enumerate() {
        let ef = EngineFs::new(fs, None);
        labels.push(format!("p{}-{}", i + 1, ef.fs_kind_str()).into_bytes());
        parts.push(ef);
    }
    Ok(Box::new(MultiPartitionFs::new(parts, labels, tmp)))
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

/// The synthetic-root inode of a [`MultiPartitionFs`].
const MP_ROOT_INO: u64 = 1;

/// A multiplexer that surfaces each partition of a multi-partition disk image as
/// a `pN` subdirectory under a synthetic root, so an analyst reaches every
/// filesystem (e.g. both the FAT EFI System Partition *and* the NTFS Windows
/// volume of a GPT disk) rather than only the first the engine finds.
///
/// Each partition is a mounted [`EngineFs`]; the multiplexer keeps a dense
/// `(partition, inner inode) -> global inode` map so partition inode spaces stay
/// disjoint. A `partition << 48` bit-pack would be simpler but overflows the FUSE
/// mount layer's `ro_ino` (backend `+ 1000`) / `decode_fuse_ino` namespace
/// `[1000, 10_000_000)`; the dense allocator (the same pattern `EngineFs` uses
/// for `FileId -> u64`) keeps globals small, so the tree flows through the mount
/// exactly like a single filesystem.
pub struct MultiPartitionFs {
    /// One mounted filesystem per surfaced partition, in disk order. Declared
    /// before `_tmp` so its open handles drop before the temp image is unlinked
    /// (correct on Windows).
    parts: Vec<EngineFs>,
    /// The `pN-<kind>` label for each partition (parallel to `parts`).
    labels: Vec<Vec<u8>>,
    /// Dense `(partition, inner inode) -> global inode` and its inverse.
    fwd: HashMap<(usize, u64), u64>,
    rev: HashMap<u64, (usize, u64)>,
    /// Next dense global inode to hand out (starts above the synthetic root).
    next: u64,
    /// A peeled inner image spilled to a temp file, removed when this drops.
    _tmp: Option<tempfile::TempPath>,
}

impl MultiPartitionFs {
    /// Wrap the per-partition filesystems and their labels. `tmp` is the temp
    /// file backing a peeled image, if any — kept alive for the mount's lifetime.
    fn new(parts: Vec<EngineFs>, labels: Vec<Vec<u8>>, tmp: Option<tempfile::TempPath>) -> Self {
        debug_assert_eq!(parts.len(), labels.len());
        Self {
            parts,
            labels,
            fwd: HashMap::new(),
            rev: HashMap::new(),
            next: MP_ROOT_INO + 1,
            _tmp: tmp,
        }
    }

    /// Map a `(partition, inner inode)` pair to a stable dense global inode,
    /// allocating on first sight.
    fn assign(&mut self, part: usize, inner: u64) -> u64 {
        if let Some(&global) = self.fwd.get(&(part, inner)) {
            return global;
        }
        let global = self.next;
        self.next += 1;
        self.fwd.insert((part, inner), global);
        self.rev.insert(global, (part, inner));
        global
    }

    /// Resolve a global inode back to its `(partition, inner inode)`, loud on miss.
    fn resolve(&self, ino: u64) -> FsResult<(usize, u64)> {
        self.rev
            .get(&ino)
            .copied()
            .ok_or_else(|| FsError::NotFound(format!("unknown inode {ino}")))
    }

    /// Resolve a non-root inode for a byte-producing op, rejecting the synthetic
    /// root (it is a directory, not a file).
    fn dispatch_file(&self, ino: u64) -> FsResult<(usize, u64)> {
        if ino == MP_ROOT_INO {
            return Err(FsError::Other(
                "the multi-partition root is a directory, not a file".to_string(),
            ));
        }
        self.resolve(ino)
    }
}

/// Metadata for the synthetic multi-partition root: a read-only directory.
fn synthetic_root_metadata() -> FsMetadata {
    FsMetadata {
        ino: MP_ROOT_INO,
        file_type: FsFileType::Directory,
        mode: 0o040_555,
        uid: 0,
        gid: 0,
        size: 0,
        links_count: 2,
        atime: FsTimestamp::default(),
        mtime: FsTimestamp::default(),
        ctime: FsTimestamp::default(),
        crtime: FsTimestamp::default(),
        allocated: true,
    }
}

impl ForensicFs for MultiPartitionFs {
    fn root_ino(&self) -> u64 {
        MP_ROOT_INO
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        if ino == MP_ROOT_INO {
            let mut out = Vec::with_capacity(self.parts.len());
            for idx in 0..self.parts.len() {
                let inner_root = self.parts[idx].root_ino();
                let inode = self.assign(idx, inner_root);
                out.push(FsDirEntry {
                    inode,
                    name: self.labels[idx].clone(),
                    file_type: FsFileType::Directory,
                });
            }
            return Ok(out);
        }
        let (part, inner) = self.resolve(ino)?;
        let entries = self.parts[part].read_dir(inner)?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let inode = self.assign(part, e.inode);
            out.push(FsDirEntry {
                inode,
                name: e.name,
                file_type: e.file_type,
            });
        }
        Ok(out)
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        if parent_ino == MP_ROOT_INO {
            if name == b"." || name == b".." {
                return Ok(Some(MP_ROOT_INO));
            }
            for idx in 0..self.parts.len() {
                if self.labels[idx].as_slice() == name {
                    let inner_root = self.parts[idx].root_ino();
                    return Ok(Some(self.assign(idx, inner_root)));
                }
            }
            return Ok(None);
        }
        let (part, inner) = self.resolve(parent_ino)?;
        match self.parts[part].lookup(inner, name)? {
            Some(child) => Ok(Some(self.assign(part, child))),
            None => Ok(None),
        }
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        if ino == MP_ROOT_INO {
            return Ok(synthetic_root_metadata());
        }
        let (part, inner) = self.resolve(ino)?;
        let mut meta = self.parts[part].metadata(inner)?;
        // Re-stamp the metadata's inode with the global one the caller passed.
        meta.ino = ino;
        Ok(meta)
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let (part, inner) = self.dispatch_file(ino)?;
        self.parts[part].read_file(inner)
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let (part, inner) = self.dispatch_file(ino)?;
        self.parts[part].read_file_range(inner, offset, len)
    }

    fn read_link(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let (part, inner) = self.dispatch_file(ino)?;
        self.parts[part].read_link(inner)
    }

    fn block_size(&self) -> u64 {
        self.parts.first().map_or(4096, ForensicFs::block_size)
    }
}

#[cfg(test)]
mod layout_tests {
    //! ADR-0010 unified `<volume>/` naming: the precedence
    //! (label → `_partition<index+1>` → `root`) and the reversible
    //! percent-sanitization, proven directly against the pure helpers so the
    //! label HOOK is exercised even though no leaf label accessor is wired yet.
    use super::{sanitize_volume_label, volume_dir_name};
    use std::collections::HashSet;

    #[test]
    fn label_kept_verbatim_including_spaces_and_unicode() {
        let used = HashSet::new();
        assert_eq!(
            volume_dir_name(Some(0), Some("System Reserved".to_string()), &used),
            "System Reserved",
            "a label keeps its spaces/case verbatim (ADR-0010)"
        );
        assert_eq!(
            sanitize_volume_label("Café"),
            "Café",
            "Unicode is kept verbatim"
        );
    }

    #[test]
    fn label_slash_is_percent_encoded() {
        let used = HashSet::new();
        assert_eq!(
            volume_dir_name(Some(1), Some("a/b".to_string()), &used),
            "a%2Fb",
            "`/` is reversibly percent-encoded so it cannot split the path"
        );
    }

    #[test]
    fn no_label_with_volume_layer_is_partition_index_plus_one() {
        let used = HashSet::new();
        assert_eq!(volume_dir_name(Some(0), None, &used), "_partition1");
        assert_eq!(volume_dir_name(Some(2), None, &used), "_partition3");
    }

    #[test]
    fn no_label_no_volume_layer_is_root() {
        let used = HashSet::new();
        assert_eq!(
            volume_dir_name(None, None, &used),
            "root",
            "a bare unpartitioned filesystem renders as a single `root` volume"
        );
    }

    #[test]
    fn empty_or_colliding_label_falls_back_to_partition() {
        let mut used = HashSet::new();
        assert_eq!(
            volume_dir_name(Some(0), Some(String::new()), &used),
            "_partition1",
            "an empty sanitized label falls back to the partition index"
        );
        used.insert("dup".to_string());
        assert_eq!(
            volume_dir_name(Some(1), Some("dup".to_string()), &used),
            "_partition2",
            "a colliding label falls back to the partition index"
        );
    }

    #[test]
    fn sanitize_encodes_control_bidi_and_percent_reversibly() {
        assert_eq!(
            sanitize_volume_label("x\ty"),
            "x%09y",
            "TAB control encoded"
        );
        assert_eq!(
            sanitize_volume_label("a\u{202E}b"),
            "a%E2%80%AEb",
            "the RIGHT-TO-LEFT OVERRIDE bidi char is encoded to its UTF-8 bytes"
        );
        assert_eq!(
            sanitize_volume_label("50%"),
            "50%25",
            "`%` is escaped for reversibility"
        );
        assert_eq!(sanitize_volume_label("NUL\0x"), "NUL%00x", "NUL encoded");
    }
}
