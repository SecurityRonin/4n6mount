# 6. Adopt `forensic-vfs-mount` on forensic-vfs 0.4; `EngineFs` hollows to a delegating adapter

Date: 2026-07-19
Status: Proposed (design accepted for review — not yet implemented)

## Context

`src/engine_fs.rs` bridges the forensic-vfs engine (`FileId`-addressed, streaming
`FileSystem` contract) into 4n6mount's own u64-inode `ForensicFs` trait. To do it, it
hand-rolls a bidirectional `FileId ↔ u64` dense interning allocator (`fwd`/`rev`
HashMaps + `next` counter) and whole-file read plumbing.

The published **`forensic-vfs-mount`** crate exists for exactly this job: its
`MountFs` wraps any `Arc<dyn FileSystem>` in the stable-inode, whole-file-read
surface a FUSE/Dokan handler wants — intern-on-first-sight `u64 ↔ FileId` mapping
(root pinned to ino 1), a short-read-safe `read` loop whose allocation is capped at
the file's own `meta().size`, POSIX-shaped guards (EISDIR on directory reads, a
symlink-length cap), loud unknown-inode errors, and poison-recovering locking.
`EngineFs` duplicates all of that, less carefully (e.g. no allocation cap on its read
path beyond what the engine provides).

Version skew compounds the duplication (verified 2026-07-19):

| Crate | Pin today | Current |
|---|---|---|
| 4n6mount → `forensic-vfs` | `"0.3"` | 0.4.2 |
| 4n6mount → `forensic-vfs-engine` | `{ version = "0.1", path = … }` | 0.1.4 (local) |
| `forensic-vfs-mount` → `forensic-vfs` | `{ version = "0.1", path = … }` | 0.4.2 |

`forensic-vfs-mount`'s own docs note the trap this invites: two resolutions of the
contract crate compile a second, incompatible `DynFs`/`FileId`. Everything must
converge on one registry version of forensic-vfs 0.4.

What `EngineFs` has that `MountFs` does not — and must keep:

- **`open_image`**: the archive-peel front door (`evidence.dd.gz` → dd via
  archive-core) feeding the engine's partition-aware `Vfs::open()`.
- **`_tmp: Option<tempfile::TempPath>`**: the peeled-image lifetime pin, with field
  order guaranteeing the fs handle drops before the temp file is unlinked (correct on
  Windows).
- **Forensic extras**: `fs_info()` (fs kind, `sector_sizes()`, `timestamp_zone()`),
  the reader's `findings()` passthrough, and the `ENUM_CAP` bomb-guard pattern for
  any enumeration surfaced to a mount cache.

## Decision

1. **`EngineFs` delegates navigation and reads to `MountFs`.** The `fwd`/`rev`/`next`
   allocator and the read loop are deleted; `EngineFs` becomes: `open_image` (peel +
   engine open + `_tmp` lifetime) constructing a `MountFs`, plus the forensic extras
   above. Its `ForensicFs` methods forward to `MountFs::{read_dir, lookup, meta,
   read, read_link}` and map `FsMeta` → `FsMetadata` at the boundary.
2. **The COW layer (ADR 0005) lands in `forensic-vfs-mount` as a `cow` module**, not
   a sibling crate. Mount surface and COW-over-mount-surface are one concern with one
   consumer shape; a sibling `forensic-vfs-mount-cow` would split a small API across
   two crates and force lock-step publishes for no isolation benefit. (Revisit only
   if a consumer materializes that wants the read adapter but must not compile the
   overlay code — none exists.) `forensic-vfs-mount` bumps to **0.2**: dep
   `forensic-vfs = "0.4"`, new `cow` module, publish.
3. **4n6mount converges its pins**: `forensic-vfs = "0.4"`,
   `forensic-vfs-mount = "0.2"`, and `forensic-vfs-engine` at its current registry
   version once published (the fleet rule: registry over path once a crate is on
   crates.io).
4. **The `ForensicFs` trait slims to what is real.** Dropped:
   `deleted_inodes`/`recover_file`/`unallocated_blocks`/`read_unallocated`
   and the silently-empty `Ok(vec![])` defaults that made hollow backends
   look populated (the in-place/`$Orphans/` rendering of ADR 0008 replaces the
   deleted-file surface once the contract delivers readable deleted entries). Kept: the core navigation ops and `fs_info`. Changed: the trait
   goes `&self` (interior mutability), matching `MountFs`/`CowFs` and Dokan's
   multithreaded dispatch. `timeline`/`journal` move behind the lazy-artifact
   surface of ADR 0007 and error `Unsupported` by default — never empty-on-error.

## Consequences

- One audited implementation of inode interning and bounded reads serves the whole
  fleet; 4n6mount inherits the allocation cap, EISDIR/symlink guards, and
  poison-safe locking it currently lacks.
- The memory backend (ADR 0003) implements the slimmed `ForensicFs` unchanged in
  spirit — it was already read-only and nav-only.
- The engine's own `FileId` intern inside `EngineFs` disappears, so there is exactly
  one inode authority per mount (`MountFs`), which ADR 0005's overlay extends —
  removing the class of bugs where two allocators disagree.
- Publishing order matters: forensicnomicon-core (`FileId` serde, if needed) →
  forensic-vfs-mount 0.2 → 4n6mount. This rides the in-flight 0.4 fleet publish
  wave.

## Residuals / open questions

- **`forensic-vfs-engine` publish state**: 4n6mount still path-deps the engine; the
  convergence step assumes the engine's 0.4-compatible version reaches crates.io
  (tracked in the fleet publish task, not here).
- **`findings()` surfacing**: the reader's `findings()` (forensicnomicon report
  vocabulary) currently has no mount-side rendering; a
  `metadata/findings.json` is a natural future artifact but is out of scope here
  (would follow the ADR 0007 lazy pattern).
- **`ENUM_CAP`**: the enumerations that remain (directory listing, timeline walk,
  the deleted-entry merge and `$Orphans/` listing of ADR 0008) still need
  bomb-guards; the cap moves with the code that streams into caches (ADR 0007's
  materializers and ADR 0008's merge).
