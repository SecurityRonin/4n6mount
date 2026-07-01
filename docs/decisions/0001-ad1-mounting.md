# 1. AD1 (AccessData logical image) mounting

Date: 2026-07-01
Status: Accepted

## Context

FTK Imager and AccessData tools emit **AD1** logical images — a segmented
(`.ad1`, `.ad2`, …) container holding a **logical file tree**: files, their
metadata (paths, hashes, timestamps), and zlib-compressed content chunks. It is
**not** a disk/sector image. Analysts want to browse an AD1 (often tens of GiB)
interactively without a full extraction step.

4n6mount already mounts disk filesystems, disk containers (EWF/VMDK), and
archives. AD1 differs from all of them on two axes that shape the design:

1. **It opens by path, not by byte stream.** AD1 is segmented, so the reader
   discovers sibling `.ad2…` segments alongside the first file — exactly like
   `ewf::EwfReader::open(&path)`. It cannot be fed a single seekable reader.
2. **It exposes a logical tree, not a disk to re-detect.** So the AD1 backend
   *is* the `ForensicFs`; there is no inner filesystem to mount.

## Decision

1. **Reuse the published `ad1-core` crate** (pure-Rust, lib name `ad1`) rather
   than reimplement the AD1 parser. It provides positioned, lazy reads
   (`read_at` inflates only the overlapping zlib chunks) and is fuzzed upstream.
2. **`Ad1ForensicFs` builds the `ForensicFs` directly from the path** via the
   shared `ArchiveTree` (synthetic inode tree), enumerating entries at open and
   reading bytes lazily on FUSE/Dokan access. It **bypasses
   `build_filesystem`** (the seekable-stream funnel) and is wired as its own
   `match` arm in `main.rs`, beside EWF/VMDK.
3. **No full extraction.** A read of inode `N` resolves the entry and loops
   `read_at`, inflating only the chunks that overlap the requested range — so a
   multi-GiB image is browsed with bounded memory.
4. **Refuse encrypted (ADCRYPT) images loudly** at open (surfaced as
   `FsError::NotSupported`); ciphertext is never mounted as garbage.
5. **`DiskOverlay` layout** (`ro/ rw/ deleted/`), consistent with the archive
   backends — AD1 inherits the browse-and-annotate overlay for free.
6. **Timestamps are epoch in v1.** AD1 stores display strings
   (`"YYYYMMDDThhmmss"`); browsing does not depend on them, so parsing is
   deferred rather than pulling a date-parsing dependency.
7. **`ad1` is a default feature**, so the format is on by default like the other
   built-in backends.

## Consequences

- AD1 joins the mount-smoke matrix as the 14th format, validated end-to-end on
  FUSE (Linux) and Dokan (Windows).
- Correctness is proven at the unit level against an **independent oracle**:
  `ad1-core`'s `testfix` builder (spec-faithful AD1 writer using flate2 zlib +
  RustCrypto hashes) yields byte-identical expected content, asserted by the
  `fs_ad1` tests (tier-2), including a mid-file read across a zlib-chunk
  boundary.
- The AD1 parser itself is fuzzed upstream in `ad1-core`; the 4n6mount wrapper
  adds no new parsing, so a dedicated fuzz target here would be defense-in-depth
  (deferred).
- The fleet now has two AD1 entry points, mirroring its E01/VMDK split: `issen`
  **extracts** AD1 for batch ingestion (`issen-ad1`); 4n6mount **mounts** it
  lazily for interactive browsing.

## Alternatives considered

- **Reimplement the AD1 parser in 4n6mount** — rejected; `ad1-core` exists, is
  pure-Rust and fuzzed, and reinventing an image parser invites the exact
  offset/bit-split bugs the fleet guards against.
- **Fully extract to a temp dir, then mount the extraction** — rejected; defeats
  the point for large images (disk + time) and loses the lazy-read property.
- **Feed AD1 through `build_filesystem`** — rejected; AD1 is a logical tree
  opened by path, not a seekable disk stream, so it does not fit that contract.
- **A dedicated UAC backend** — out of scope; UAC collections are `.tar.gz`,
  already mounted by the tar backend, so a UAC backend would add only cosmetic
  labeling.
