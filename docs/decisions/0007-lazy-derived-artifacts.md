# 7. `$Journal/` and `$Metadata/timeline.jsonl` materialize lazily, on first read

Date: 2026-07-19
Status: Proposed (design accepted for review — not yet implemented)

## Context

Two mount surfaces are *derived artifacts*, not views of existing bytes:

- **`$Journal/`** — decoded filesystem-journal transactions. Real cost: parse NTFS
  `$LogFile` (and, a distinct source, `$UsnJrnl`) or ext4 jbd2 and render typed
  transaction records.
- **`$Metadata/timeline.jsonl`** — a super-timeline of per-file MACB events (plus
  journal events where available), one JSON object per line.

The shipped code already computes them on first *directory access* (the
`ensure_journal_cache`/`ensure_metadata_cache` lazy `RefCell` caches in
`src/fusefs.rs`), but with three defects:

1. **Errors are silently flattened**: `journal_transactions()` errors become an empty
   listing (`Err(_) => Vec::new()`, `fusefs.rs:208`); `timeline()` errors become an
   empty `timeline.jsonl`; `fs_info()` errors become `{}`. Since the engine adapter
   currently returns loud `NotSupported` for journal and timeline, **the shipped
   `$Journal/` is always empty and `timeline.jsonl` is always zero bytes** — rendered
   exactly like a filesystem with no journal and no files, the fail-loud violation.
2. **Results are RAM-buffered** (`Vec<u8>` per artifact), unbounded by design.
3. **The contract cannot feed them**: the forensic-vfs 0.4 `FileSystem` trait has no
   journal surface at all, and while `meta()` exposes `MacbTimes` (so a MACB timeline
   is derivable), the only enumeration is a recursive `read_dir` walk.

## Decision

1. **Lazy, single-flight, per-artifact materialization.** Listing `$Journal/` or
   `$Metadata/` is free (names only). The first `getattr`/`open` of an artifact file
   triggers its materializer, guarded so concurrent readers block on one computation
   (session-scoped once-cell per artifact). Subsequent reads serve the cache.
2. **Spill to disk, not RAM.** Materialized artifacts are written to the overlay
   scratch area (`<session>/derived/` when `--session`, the ephemeral scratch
   otherwise), then served by positioned reads. With `--session`, derived artifacts
   persist across mounts; the cache key is the image SHA-256 already recorded in
   `session.json`, so a rebuilt session never serves another image's timeline.
3. **Fail loud, gate on capability.** A materializer error fails the `open` with
   `EIO` and records the reason; it never produces an empty artifact.
   `metadata/capabilities.json` (cheap, computed at mount from the reader's
   capability surface) states which artifacts this filesystem/reader supports and why
   absent ones are absent. `$Journal/` **appears only when the reader reports journal
   support**; an empty-but-present artifact means a *successful* decode that found
   zero records — absence and emptiness are never conflated.
4. **The timeline describes the EVIDENCE, never the overlay.** ADR 0004's writable
   view must not leak into the forensic record: materializers run against the read
   surface below the COW layer. (A view-diff already exists — the session manifest.)
5. **Contract additions flagged for forensic-vfs 0.4.x** (both default-`Unsupported`,
   additive, non-breaking):
   - `fn journal(&self) -> VfsResult<JournalStream>` — a typed stream of journal
     transaction records (sequence, timestamp, operation, affected `FileId`/name
     where recoverable). NTFS `$LogFile` and `$UsnJrnl` are distinct sources and the
     record type must say which; ext4 is jbd2.
   - `fn nodes(&self) -> VfsResult<NodeStream>` — bulk enumeration of all live nodes,
     so the timeline can linear-scan an MFT/inode table instead of a recursive
     `read_dir` walk. Optional optimization: a MACB timeline is *derivable today*
     from walk + `meta().times` (`MacbTimes` is already in `FsMeta`) and v2 ships
     that first; `$Journal/` genuinely blocks on the `journal()` accessor.

## Consequences

- Mount time stays O(open image); the cost of a timeline is paid exactly once, by
  the analyst who asks for it. Piping (`head`, `grep`) works against a disk-backed
  JSONL file instead of a RAM buffer.
- `ls metadata/` is instant; `ls -l metadata/` (stat) triggers materialization to
  report a true size. This surprise is documented in the README and softened by the
  banner. The rejected alternative — reporting size 0 until first open — breaks
  `cp`/tools that pre-allocate from stat, a worse lie.
- Until `journal()` ships in forensic-vfs, disk mounts carry **no `$Journal/`
  directory** and `capabilities.json` says why — versus today's always-empty one.
  This is the honest regression-shaped change: less advertised surface, zero lies.
- `timeline.jsonl` stays machine-faithful (JSONL, verbatim values, no truncation),
  per the human-vs-machine output discipline.

## Residuals / open questions

- **Materialization progress**: a multi-minute timeline build behind a blocking
  `open` gives no feedback. Options (status file in `$Metadata/`, log line, partial
  streaming) are implementation detail; v2 minimally logs start/finish to stderr.
- **Bomb-guards**: the walk and journal decode need the `ENUM_CAP`-style caps from
  ADR 0006, plus a disk-space cap for the spill (fail loud when exceeded, stating
  the cap and count reached).
- **Timeline schema**: today's line shape (`timestamp_secs`/`event_type`/`inode`/…)
  predates the MACB derivation; the v2 schema (one line per event with M/A/C/B
  flags, `FileId`, path, source = macb|journal) needs a short spec before
  implementation — it is a published machine contract once shipped.
- **`superblock.json`** stays eager (it is one `fs_info()` call — cheap), but its
  error path changes from `{}` to a loud open error, same rule as the lazy
  artifacts.
