# 5. Platform-agnostic COW overlay keyed by `FileId`; Dokan becomes writable

Date: 2026-07-19
Status: Proposed (design accepted for review — not yet implemented)

## Context

COW today is welded to the Unix FUSE handler: copy-up, whiteouts, and overlay
bookkeeping live in `#[cfg(unix)]` `src/fusefs.rs` (~2k lines) against
`src/session.rs`. The Windows backend (`src/fuse_windows.rs`) mounts Dokan with
`MountFlags::WRITE_PROTECT` and ignores its `session` parameter — Windows analysts
get a read-only raw tree and no ADR-0004 semantics at all.

Three structural problems block a shared implementation:

1. **The overlay key is unstable.** A modified file is recorded as
   `overlay.modified: HashMap<u64, String>` mapping the backend inode to overlay id
   `ino_{fs_ino}` (`fusefs.rs::modified_overlay_id`). But `EngineFs` mints those
   `u64`s from a dense first-seen interning allocator (`next` counter starting at 10),
   so a file's number depends on **browse order**. Resume a session, browse in a
   different order, and an overlay blob can attach to the *wrong file*. (The scheme
   was harmless when the ext4 backend exposed real, stable ext4 inode numbers; the
   engine adapter broke its assumption.)
2. **Created files ride a magic-number hack**: overlay-created nodes are encoded as
   `rw_id >= 9_000_000` with `new_{counter}` ids, on top of arithmetic inode-offset
   namespaces (`+1_000` ro, `+10_000_000` rw, `+20M`…`+60M` for the virtual dirs) that
   only work while real inodes stay small.
3. **The two shells speak different shapes**: FUSE is inode-addressed; Dokan is
   path-addressed (it already resolves `\dir\file` to an inode by walking `lookup`
   from the root). Any shared write layer must serve both.

The user asked specifically whether WinFsp's FUSE compatibility could let Windows
reuse the one Unix handler.

## Decision

### (a) Overlay key = the contract's `FileId`

The persisted overlay key becomes the serialized **`forensic_vfs::FileId`** — the
opaque per-filesystem node identity the contract guarantees stable for the life of
the filesystem (forensic-vfs ADR 0002; relocated to `forensicnomicon-core` by
forensic-vfs ADR 0009). Each manifest entry also records the **path at first write**
as a human-readable annotation, so the session manifest doubles as an examiner-facing
audit trail.

Rejected alternatives:

- **The dense `u64` inode (status quo)** — session-local by construction; the resume
  bug above.
- **Canonical path** — Dokan-convenient and human-readable, but identity-wrong:
  hardlinks give one node several paths; byte-exact names need normalization policy
  (case, encoding); and a rename would orphan the key. `FileId` *is* the identity the
  stack already promises; the path rides along as annotation, not as key.

In memory, the hot map is keyed by the interned `u64` for speed; the `FileId` key is
what crosses mounts.

### (b) One platform-agnostic `CowFs` layer

A new **`CowFs`** composes the overlay **over** the read surface
(`forensic-vfs-mount::MountFs`, ADR 0006) and exposes the u64-inode vocabulary both
shells consume:

- reads: `read_dir` (overlay-merged: created entries added, whiteouts removed),
  `lookup`, `meta` (overlay size/times win for modified nodes), `read`
  (overlay-file first, else pass-through), `read_link`;
- writes: `write`, `truncate`/`setattr` (size + timestamps subset), `create`,
  `mkdir`, `unlink`, `rmdir`, `rename` — each mutating only overlay state, with
  whole-file copy-up on first modification (today's model, kept for v2).

Overlay-created nodes are interned into the **same allocator** as real nodes (the
`MountFs` interning table extended with synthetic overlay ids), which retires the
`>= 9_000_000` hack and the arithmetic offset namespaces: virtual directories keep a
small reserved inode range (as today, `1..=9`), and everything else — real, modified,
or created — draws from one dense space. `CowFs` is `&self` with interior mutability
(mutex over overlay state), because Dokan drives handlers from multiple threads.

Both platform shells become Humble Objects over `CowFs`: the FUSE shell translates
inode calls 1:1; the Dokan shell keeps its existing path→inode walk and adds the
write callbacks.

### (c) Windows backend: extend Dokan to writable COW (WinFsp rejected)

**Keep Dokan; drop `WRITE_PROTECT` when COW is active** (retain it for
`--read-only`), and implement the mutating `FileSystemHandler` callbacks —
`write_file`, `set_end_of_file`, `set_allocation_size`, create dispositions in
`create_file`, `delete_file`/`delete_directory`, `move_file`,
`set_file_time`/`set_file_attributes` — as thin delegations to `CowFs`.

WinFsp was weighed and rejected:

- **"FUSE-compatible" does not reach our handler.** WinFsp is API-compatible with
  FUSE at the **libfuse C API** level (its `fuse.h` compatibility layer). Our Unix
  handler is built on `fuser`, which speaks the **kernel FUSE wire protocol** over
  `/dev/fuse` directly — it never touches libfuse, so it cannot run on WinFsp's
  compatibility layer. "Reuse the one Unix handler" would first require porting the
  Unix side onto C libfuse bindings — trading a pure-Rust handler for a C-FFI
  dependency, the worst-weighted class of unsafe under the fleet's posture — or
  adopting `winfsp-rs`'s native API, which is a full Windows-shell rewrite anyway
  (WinFsp's native API is neither Dokan-shaped nor fuser-shaped).
- **Licensing**: the WinFsp runtime is GPLv3 with a FLOSS exception (commercial
  licensing otherwise) — a heavier posture than the current Dokan setup, where the
  MIT `dokan` crate binds a separately-installed Dokany runtime and only MIT code
  enters our dependency graph (per the in-repo Cargo.toml note).
- **Incumbency**: the Dokan shell exists, is a validated Humble Object (`win_map`
  unit-tested; mount-smoke passing), and the unification this ADR delivers happens
  *below* the shell — in `CowFs` — so the backend choice affects only a thin layer.
  Swapping backends would buy nothing the shared layer doesn't already provide.

## Consequences

- Windows reaches full ADR-0004 parity: same tree, same COW, same session semantics
  (`fuse_windows.rs` stops ignoring its session parameter).
- The resume-instability bug class is closed by construction: the persisted key no
  longer depends on enumeration order.
- Parity is testable without mounting: a shared `CowFs` test suite drives the
  platform-neutral layer against an in-memory fake `FileSystem`; each shell keeps a
  platform mount-smoke extended to the write path (create → write → readback →
  unmount → resume for the session mode).
- Rename is recorded as a first-class manifest operation (better audit trail than
  delete+create), implemented as an overlay-state move.
- The COW layer's natural home is `forensic-vfs-mount` (ADR 0006), so any future
  fleet mount consumer inherits it.

## Residuals / open questions

- **`FileId` serialization**: the manifest needs `Serialize`/`Deserialize` for
  `FileId` (now owned by `forensicnomicon-core`). Verify it exists; if not, add it
  behind a `serde` feature there. The serialized form becomes part of the session
  format — note the semver coupling.
- **v1 session migration is refused, not attempted**: existing `ino_{n}` keys are
  browse-order-dependent, so the original file binding is unrecoverable after the
  fact; v2 errors loudly on a v1 session rather than guess (PRD §8.5).
- **Copy-up latency**: first write to a multi-GB file blocks for a full copy.
  Documented behavior in v2; block-level COW (extent map in the overlay) is the
  designed successor, deliberately out of scope now.
- **Windows path semantics**: case-insensitive lookup expectations of Windows tools
  against case-sensitive source filesystems remain the Dokan shell's problem
  (unchanged from today); the overlay merge must follow whatever the shell's lookup
  policy is, not impose its own.
- **`session.save()` write amplification**: today the manifest is rewritten on every
  mutation; with a shared layer this becomes a policy knob (sync-on-op vs periodic +
  unmount flush). Default must favor durability (sync-on-op) until measured.
