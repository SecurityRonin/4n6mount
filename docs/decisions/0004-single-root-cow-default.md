# 4. One `root/` tree, copy-on-write by default; `--read-only` opts out

Date: 2026-07-19
Status: Proposed (design accepted for review — not yet implemented)

## Context

The shipped disk-overlay layout presents twin trees: `ro/` (the evidence, always
read-only) and `rw/` (the same tree again, writable only when `--session` was
passed). Every file has two paths; the analyst must know which twin a tool should be
pointed at; and in the default invocation (no `--session`) *both* twins are read-only
(`MountOptions.read_only = session.is_none()` in `src/main.rs`), so the distinction
is pure noise. On Windows the question never arises — the Dokan backend is
unconditionally read-only and ignores its session parameter.

Meanwhile the actual analyst workflow *needs* writes to the view: running a triage
tool that drops a lock/temp file, opening a mounted browser profile, letting an office
suite open a document (lock files), pointing an AV scanner at the tree. A read-only
mount breaks these tools; the analyst's real requirement is only that the *evidence*
never changes.

The forensic-vfs read stack makes evidence immutability structural: the byte-source
and `FileSystem` contracts are read-only — no method can mutate the underlying image
(forensic-vfs ADR 0001). A writable *view* therefore cannot endanger the evidence; the
only question is where the written bytes live.

## Decision

1. **One tree: `root/`.** `rw/` is renamed to `root/`; `ro/` is deleted. A path under
   `root/` is the only path a file has. What a read returns depends on overlay state;
   where a file lives does not.

2. **Default = writable via copy-on-write.** With no flags, the mount creates an
   **ephemeral overlay** in a scratch directory under the OS temp dir
   (`4n6mount-<image-hash8>-<pid>/`), used exactly like today's session overlay
   (copy-up on first write, whiteouts for deletes) and discarded at clean unmount.
   `--session DIR` upgrades the overlay to **persistent and resumable**: SHA-256-bound
   to the image (resume refuses on hash mismatch — today's behavior, kept), exportable
   as a tarball (kept).

3. **`--read-only` disables the overlay.** Same single tree; every mutating operation
   is rejected — `EROFS` from the FUSE shell, `MountFlags::WRITE_PROTECT` on Dokan so
   the kernel driver rejects writes before user code runs. `--read-only` conflicts
   with `--session` and `--resume` (clap `conflicts_with`). Use cases: a tool or
   procedure that must observe an immutable target, and defense against accidental
   analyst edits.

4. **The flag is named by outcome, not mechanism.** `--read-only`, not `--no-cow`:
   the analyst's mental model is `mount -o ro` — "this mount rejects writes" — a
   contract they can observe. `--no-cow` names an internal mechanism and invites the
   misreading that writes might still happen somewhere (just without COW). This
   follows the fleet naming rule: name by the role the analyst recognizes (the
   outcome), never the implementation. It also avoids framing the default by negation.

5. **Memory mounts stay read-only.** `MountLayout::Raw` (ADR 0003) implies
   `--read-only`; a COW overlay over a synthesized process/module tree has no use
   case.

## Consequences

- The zero-config path finally matches the common workflow: mount, point any tool at
  `root/`, and it works — while evidence safety needs no flag at all (secure by
  default; the safe thing and the zero-knowledge thing are the same thing).
- "Which of these bytes are mine?" is answered by the session, not by twin trees:
  `session/` exposes the overlay manifest (every created / modified / deleted path),
  so the examiner can always diff view against evidence. This replaces the one
  legitimate job `ro/` performed (an untouched reference copy) with an explicit,
  auditable record.
- An **ephemeral overlay is lost at unmount** — deliberate. Scratch writes (lock
  files, tool droppings) are litter, not work product; an analyst producing work
  product uses `--session`. The mount banner states which mode is active and, for
  ephemeral mode, that changes will be discarded.
- Today's inverted default (`read_only = session.is_none()`) disappears: writability
  no longer depends on whether persistence was requested.
- `MountLayout::DiskOverlay` is re-specified to render the new tree
  (`root/ journal/ metadata/ session/`, plus `$Orphans/` when the reader produces
  real recovered entries — ADR 0008); the seven-directory layout and its arithmetic
  inode namespaces go with it (mechanics in ADR 0005).

## Residuals / open questions

- **Ephemeral overlay location**: OS temp is the default for zero-config; a crash
  (unclean unmount) can leave a scratch dir behind. Cleanup-on-next-run of stale
  `4n6mount-*` dirs is implementation detail to settle.
- **Disk-space exposure**: COW copy-up of large files consumes temp space silently in
  ephemeral mode. The mount should surface overlay usage in `session/status.json`
  either way.
