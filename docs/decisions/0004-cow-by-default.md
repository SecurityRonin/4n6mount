# 4. Copy-on-write by default; `--read-only` opts out

Date: 2026-07-19
Status: Accepted (design; the write-model policy — layout is ADR-0010)

## Context

The analyst workflow needs writes to the *view*: a triage tool drops a lock/temp file,
a mounted browser profile or office suite writes lock files, an AV scanner touches the
tree. A read-only mount breaks these tools. The analyst's real requirement is only that
the **evidence** never changes.

forensic-vfs makes evidence immutability structural: the byte-source and `FileSystem`
contracts are read-only — no method can mutate the underlying image (forensic-vfs ADR
0001). A writable *view* therefore cannot endanger the evidence; the only question is
where the written bytes go.

## Decision

1. **Default = writable via copy-on-write.** With no flags, the mount creates an
   **ephemeral overlay** in a scratch dir under the OS temp dir
   (`4n6mount-<image-hash8>-<pid>/`): copy-up on first write, whiteouts for deletes,
   discarded at clean unmount. `--session DIR` upgrades the overlay to **persistent and
   resumable** — SHA-256-bound to the image (resume refuses on hash mismatch),
   exportable as a tarball. The overlay is **per-volume** (each mounted volume's
   filesystem carries its own `FileId`-keyed overlay — ADR 0005; layout ADR 0010).

2. **`--read-only` disables the overlay.** Every mutating op is rejected — `EROFS` from
   the FUSE shell, `MountFlags::WRITE_PROTECT` on Dokan so the driver rejects writes
   before user code runs. Conflicts with `--session`/`--resume` (clap `conflicts_with`).

3. **The flag is named by outcome, not mechanism** — `--read-only`, not `--no-cow`:
   the analyst's model is `mount -o ro` ("this mount rejects writes"), an observable
   contract. `--no-cow` names an internal mechanism and invites the misread that writes
   might still land somewhere. Fleet rule: name by the role the analyst recognizes.

4. **Memory mounts stay read-only.** `MountLayout::Raw` (ADR 0003) implies
   `--read-only`; a COW overlay over a synthesized process/module tree has no use case.

## Consequences

- The zero-config path matches the common workflow: mount, point any tool at the volume
  tree, and it works — while evidence safety needs no flag (secure by default; the safe
  thing and the zero-knowledge thing are the same thing).
- "Which bytes are mine?" is answered by the session, not by twin trees: the overlay
  manifest records every created / modified / deleted path, so the examiner can diff
  view against evidence — an explicit, auditable record.
- An **ephemeral overlay is lost at unmount** — deliberate. Scratch writes are litter,
  not work product; an analyst producing work product uses `--session`. The mount
  banner states the active mode and, for ephemeral, that changes are discarded.

## Residuals

- **Ephemeral overlay location**: OS temp is the zero-config default; an unclean unmount
  can leave a scratch dir behind — cleanup-on-next-run of stale `4n6mount-*` dirs is an
  implementation detail.
- **Disk-space exposure**: COW copy-up of large files consumes temp space silently in
  ephemeral mode; surface overlay usage in `$Metadata/status.json`.
