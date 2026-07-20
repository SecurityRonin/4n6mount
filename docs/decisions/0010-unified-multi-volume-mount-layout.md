# 10. Every image renders `<mount>/<volume>/<fs tree>` at constant depth — a single filesystem is just one `<volume>`, named `root`

Date: 2026-07-20
Status: Accepted — structural layer implemented (`engine_fs`); per-volume `$`-dirs deferred (see Implementation status)

## Context

`open_image_all` (`src/engine_fs.rs`) surfaced multiple partitions under a
synthetic root as `p1-fat` / `p2-ntfs` … but **returned a single filesystem
directly at the root** when the image held only one (`fss.len() == 1`). So the
depth of the mounted tree depended on the image: `<mount>/<fs tree>` for a bare
volume, `<mount>/pN/<fs tree>` for a partitioned disk. A consumer that walks the
tree had to special-case the two shapes, and the `pN-<kind>` name leaked an
internal mechanism (the engine's filesystem probe) into the path.

The FUSE layer (`src/fusefs.rs`) compounded this: the synthetic `$Orphans/`,
`journal/`, and `metadata/` directories live at the FUSE **root** on the
single-volume assumption, so on a multi-volume disk they cannot be attributed to
the volume they describe.

## Decision

### 1. One layout: `<mount>/<volume>/<fs tree>`, constant depth

Every image — one filesystem or many — renders each filesystem as a `<volume>/`
directory under a synthetic root. A single filesystem is **one `<volume>`**; the
`fss.len() == 1` special case is removed. A consumer walks the identical shape
regardless of partitioning.

### 2. `<volume>` naming precedence (with a label HOOK)

Each volume's directory name is chosen by, in order:

1. **A wired volume label**, sanitized (see §3) and used **verbatim** — spaces,
   Unicode, and case kept — when it is non-empty and does not collide with a
   name already taken. The label comes from a single hook,
   `volume_label(&PathSpec, &DynFs) -> Option<String>`, which is the ONE place
   label extraction lights up when a leaf accessor for it lands.
2. **`_partition<index+1>`** when the evidence's `PathSpec` carries a
   `Layer::Volume { index, .. }` — the true volume-table index, so a GPT disk
   whose slot 1 holds no filesystem yields `_partition1`, `_partition3`,
   `_partition4` (the filesystem-less slot is simply absent), never a resequenced
   `_partition1/2/3` that would misreport which slot a volume came from.
3. **`root`** — a bare, unpartitioned filesystem (its `PathSpec` has no
   `Layer::Volume`).

An empty-after-sanitization or colliding label falls back to step 2 (or step 3
when there is no volume index).

### 3. Reversible sanitization of a wired label

A label is kept verbatim except for characters that cannot safely sit in a path
component, which are **reversibly** percent-encoded (each becomes `%XX` per UTF-8
byte): `%` (the escape introducer, so the transform round-trips), `/`, NUL and
all control characters, the Unicode bidirectional formatting/override characters,
and — only on Windows — the Dokan-reserved filename set (`< > : " \ | ? *`). A
label that sanitizes to empty falls back to the `_partition<N>` / `root` steps.

### 4. The three synthetic dirs become per-volume `$Orphans/`, `$Journal/`, `$Metadata/`

`$Orphans/`, `$Journal/`, and `$Metadata/` move **inside each `<volume>/`** (not
the FUSE root), each capability-gated per ADR 0007 / ADR 0008:

- `$Orphans/` appears when the volume's reader yields recovered orphan-class
  entries (`deleted_nodes()`), with the ADR 0008 disambiguated naming.
- `$Journal/` and `$Metadata/` appear only when their accessor is available;
  absent (never fabricated empty) when it is not.

### 5. Inode multiplexing unchanged

The dense per-partition inode allocator in `MultiPartitionFs` — which keeps each
volume's inode space disjoint while collapsing to the small inodes the FUSE
`[1000, 10_000_000)` routing requires — is kept. A `partition << 48` bit-pack is
**not** used (it overflows that namespace).

## Implementation status (2026-07-20)

**Implemented (this pass, strict TDD, `engine_fs.rs`):** §1 (universal
`<volume>/` wrapper, `fss.len() == 1` special case removed), §2 (naming
precedence + `volume_label` hook, returning `None` today), §3 (sanitization),
§5 (inode mux preserved). Proven by the `engine_fs::layout_tests` unit tests, an
`open_image_all` bare-`root` test over the committed `hfsplus.img`, and the
env-gated real-image e2e (`FN_E2E_IMAGE`), which surfaces `_partition1/3/4` on
the Case-001 DESKTOP GPT disk and reads `$AttrDef` back through the NTFS volume.

**Deferred (§4, and the FUSE-root virtual-dir relocation):** moving `$Orphans/`,
`$Journal/`, `$Metadata/` per-volume is a `fusefs.rs` refactor that also
determines where the overlay dirs (`ro/`, `rw/`, `session/`) sit relative to
`<volume>/` — out of scope for the structural pass and gated on leaf accessors:

- **Label extraction** — `volume_label` returns `None`: `forensic_vfs::FileSystem`
  exposes no volume label, and `EngineFs::fs_info()` reports the filesystem
  *kind*, not a label. Blocked on a leaf accessor.
- **`$Journal/` / `$Metadata` timeline** — `EngineFs::journal_transactions()` and
  `timeline()` return `NotSupported` (the forensic-vfs `FileSystem` trait has no
  journal or event-timeline surface), so these render **absent**, honestly, per
  ADR 0007. Blocked on the contract additions ADR 0007 flags.
- **`$Orphans/` per-volume** — `deleted_nodes()` *is* wired on `EngineFs`, so the
  data exists; only the per-volume *rendering* (a `fusefs`/wrapper change with no
  authoritative test corpus for deterministic CI) is deferred, to avoid shipping
  untested forensic behavior.

## Consequences

- Single-volume disk images now render under `<mount>/<volume>/root/…` rather
  than `<mount>/<fs tree>` — the deliberate unification. Until §4 lands, the
  FUSE-root `$Orphans/` / `journal/` / `metadata/` surfaces that a single-volume
  mount previously drove from the top `ForensicFs` are not re-attributed
  per-volume; that is the pending follow-up, not a silent loss (the recovered
  data is still reachable through the wired `deleted_nodes()` once §4 renders it).
- `_partition<index+1>` reports the true volume-table slot, so a gap in the
  numbering is meaningful (a slot with no filesystem), not a bug.
- Names are path-safe on all three mount backends (macFUSE / FUSE / Dokan) and a
  sanitized label round-trips back to the original bytes.

## Note on this record

This ADR was authored on 2026-07-20 from the accepted design brief when the
implementation landed; the numbered file was referenced before it was committed.
It states the current decision and the implemented-vs-deferred status, not the
history of the gap.
