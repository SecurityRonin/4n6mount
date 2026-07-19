# 8. Deleted files render in their real forensic location — in-place in `root/` or `$Orphans/` — never a flat hollow directory; `unallocated/` removed until carving is real

Date: 2026-07-19
Status: Proposed (design accepted for review — not yet implemented)

## Context

Two advertised surfaces cannot currently deliver what their names promise, and the
code hides that:

**What each surface *is*** (the two are distinct capabilities and must not share a
fate):

- **Deleted-file recovery** is *metadata-driven*: the filesystem still holds records
  for unlinked files (MFT `FILE` records with the in-use bit clear, orphaned ext4
  inodes), so names, parent links, timestamps, and — when the data runs survive —
  content are recoverable *by structure*, no carving needed. forensic-vfs 0.4 already
  models the three states: `FsMeta.allocated: Allocation { Allocated, Deleted,
  Orphan }` (`crates/core/src/fs.rs:82`).
- **`unallocated/`** is the *raw free space*: extents no live or deleted record
  claims. Nothing structural to recover; its only value is as carve-input (signature
  scanning) — raw bytes addressed by image offset.

**How the shipped code lies about both:** the trait can enumerate (`deleted()` →
`NodeStream` of `FsMeta`, `unallocated()` → `ExtentStream`), but `deleted()`'s
`FsMeta` carries **no `FileId`**, so a deleted file's bytes are unreadable through
the trait, and the inode-addressed trait has **no raw image byte reader** for
unallocated runs. `EngineFs` is honest about this (`recover_file` /
`read_unallocated` return loud `NotSupported` — the `TODO(engine)` gates); the FUSE
layer then destroys that honesty: `ensure_deleted_cache` swallows enumeration errors
into an empty directory (`fs.deleted_inodes().unwrap_or_default()`,
`src/fusefs.rs:175`) and maps every recovery error to a **0-byte entry**, so
`deleted/` renders either as "clean image" or as a list of files that "recovered"
empty. A silently fabricated negative finding — the fail-loud violation this ADR
kills.

A flat `deleted/` dump was also the wrong *shape*: it strips the most probative
recovered fact — **where the file lived**. The established forensic model (TSK
`fls -r`, FTK/X-Ways tree views) shows recovered-deleted entries *in the tree*, next
to their live siblings, with true orphans collected under a special directory
(TSK's `$OrphanFiles`).

One more constraint shapes the rendering: per ADR 0004 the mount is a **working
filesystem** — programs run against `root/` expecting files at their real paths with
their real names, and may write to them. Any marking scheme that changes names or
permissions breaks the tools the writable mount exists to serve.

## Decision

### 1. Placement rule (driven by `FsMeta.allocated`)

| Recovered entry | Rendered at |
|---|---|
| `Deleted`, parent known, real name free in that directory | **in-place in `root/`**, at its real path, under its **real name** |
| `Deleted`, parent known, but a live sibling holds the name (collision) | **`$Orphans/`** |
| `Orphan` (parent link gone) | **`$Orphans/`** |

`$Orphans/` (the `$` follows the NTFS/TSK metadata-name convention — `$MFT`,
`$OrphanFiles` — signalling a special non-user directory) therefore collects the two
*unplaceable* classes: true orphans and name-collision deletes. The directory-entry
merge composes **below** the COW layer (ADR 0005), so overlay semantics apply
uniformly on top of it.

**`$Orphans/` naming.** Same-name deletes are *common* (repeated save→delete cycles
leave several freed records for the same name at the same path), so entries must
disambiguate beyond the name:

- Primary form: **`<name>@<mtime>Z~<id>`** — the recovered name, `@`, the recovered
  last-modified time in **filename-safe UTC ISO-8601**, `~`, the stable record id.
  Example: `$Orphans/notes.txt@2024-01-05T12-30-00Z~mft12345` (NTFS),
  `…~inode678` (ext4).
- **Filename-safe timestamp is a load-bearing rule**: `:` is illegal in Windows
  filenames, so the time can never render as `12:30:00Z` — colons become hyphens
  (`2024-01-05T12-30-00Z`; basic `20240105T123000Z` is the acceptable alternative).
  The trailing `Z` marks UTC. This rule applies to *any* timestamp the mount ever
  puts in a path.
- The mtime is the human-readable disambiguator; the **id is the uniqueness
  guarantee** (two deletes can share name *and* mtime at second granularity), so the
  id suffix is always present.
- No recovered name (a true orphan with none): id-only, `$Orphans/mft-12345`, plus
  the `@<mtime>Z` when a time was recovered.

**When several `Deleted` records contend for one free in-place name**, exactly one
renders in-place — the latest recovered mtime, ties broken by highest record id —
and the rest go to `$Orphans/` under the naming above (they are name-collisions among
themselves). Deterministic by construction.

### 2. Marking is xattr-only — no name decoration, no forced read-only

An in-place recovered-deleted file behaves **exactly like a live file**: real name
(no `(deleted)` suffix), and **COW-writable** like everything else in `root/` — a
write copies-up onto the overlay while the recovered base bytes stay untouched, so
writability costs nothing in evidence safety. Ordinary programs run unaffected and
never see the status.

**Why out-of-band marking, not name decoration (the FTK equivalence).** This is the
same forensic model as FTK Imager's tree view: a metadata-recovered deleted file
shown *at its real name, in its real place*, with a red-X overlay marking its
status. The only difference is the marking channel, and it is forced by tool type:
FTK is a GUI viewer that owns the pixels, so it can paint a red X *beside* the name
without touching it. A mount's consumer is arbitrary software — there are no pixels
to paint, and the only in-band channels are the name and the mode, both of which
programs depend on (`open()` by real name breaks on a `(deleted)` suffix; writes
break on forced read-only). The red-X equivalent for a mount is therefore the
out-of-band attribute: `user.4n6.status` / `<name>:4n6.status`. Same model as the
established tool; the channel is the only translation.

The deleted status is conveyed **only out-of-band**, via extended attributes:
`user.4n6.status = deleted | orphan` plus the recovered MACB timestamps
(`user.4n6.macb.*`). Forensic tools that opt in read them; nothing else is disturbed.
A recovered entry must **never present as `Allocated`** on this channel — the xattr
always tells the truth even though the name and mode do not distinguish.

Per-platform channel — load-bearing (it is the *only* marking), and **decided for
all three platforms**: one logical schema, two physical channels.

- **macOS (macFUSE) / Linux (FUSE)**: native xattrs (`user.4n6.status`,
  `user.4n6.macb.*`). The current handler implements no xattr methods —
  `getxattr`/`listxattr` are **new work** in the FUSE shell.
- **Windows (Dokan)**: **NTFS Alternate Data Streams** — `<name>:4n6.status` and
  `<name>:4n6.macb`, surfaced via Dokan's stream enumeration (`find_streams`).
  Not a sidecar file, not a Dokan file-property: an ADS travels with the file's
  directory entry, needs no second namespace to keep in sync, and is readable by
  standard tooling (`Get-Item -Stream`, `dir /r`).

### 3. Honesty gate (unchanged in force, restated for the new shape)

- In-place markings and `$Orphans/` appear **only when the mounted reader produces
  real recovered entries** (`allocated == Deleted | Orphan` with readable content).
  A reader without deleted-recovery support ⇒ no marked entries, no `$Orphans/`,
  and `metadata/capabilities.json` (ADR 0007) says so.
- Enumeration errors surface as `readdir`/`open` errors (`EIO` + logged reason),
  **never** an empty result; a per-file recovery failure is a read error on that
  entry, **never** a 0-byte success. An empty `$Orphans/` is permitted only after a
  *successful* enumeration that found zero unplaceable entries.
- The old flat `deleted/` directory and the `ForensicFs` ops behind it
  (`deleted_inodes`, `recover_file`) are removed along with their silently-empty
  defaults (ADR 0006's trait slim-down); the new rendering replaces them.

### 4. `unallocated/` stays removed

Raw free space is a carve-only capability, distinct from deleted-recovery. It
returns only when a raw image byte reader (e.g. the engine exposing its underlying
`ImageSource`) plus the extent list let range files serve real bytes — under the same
fail-loud and capability-gated rules. Until then: absent, with the reason in
`capabilities.json`.

### Per-filesystem name completeness (drives the render path)

Deletion destroys different layers on different filesystems, so the recovered name
is **not uniformly complete** and the renderer must account for partial names:

| Filesystem | What deletion leaves | Render consequence |
|---|---|---|
| NTFS | MFT record's in-use bit cleared; `$FILE_NAME` and the full record reference (entry, seq) intact | full name + identity → renders in-place cleanly |
| exFAT | InUse bit (0x80) cleared in the directory-entry type byte (File 0x85→0x05, File-Name 0xC1→0x41); the full UTF-16 name in the File-Name entries is untouched, and `NoFatChain` files keep first-cluster+length with no FAT chain to lose | complete name (and often the full extent) survives → renders in-place cleanly, like NTFS — no placeholder, no `name-incomplete` flag |
| FAT12/16/32 | first filename byte overwritten with `0xE5` | name arrives minus its first character → render with a reconstructed-placeholder first char plus a `user.4n6.name-incomplete` xattr/ADS flag, or route to `$Orphans/` if unplaceable |
| ext3/ext4 | name often survives in directory slack; ext4 zeroes the extent tree on delete | name-yes / content-often-no — a placeable entry whose reads may fail loud |
| APFS / Btrfs / ZFS (COW trees) | deleted records dropped from the live tree quickly | frequently nothing recoverable without a snapshot → often no entries at all (honest empty) |

## Contract dependency (forensic-vfs 0.4.x — what the readers must expose)

The precise gap, from a same-session read of
`~/src/forensic-vfs/crates/core/src/fs.rs`: `FileSystem::deleted()` (fs.rs:336)
returns `NodeStream` (fs.rs:249) — an iterator of **`FsMeta`** (fs.rs:225), which
carries `ino: u64`, `allocated: Allocation`, sizes/times/streams, but **no `FileId`,
no name, no parent**. Contrast the live path: `DirEntry` carries `name: Vec<u8>` +
`id: FileId` + `kind`. The deleted-enumeration surface is therefore structurally too
thin for the in-place model on all three axes:

- **unreadable** — `read_at`/`extents`/`meta` take `FileId`, not `u64`, so a bare
  `ino` cannot reach the content;
- **unplaceable** — no recovered name to render;
- **unparentable** — no parent link to place it under.

The concrete fix is to **widen what `deleted()` yields**: a richer deleted-node form
carrying (a) the `FileId` (content becomes readable through the existing methods),
(b) the recovered name (`Option<Vec<u8>>`, absent for nameless records), (c) the
parent `FileId` or an explicit orphan marker. Allocation state and recovered
timestamps already exist (`FsMeta.allocated`, `MacbTimes`). This is a **fixable
type-widening, not a forensic dead-end** — NTFS still holds the full name and record
reference on disk; the trait just does not return them. Additive contract work
(default-`Unsupported`), and it must land in forensic-vfs **before** 4n6mount can
render deleted-in-place: today it is the hard blocker. The filesystem readers
(ntfs, ext4fs, …) then populate it for their deleted records — reader/contract work
first, mount work second; that is where the two prior investigations located the gap
(`TODO(engine)`).

## Consequences

- The mount stops lying *and* stops discarding provenance: a recovered file appears
  where it lived, and "no deleted files" can only mean the reader looked and found
  none.
- **A recursive tool over `root/` now transparently includes recovered-deleted
  content** — `cp -r`, hashing sweeps, AV scans see live + recovered files
  indistinguishably unless they read the xattr. That is the deliberate trade of the
  working-filesystem priority: complete logical acquisition by default, with the
  xattr as the discriminator. The README and mount banner must state it, and
  examiner-facing exports must carry the status column.
- Same-name live and deleted siblings never collide in-tree: the live file holds the
  path; the deleted one lands in `$Orphans/` under its stable id.
- **Marking survives only channel-aware copies — a known limitation, not a
  blocker.** ADS is an NTFS feature: the marking works when the mount is consumed on
  NTFS (the normal Windows case) but is stripped when a file is copied to a
  non-NTFS target (FAT/exFAT, many network shares). The same class of caveat holds
  on Unix, where `cp` without xattr preservation drops `user.4n6.*`. Examiner
  guidance: preserve the status via xattr/ADS-aware copies or the session manifest.
- Both surfaces keep `ENUM_CAP`-style bomb-guards; timeline (ADR 0007) can attribute
  events to deleted entries once they carry identity.

## Residuals / open questions

- **Marking schema**: exact names/values across both channels
  (`user.4n6.status`/`user.4n6.macb.*` xattrs; `<name>:4n6.status`/`<name>:4n6.macb`
  ADS payloads — same logical schema) need a one-page spec; once shipped it is a
  published machine contract.
- **Timestamp provenance in `$Orphans/` names**: the `@<mtime>Z` renders in UTC via
  the reader's `TimeZonePolicy`; filesystems storing local time without zone (FAT)
  make the UTC rendering approximate — acceptable for a disambiguator (the id
  carries uniqueness), but the xattr timestamps must state the policy.
- **Deleted directories with recoverable children**: subtree placement (an in-place
  deleted dir containing further deleted entries) follows the same rule recursively;
  cycle/loop guards needed for corrupt parent chains.
- **Case-insensitive collision test on Windows lookups**: the collision rule must use
  the shell's lookup policy (ADR 0005 residual), or a "free" name may still collide
  case-insensitively.
- **Slack space** sits between deleted and unallocated (allocated file, tail bytes
  beyond EOF). The trait already has `slack()`; any mount surface for it follows the
  same gate — out of scope here.
