# 3. Memory-dump mounting architecture

Date: 2026-07-01
Status: Accepted

## Context

4n6mount mounts a memory image (LiME/AVML/ELF-core/Windows crash dump) as a
browsable filesystem (the MemProcFS/MemNixFS paradigm): analysis artifacts —
process lists, modules, network connections, kernel log — appear as readable
files under `sys/`, rendered lazily on access. The forensic walking itself lives
in the `memf` library crates; 4n6mount maps their output onto a VFS tree.

This ADR records the architecture that shipped (Phases 0–2). The remaining
phases are tracked in `docs/plans/memory-mounting-roadmap.md`.

## Decision

1. **Library seam, not a fork.** The memory walkers live in `memf-*` library
   crates (`memf-format`/`memf-core`/`memf-session`/`memf-symbols`/`memf-windows`/
   `memf-linux`); 4n6mount depends on them and owns only the VFS mapping. It does
   **not** wrap MemProcFS/MemNixFS (C/C++, platform-scoped) — those serve as
   *validation oracles* on real dumps instead.

2. **Lazy artifact providers.** `MemoryFs` (in `src/mem/`) carries an
   `ObjectReader` over the dump and renders each `sys/<artifact>.txt` on demand by
   calling the relevant walker — no eager analysis at mount time.

3. **Humble Object for every artifact.** The testable decision — turning a
   walker's structured records into the text of a file — is a pure `render_*`
   function unit-tested on synthetic records (tier-3); the thin glue that calls
   the real walker is validated end-to-end against real dumps (tier-2, gated on a
   dump corpus via `MEMF_TEST_DATA`, skipped cleanly in CI).

4. **Fail-soft contract.** A walker that errors or finds nothing still yields a
   file, with a one-line diagnostic header (e.g. `# pslist: 0 processes`), never
   a missing or silently-empty file. A per-artifact failure never fails the mount;
   only a failed *bootstrap* (OS/kernel-base resolution) errors loudly.

5. **Symbol-free Windows fallback.** Windows walkers fall back to pool scanners
   when head-based traversal is unreliable (the "kernel base resolved ~6 MiB off"
   lesson), so a mount degrades to best-effort artifacts rather than nothing.

6. **Optional feature.** Memory mounting is behind `#[cfg(feature = "memory")]`;
   non-memory builds carry none of the memf dependency weight.

## Consequences

- Shipped: Phase 0 (library seam), Phase 1 (skeleton `MemoryFs` + detection +
  routing + `sys/os-info.txt`), Phase 2 (`sys/processes.txt`, `modules.txt`,
  `network.txt`, `dmesg.txt`). The memory mount-smoke row (`crash.dmp` →
  `sys/os-info.txt`) exercises the path on FUSE and Dokan.
- Deferred (see the roadmap): `sys/services.txt`; per-process `proc/<pid>/`;
  `forensic/` findings; file recovery (`fs/`) and raw (`mem/`); tier-2 oracle
  diffs against MemProcFS/vol3 on a real-dump corpus.

## Alternatives considered

- **Wrap MemProcFS/MemNixFS** — rejected; both are C/C++ and Windows- or
  Linux-scoped, while `memf` already provides the walkers in `forbid(unsafe)`
  Rust. Their designs are reused and they serve as oracles.
- **Eagerly render all artifacts at mount** — rejected; lazy per-file rendering
  keeps mount instant and matches the FUSE/Dokan access model.
