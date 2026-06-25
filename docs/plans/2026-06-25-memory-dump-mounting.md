# Memory-Dump Mounting Implementation Plan

> **STATUS (2026-06-25): Phase 0 is DONE — start at Phase 1.**
> Phase 0 (extract the memf analysis bootstrap into a library crate) is complete:
> the `memf-session` crate is merged into `memory-forensic` main and shipped in its
> **v0.1.0** release (16 unit + 2 integration tests green; `build_analysis_context`,
> `detect_os`, `extract_cr3`, `resolve_kernel_list_heads` now live in
> `memory-forensic/crates/memf-session`). Depend on it as a path+version crate
> (`{ version = "0.2", path = "../memory-forensic/crates/memf-session" }`).
> **Do not re-do the extraction.** The next task is **Phase 1, Task 1.1** (deps + the
> `memory` feature), then the `MemoryFs` skeleton and `sys/os-info.txt`.

> **For Claude:** REQUIRED SUB-SKILL: use `superpowers:executing-plans` (or `subagent-driven-development`) to implement this task-by-task. Strict TDD: separate RED and GREEN commits per task.

**Goal:** Extend 4n6mount to mount a **memory dump** (any format) as a browsable filesystem — the MemProcFS / MemNixFS paradigm — reusing memf's walkers, so an examiner runs `4n6mount memory.lime /mnt/case` and browses `proc/<pid>/`, `sys/`, `forensic/` with `ls`/`cat`/`grep`.

**Architecture:** 4n6mount already is a FUSE mount framework with a `ForensicFs` trait + a disk-image overlay (ro/rw/deleted/…). Memory mounting is a *second provider* behind the same FUSE backend: a new `MemoryFs: ForensicFs` whose synthetic, **lazily-generated** tree is produced on read by calling memf's library crates. The disk COW overlay is bypassed for memory (a `MountLayout::Raw` seam); memory artifacts are read-only by construction.

**Tech Stack:** Rust, `fuser` (libfuse/macFUSE) + WinFsp; memf library crates (`memf-format`, `memf-core`, `memf-windows`, `memf-linux`, `memf-symbols`, `memf-correlate`); the existing `forensic-mount` crate.

---

## Executive summary

memf already does all the forensics — every dump format (`open_dump`), ISF **and** BTF symbols, Linux + Windows walkers, injection detection, file recovery, correlation. It exposes them only as a CLI. MemProcFS and MemNixFS prove the value of the *filesystem* interface: point a memory dump at a mountpoint and every existing tool (`grep`, `less`, Explorer, an indexing pipeline) becomes a memory-analysis tool with zero integration.

This plan adds that interface to 4n6mount as a presentation layer — **not** new forensics. The only memf-side change is a small, behaviour-preserving library extraction (Phase 0) so the analysis bootstrap stops being trapped in the CLI binary.

**Build-vs-reuse decision (Research-First):** MemProcFS (C, Dokany/WinFsp/FUSE) and MemNixFS (C++17, WinFsp/FUSE, Linux-only) are the prior art. We do **not** wrap either — both are C/C++ and Windows- or Linux-scoped, and memf already has the walker layer in `forbid(unsafe)` Rust. We reuse their *designs* (layered VFS + lazy file nodes; the `proc`/`sys`/`forensic` layout) and use them as **validation oracles** on real dumps, which is the higher-value role.

---

## Prior art studied (what we take from each)

| Source | Design we adopt | Where it lands |
|---|---|---|
| **MemNixFS** | Strictly *layered* engine: physical → translation → OS → **VFS tree** → **mount backends**, each swappable. `Node`/`DirNode`/`LazyFileNode`/`StreamFileNode`. 16 MiB LRU page cache. `findevil` = `malfind + psscan + hidden_modules` aggregated verdict. BTF-from-dump when no ISF. | The VFS-node model (Phase 1); lazy + LRU read cache; the `forensic/findevil` aggregation (Phase 4); `proc/` naming. |
| **MemProcFS** | Everything is also an API (the FS is the API, mounted *or* called). `pid/<pid>/`, `sys/`, `forensic/`, `registry/` layout. On-demand module-generated files. Auto-mount on file-extension association. | `sys/`+`forensic/`+`registry/` richness (Phases 2/4); FS-is-the-library principle (`MemoryFs` is usable headless); the 18-entry DNS / pslist / handle oracles. |
| **memf (reuse)** | `memf-format::open_dump`, `memf-core::{ObjectReader, VirtualAddressSpace, ListIter}`, walkers `<P: PhysicalMemoryProvider>`, `memf-symbols` (ISF+BTF), `memf-correlate` (timeline+severity). | All file *contents*. 4n6mount never re-implements a walker. |

---

## The reuse boundary (grounded in the current trees)

**Reusable as a library today:**
- `memf-format::open_dump(&Path) -> Result<Box<dyn PhysicalMemoryProvider>>` — universal format opener (LiME/AVML/ELF-core/crash/raw/…). `open_dump_with_raw_fallback` for headerless.
- `memf-core`: `ObjectReader<P>`, `VirtualAddressSpace<P>`, `ListIter<P>`, `PagefileProvider` — translation + structured reads.
- `memf-windows` / `memf-linux`: walker fns, all generic `<P: PhysicalMemoryProvider>` (e.g. `walk_ldr_modules`, `scan_apc_queues`, `walk_amcache`). They return `memf-core::WalkResult<T>` (typed + `skipped` count).
- `memf-symbols`: ISF JSON, BTF, PDB/symserver backends.
- `memf-correlate`: `ForensicEvent` + severity (the timeline + a triage feed).

**Trapped in the `memory-forensic` *binary* (`src/`, not a lib) — the Phase-0 seam:**
- `src/os_detect.rs`: `AnalysisContext`, `build_analysis_context()`, `detect_os()`, `extract_cr3()`, `resolve_kernel_list_heads()`, `parse_hex_addr()`.
- `src/main.rs` (352 KB, 293 fns): per-walker dispatch + formatting. We do **not** reuse the formatting (4n6mount owns its presentation); we only need the bootstrap above.

---

## VFS layout (synthesis of MemProcFS + MemNixFS, OS-aware)

`proc/` is the universal process dir (works for both OSes); `sys/`+`forensic/` carry MemProcFS's richness. Per-OS contents differ; the top level does not. (No box-drawing chars per house style — plain indentation.)

```
/mnt/case/
  sys/                      system-wide
    os-info.txt             profile: OS, build, kernel base, DTB/CR3, symbol source (ISF|BTF)
    processes.txt           pslist (pid, ppid, name, create-time, exit)
    modules.txt             kernel modules / drivers
    network.txt             netscan (tcp/udp, owner pid)        [Win: parity with vol3/MemProcFS]
    services.txt            services / systemd units
    dmesg.txt               kernel ring buffer                  [Linux]
  proc/
    <pid>/
      cmdline.txt           argv
      status.txt            process summary (vad/maps summary, threads, sids/uid)
      maps.txt              VAD (Win) / VMA (Linux) regions
      modules.txt           loaded DLLs (Win) / mapped libs (Linux)
      handles.txt           handle table                        [Win]
      environ.txt           environment block
      mem                   the process virtual AS as a sparse readable stream
  forensic/
    timeline.jsonl          memf-correlate ForensicEvent stream (sorted)
    findevil.txt            aggregated verdict: malfind + injected-threads + hidden modules (MemNixFS model)
    injected/<pid>-<va>     one file per malfind/hollowing/APC hit (raw region bytes)
    strings.txt             ranked strings (memf-strings)
  fs/                       recovered file content
    ...                     tmpfs/ramfs page-cache files (Linux); mapped files / MFT (Win)
  registry/                 hive cells as paths                 [Win, later]
  mem/
    physical                the raw physical address space as one sparse file
```

OS detection (Phase 1) picks which subtrees populate; an absent subtree for the dump's OS simply isn't listed.

---

## Architecture decisions

1. **`MemoryFs` implements the existing `ForensicFs` trait.** The trait is already a read-only tree abstraction (`root_ino`/`read_dir`/`lookup`/`metadata`/`read_file`/`read_file_range`/`read_link`) with optional forensic ops (`timeline` → memf-correlate; `deleted_inodes`/`recover_file` → unused for memory, default-empty). The synthetic tree fits it; **lazy generation lives in `read_file`**.
2. **Inode registry, not a real FS.** `MemoryFs` owns `ino -> Artifact`, where `Artifact = System(SysKind) | Process{pid, ProcKind} | Forensic(FKind) | RawMem(MemKind) | Dir`. Built incrementally: `proc/` children (the pid list) materialise on first `read_dir(proc)`.
3. **`MountLayout::Raw` seam.** The current mount wraps a `ForensicFs` in the disk ro/rw/deleted overlay. Add a mount mode that renders a `ForensicFs` tree *directly* (no overlay) — memory is read-only and has its own top level. Disk mounts keep `MountLayout::DiskOverlay` unchanged. This is the one structural change in 4n6mount's mount path.
4. **Lazy + LRU read cache** (MemNixFS's 16 MiB idea): `read_file` runs the walker once, caches the rendered bytes per inode (bounded LRU), so `cat` then `grep` on the same file doesn't re-walk. `mem` / `physical` are *streamed* (range reads straight through the provider), never fully materialised.
5. **Feature-gated** under a `memory` Cargo feature (mirrors the existing `ext4`/`ewf`/`iso`/`vmdk` optional-dep pattern). memf crates are `../memory-forensic/crates/*` path-deps + published version, like the existing `../ewf`, `../vmdk` deps.
6. **`MemoryFs` is usable headless** (MemProcFS's "FS is the API" principle): the same struct backs a future `4n6mount mem --cat proc/4/maps memory.lime` no-mount read. Don't design it mount-only.

---

## Security & robustness (non-negotiable, from the fleet disciplines)

- **Read-only by construction.** The memory mount never writes to the dump; the provider is read-only and there is no rw/ overlay. Secure-by-default: the zero-flag path cannot mutate evidence.
- **Fail LOUD on bootstrap, degrade-to-empty ONLY per-artifact.** A failed *bootstrap* — `open_dump`, OS detect, kernel-base/DTB resolution, symbol load — must surface as a loud diagnostic at mount time (non-zero exit / named error / the offending value: candidate base VA, missing symbol), **never** a silently-empty tree. A successfully-bootstrapped mount where one *walker* finds nothing yields an empty file **with a one-line diagnostic header**, not a missing file. (This is the memf "kernel base 6 MiB off → silent empty" lesson; validate the base translates + passes an MZ/PE or kallsyms check before trusting it.)
- **Show the unrecognised value.** A walker that hits an unknown tag/version writes the raw bytes + offset into the file, never a bare "unrecognised".
- **No placeholder anything.** A not-yet-implemented artifact file returns a clear "not implemented for <os>" error, never fabricated plausible content.

---

## Validation (oracle tiers — label every claim)

- **Tier 2 (independent oracle on real data):** mount `tests/data/.../citadeldc01.mem` (Windows DC, szechuan corpus) and diff `sys/processes.txt`, `proc/<pid>/handles.txt`, `sys/network.txt` against **MemProcFS** (the existing 18-entry DNS oracle, pslist, handles). Mount a **Linux** dump and diff `proc/`, `sys/modules`, `forensic/findevil` against **MemNixFS** (its BTF symbol-free path is the headline parity test). memf's own walkers are already validated; this proves the *VFS mapping* is faithful, not the forensics.
- **Tier 3 (self-authored, must be labelled):** unit tests use a `MockMemProvider` (a `PhysicalMemoryProvider` over a hand-built page set) + the existing `MockForensicFs` pattern — to exercise inode mapping, lazy-read caching, and `read_dir`/`lookup`/`metadata`, **not** forensic correctness.
- Env-gated, large dumps gitignored, extracted to `/tmp` per the fleet test-data standard; provenance in `tests/data/README.md`.

---

## Phase 0 — memf library seam (in `~/src/memory-forensic`, behaviour-preserving)

**Why first:** without it, 4n6mount cannot call the analysis bootstrap. Worktree-isolate (memf has active work on main).

### Task 0.1 — extract the bootstrap into a library crate

**Files:**
- Create: `crates/memf-session/Cargo.toml`, `crates/memf-session/src/lib.rs`
- Move: `src/os_detect.rs` → `crates/memf-session/src/context.rs` (`AnalysisContext`, `build_analysis_context`, `detect_os`, `extract_cr3`, `resolve_kernel_list_heads`, `parse_hex_addr`)
- Modify: root `Cargo.toml` (add member + workspace dep), `src/main.rs` (re-point to `memf_session::…`), `src/os_detect.rs` (becomes a thin `pub use` re-export or is deleted)
- Test: `crates/memf-session/tests/bootstrap.rs`

**Steps (TDD):**
1. **RED** — write `crates/memf-session/tests/bootstrap.rs`: `build_analysis_context(open_dump(citadeldc01)?)` returns `os == Windows`, a kernel base that translates + passes an MZ/PE check, and a non-zero CR3. Run → fails to compile (crate doesn't exist). **Commit (RED).**
2. **GREEN** — create the crate, move the code verbatim, wire the workspace, re-point `main.rs`. `cargo test -p memf-session` passes; **`cargo build` of the `memory-forensic` binary still succeeds and its existing tests stay green** (behaviour-preserving). Verify real clippy exit (not the rtk summary). **Commit (GREEN).**
3. **REFACTOR** — keep `src/os_detect.rs` as `pub use memf_session::*;` only if other binary modules import it; otherwise delete. Tests stay green.

**Exit:** `memf-session` is a published-style lib crate (low MSRV like its siblings) exporting the bootstrap. Bump the memf crates to a publishable version so 4n6mount's version+path deps resolve.

---

## Phase 1 — end-to-end skeleton mount (in `~/src/4n6mount`)

Prove a memory dump mounts and one real file reads, before breadth.

### Task 1.1 — deps + `memory` feature

**Files:** Modify `Cargo.toml`.
- Add optional path+version deps `memf-format`, `memf-core`, `memf-session`, `memf-symbols` (+ `memf-windows`, `memf-linux`, `memf-correlate` arrive in later phases), each `{ version = "0.2", path = "../memory-forensic/crates/<c>", optional = true }`.
- Add `memory = ["dep:memf-format","dep:memf-core","dep:memf-session","dep:memf-symbols"]`; add to `default`.
- **RED/GREEN:** a `#[cfg(feature="memory")]` smoke test that `memf_format::open_dump` is in scope; `cargo build --features memory`. Commit RED (test referencing absent module) then GREEN (deps wired).

### Task 1.2 — `MemoryFs` skeleton + inode registry

**Files:** Create `src/mem/mod.rs`, `src/mem/memoryfs.rs`, `src/mem/inode.rs`; Modify `src/lib.rs` (`#[cfg(feature="memory")] pub mod mem;`). Test: `src/mem/memoryfs.rs` `#[cfg(test)]` with a `MockMemProvider`.
- **RED** — `test_root_lists_sys_and_proc`: a `MemoryFs` over a mock provider returns `read_dir(root)` containing `sys`, `proc`, `forensic`, `mem`; `lookup(root,"sys")` resolves; `metadata` of a dir is a dir. Run → fails. Commit (RED).
- **GREEN** — `MemoryFs { provider, ctx, registry, cache }` implementing `ForensicFs`; static top-level dirs in the registry; `read_dir`/`lookup`/`metadata` over the registry; `read_file`/`timeline` stubbed. Tests pass. Commit (GREEN).

### Task 1.3 — `sys/os-info.txt` (first lazy real file) + the `Raw` mount seam

**Files:** Modify `src/mem/memoryfs.rs`, `src/fusefs.rs` (or wherever mount wrapping lives) for `MountLayout::Raw`, `src/main.rs` (detect memory input → memory mount path), `src/detect.rs` (memory-dump signature detection).
- **RED** — `test_os_info_renders_profile`: `read_file(os_info_ino)` (mock bootstrap → Windows) yields text containing `OS:`, `Kernel base:`, `Symbol source:`. And `test_raw_layout_has_no_rw_dir`: a memory mount's root has no `rw`/`deleted`. Run → fails. Commit (RED).
- **GREEN** — `read_file` for `Artifact::System(OsInfo)` formats `ctx` (OS, build, kernel base, DTB/CR3, ISF|BTF source) with the LRU cache; add `MountLayout::Raw`; route memory dumps to it; `detect.rs` recognises LiME/AVML/ELF-core/crash/raw-memory signatures (fail-loud + show-bytes when ambiguous). Tests pass. Commit (GREEN).
- **Manual smoke (Tier-2 setup):** `4n6mount citadeldc01.mem /tmp/case --features memory` then `cat /tmp/case/sys/os-info.txt` shows the DC's profile; `umount`.

---

## Phase 2 — system-wide artifacts (`sys/`)

One task per artifact, each: RED (mock-provider mapping test) → GREEN (call the memf walker, render, cache) → Tier-2 diff vs MemProcFS/MemNixFS on a real dump.
- `sys/processes.txt` — pslist (Win EPROCESS list / Linux task list via `memf-session` list-heads + the memf walker). Oracle: MemProcFS `sys/proc`, vol3 `pslist`.
- `sys/modules.txt` — kernel modules/drivers.
- `sys/network.txt` — netscan (the committed C2/listener census is the oracle anchor).
- `sys/services.txt` — services / systemd units.
- `sys/dmesg.txt` — Linux ring buffer.
Each walker miss after a good bootstrap → empty file **with diagnostic header**, never a missing file.

---

## Phase 3 — per-process tree (`proc/<pid>/`)

- Materialise `read_dir(proc)` from the pslist walker → one `Dir` inode per pid (lazy; registry grows on first access).
- Per-pid files: `cmdline.txt`, `status.txt`, `maps.txt` (VAD/VMA), `modules.txt` (`walk_ldr_modules`), `handles.txt` [Win], `environ.txt`, and `mem` (the process `VirtualAddressSpace<P>` as a **sparse, range-read** stream — `read_file_range` translates per-page on demand; unmapped ranges read as zero-fill holes).
- Oracle: MemProcFS `pid/<pid>/{modules,handles,vmemd}`; MemNixFS `proc/<pid>/{maps,status}`.

---

## Phase 4 — forensic findings (`forensic/`)

- `forensic/timeline.jsonl` — stream `memf-correlate::ForensicEvent` sorted (reuse the timeline-query typed layer).
- `forensic/findevil.txt` — **aggregated verdict** (MemNixFS model): combine memf's `malfind`/hollowing/APC/suspicious-threads + hidden kernel modules + suspicious netconns into one ranked "is this box owned?" file. memf has every component; this is the aggregation memf currently lacks.
- `forensic/injected/<pid>-<va>` — one file per hit, raw region bytes (for `strings`/`xxd`/yara).
- `forensic/strings.txt` — ranked `memf-strings`.

---

## Phase 5 — file recovery (`fs/`) + raw (`mem/`)

- `fs/` — Linux tmpfs/ramfs page-cache files (`memf-linux::tmpfs_recovery`, `fs.rs`); Windows mapped files / MFT-resident content. Lazy per-file.
- `mem/physical` — the whole physical AS as one sparse file (pure range passthrough; the simplest, do early if useful for `dd`/yara workflows).

---

## Phase 6 — cross-platform mount backend

- Linux/macOS via `fuser` already works (disk path). Memory tree reuses it.
- Windows: the README marks WinFsp as a stub. Implement the WinFsp adapter against the **same `ForensicFs`/`MemoryFs`** (MemNixFS's `winfsp_mount.cpp` is the reference for stateless callbacks + delay-loaded DLL). Gate behind the existing Windows path so non-Windows builds are unaffected.

---

## Risks & open questions

- **Bootstrap coverage:** `build_analysis_context` must cover both OSes from a bare provider. If Linux symbol *addresses* still need an ISF (memf's BTF gives layouts, not addresses — no kallsyms today), the MemNixFS BTF-symbol-free parity is *partial* until a kallsyms address-recovery path lands. **Surface this honestly in `sys/os-info.txt`** (`Symbol source: BTF (layouts) + ISF (addresses)` vs `BTF only`); track kallsyms as a separate memf item, do not fake it.
- **FUSE metadata for synthetic files:** size is unknown before generation. Report `0` and let `read_file` return the real bytes (tools tolerate this), or generate-on-`getattr` for small artifacts; decide per-artifact, test both `stat` then `cat`.
- **Concurrency:** FUSE calls are concurrent; the LRU cache + provider need `Send`/`Sync` (or a per-mount lock). Bench a large dump before declaring done.
- **Don't regress the disk path:** every change to the shared mount/inode layer keeps the 96 existing tests green.

---

## Process notes

- Strict TDD, **separate RED and GREEN commits** per task. Gitsign (credential-cache daemon for any subagents). Verify the *real* `cargo`/clippy exit, not the rtk summary.
- Phase 0 is in `memory-forensic` (worktree-isolated); Phases 1+ are in `4n6mount`.
- When a later phase starts, expand it into its own `docs/plans/` doc at this granularity. This file is the spine.
