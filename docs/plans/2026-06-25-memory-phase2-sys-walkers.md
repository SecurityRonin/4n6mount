# Memory Mounting — Phase 2: system-wide artifacts (`sys/`)

> Expansion of Phase 2 from `2026-06-25-memory-dump-mounting.md`. Strict TDD,
> separate RED/GREEN signed commits per task.

**Goal:** Populate `sys/` with the system-wide memf walkers — `processes.txt`,
`modules.txt`, `network.txt`, `services.txt`, `dmesg.txt` — each lazily rendered
on `read_file` by calling the existing memf walker and formatting its typed
result. 4n6mount adds **no forensics**; it maps walker output into VFS files.

## Structural prerequisite — `MemoryFs` carries an `ObjectReader`

Phase 1's `MemoryFs::new(provider, ctx)` is insufficient: the walkers need a
`&ObjectReader<P>` (virtual-address translation + struct layouts), not the raw
provider. From the grounded memf API:

- `VirtualAddressSpace::new(provider: P, page_table_root: u64, mode) -> VAS<P>` — consumes the provider, uses `ctx.cr3` as the DTB.
- `ObjectReader::new(vas, symbols: Box<dyn SymbolResolver>) -> ObjectReader<P>`; `reader.vas()` gives translation access back for `mem/physical`.
- `memf_windows::walk_processes(&ObjectReader<P>, ps_active_process_head) -> Result<Vec<WinProcessInfo>>` (`{pid, ppid, image_name, create_time, …}`); `memf_linux::walk_processes(...)` returns `ProcessInfo`.

**Change (Task 2.0, behaviour-preserving for Phase-1 tests):**
`MemoryFs::new(provider, ctx, symbols)` builds and stores `reader: ObjectReader<P>`
(from `provider` + `ctx.cr3` + `symbols`) instead of the bare provider. The OS
dictates which walker runs (`ctx.os`). `build_memory_fs` already has the resolver
— it stops dropping it. Phase-1 `sys/os-info.txt` and the tree tests still pass
(os-info renders from `ctx`, unchanged).

## Validation reality (honest, given no real-dump corpus on this host)

`MEMF_TEST_DATA` is unset, so the plan's **tier-2** oracle diff (mount the
szechuan/citadel dump, diff `sys/processes.txt` vs MemProcFS/vol3) **cannot run
here** and is deferred — gated on the corpus, documented in `tests/data/README.md`.

What memf already guarantees: the walkers themselves are validated *inside* memf
(memf's own tier-2 tests). 4n6mount's job is the **VFS mapping**, so Phase 2 tests
prove that, not the forensics, via the **Humble Object** split:

- **Pure render fns** (`render_process_table(&[WinProcessInfo]) -> String`, etc.) — unit-tested on hand-built records (**tier-3**, rendering correctness: columns, ordering, empties).
- **Fail-soft contract** — a walker error or empty result after a *good* bootstrap yields an **empty file with a one-line diagnostic header** (e.g. `# pslist: 0 processes (walker returned empty)`), never a missing file or silent empty (the memf "kernel base 6 MiB off" lesson). Unit-tested.
- **End-to-end glue** — on the synthetic crash dump (`examples/mkdump`), `read_file(sys/processes.txt)` exercises the real walker call and must not panic; it surfaces the diagnostic header (no real EPROCESS list in a header-only synthetic dump). Proves the call path + fail-soft, not pslist correctness.
- **Tier-2** (real pslist parity) runs when a dump is present — env-gated test, skips cleanly otherwise.

memf-windows' richer synthetic-EPROCESS fixtures are `#[cfg(test)]` (not exported), so 4n6mount does **not** reimplement them — that would duplicate memf's fixtures and re-test memf's forensics. We test our mapping; memf tests its walkers.

## Tasks (each RED → GREEN, signed)

- **2.0** `MemoryFs` carries `ObjectReader` (`new(provider, ctx, symbols)`); Phase-1 tests green.
- **2.1** `sys/processes.txt` — `render_process_table` + lazy artifact + fail-soft header; OS-dispatch (Win/Linux walker).
- **2.2** `sys/modules.txt` — kernel modules/drivers (`walk_*` modules).
- **2.3** `sys/network.txt` — netscan (tcp/udp + owner pid).
- **2.4** `sys/services.txt` — services / systemd units.
- **2.5** `sys/dmesg.txt` — Linux kernel ring buffer.

Each new artifact: an `Artifact::Sys*` registry node under `sys/`, a pure render
fn (tier-3 tested), and the fail-soft diagnostic-header contract.

## Risks

- **macOS dumps:** `ctx.os == MacOs` has no process walker in memf — the artifact returns a clear "not implemented for macOS" header, never fabricated content.
- **Symbols for raw/Linux dumps:** without `--symbols` the bootstrap may resolve OS but not list-heads; `sys/processes.txt` then shows the diagnostic header. os-info already surfaces the symbol gap honestly.
- **Provider ownership:** `ObjectReader` owns the provider (via VAS); `mem/physical` (Phase 5) reads through `reader.vas()`, not a separate provider handle.
