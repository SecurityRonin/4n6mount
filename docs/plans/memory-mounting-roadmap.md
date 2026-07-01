# Memory mounting — roadmap

Current-state roadmap for mounting a memory image as a filesystem. The shipped
architecture and its rationale are in
[ADR 0003](../decisions/0003-memory-dump-mounting.md); this file tracks only the
**remaining** scope.

## Shipped (see ADR 0003)

- **Phase 0** — `memf-*` library seam.
- **Phase 1** — `MemoryFs` skeleton, dump detection + routing, `sys/os-info.txt`.
- **Phase 2** — `sys/processes.txt`, `sys/modules.txt`, `sys/network.txt`,
  `sys/dmesg.txt`. Mount-smoke covers the path on FUSE + Dokan.

## Remaining

Each item follows the shipped pattern: a pure `render_*` function (tier-3 unit
tests on synthetic records) behind a thin walker-calling glue, with the
fail-soft contract (a file always appears, with a diagnostic header on empty).

- **`sys/services.txt`** — Windows services + systemd units. Needs a memf
  services walker; deferred pending walker support.
- **`proc/<pid>/`** — per-process tree (cmdline, maps, handles, ...). A skeleton
  registry exists; the walker-to-tree mapping is unbuilt.
- **`forensic/`** — derived findings (suspicious injections, hidden processes,
  hollowing). Depends on memf's correlation layer.
- **`fs/` and `mem/`** — file recovery (cached files) and raw region export.
- **Tier-2 oracle validation** — mount real dumps and diff `sys/*` against
  MemProcFS / Volatility 3, env-gated on a dump corpus (`MEMF_TEST_DATA`);
  currently skipped in CI (no corpus on the dev host).

## Not planned here

Windows WinFsp-specific memory mounting is unnecessary — the Dokan backend
(`src/fuse_windows.rs`) already serves `MemoryFs` on Windows like any other
`ForensicFs`.
