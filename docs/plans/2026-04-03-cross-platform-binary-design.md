# 4n6mount Cross-Platform Binary — Design

## Goal
Add a cross-platform binary to 4n6mount that auto-detects filesystems, mounts via FUSE on macOS/Linux (fuser) and Windows (WinFSP), with compile-time feature flags for filesystem support.

## CLI
```bash
4n6mount mount <image> <mountpoint> [--fs ext4|ntfs|exfat] [--session <dir>] [--resume] [--daemon] [--filter-db <path>]
4n6mount export-session <session-dir> --output <tarball>
4n6mount import-session <tarball> --session <dir>
```

## Filesystem Detection
Auto-detect via magic numbers, `--fs` overrides:
- ext4: 0xEF53 at byte offset 1080
- NTFS: "NTFS" at byte offset 3
- exFAT: "EXFAT" at byte offset 3

## Feature Flags
```toml
[features]
default = ["ext4"]
ext4 = ["dep:ext4fs"]
# ntfs = ["dep:ntfsrs"]   # future
# exfat = ["dep:exfatrs"]  # future
```

## Cross-Platform FUSE
- macOS/Linux: `fuser` behind `#[cfg(unix)]`
- Windows: `winfsp-wrs` behind `#[cfg(windows)]`
- Shared logic in fusefs.rs (ForensicFuseFs struct, callbacks)
- Platform-specific mount entry point only

## Structure
```
src/
├── lib.rs           # ForensicFs trait + mount()
├── types.rs         # Filesystem-agnostic types
├── fusefs.rs        # FUSE callbacks (shared logic)
├── fuse_unix.rs     # #[cfg(unix)] fuser mount
├── fuse_windows.rs  # #[cfg(windows)] winfsp mount
├── inode_map.rs
├── session.rs
├── filter.rs
├── detect.rs        # Magic number detection
└── main.rs          # CLI + dispatch
```

## Notes
- ext4fs-fuse becomes obsolete (4n6mount replaces it with --features ext4)
- WinFSP requires winfsp-wrs crate
- Each filesystem impl maps its types to ForensicFs trait types
