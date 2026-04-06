# 4n6mount

**Mount forensic images as a filesystem. Browse evidence like files. Write without touching the original.**

One command turns a forensic disk image into a mounted filesystem with read-only evidence access, a writable copy-on-write overlay, deleted file recovery, forensic timelines, and hash-based filtering — all without modifying a single byte of the original image.

## Why this exists

Forensic examiners spend too much time on tooling friction:

- **Mounting images read-only** works, but you can't run grep, save notes, or pipe output to files on the same mount
- **Copying evidence** breaks chain of custody and wastes disk space
- **GUI-only tools** don't fit into scripted workflows or CI pipelines
- **Known-good file filtering** requires separate tools with separate hash databases

4n6mount solves all of these. Mount once. Browse evidence in `ro/`. Run analysis tools against `rw/` (writes go to a sidecar, never the image). Filter out OS noise in `evidence/`. Everything in one mount, one command.

## Quick start

```bash
# Mount an ext4 image
4n6mount image.dd /mnt/evidence

# Auto-detects filesystem type (ext4, NTFS, exFAT)
# Creates virtual directories:
ls /mnt/evidence/
#   ro/          - read-only pristine evidence
#   rw/          - writable (COW overlay, image untouched)
#   deleted/     - recovered deleted files
#   journal/     - journal transaction snapshots
#   metadata/    - superblock.json, timeline.jsonl
#   unallocated/ - raw unallocated block ranges
#   session/     - session state
```

## The virtual directory layout

```
/mnt/evidence/
├── ro/              Read-only. Pristine evidence. Never modified.
├── rw/              Writable. Copy-on-write overlay.
│                    All writes go to a sidecar directory.
│                    Identical to ro/ until you write something.
├── deleted/         Recovered deleted files: {inode}_{name}
├── journal/         Journal transaction snapshots
├── metadata/        superblock.json, timeline.jsonl
├── unallocated/     Raw unallocated block data
├── evidence/        Like rw/, but known-good files hidden
│                    (only when --filter-db is provided)
└── session/         Session metadata
```

## Key features

### Write without modifying evidence

```bash
# Run grep on the evidence, save results — image is untouched
grep -r "password" /mnt/evidence/rw/ > /mnt/evidence/rw/grep-results.txt

# Your analysis tools work normally
strings /mnt/evidence/rw/var/log/auth.log | sort -u > /mnt/evidence/rw/unique-strings.txt
```

All writes go to a **sidecar directory** alongside the image. The original image is never modified. Session export packages the sidecar for sharing with other examiners.

### Filter known-good files

```bash
# Mount with NSRL database — evidence/ hides known OS/app files
4n6mount image.dd /mnt/evidence --filter-db /path/to/nsrl.db

# Only see files that matter
ls /mnt/evidence/evidence/home/suspect/
```

Supports **NSRL RDSv3** (SQLite), **HashKeeper** (CSV), and **custom hash lists** (one MD5 per line).

### Session persistence

```bash
# Start analysis with a session
4n6mount image.dd /mnt/evidence --session ./case-001

# Come back later
4n6mount image.dd /mnt/evidence --session ./case-001 --resume

# Share with another examiner
4n6mount --export-session ./case-001 --output case-001.tar.gz

# They import and continue
4n6mount --import-session case-001.tar.gz --session ./case-001-copy
```

Image hash (SHA-256) is verified on resume — detects evidence tampering.

### Daemon mode

```bash
# Background mount
4n6mount image.dd /mnt/evidence --daemon

# Foreground (default) — Ctrl+C to unmount
4n6mount image.dd /mnt/evidence
```

## Filesystem support

| Filesystem | Status | Feature flag |
|-----------|--------|-------------|
| **ext4** | Supported | `--features ext4` (default) |
| NTFS | Planned | `--features ntfs` |
| exFAT | Planned | `--features exfat` |
| HFS+ | Planned | `--features hfsplus` |
| APFS | Planned | `--features apfs` |

Auto-detection via magic numbers. Override with `--fs ext4`.

## Platform support

| Platform | FUSE backend | Status |
|----------|-------------|--------|
| **Linux** | fuser (libfuse) | Supported |
| **macOS** | fuser (macFUSE) | Supported |
| **Windows** | WinFSP | Stub (in progress) |

## Install

```bash
cargo install forensic-mount
```

Or build from source:

```bash
git clone https://github.com/SecurityRonin/4n6mount
cd 4n6mount
cargo build --release
# Binary at target/release/4n6mount
```

## The ForensicFs trait

4n6mount is also a **library**. Any forensic filesystem parser can plug in by implementing the `ForensicFs` trait:

```rust
use forensic_mount::{ForensicFs, FsDirEntry, FsMetadata, FsResult};

impl ForensicFs for MyFilesystemParser {
    fn root_ino(&self) -> u64 { 2 }
    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> { /* ... */ }
    fn lookup(&mut self, parent: u64, name: &[u8]) -> FsResult<Option<u64>> { /* ... */ }
    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> { /* ... */ }
    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> { /* ... */ }
    fn read_file_range(&mut self, ino: u64, off: u64, len: u64) -> FsResult<Vec<u8>> { /* ... */ }
    fn read_link(&mut self, ino: u64) -> FsResult<Vec<u8>> { /* ... */ }
    
    // Optional forensic ops — default implementations return empty/unsupported
    fn deleted_inodes(&mut self) -> FsResult<Vec<FsDeletedInode>> { /* ... */ }
    fn recover_file(&mut self, ino: u64) -> FsResult<FsRecoveryResult> { /* ... */ }
    fn timeline(&mut self) -> FsResult<Vec<FsTimelineEvent>> { /* ... */ }
    // ...
}
```

You get ro/, rw/, deleted/, journal/, metadata/, session management, and evidence filtering for free.

## Test coverage

- **96 tests** across library modules (FUSE callbacks, inode mapping, session, filter, detect, ext4 impl)
- Mock-based FUSE testing with `MockForensicFs`
- CLI parsing tests for all argument combinations

## Part of the SecurityRonin forensic suite

| Tool | Purpose |
|------|---------|
| [**ext4fs-forensic**](https://github.com/SecurityRonin/ext4fs-forensic) | ext4 filesystem parser with 12 forensic capabilities |
| [**ewf**](https://github.com/SecurityRonin/ewf) | E01/EWF forensic disk image reader |
| [**blazehash**](https://github.com/SecurityRonin/blazehash) | Forensic file hasher — hashdeep for the modern era |
| **4n6mount** | Universal forensic FUSE mount (this crate) |

All pure Rust. All MIT licensed. All designed to work together.

## Acknowledgments

This project builds on decades of work by the digital forensics community:

- **Brian Carrier** — for [The Sleuth Kit](https://www.sleuthkit.org/) and [Autopsy](https://www.autopsy.com/), which defined how forensic tools interact with filesystems and set the standard every tool since has followed
- **Rob T. Lee** — for [SANS FOR508](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/), which taught me that forensic analysis is about timelines, evidence integrity, and telling the story of what happened (GCFA #285)
- **Jesse Kornblum** — for [hashdeep](https://github.com/jessek/hashdeep) and md5deep, the original forensic hashing tools that [blazehash](https://github.com/SecurityRonin/blazehash) carries forward

## License

MIT
