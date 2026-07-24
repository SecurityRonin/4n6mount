# 4n6mount

**Mount forensic images as a filesystem. Browse evidence like files. Write without touching the original.**

One command turns a forensic disk image — or an archive, or a **memory dump** — into a mounted filesystem with read-only evidence access, a writable copy-on-write overlay, deleted file recovery, forensic timelines, and hash-based filtering, all without modifying a single byte of the original. Disk filesystems (ext4, NTFS, exFAT, HFS+, APFS, ISO9660), EWF/VMDK/AFF4 containers, AccessData AD1 and AFF4-Logical images, zip/7z/tar archives, and memory dumps all mount through one command.

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

# Auto-detects the format: filesystems (ext4 / NTFS / exFAT / HFS+ / APFS /
# ISO9660), EWF / VMDK / AFF4 containers, AD1 & AFF4-Logical images,
# zip / 7z / tar.gz / tar.bz2 archives, and
# memory dumps (LiME / AVML / ELF-core / Windows crash dump)
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

## Format support

Auto-detection is by magic number; override with `--fs <type>`. Every format is
validated against real-world data with an independent oracle (The Sleuth Kit, or
the OS's own driver) — never a self-encoded round-trip.

### Filesystems

| Filesystem | Status | Feature flag | Validated against |
|-----------|--------|-------------|-------------------|
| **ext4** | Supported | `ext4` (default) | real ext4 image |
| **NTFS** | Supported | `ntfs` (default) | real NTFS volume, TSK `fls`/`icat` |
| **exFAT** | Supported | `exfat` (default) | macOS-minted volume, TSK oracle |
| **HFS+ / HFSX** | Supported | `hfsplus` (default) | macOS-minted volume, TSK oracle |
| **ISO 9660 / UDF** | Supported | `iso` (default) | Rock Ridge ISO |
| **APFS** | Supported (read-only) | `apfs` (default) | real APFS container carve, TSK `fls`/`istat` |

APFS mounts the container's live volume (point-in-time view) via `apfs-core`.
Encrypted (FileVault) APFS volumes are not yet supported — apfs-core's
encryption path is still in progress, so a sealed/encrypted volume surfaces a
clear error rather than wrong output.

### Archives

Archives mount as a browsable read-only tree (their entries become files).

| Archive | Status | Feature flag | Validated against |
|---------|--------|-------------|-------------------|
| **zip** | Supported | `zip` (default) | real `zip`-tool output |
| **7-Zip (.7z)** | Supported | `sevenz` (default) | real `7z`-tool output |
| **tar.gz / .tgz** | Supported | `tarball` (default) | real `tar`-tool output |
| **tar.bz2 / .tbz2** | Supported | `tarball` (default) | real `tar -j` output |

### Containers

`EWF` (`.E01`), `VMDK`, and `AFF4` disk images are opened transparently and their
**inner** filesystem (ext4 / NTFS / exFAT / HFS+ / APFS / ISO) is detected and
mounted; an unrecognized inner volume falls back to a single raw file. AFF4 is a
ZIP-based container with no magic bytes, so its shape is read from the embedded
`information.turtle` (via `aff4`'s `container_kind`).

### Logical images

`AD1` (AccessData logical image) and `AFF4-Logical` are **file collections**, not
disk images, so they mount as a browsable tree like an archive. Both read
**lazily** — a large image is browsed without full extraction. Encrypted AD1
(`ADCRYPT`) and encrypted AFF4 are refused with a clear error, never mounted as
garbage.

| Logical image | Status | Feature flag | Validated against |
|---------------|--------|-------------|-------------------|
| **AD1** | Supported | `ad1` (default) | `ad1-core` testfix oracle (independent zlib + hashes) |
| **AFF4-Logical** | Supported | `aff4` (default) | `aff4` testutil oracle; real Evimetry / pyaff4 images |

### Memory dumps

Point a memory dump at a mountpoint and browse it as a filesystem — the
MemProcFS / MemNixFS paradigm, backed by the [memf](https://github.com/SecurityRonin/memory-forensic)
analysis library. The dump mounts read-only with a `sys/ proc/ forensic/ mem/`
layout (no disk overlay); each artifact is rendered lazily from a memf walker.

```bash
4n6mount memory.lime /mnt/case --features memory
cat /mnt/case/sys/os-info.txt        # OS, DTB/CR3, kernel symbols
cat /mnt/case/sys/processes.txt      # pslist
cat /mnt/case/sys/network.txt        # connections (netscan)
```

| Format | Detection | Feature flag |
|--------|-----------|-------------|
| **LiME** | `EMiL` magic | `memory` |
| **AVML** | `AVML` magic | `memory` |
| **ELF core dump** | ELF + `ET_CORE` | `memory` |
| **Windows crash dump** | `PAGEDU64` magic | `memory` |
| raw / headerless | `--fs memory` | `memory` |

Working `sys/` artifacts: `os-info`, `processes`, `modules`, `network`
(Linux + Windows), `dmesg` (Linux). A walker that finds nothing after a valid
bootstrap yields an empty file with a one-line diagnostic — never a silent
empty or a fabricated result. Per-process `proc/<pid>/`, `forensic/`, and raw
`mem/` views are in progress. The `memory` feature is opt-in (not default).

## Platform support

| Platform | Mount backend | Status |
|----------|--------------|--------|
| **Linux** | fuser (libfuse) | Supported |
| **macOS** | fuser (macFUSE) | Supported |
| **Windows** | Dokan | Supported (read-only) |

On Windows the filesystem tree is presented read-only at the mount point (no
`ro/`/`rw/` overlay — that's the Unix backend's model); install the
[Dokany](https://github.com/dokan-dev/dokany/releases) library first. The Dokan
bindings are MIT-licensed and the Dokany runtime is LGPL/MIT, so no copyleft
code is linked into the binary.

### Recovered-deleted marking (ADR-0008)

A metadata-recovered deleted or orphan file is marked out-of-band, at its real
name, through one logical schema rendered on each platform's native channel:

- **Unix** (macFUSE / Linux): extended attributes `user.4n6.status`
  (`deleted` / `orphan`) and `user.4n6.macb.{modified,accessed,changed,born}`
  (ISO-8601 UTC). Read them with `getfattr -n user.4n6.status <file>`.
- **Windows** (Dokan): NTFS Alternate Data Streams `<name>:4n6.status` and
  `<name>:4n6.macb`, enumerated by `find_streams`. Read them with
  `Get-Item -Stream 4n6.status <file>` or `Get-Content <file>:4n6.status`.

Both render from one cross-platform schema module, so the bytes are identical
between the channels; the schema values are unit-tested on every platform. The
Windows ADS channel is implemented; because Dokan is Windows-only it is verified
on a Windows runner (the Dokan mount-smoke matrix), not by the macOS/Linux
`cargo test`.

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

- **End-to-end mount smoke matrix** (`scripts/smoke/`, CI): every format is mounted and a known file is **read back through the mount** — on both **FUSE (Linux)** and **Dokan (Windows)**. All 15 formats pass on both backends, enforced on every push.
- **208 library tests** (more with the `memory` feature) across FUSE callbacks, inode mapping, session, filter, format detection, and every filesystem/archive/logical-image/memory backend
- Each format validated against **real-world data with an independent oracle** (The Sleuth Kit, the OS's own driver, or Volatility) — not a self-encoded round-trip
- Mock-based FUSE testing with `MockForensicFs`; CLI parsing tests for all argument combinations
- **On-demand archive-read e2e** (`tests/e2e_archive_read.rs`): reads a real `.zip` through the same archive reader the mount peels evidence with (`archive_core::Archive`), picks the member at the 66% position, and asserts its content magic matches its extension (advancing past members whose type can't be determined). Synthetic unit tests run in CI; the real-data leg is env-gated:

  ```sh
  FN_E2E_ARCHIVE_ZIP=~/src/issen/tests/data/dfirmadness-szechuan-sauce/case001-pcap.zip \
    cargo test --test e2e_archive_read -- --nocapture
  ```

  It skips cleanly when `FN_E2E_ARCHIVE_ZIP` is unset or the file is absent.

## Part of the SecurityRonin forensic suite

| Tool | Purpose |
|------|---------|
| [**ext4fs-forensic**](https://github.com/SecurityRonin/ext4fs-forensic) | ext4 filesystem parser with forensic capabilities |
| [**ntfs-forensic**](https://github.com/SecurityRonin/ntfs-forensic) | NTFS parser (MFT, `$DATA`, ADS, LZNT1) |
| [**apfs-forensic**](https://github.com/SecurityRonin/apfs-forensic) | APFS container + volume reader |
| [**ewf-forensic**](https://github.com/SecurityRonin/ewf-forensic) | E01/EWF forensic disk image reader |
| [**aff4**](https://github.com/SecurityRonin/aff4-forensic) | AFF4 reader (disk + logical, AES-XTS decrypt) |
| [**ad1-core**](https://github.com/SecurityRonin/ad1-forensic) | AccessData AD1 logical-image reader |
| [**memory-forensic** (memf)](https://github.com/SecurityRonin/memory-forensic) | Memory-dump analysis (Volatility-parity walkers) |
| [**blazehash**](https://github.com/SecurityRonin/blazehash) | Forensic file hasher — hashdeep for the modern era |
| **4n6mount** | Universal forensic FUSE mount (this crate) |

All pure Rust. All Apache-2.0 licensed. All designed to work together.

## Acknowledgments

This project builds on decades of work by the digital forensics community:

- **Brian Carrier** — for [The Sleuth Kit](https://www.sleuthkit.org/) and [Autopsy](https://www.autopsy.com/), which defined how forensic tools interact with filesystems and set the standard every tool since has followed
- **Rob T. Lee** — for [SANS FOR508](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/), which taught me that forensic analysis is about timelines, evidence integrity, and telling the story of what happened (GCFA #285)

## License

Apache-2.0

---

[Privacy Policy](https://securityronin.github.io/4n6mount/privacy/) · [Terms of Service](https://securityronin.github.io/4n6mount/terms/) · © 2026 Security Ronin Ltd
