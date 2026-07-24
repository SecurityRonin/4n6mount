# 4n6mount

**Mount forensic images as a filesystem. Browse evidence like files. Write without touching the original.**

```bash
# Auto-detects the format and mounts it
4n6mount image.dd /mnt/evidence

ls /mnt/evidence/
#   ro/          - read-only pristine evidence
#   rw/          - writable copy-on-write overlay (image untouched)
#   deleted/     - recovered deleted files
#   journal/     - journal transaction snapshots
#   metadata/    - superblock.json, timeline.jsonl
#   unallocated/ - raw unallocated block ranges
#   session/     - session state
```

**[GitHub Repository →](https://github.com/SecurityRonin/4n6mount)**

---

## What it does

4n6mount turns a forensic disk image — or an archive, or a memory dump — into a mounted filesystem. One command gives you read-only evidence access, a writable copy-on-write overlay, deleted-file recovery, forensic timelines, and hash-based filtering, all without modifying a single byte of the original.

Writes go to a sidecar directory alongside the image, so you can `grep`, save notes, and pipe output to files on the same mount while the evidence stays pristine. Known-good files (NSRL, HashKeeper, custom hash lists) can be filtered out so `evidence/` shows only what matters.

---

## Formats it mounts

Auto-detection is by magic number; override with `--fs <type>`. Each format is validated against real-world data with an independent oracle (The Sleuth Kit, the OS's own driver, or Volatility) — never a self-encoded round-trip.

- **Filesystems** — ext4, NTFS, exFAT, HFS+/HFSX, ISO 9660 / UDF, APFS (read-only)
- **Containers** — EWF (`.E01`), VMDK, AFF4; the inner filesystem is detected and mounted transparently
- **Logical images** — AccessData AD1 and AFF4-Logical, mounted as a browsable tree (read lazily)
- **Archives** — zip, 7-Zip, tar.gz, tar.bz2, mounted as a read-only tree
- **Memory dumps** — LiME, AVML, ELF core, Windows crash dump, browsed as a filesystem (the MemProcFS paradigm), backed by the [memf](https://github.com/SecurityRonin/memory-forensic) library

---

## Platforms

| Platform | Mount backend | Status |
|---|---|---|
| Linux | fuser (libfuse) | Supported |
| macOS | fuser (macFUSE) | Supported |
| Windows | Dokan | Supported (read-only) |

---

## A library too

4n6mount is also a library: any forensic filesystem parser plugs in by implementing the `ForensicFs` trait, and gets `ro/`, `rw/`, `deleted/`, `journal/`, `metadata/`, session management, and evidence filtering for free.

---

## Part of the SecurityRonin forensic suite

4n6mount sits alongside [ext4fs-forensic](https://github.com/SecurityRonin/ext4fs-forensic), [ntfs-forensic](https://github.com/SecurityRonin/ntfs-forensic), [apfs-forensic](https://github.com/SecurityRonin/apfs-forensic), [ewf-forensic](https://github.com/SecurityRonin/ewf-forensic), [aff4](https://github.com/SecurityRonin/aff4-forensic), [memory-forensic](https://github.com/SecurityRonin/memory-forensic), and [blazehash](https://github.com/SecurityRonin/blazehash). All pure Rust, all Apache-2.0, all designed to work together.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/4n6mount) · © 2026 Security Ronin Ltd.
