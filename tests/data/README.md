# `4n6mount` test fixtures

Per-file provenance for committed test data. Large artifacts (real disk images,
memory dumps) are **not** committed — they are documented here, gitignored, and
read in place via an env var, skipping cleanly when absent. Small, clearly
self-licensed fixtures are committed with their md5 below.

## Committed fixtures

### `hfsplus.img`

- **Source / Identity:** a 512 KiB HFS+ volume minted locally on macOS with the
  OS-native tooling — `hdiutil create -size 512k -fs HFS+ -volname HFSTEST
  -layout NONE` (no partition map, so the HFS+ volume header sits at byte 1024),
  populated by the macOS HFS+ driver, then flattened to a raw image with
  `hdiutil convert -format UDTO`.
- **Authoring engine = independent oracle:** the bytes were written by Apple's
  HFS+ implementation, not by the parser under test, so reads are validated
  against a real engine's output (doer-checker). Ground truth is additionally
  cross-checked with The Sleuth Kit (`fls`/`icat`).
- **Contents (TSK `fls`):** `hello.txt` (CNID 18, `"hello from hfsplus\n"`) and
  `sub/` (CNID 19) holding `deep.txt` (`"deep hfs content\n"`).
- **Used by:** `src/fs_hfsplus.rs` unit tests.
- **License:** CC0 / public-domain — synthetic, authored here, no third-party
  content.

| File | Bytes | MD5 |
|---|---|---|
| `hfsplus.img` | 524288 | `bf744eb64ff2c4ce0948d78474298d3a` |

### `exfat.img`

- **Source / Identity:** a 1 MiB exFAT volume minted locally on macOS with
  OS-native tooling — `hdiutil create -size 1m -fs ExFAT -volname EXFTEST
  -layout NONE`, populated by the macOS exFAT driver, flattened to a raw image
  with `hdiutil convert -format UDTO`.
- **Authoring engine = independent oracle:** bytes written by Apple's exFAT
  implementation, cross-checked with TSK `fls`/`icat`.
- **Contents (TSK `fls`):** `hello.txt` (`"hello from exfat\n"`) and `sub/`
  holding `deep.txt` (`"deep exfat content\n"`).
- **Used by:** `src/fs_exfat.rs` unit tests.
- **License:** CC0 / public-domain — synthetic, authored here.

| File | Bytes | MD5 |
|---|---|---|
| `exfat.img` | 1048576 | `7265865c090f13d699532e0f70ee3610` |

## Referenced (not committed) corpora

- **NTFS:** `SampleTinyNtfsVolume/partition.dd` (real NTFS volume from
  [jschicht/LogFileParser](https://github.com/jschicht/LogFileParser)), consumed
  in place from the sibling `ntfs-forensic/tests/data/SampleTinyNtfsVolume.zip`.
  Ground truth via TSK `fls`/`icat` (root holds `file1.txt`..`file8.txt` +
  `$RECYCLE.BIN`; `file1.txt` is MFT record 37). `src/fs_ntfs.rs` skips cleanly
  if the corpus or `unzip` is absent.
- **Archives (zip / tar.gz / 7z):** minted at test time with the system
  `zip` / `tar` / `7z` CLIs (independent oracles); tests skip if a tool is
  missing.

### `apfs.img`

- **Source / Identity:** a 2 MiB APFS container minted locally on macOS with
  Apple's own tooling — `hdiutil create -size 2m -fs APFS`, populated by the
  macOS APFS driver, flattened (`hdiutil convert -format UDTO`) and the APFS
  partition carved out (`dd skip=40`).
- **Authoring engine = independent oracle:** bytes written by Apple's APFS
  implementation.
- **Contents:** `hello.txt` (`"hello from apfs\n"`) and `sub/deep.txt`.
- **Used by:** the mount smoke matrix (`scripts/smoke/manifest.tsv`, `apfs` row).
- **License:** CC0 / public-domain — synthetic, authored here.

### `crash.dmp`

- **Source / Identity:** an 8 KiB synthetic Windows kernel crash dump (PAGEDU64)
  produced by `cargo run --features memory --example mkdump` (memf's
  `CrashDumpBuilder`). Tier-3 (self-authored) — exercises the memory-mount
  plumbing only; real-dump forensic parity is covered by env-gated corpora.
- **Contents:** a minimal header (CR3 + machine type) so the analysis bootstrap
  resolves OS = Windows; `sys/os-info.txt` renders the profile.
- **Used by:** the mount smoke matrix (`memory` row).
- **License:** CC0 / public-domain — synthetic, authored here.

### `ad1.ad1`

- **Source / Identity:** a 1150-byte AccessData AD1 logical image built by
  `ad1-core`'s spec-faithful `testfix` writer (independent flate2 zlib +
  RustCrypto hashes), holding the single tree `root/hello.txt`.
- **Reproduce:** `Node::Dir("root", [Node::File("hello.txt", b"hello from ad1\n")])`
  → `ad1::testfix::build(tree).bytes`, verified to read back through
  `Ad1ForensicFs`.
- **Contents:** `root/hello.txt` (`"hello from ad1\n"`).
- **Used by:** the mount smoke matrix (`ad1` row).
- **License:** CC0 / public-domain — synthetic, authored here.

| File | Bytes | MD5 |
|---|---|---|
| `ad1.ad1` | 1150 | `e9295f14974e0e661b58f234f34a0273` |
