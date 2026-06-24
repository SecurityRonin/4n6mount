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
