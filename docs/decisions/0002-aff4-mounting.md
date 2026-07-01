# 2. AFF4 (Advanced Forensic Format 4) mounting

Date: 2026-07-01
Status: Accepted

## Context

AFF4 is the modern forensic container standard (Evimetry, aff4-imager,
pyaff4). Unlike EWF/AD1 it is a **ZIP archive** whose type is declared in an
`information.turtle` RDF document, and it comes in two mount shapes:

| AFF4 shape | RDF | Analogue |
|---|---|---|
| Disk image | `aff4:ImageStream` / `aff4:Map` | EWF / VMDK — a `Read + Seek` stream whose inner filesystem is mounted |
| AFF4-Logical | `aff4:FileImage` | AD1 — a file collection mounted as a synthetic tree |

Two facts shape the design:

1. **AFF4 has no magic bytes** — a byte probe sees only the ZIP `PK\x03\x04`, so
   it is indistinguishable from a plain ZIP without reading the turtle.
2. **Encrypted containers** (`aff4:EncryptedStream`, AES-XTS) hide the inner
   shape behind ciphertext and need a password.

## Decision

1. **Reuse the published `aff4` crate** (pure-Rust) rather than reimplement the
   parser; it is validated tier-1 against the real Evimetry reference images.
2. **Detection via a new `aff4::container_kind()`.** Rather than a fragile
   try-open heuristic in 4n6mount, a lightweight `container_kind(&Path)` was
   added to the `aff4` crate (published **0.2.1**) that reads `information.turtle`
   once and returns `Disk` / `Logical` / `Encrypted`. `detect::detect_aff4`
   refines an auto-detected `Zip` into `FsType::Aff4Disk` / `Aff4Logical`. A
   forced `--fs` is respected as-is.
3. **AFF4-Logical → `fs_aff4::Aff4ForensicFs`**, built directly from the path
   (AD1-like) over the shared `ArchiveTree`. AFF4-Logical has no positioned
   read, so `read_file_range` inflates the whole file and slices it (adequate
   for v1; a streaming API can be added upstream later).
4. **AFF4 disk image → `aff4::Aff4Reader`** (a `Read + Seek` source): open it,
   re-detect the inner filesystem, and mount it via `build_filesystem` — the
   same path as EWF/VMDK.
5. **Encrypted containers are refused loudly** at open (routed to the disk arm,
   whose passwordless `Aff4Reader::open` returns a named `Encrypted` error).
   Key-bearing decryption is a later epic.

## Consequences

- AFF4-Logical is the mount matrix's newest format, validated end-to-end on
  FUSE (Linux) and Dokan (Windows) via an `aff4::testutil`-built fixture
  (tier-2, spec-faithful writer).
- The AFF4 **disk** shape is deliberately not smoke-fixtured: the test writer is
  single-chunk and cannot wrap a real inner filesystem. Its correctness rests on
  `Aff4Reader`'s tier-1 validation in the `aff4` crate (real Evimetry images:
  virtual disk size, Snappy/sparse chunks, Map resolution) plus the
  EWF/VMDK-identical mount glue.
- `container_kind()` is a general, non-breaking addition to the `aff4` crate,
  useful to any downstream AFF4 consumer.

## Alternatives considered

- **Reimplement the AFF4 reader in 4n6mount** — rejected; the `aff4` crate exists,
  is pure-Rust, and is fuzzed + tier-1 validated.
- **Byte-magic detection** — impossible; AFF4 is a ZIP with no distinguishing
  signature.
- **Interim try-open detection inside `detect.rs`** — rejected in favour of the
  cleaner, cheaper `aff4::container_kind()` probe that reads the turtle once.
