# Deletion-Recoverability Corpus — Initial Results (macOS filesystems)

**Status: partial — the four macOS-native filesystems ran; the Linux filesystems
are deferred to a Linux runner (protocol below).** This is the first iteration of
the pre-registered validation protocol in [`../deletion-sok.md`](../deletion-sok.md)
§7. It is Tier-1 by the fleet standard: real filesystems, real drivers, real
deletions, measured residue — no synthetic self-fixtures.

## Executive Summary

- **What ran:** FAT32, exFAT, HFS+, and APFS, each built as a real filesystem in
  a raw disk image on the host, populated with a fixed 6-file manifest spanning
  the residue-relevant classes, deleted, churned, and snapshotted at T0
  (post-populate) / T1 (post-delete) / T2 (post-churn). Residue was measured per
  (file, layer, time-point) using **The Sleuth Kit 4.12.1 as an independent
  oracle** (L1 name via `fls -rd`, L2 map via `icat` reconstruction) plus a
  filesystem-agnostic per-chunk marker byte-scan for L3 content survival.
- **Scored cells:** 66 (24 L1 + 18 L2 + 24 L3; APFS L2 excluded — mainline TSK
  has no APFS map reader). This is a **small corpus**; every figure below is
  reported with its n and an exact binomial confidence interval, and nothing is
  extrapolated beyond the cells tested.
- **Headline (T1, the immediate-post-delete residue the models describe):** the
  two-axis model scored **52/66 = 78.8% [67.0, 87.9]**; the Axis-A-only and
  Carrier-category baselines **tied at 49/66 = 74.2% [62.0, 84.2]**. The two-axis
  model is **directionally higher but its interval overlaps both baselines**.
- **Verdict, by the protocol's own pre-registered criterion:** the two-axis model
  does **not** beat both baselines with non-overlapping intervals, so **§2.2
  remains descriptive organization, not a validated predictor** — exactly the
  outcome §7 was written to test honestly. The two-axis edge is concentrated in
  the two cells where its extra structure bites: **L2 (61.1% vs 50.0%)** — the
  fragmented-file map-loss discriminator — and **L1 (75.0% vs 70.8%)** — the FAT
  8.3 first-byte tombstone. Both are Axis-B / update-strategy effects the
  baselines are blind to; the corpus is too small for the edge to reach
  significance. The Linux filesystems (ext3 policy-zeroing, XFS freetag, Btrfs/
  F2FS COW) are the cells expected to discriminate the models more sharply.
- **The paper's central descriptive claim is directly corroborated:** the three
  layers do **not** fail in lockstep. Measured counterexamples below.

## Host and Tooling

| | |
|---|---|
| Host | macOS 15.7.8 (build 24G809), Apple Silicon (arm64) |
| Image build | `hdiutil` raw CRawDiskImage + `newfs_msdos` / `newfs_exfat` / `newfs_hfs` / `diskutil apfs`; **no sudo** |
| Oracle (L1/L2) | The Sleuth Kit 4.12.1 (`fls`, `istat`, `icat`) — an independent third-party reference tool |
| L3 measure | per-chunk marker byte-scan (fragmentation-robust, filesystem-agnostic) |
| Reproduce | `./run_all.sh` (rebuilds all four, re-measures, re-scores) |

**Why TSK as the oracle rather than the fleet's own readers.** Doer-Checker: the
paper's claims are validated against an *independent* implementation, not our own
code that shares its authors' blind spots. TSK is the reference operationalization
of Carrier's category model the paper builds on. APFS is the one format TSK cannot
parse; there L1/L3 fall back to the byte-scan and L2 is reported unmeasured.

## The Corpus (fixed manifest)

Six files per filesystem, spanning the §7 residue-relevant axes. Content is
deterministic (reproducible from a per-file nonce) and built from 512-byte chunks
each carrying a unique greppable marker `<nonce>#NNNNN#`, so L3 survival is
measurable by raw scan even under fragmentation. Exact names, sizes, and SHA-256s
are in `results/manifest_<fs>.json`.

| id | name | size | class exercised |
|---|---|---|---|
| short83 | `AB.TXT` | 512 B | tiny, 8.3 short name (FAT tombstone target) |
| lfn | `evidence_report_final_copy.txt` | 512 B | tiny, long (LFN) name |
| unicode | `秘密資料.txt` | 512 B | tiny, non-ASCII name |
| deep | `d1/d2/d3/d4/nested_secret.txt` | 512 B | deep path |
| contig | `big_contiguous_blob.bin` | 128 KB | large, single-extent |
| frag | `fragmented_blob.bin` | 128 KB | large, **deliberately fragmented** |

Fragmentation is forced by filling the volume, punching alternating 64 KB holes,
then writing the 128 KB target so no contiguous 128 KB run remains — verified via
`istat` sector runs (frag = 2–3 non-adjacent runs; contig = 1 run). This is what
turns the fragmented file into the L2 discriminator: only a filesystem that
*retains its real extent map* reproduces it; FAT's zeroed chain forces a
contiguity assumption that fails.

## Measured Outcomes

Outcome vocabularies: **L1** {full, partial, none}; **L2** {sufficient, partial,
none}; **L3** {match, partial, none}. Operational definitions:

- **L1** — `fls -rd` recovers the deleted entry's name. `full` = recovered name
  equals original; `partial` = a truncated/first-char-lost form (e.g. FAT 8.3
  tombstone renders `AB.TXT` as `_B.TXT`); `none` = not recovered from the live
  structure (and, cross-checked, absent from the raw image on a byte-scan). APFS:
  byte-scan for the name (UTF-8/UTF-16).
- **L2** — `icat` reconstructs content *using only the recovered map*.
  `sufficient` = output hash equals the manifest hash (map alone yielded the
  correct full content); `partial` = non-empty but incomplete (e.g. FAT's
  contiguity guess recovers a fragmented file's first extent only); `none` =
  empty/error / no data units. APFS: `na` (no TSK map reader).
- **L3** — surviving per-chunk markers / total, read straight from the raw image
  (independent of the map). `match` = all chunks present; `partial` = some;
  `none` = zero.

| FS | file (class) | L1 T1 | L2 T1 | L3 T1 | L1 T2 | L2 T2 | L3 T2 |
|---|---|---|---|---|---|---|---|
| FAT | short83 (8.3) | **partial** | sufficient | match | partial | none | none |
| FAT | lfn | full | sufficient | match | partial | none | none |
| FAT | unicode | full | sufficient | match | partial | none | none |
| FAT | deep | full | sufficient | match | full | none | none |
| FAT | contig | full | sufficient | match | partial | none | none |
| FAT | frag | full | **partial** | match | full | partial | match |
| exFAT | short83 (8.3) | **full** | sufficient | match | partial | none | none |
| exFAT | lfn | full | sufficient | match | none | none | none |
| exFAT | unicode | full | sufficient | match | none | none | none |
| exFAT | deep | full | sufficient | match | full | none | none |
| exFAT | contig | full | **partial** | partial (254/256) | partial | none | none |
| exFAT | frag | full | **partial** | match | full | partial | match |
| HFS+ | short83 | **none** | **none** | match | none | none | none |
| HFS+ | lfn | none | none | match | none | none | none |
| HFS+ | unicode | none | none | match | none | none | none |
| HFS+ | deep | none | none | match | none | none | none |
| HFS+ | contig | none | none | match | none | none | none |
| HFS+ | frag | none | none | match | none | none | partial (96/256) |
| APFS | short83 | full | na | match | full | na | match |
| APFS | lfn | full | na | match | full | na | match |
| APFS | unicode | full | na | match | full | na | match |
| APFS | deep | full | na | match | full | na | match |
| APFS | contig | full | na | match | full | na | match |
| APFS | frag | full | na | match | full | na | match |

Full per-cell records (recovered names, `icat` hashes, `istat` block counts,
chunk fractions) are in `results/measured_<fs>.json`.

### The layers do not fail in lockstep — measured counterexamples

- **FAT `frag`** (T1): **L1 = full, L2 = partial, L3 = match** — three different
  per-layer outcomes in a single file. The LFN payload keeps the name, the zeroed
  chain destroys the map (TSK recovers only the first extent), and the content
  blocks physically survive.
- **HFS+ (all files)** (T1): **L1 = none, L2 = none, L3 = match** — the opposite
  pole. Record-removal from the live catalog B-tree destroys the name and map
  entirely (and no journal residue survived in the raw image at snapshot time —
  a byte-scan across UTF-16BE/LE/UTF-8 found zero name hits at T1), while every
  content block persists.
- **FAT `short83` vs `lfn`** (T1): **L1 partial vs full** — the 8.3 name loses its
  first byte to the `0xE5` tombstone, the LFN name does not. Name-payload handling
  (Axis B), not the update strategy, decides completeness.

These are the survey's lockstep counterexamples, now measured on real drivers.

### Filesystem-cluster signatures (consistent with §3)

- **FAT** — tombstone slots + chain loss: 8.3 L1 partial / LFN L1 full;
  contiguous L2 sufficient / fragmented L2 partial; content idle at T1.
- **exFAT** — no `0xE5` tombstone: **every** name (incl. 8.3) recovers full,
  sharper than FAT's tombstone. `contig` lost 2 content chunks by T1 and all by
  T2 — a live illustration of §6's probabilistic overwrite timing, with the same
  driver reusing freed clusters quickly.
- **HFS+** — record-removal: names and maps gone from the live tree, content
  intact. On this macOS driver the journal window left no raw-image name residue
  at snapshot, resolving the matrix's `[I]` for this configuration toward "no
  live/journal residue" (spec-vs-implementation, §6 — re-verify per macOS build).
- **APFS** — copy-on-write: names and content persist through T1 **and** T2
  (churn did not reclaim the stale nodes/checkpoints), the expected out-of-place
  signature. L2 unmeasured here (needs an APFS-aware map reader).

## Pre-Registered Scoring

Three models, each committing one expected class per (filesystem, file-class,
layer) cell **before** the run, in `predictions.py`, derived only from §2.2 and
§3.6. **T** two-axis (Axis A update-strategy + Axis B name-payload, E1–E4);
**A** Axis-A-only (in-place vs out-of-place, nothing else); **C** Carrier-category
("the category exists ⇒ residue expected" — the no-model default). Accuracy =
matched cells / measured cells, with Clopper-Pearson **exact** binomial 95% CIs.

### T1 — immediate post-delete (primary; the residue §2.2/§3 describe)

| model | L1 name | L2 map | L3 content | **overall** |
|---|---|---|---|---|
| two-axis | 18/24 = 75.0% [53.3, 90.2] | **11/18 = 61.1% [35.7, 82.7]** | 23/24 = 95.8% [78.9, 99.9] | **52/66 = 78.8% [67.0, 87.9]** |
| axis-A-only | 17/24 = 70.8% [48.9, 87.4] | 9/18 = 50.0% [26.0, 74.0] | 23/24 = 95.8% [78.9, 99.9] | 49/66 = 74.2% [62.0, 84.2] |
| carrier | 17/24 = 70.8% [48.9, 87.4] | 9/18 = 50.0% [26.0, 74.0] | 23/24 = 95.8% [78.9, 99.9] | 49/66 = 74.2% [62.0, 84.2] |

**Verdict:** two-axis is directionally higher overall and on L1/L2, but the CIs
overlap the baselines'. By the pre-registered criterion (§7), it is **not** a
validated predictor on this corpus — **§2.2 stands as descriptive organization.**

Two observations the numbers make concrete:

1. **On the four macOS filesystems at T1, the Axis-A-only and Carrier baselines
   produce identical class predictions** (both predict full residue on every
   layer). They can only diverge on cells this corpus does not contain:
   out-of-place volumes *after* reclaim/GC, or snapshot-pinned residue. Here they
   are the same "everything survives" strawman.
2. **The two-axis edge (+3 cells) is entirely Axis-B / chain-loss:** FAT
   `short83` L1 (tombstone → partial), FAT `frag` L2 and exFAT `frag` L2
   (fragmented map loss → partial). Those are exactly the phenomena the second
   axis and the update-strategy nuance encode, and exactly where a larger,
   Linux-inclusive corpus is expected to separate the models.

### T2 — post-churn (overwrite-pressure sensitivity)

| model | overall |
|---|---|
| two-axis | 21/66 = 31.8% [20.9, 44.4] |
| axis-A-only | 18/66 = 27.3% [17.0, 39.6] |
| carrier | 18/66 = 27.3% [17.0, 39.6] |

Accuracy collapses for all models after churn because the churn workload
overwrote much of the residue (FAT/exFAT content largely gone; APFS untouched).
This is a §6 result — recoverability degrades with overwrite pressure, which is
probabilistic and not examiner-controlled — not a property of the models. It is
reported for completeness; T1 is the correct scoring point for a survey of what
survives *at the moment of deletion*. (T2's low numbers reflect that the models
predict immediate-post-delete residue, then overwrite pressure removes it.)

## Limitations (stated, not hidden)

- **Small n (66 cells, one host, one driver/version each).** No cross-cell
  aggregation beyond the stratified table; CIs are wide by construction.
- **APFS L2 is unmeasured** (no APFS map reader in mainline TSK) — 6 cells absent
  from L2, reported `na`, never imputed.
- **HFS+ recoverable residue lives in the journal**, which `fls` does not parse;
  the byte-scan found no journal name residue at snapshot on this driver, so the
  `none` results are "none in live tree and in the raw image at T1", not a claim
  that HFS+ journals never help.
- **Driver/version scope (§6).** Every result is one macOS build's driver
  behavior; a different OS or kernel may differ. Re-verify per implementation.
- **The two baselines coincide on this corpus** (see above), so this iteration
  does not exercise the Axis-A-vs-Carrier distinction; the Linux/COW-with-snapshot
  cells do.

## Deferred: Linux filesystems (requires a Linux runner)

ext4, XFS, Btrfs, and F2FS need a Linux host to `mkfs` and mount with their real
drivers (and `debugfs`/`xfs_db`/`btrfs-inspect-internal`/dump.f2fs for residue
inspection). They are **not** faked here. On a Linux runner, run the identical
protocol:

1. **Build & drivers** — per filesystem, in a loop-mounted image:
   `mkfs.ext4` (test both `data=ordered` default and a run with map-zeroing
   observed), `mkfs.xfs`, `mkfs.btrfs`, `mkfs.f2fs`; record kernel release +
   `mkfs` tool versions. Vary the §6 dominators: journaled vs not where offered;
   discard on/off; snapshots present/absent on Btrfs.
2. **Populate** the same `manifest.py` corpus (it is OS-neutral), forcing
   fragmentation the same way; `sync`; snapshot T0.
3. **Delete** the manifest subset; snapshot T1; churn; snapshot T2.
4. **Measure** — L1/L2 with `debugfs` (ext), `xfs_db` (XFS),
   `btrfs-inspect-internal dump-tree` / stale roots (Btrfs), dump.f2fs (F2FS),
   plus TSK where it supports the format (ext); L3 with the same marker byte-scan
   (`measure.py` already does L3 filesystem-agnostically — add an `--l1l2 debugfs`
   backend per format). The pre-registered `predictions.py` already carries the
   two-axis / Axis-A / Carrier expectations these formats need (extend the FS
   list); the ext3-vs-ext4 map-zeroing policy cell (E3) and the XFS freetag
   partial-name cell are the specific discriminators to watch.
5. **Score** with the same `score.py`. These formats are where the two-axis model
   and the two baselines are most likely to separate with non-overlapping
   intervals — or where the two-axis model is refuted.

## Reproduction

```
cd paper/experiment
./run_all.sh            # builds all four FS, measures, scores; writes results/
```

Raw T0/T1/T2 images (~160 MB each) are written under `/tmp` and are **not**
committed (fleet test-data provenance standard). The committed artifacts are the
harness, the per-filesystem `results/measured_<fs>.json` and `results/
manifest_<fs>.json`, and `results/score_results.json`.
