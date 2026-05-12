# Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden 4n6mount, ext4fs-forensic, and ewf against crafted input via pre-commit hooks, CI, cargo-deny, secret scanning, renovate, and libfuzzer fuzz targets across all three independent repos.

**Architecture:** Each repo gets identical tooling (pre-commit, CI, deny.toml, renovate.json, rustfmt.toml, clippy lints). Fuzz targets live in each repo's `fuzz/` directory using `libfuzzer-sys`. ewf already has ~60% of the tooling; it only needs additive changes. 4n6mount's CI must check out sibling repos (ext4fs-forensic, ewf) at relative paths because Cargo.toml references them as `path = "../ext4fs-forensic/ext4fs"` and `path = "../ewf/ewf"`.

**Tech Stack:** cargo-fuzz (libfuzzer-sys 0.4), pre-commit, gitleaks v8.18.4, EmbarkStudios/cargo-deny-action, cargo-geiger, tempfile (ewf fuzz only), Rust 1.85 MSRV.

**TDD note:** Tooling config files (Tasks 1–3) have no RED/GREEN split — they are config, not logic. Fuzz targets (Tasks 4–6) follow RED (target compiles + runs, panics documented) → GREEN (panics fixed) per commit discipline.

---

## Reference Files

All configs mirror `~/src/vhdx-forensic/` exactly unless noted. Read those files before writing to avoid divergence.

---

## Task 1: 4n6mount — Tooling Config

**Repo:** `~/src/4n6mount`

**Files:**
- Create: `.pre-commit-config.yaml`
- Create: `.github/workflows/ci.yml`
- Create: `deny.toml`
- Create: `renovate.json`
- Create: `rustfmt.toml`
- Modify: `Cargo.toml` (add `rust-version`, `[lints.clippy]`)

### Step 1: Create `.pre-commit-config.yaml`

Copy exactly from vhdx-forensic. The `cargo test` hook runs the full default test suite.

```yaml
repos:
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: cargo fmt --check
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --all-targets -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-test
        name: cargo test
        entry: cargo test
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-deny
        name: cargo deny
        entry: cargo deny check
        language: system
        files: (Cargo\.toml|Cargo\.lock|deny\.toml)
        pass_filenames: false

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

### Step 2: Create `.github/workflows/ci.yml`

4n6mount references sibling repos via `path = "../ext4fs-forensic/ext4fs"` and `path = "../ewf/ewf"`. The CI must check these out at the correct relative paths. All jobs that compile code use the three-checkout pattern.

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

jobs:
  fmt:
    name: Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          path: 4n6mount
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --check
        working-directory: 4n6mount

  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          path: 4n6mount
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ext4fs-forensic
          path: ext4fs-forensic
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ewf
          path: ewf
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo clippy --all-targets -- -D warnings
        working-directory: 4n6mount

  test:
    name: Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          path: 4n6mount
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ext4fs-forensic
          path: ext4fs-forensic
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ewf
          path: ewf
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo test
        working-directory: 4n6mount

  msrv:
    name: MSRV (1.85)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          path: 4n6mount
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ext4fs-forensic
          path: ext4fs-forensic
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ewf
          path: ewf
      - uses: dtolnay/rust-toolchain@1.85
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo test
        working-directory: 4n6mount

  deny:
    name: Cargo Deny
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: EmbarkStudios/cargo-deny-action@3fd3802e88374d3fe9159b834c7714ec57d6c979 # v2.0.15

  secrets:
    name: Secret Scan (gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3 # v2.3.7
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  geiger:
    name: Unsafe Audit (cargo-geiger)
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          path: 4n6mount
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ext4fs-forensic
          path: ext4fs-forensic
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository_owner }}/ewf
          path: ewf
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo install cargo-geiger --locked
      - run: cargo geiger 2>&1 || true
        working-directory: 4n6mount
```

### Step 3: Create `deny.toml`

Path deps (ext4fs, ewf) are not affected by `[sources]` — that only covers registry and git sources.

```toml
[advisories]
version = 2
ignore = []

[licenses]
version = 2
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
]

[bans]
multiple-versions = "deny"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

### Step 4: Create `renovate.json`

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:recommended",
    "helpers:pinGitHubActionDigests"
  ],
  "packageRules": [
    {
      "matchManagers": ["github-actions"],
      "automerge": true,
      "automergeType": "pr",
      "matchUpdateTypes": ["digest", "patch", "minor"]
    },
    {
      "matchManagers": ["cargo"],
      "automerge": true,
      "matchUpdateTypes": ["patch", "minor"]
    }
  ]
}
```

### Step 5: Create `rustfmt.toml`

```toml
max_width = 100
imports_granularity = "Crate"
```

### Step 6: Update `Cargo.toml`

Add `rust-version` to `[package]` and a `[lints.clippy]` section. Do not change any existing fields.

In `[package]`, add:
```toml
rust-version = "1.85"
```

After the existing `[dependencies]` section, add:
```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
pedantic = "warn"
correctness = "deny"
suspicious = "deny"
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
cast_possible_truncation = "allow"
cast_possible_wrap = "allow"
cast_sign_loss = "allow"
```

Note: `unsafe_code = "forbid"` mirrors the `#![forbid(unsafe_code)]` already in most source files — make it the crate-level default.

### Step 7: Verify tooling

Run each tool locally to confirm no pre-existing violations before committing:

```bash
cd ~/src/4n6mount
cargo fmt --check
# Expected: no output (already formatted)

cargo clippy --all-targets -- -D warnings
# Expected: no warnings/errors

cargo deny check
# Expected: "advisories ok", "licenses ok", "bans ok", "sources ok"
```

Fix any clippy or deny violations found before committing.

### Step 8: Install pre-commit and hooks

```bash
cd ~/src/4n6mount
pip install pre-commit   # if not installed
pre-commit install
pre-commit run --all-files
# Expected: all hooks pass
```

### Step 9: Commit

```bash
cd ~/src/4n6mount
git add .pre-commit-config.yaml .github/workflows/ci.yml deny.toml renovate.json rustfmt.toml Cargo.toml
git commit -m "chore: add pre-commit hooks, CI, deny, renovate, clippy, rustfmt"
```

---

## Task 2: ext4fs-forensic — Tooling Config

**Repo:** `~/src/ext4fs-forensic`

This is a workspace with members: `ext4fs`, `ext4fs-fuse`, `ext4fs-cli`. Clippy lints go in the workspace root `Cargo.toml`; each member inherits via `[lints] workspace = true`.

**Files:**
- Create: `.pre-commit-config.yaml` (same as Task 1)
- Create: `.github/workflows/ci.yml`
- Create: `deny.toml` (same as Task 1)
- Create: `renovate.json` (same as Task 1)
- Create: `rustfmt.toml` (same as Task 1)
- Modify: `Cargo.toml` (workspace root — add `[workspace.lints.clippy]`)
- Modify: `ext4fs/Cargo.toml` (add `rust-version`, `[lints] workspace = true`)

### Step 1: Create `.pre-commit-config.yaml`

Same content as Task 1 exactly. The `cargo test` entry will run workspace-wide.

### Step 2: Create `.github/workflows/ci.yml`

Self-contained workspace — no sibling checkouts needed. ext4fs-fuse requires libfuse3 headers to compile.

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

jobs:
  fmt:
    name: Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --check

  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: sudo apt-get install -y libfuse3-dev pkg-config
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo clippy --all-targets -- -D warnings

  test:
    name: Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: sudo apt-get install -y libfuse3-dev pkg-config
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo test

  msrv:
    name: MSRV (1.85)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: sudo apt-get install -y libfuse3-dev pkg-config
      - uses: dtolnay/rust-toolchain@1.85
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo test

  deny:
    name: Cargo Deny
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: EmbarkStudios/cargo-deny-action@3fd3802e88374d3fe9159b834c7714ec57d6c979 # v2.0.15

  secrets:
    name: Secret Scan (gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3 # v2.3.7
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  geiger:
    name: Unsafe Audit (cargo-geiger)
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: sudo apt-get install -y libfuse3-dev pkg-config
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo install cargo-geiger --locked
      - run: cargo geiger 2>&1 || true
```

### Step 3: Create `deny.toml`, `renovate.json`, `rustfmt.toml`

Same content as Task 1 for all three files.

### Step 4: Update workspace root `Cargo.toml`

The root `Cargo.toml` has only `[workspace]`. Add after it:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
pedantic = "warn"
correctness = "deny"
suspicious = "deny"
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
cast_possible_truncation = "allow"
cast_possible_wrap = "allow"
cast_sign_loss = "allow"
```

### Step 5: Update `ext4fs/Cargo.toml`

Add `rust-version = "1.85"` to `[package]`. Add at the end:

```toml
[lints]
workspace = true
```

Apply the same two changes to `ext4fs-fuse/Cargo.toml` and `ext4fs-cli/Cargo.toml`.

### Step 6: Verify, install, and commit

```bash
cd ~/src/ext4fs-forensic
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo deny check
pre-commit install
pre-commit run --all-files
git add -A
git commit -m "chore: add pre-commit hooks, CI, deny, renovate, clippy, rustfmt"
```

---

## Task 3: ewf — Update Existing Tooling

**Repo:** `~/src/ewf`

ewf already has: `.pre-commit-config.yaml` (missing gitleaks), `deny.toml` (multiple-versions = "warn" not "deny"), `.github/workflows/ci.yml` (missing msrv, secrets, geiger), `renovate.json` (correct). Changes are additive.

**Files:**
- Modify: `.pre-commit-config.yaml` (add gitleaks block)
- Modify: `.github/workflows/ci.yml` (add msrv, secrets, geiger jobs)
- Modify: `deny.toml` (change multiple-versions "warn" → "deny")
- Create: `rustfmt.toml`
- Modify: `Cargo.toml` (workspace root — add `[workspace.lints.clippy]`)
- Modify: `ewf/Cargo.toml` (update `rust-version` to 1.85, add `[lints] workspace = true`)

Note: ewf currently declares `rust-version = "1.74"`. Updating to 1.85 means users on Rust < 1.85 will see a deprecation warning. This is intentional per design.

### Step 1: Update `.pre-commit-config.yaml`

Append this block after the existing local hooks repo:

```yaml
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

### Step 2: Update `.github/workflows/ci.yml`

The existing file has: fmt, clippy, test, deny. Append three new jobs after the `deny` job:

```yaml
  msrv:
    name: MSRV (1.85)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@1.85
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo test --lib --test e2e_dftt

  secrets:
    name: Secret Scan (gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3 # v2.3.7
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  geiger:
    name: Unsafe Audit (cargo-geiger)
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - run: cargo install cargo-geiger --locked
      - run: cargo geiger 2>&1 || true
```

### Step 3: Update `deny.toml`

Change line `multiple-versions = "warn"` to `multiple-versions = "deny"`.

### Step 4: Create `rustfmt.toml`

Same as Task 1.

### Step 5: Update workspace `Cargo.toml`

Add after `[workspace]`:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
pedantic = "warn"
correctness = "deny"
suspicious = "deny"
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
cast_possible_truncation = "allow"
cast_possible_wrap = "allow"
cast_sign_loss = "allow"
```

### Step 6: Update `ewf/Cargo.toml`

Change `rust-version = "1.74"` to `rust-version = "1.85"`. Add at end:

```toml
[lints]
workspace = true
```

Apply same `[lints] workspace = true` to `ewf-cli/Cargo.toml` (no rust-version change needed there).

### Step 7: Verify and commit

```bash
cd ~/src/ewf
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo deny check
pre-commit run --all-files
git add -A
git commit -m "chore: add gitleaks, msrv/secrets/geiger CI, harden deny.toml, add rustfmt, clippy lints"
```

---

## Task 4: 4n6mount — Fuzz Targets

**Repo:** `~/src/4n6mount`

**Attack surface covered:**
- `detect_filesystem`: reads magic bytes at fixed offsets — crafted images could cause panic on seek errors or corrupt offset arithmetic
- `session_deserialize`: JSON deserialization of untrusted session files — serde panics are possible on deeply nested input
- `filter_parse`: line-by-line hash DB parsing — crafted files with unusual encoding could panic
- `inode_map_roundtrip`: `u64` offset arithmetic — crafted inodes near offset boundaries could overflow or decode to wrong namespace

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/detect_filesystem.rs`
- Create: `fuzz/fuzz_targets/session_deserialize.rs`
- Create: `fuzz/fuzz_targets/filter_parse.rs`
- Create: `fuzz/fuzz_targets/inode_map_roundtrip.rs`
- Create: `fuzz/corpus/detect_filesystem/seed` (512-byte ext4 superblock seed)

### Step 1 (RED): Create `fuzz/Cargo.toml`

```toml
[package]
name = "forensic-mount-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[[bin]]
name = "detect_filesystem"
path = "fuzz_targets/detect_filesystem.rs"
test = false
doc = false

[[bin]]
name = "session_deserialize"
path = "fuzz_targets/session_deserialize.rs"
test = false
doc = false

[[bin]]
name = "filter_parse"
path = "fuzz_targets/filter_parse.rs"
test = false
doc = false

[[bin]]
name = "inode_map_roundtrip"
path = "fuzz_targets/inode_map_roundtrip.rs"
test = false
doc = false

[dependencies]
libfuzzer-sys = "0.4"
forensic-mount = { path = ".." }
serde_json = "1"
tempfile = "3"
```

### Step 2 (RED): Create `fuzz/fuzz_targets/detect_filesystem.rs`

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::detect::detect_filesystem;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = detect_filesystem(&mut cursor);
});
```

### Step 3 (RED): Create `fuzz/fuzz_targets/session_deserialize.rs`

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::session::{SessionMetadata, OverlayMetadata};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SessionMetadata>(data);
    let _ = serde_json::from_slice::<OverlayMetadata>(data);
});
```

### Step 4 (RED): Create `fuzz/fuzz_targets/filter_parse.rs`

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::filter::CustomDb;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hashes.txt");
    std::fs::write(&path, data).unwrap();
    let _ = CustomDb::load(&path);
    // dir and file cleaned up on drop
});
```

### Step 5 (RED): Create `fuzz/fuzz_targets/inode_map_roundtrip.rs`

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::inode_map::{decode_fuse_ino, ro_ino, rw_ino, deleted_ino, journal_ino, metadata_ino};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let ino = u64::from_le_bytes(data[..8].try_into().unwrap());
    // Encoding must not panic for any u64.
    let ro = ro_ino(ino);
    let rw = rw_ino(ino);
    let del = deleted_ino(ino);
    let jrn = journal_ino(ino);
    let meta = metadata_ino(ino);
    // Decoding must not panic for any u64.
    let _ = decode_fuse_ino(ro);
    let _ = decode_fuse_ino(rw);
    let _ = decode_fuse_ino(del);
    let _ = decode_fuse_ino(jrn);
    let _ = decode_fuse_ino(meta);
});
```

### Step 6 (RED): Create corpus seed for `detect_filesystem`

The seed is the first 512 bytes starting at offset 0x400 of `disk4s1` — a real ext4 superblock. This lets the fuzzer start from a valid structure and mutate outward, reaching ext4-specific paths faster than random bytes.

```bash
sudo dd if=/dev/disk4s1 bs=1 skip=1024 count=512 of=~/src/4n6mount/fuzz/corpus/detect_filesystem/seed 2>/dev/null
```

If `/dev/disk4s1` is unavailable, create a minimal 1080-byte seed with `53 ef` at offset 56 (ext4 magic):

```bash
mkdir -p ~/src/4n6mount/fuzz/corpus/detect_filesystem
python3 -c "
import struct
buf = bytearray(1100)
# ext4 magic 0xEF53 at superblock offset 56 (absolute offset 1024+56=1080)
buf[1080] = 0x53
buf[1081] = 0xEF
open('/Users/4n6h4x0r/src/4n6mount/fuzz/corpus/detect_filesystem/seed', 'wb').write(bytes(buf))
"
```

### Step 7 (RED): Build fuzz targets and run briefly

```bash
cd ~/src/4n6mount
cargo fuzz build
# Expected: all 4 targets compile without error

cargo fuzz run detect_filesystem -- -max_total_time=30
# Note any panics/crashes to corpus. If crash found: note crash file path.
```

Run all four:
```bash
cargo fuzz run session_deserialize -- -max_total_time=30
cargo fuzz run filter_parse -- -max_total_time=30
cargo fuzz run inode_map_roundtrip -- -max_total_time=30
```

Run sequentially — never in parallel (see CLAUDE.md: never run multiple test processes concurrently).

### Step 8 (RED): Commit fuzz targets

Whether or not panics were found, commit the targets as the RED state:

```bash
cd ~/src/4n6mount
git add fuzz/
git commit -m "test(RED): fuzz targets for detect_filesystem, session, filter, inode_map"
```

### Step 9 (GREEN): Fix any panics found

For each crash file in `fuzz/artifacts/<target>/`, reproduce and fix:

```bash
cargo fuzz run detect_filesystem fuzz/artifacts/detect_filesystem/crash-<hash>
```

Common fixes:
- **Panic on seek beyond end of buffer**: add bounds check before seek in `detect.rs`
- **Integer overflow in inode offsets**: use `checked_add` in `inode_map.rs`
- **Panic in serde**: these are almost always `expect()` or `unwrap()` in deserialization paths — convert to `?`

After fixing, re-run the crashed input to confirm it no longer panics:
```bash
cargo fuzz run detect_filesystem fuzz/artifacts/detect_filesystem/crash-<hash>
# Expected: target exits cleanly (no crash output)
```

### Step 10 (GREEN): Commit fixes

```bash
git add src/
git commit -m "fix(GREEN): harden against crafted input found by fuzzer"
```

---

## Task 5: ext4fs-forensic — Fuzz Targets

**Repo:** `~/src/ext4fs-forensic`

**Attack surface covered:**
- `parse_superblock`: crafted superblock with corrupt field values (block size 0, negative inode counts, etc.)
- `parse_inode`: crafted inode with corrupt extent trees, overflowing timestamps, invalid flags
- `read_dir`: crafted directory blocks with overlong filenames, corrupt entry lengths, cycles

`Ext4Fs::open(Cursor::new(data))` is the natural entry point — it takes `R: Read + Seek` so a `Cursor<&[u8]>` works directly, no temp files needed.

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/parse_superblock.rs`
- Create: `fuzz/fuzz_targets/parse_inode.rs`
- Create: `fuzz/fuzz_targets/read_dir.rs`
- Create: `fuzz/corpus/parse_superblock/seed`

### Step 1 (RED): Create `fuzz/Cargo.toml`

```toml
[package]
name = "ext4fs-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[[bin]]
name = "parse_superblock"
path = "fuzz_targets/parse_superblock.rs"
test = false
doc = false

[[bin]]
name = "parse_inode"
path = "fuzz_targets/parse_inode.rs"
test = false
doc = false

[[bin]]
name = "read_dir"
path = "fuzz_targets/read_dir.rs"
test = false
doc = false

[dependencies]
libfuzzer-sys = "0.4"
ext4fs = { path = "../ext4fs" }
```

### Step 2 (RED): Create `fuzz/fuzz_targets/parse_superblock.rs`

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use ext4fs::Ext4Fs;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let cursor = Cursor::new(data);
    let _ = Ext4Fs::open(cursor);
});
```

### Step 3 (RED): Create `fuzz/fuzz_targets/parse_inode.rs`

Open the filesystem and immediately attempt inode reads. If open fails, the fuzzer still exercises error paths.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use ext4fs::Ext4Fs;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let cursor = Cursor::new(data);
    if let Ok(mut fs) = Ext4Fs::open(cursor) {
        let root = fs.root_ino();
        let _ = fs.inode(root);
        for ino in [1u64, 2, 3, 8, 11, 12] {
            let _ = fs.inode(ino);
        }
    }
});
```

### Step 4 (RED): Create `fuzz/fuzz_targets/read_dir.rs`

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use ext4fs::Ext4Fs;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let cursor = Cursor::new(data);
    if let Ok(mut fs) = Ext4Fs::open(cursor) {
        let root = fs.root_ino();
        if let Ok(entries) = fs.read_dir(root) {
            for entry in entries.iter().take(16) {
                let _ = fs.inode(entry.ino);
                let _ = fs.read_dir(entry.ino);
            }
        }
    }
});
```

### Step 5 (RED): Create corpus seed

```bash
sudo dd if=/dev/disk4s1 bs=4096 count=64 of=~/src/ext4fs-forensic/fuzz/corpus/parse_superblock/seed 2>/dev/null
```

This gives the fuzzer 256 KB of real ext4 data including the superblock and first few block groups.

### Step 6 (RED): Build and run

```bash
cd ~/src/ext4fs-forensic
cargo fuzz build
cargo fuzz run parse_superblock -- -max_total_time=60
cargo fuzz run parse_inode -- -max_total_time=60
cargo fuzz run read_dir -- -max_total_time=60
```

Run sequentially.

### Step 7 (RED): Commit targets

```bash
git add fuzz/
git commit -m "test(RED): fuzz targets for superblock, inode, and directory parsing"
```

### Step 8 (GREEN): Fix panics, commit

Same process as Task 4 Steps 9–10. Common ext4 panic sources:
- `expect()` / `unwrap()` on block reads with out-of-bounds block numbers
- Integer overflow when computing block group offsets from corrupt superblock fields
- Infinite loops in directory entry traversal (corrupt `rec_len = 0`)

```bash
git add src/
git commit -m "fix(GREEN): harden ext4 parser against crafted images"
```

---

## Task 6: ewf — Fuzz Targets

**Repo:** `~/src/ewf`

`EwfReader::open` takes a file path (not `Read + Seek`), so fuzz targets must write to a temp file. Use `tempfile::tempdir()` — it cleans up on drop, preventing test artifact accumulation.

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/parse_header.rs`
- Create: `fuzz/fuzz_targets/parse_segment.rs`

### Step 1 (RED): Create `fuzz/Cargo.toml`

```toml
[package]
name = "ewf-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[[bin]]
name = "parse_header"
path = "fuzz_targets/parse_header.rs"
test = false
doc = false

[[bin]]
name = "parse_segment"
path = "fuzz_targets/parse_segment.rs"
test = false
doc = false

[dependencies]
libfuzzer-sys = "0.4"
ewf = { path = "../ewf" }
tempfile = "3"
```

### Step 2 (RED): Create `fuzz/fuzz_targets/parse_header.rs`

Tests header and section parsing up to the point where EwfReader::open returns.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use ewf::EwfReader;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.E01");
    std::fs::write(&path, data).unwrap();
    let _ = EwfReader::open(&path);
    // dir cleans up on drop
});
```

### Step 3 (RED): Create `fuzz/fuzz_targets/parse_segment.rs`

Tests chunk decompression and read paths beyond just the header.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use ewf::EwfReader;
use std::io::Read;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.E01");
    std::fs::write(&path, data).unwrap();
    if let Ok(mut reader) = EwfReader::open(&path) {
        let read_size = 4096_u64.min(reader.total_size()) as usize;
        let mut buf = vec![0u8; read_size];
        let _ = reader.read(&mut buf);
    }
    // dir cleans up on drop
});
```

### Step 4 (RED): Build and run

```bash
cd ~/src/ewf
cargo fuzz build
cargo fuzz run parse_header -- -max_total_time=60
cargo fuzz run parse_segment -- -max_total_time=60
```

Run sequentially.

### Step 5 (RED): Commit targets

```bash
git add fuzz/
git commit -m "test(RED): fuzz targets for EWF header and segment parsing"
```

### Step 6 (GREEN): Fix panics, commit

Common EWF panic sources:
- `unwrap()` on section size or offset arithmetic (section sizes can be crafted to underflow)
- `expect()` on segment chain continuation (crafted segment count could exhaust memory)
- Decompressor panics on crafted zlib streams

```bash
git add src/
git commit -m "fix(GREEN): harden EWF parser against crafted images"
```

---

## Task 7: Extended Fuzz Run — Find Vulnerabilities

Run all 9 targets for longer (120s each) after fixes are in place to catch issues missed in the initial 30–60s runs. Run one at a time.

```bash
# 4n6mount targets
cd ~/src/4n6mount
cargo fuzz run detect_filesystem -- -max_total_time=120
cargo fuzz run session_deserialize -- -max_total_time=120
cargo fuzz run filter_parse -- -max_total_time=120
cargo fuzz run inode_map_roundtrip -- -max_total_time=120

# ext4fs-forensic targets
cd ~/src/ext4fs-forensic
cargo fuzz run parse_superblock -- -max_total_time=120
cargo fuzz run parse_inode -- -max_total_time=120
cargo fuzz run read_dir -- -max_total_time=120

# ewf targets
cd ~/src/ewf
cargo fuzz run parse_header -- -max_total_time=120
cargo fuzz run parse_segment -- -max_total_time=120
```

After each repo's targets complete, check system memory health before proceeding:

```bash
vm_stat | head -5
```

If any new crashes are found, fix them following the same RED→GREEN pattern (fix + commit) before running the next repo's targets.

### Final status check

```bash
# Confirm no outstanding crash artifacts
ls ~/src/4n6mount/fuzz/artifacts/
ls ~/src/ext4fs-forensic/fuzz/artifacts/
ls ~/src/ewf/fuzz/artifacts/
# Expected: empty or only directories with no crash-* files
```
