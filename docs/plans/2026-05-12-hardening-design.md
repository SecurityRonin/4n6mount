# Hardening Design: 4n6mount, ext4fs-forensic, ewf

Date: 2026-05-12
Status: Approved

## Scope

Three independent repos treated identically:
- `4n6mount` (primary binary)
- `ext4fs-forensic` (ext4 parser)
- `ewf` (EWF/E01 parser)

Each repo gets its own pre-commit hooks, GitHub Actions CI, fuzz targets, cargo-deny policy, renovate config, and clippy lint baseline. No workspace merge — repos stay independent.

## Pre-commit Hooks

Each repo gets `.pre-commit-config.yaml` with local hooks and gitleaks:

```yaml
repos:
  - repo: local
    hooks:
      - id: fmt        # cargo fmt --check
      - id: clippy     # cargo clippy --all-targets -- -D warnings
      - id: test       # cargo test
      - id: deny       # cargo deny check
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

## CI Jobs (GitHub Actions)

All jobs set `RUSTFLAGS: -Dwarnings`. Test job runs `ubuntu-latest` only (FUSE requires Linux/macOS; Windows stub is untestable).

| Job | Tool | Gate |
|---|---|---|
| `fmt` | `cargo fmt --check` | blocking |
| `clippy` | `cargo clippy --all-targets -- -D warnings` | blocking |
| `test` | `cargo test` | blocking |
| `msrv` | `cargo check` on Rust 1.85 | blocking |
| `deny` | `cargo-deny-action` | blocking |
| `secrets` | gitleaks v2.3.7 (full history) | blocking |
| `geiger` | `cargo-geiger` | reporting only |

## Fuzz Targets

Fuzzing runs locally (not in CI). Each crate gets a `fuzz/` directory using `libfuzzer-sys`.

### 4n6mount (4 targets)

| Target | Entry point | Intent |
|---|---|---|
| `detect_filesystem` | `detect::detect_filesystem()` | Panic safety on arbitrary disk image bytes |
| `session_deserialize` | session JSON parse | Panic/OOM safety on crafted session files |
| `filter_parse` | `CustomDb` plaintext parser | Panic safety on crafted hash DB input |
| `inode_map_roundtrip` | `inode_map` encode/decode | Roundtrip correctness + panic safety |

### ext4fs-forensic (3 targets)

| Target | Entry point | Intent |
|---|---|---|
| `parse_superblock` | superblock parse | Crafted ext4 superblock |
| `parse_inode` | inode parse | Crafted inode structures |
| `read_dir` | directory block parse | Crafted directory entries |

### ewf (2 targets)

| Target | Entry point | Intent |
|---|---|---|
| `parse_header` | EWF header/section parse | Crafted EWF header bytes |
| `parse_segment` | EWF reader entry point | Multi-section crafted EWF |

**Corpus seeding:** each target ships one real valid input in `fuzz/corpus/<target>/` so the fuzzer starts from a valid structure rather than random bytes.

## cargo-deny (`deny.toml`)

Same policy across all three repos:

- **Advisories:** strict, no ignores
- **Licenses:** MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib
- **Bans:** deny duplicate crate versions; deny wildcard deps
- **Sources:** crates.io only

## Renovate (`renovate.json`)

Same config across all three repos:
- GitHub Actions: auto-merge digest/patch/minor updates (as PRs)
- Cargo deps: auto-merge patch/minor updates (as PRs)
- No direct commits

## Clippy Lint Config (`Cargo.toml [lints.clippy]`)

```toml
[lints.clippy]
pedantic = "warn"
correctness = "deny"
suspicious = "deny"
# suppressed noisy-but-harmless pedantic rules:
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
cast_possible_truncation = "allow"
cast_possible_wrap = "allow"
cast_sign_loss = "allow"
```

`correctness` and `suspicious` at `deny` (not just warn) — these catch logic bugs relevant to crafted-input safety.

## Formatting (`rustfmt.toml`)

```toml
max_width = 100
imports_granularity = "Crate"
```

## Reference

Pattern sourced from `~/src/vhdx-forensic`, which uses the same toolchain.
