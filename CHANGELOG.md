# Changelog

## [0.6.3](https://github.com/SecurityRonin/4n6mount/compare/forensic-mount-v0.6.2...forensic-mount-v0.6.3) - 2026-08-09

### Fixed

- *(gitignore)* unanchor the target rule so nested cargo projects are ignored

## [0.6.2](https://github.com/SecurityRonin/4n6mount/compare/forensic-mount-v0.6.1...forensic-mount-v0.6.2) - 2026-08-06

### Fixed

- repair the dead fuzz target and six broken doc links adoption exposed
- *(supply-chain)* vet records for the crates the lru fix resolved

## [0.6.1](https://github.com/SecurityRonin/4n6mount/compare/forensic-mount-v0.6.0...forensic-mount-v0.6.1) - 2026-08-05

### Fixed

- *(security)* bump fuser 0.15 -> 0.16 (RUSTSEC-2021-0154) and unblind the deny gate
- *(fusefs)* complete the lint set; replace session unwraps with let-else
- *(supply-chain)* trust our own crates instead of exempting them

## [0.6.0] - 2026-07-26

### Changed
- Reconverge onto `forensic-vfs-engine` for all container/filesystem access. The
  direct format-reader dependencies and their feature flags (`ext4`, `ewf`, `iso`,
  `vmdk`, `ntfs`, `hfsplus`, `exfat`, `apfs`, `ad1`, `aff4`, `tarball`, `zip`,
  `sevenz`) are removed from the manifest; every format is now reached through the
  engine's unified `Vfs` surface (archive + logical containers included, per
  ADR-0014). No local `SyntheticFs`, no `disk-forensic` dependency. This is a
  breaking manifest change (the removed features no longer exist), hence the minor
  bump.
