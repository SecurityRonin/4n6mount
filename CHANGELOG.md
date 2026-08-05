# Changelog

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
