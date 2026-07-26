# Changelog

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
