#![forbid(unsafe_code)]

//! `MemoryFs` — the `ForensicFs` provider for a memory dump.
//!
//! Phase 1 is the skeleton: a static top-level tree (`sys/`, `proc/`,
//! `forensic/`, `mem/`) served from the [`Registry`], with artifact rendering
//! (`read_file`) and the timeline deferred to later phases. The provider is
//! held now (unused until the Phase 2 walkers) so the type and its mount wiring
//! are stable.

use memf_format::PhysicalMemoryProvider;

use crate::mem::inode::{Registry, ROOT_INO};
use crate::{
    not_supported, ForensicFs, FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp,
};

/// `ForensicFs` over a memory dump's physical-memory provider.
pub struct MemoryFs<P: PhysicalMemoryProvider> {
    /// The dump's physical memory provider (used by the Phase 2+ walkers).
    #[allow(dead_code)]
    provider: P,
    registry: Registry,
}

impl<P: PhysicalMemoryProvider> MemoryFs<P> {
    /// Build a memory filesystem over `provider` with the static top-level tree.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            registry: Registry::skeleton(),
        }
    }

    fn dir_metadata(ino: u64) -> FsMetadata {
        FsMetadata {
            ino,
            file_type: FsFileType::Directory,
            mode: 0o40555,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 2,
            atime: FsTimestamp::default(),
            mtime: FsTimestamp::default(),
            ctime: FsTimestamp::default(),
            crtime: FsTimestamp::default(),
            allocated: true,
        }
    }
}

impl<P: PhysicalMemoryProvider> ForensicFs for MemoryFs<P> {
    fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    fn read_dir(&mut self, ino: u64) -> FsResult<Vec<FsDirEntry>> {
        let node = self
            .registry
            .node(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))?;
        let mut out = Vec::with_capacity(node.children.len());
        for &child in &node.children {
            if let Some(c) = self.registry.node(child) {
                out.push(FsDirEntry {
                    inode: child,
                    name: c.name.clone(),
                    file_type: if c.is_dir() {
                        FsFileType::Directory
                    } else {
                        FsFileType::RegularFile
                    },
                });
            }
        }
        Ok(out)
    }

    fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> FsResult<Option<u64>> {
        self.registry
            .node(parent_ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {parent_ino}")))?;
        Ok(self.registry.lookup(parent_ino, name))
    }

    fn metadata(&mut self, ino: u64) -> FsResult<FsMetadata> {
        let node = self
            .registry
            .node(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))?;
        // Phase 1: every registered node is a directory.
        if node.is_dir() {
            Ok(Self::dir_metadata(ino))
        } else {
            Err(not_supported(
                "memory file metadata arrives in a later phase",
            ))
        }
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        // Phase 1 has only directories; lazy artifact rendering is a later phase.
        let _ = ino;
        Err(not_supported(
            "memory artifact rendering arrives in a later phase",
        ))
    }

    fn read_file_range(&mut self, ino: u64, _offset: u64, _len: u64) -> FsResult<Vec<u8>> {
        let _ = ino;
        Err(not_supported(
            "memory artifact rendering arrives in a later phase",
        ))
    }

    fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
        Err(not_supported("no symlinks in the memory VFS"))
    }

    fn fs_info(&self) -> FsResult<serde_json::Value> {
        Ok(serde_json::json!({
            "type": "memory",
            "phase": "1-skeleton",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_format::lime::LimeProvider;
    use memf_format::test_builders::LimeBuilder;

    /// A `MemoryFs` over a trivial real provider (a 1-page LiME dump). Phase 1
    /// does not touch the provider, so any valid provider exercises the tree.
    fn mem_fs() -> MemoryFs<LimeProvider> {
        let dump = LimeBuilder::new().add_range(0, &[0u8; 64]).build();
        MemoryFs::new(LimeProvider::from_bytes(&dump).unwrap())
    }

    #[test]
    fn root_ino_is_2() {
        assert_eq!(mem_fs().root_ino(), 2);
    }

    #[test]
    fn root_lists_sys_proc_forensic_mem() {
        let mut fs = mem_fs();
        let names: Vec<String> = fs
            .read_dir(ROOT_INO)
            .unwrap()
            .iter()
            .map(FsDirEntry::name_str)
            .collect();
        for d in ["sys", "proc", "forensic", "mem"] {
            assert!(names.contains(&d.to_string()), "missing {d}, got {names:?}");
        }
    }

    #[test]
    fn lookup_sys_resolves_to_a_directory() {
        let mut fs = mem_fs();
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().expect("sys exists");
        assert_eq!(fs.metadata(sys).unwrap().file_type, FsFileType::Directory);
    }

    #[test]
    fn lookup_missing_is_none() {
        let mut fs = mem_fs();
        assert_eq!(fs.lookup(ROOT_INO, b"nope").unwrap(), None);
    }

    #[test]
    fn read_file_on_dir_is_unsupported_not_silent() {
        let mut fs = mem_fs();
        assert!(fs.read_file(ROOT_INO).is_err());
    }

    #[test]
    fn fs_info_reports_memory() {
        let fs = mem_fs();
        assert_eq!(fs.fs_info().unwrap()["type"], "memory");
    }
}
