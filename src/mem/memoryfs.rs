#![forbid(unsafe_code)]

//! `MemoryFs` — the `ForensicFs` provider for a memory dump.
//!
//! Phase 1 is the skeleton: a static top-level tree (`sys/`, `proc/`,
//! `forensic/`, `mem/`) served from the [`Registry`], with artifact rendering
//! (`read_file`) and the timeline deferred to later phases. The provider is
//! held now (unused until the Phase 2 walkers) so the type and its mount wiring
//! are stable.

use memf_format::PhysicalMemoryProvider;
use memf_session::AnalysisContext;

use crate::mem::inode::{Artifact, Registry, ROOT_INO};
use crate::{
    not_supported, ForensicFs, FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp,
};

/// `ForensicFs` over a memory dump's physical-memory provider.
pub struct MemoryFs<P: PhysicalMemoryProvider> {
    /// The dump's physical memory provider (used by the Phase 2+ walkers).
    #[allow(dead_code)]
    provider: P,
    /// The bootstrapped analysis context (OS, DTB/CR3, kernel list heads).
    ctx: AnalysisContext,
    registry: Registry,
}

impl<P: PhysicalMemoryProvider> MemoryFs<P> {
    /// Build a memory filesystem over `provider` with the static top-level tree
    /// and the bootstrapped analysis `ctx` (rendered into `sys/os-info.txt`).
    pub fn new(provider: P, ctx: AnalysisContext) -> Self {
        Self {
            provider,
            ctx,
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

    fn file_metadata(ino: u64, size: u64) -> FsMetadata {
        FsMetadata {
            ino,
            file_type: FsFileType::RegularFile,
            mode: 0o100_444,
            uid: 0,
            gid: 0,
            size,
            links_count: 1,
            atime: FsTimestamp::default(),
            mtime: FsTimestamp::default(),
            ctime: FsTimestamp::default(),
            crtime: FsTimestamp::default(),
            allocated: true,
        }
    }

    /// Render `sys/os-info.txt` from the analysis context. Fields the extracted
    /// `AnalysisContext` does not carry (kernel base, symbol source) are marked
    /// "not surfaced" rather than fabricated — to be filled by a later
    /// `memf-session` extension.
    fn render_os_info(&self) -> String {
        let c = &self.ctx;
        let addr =
            |o: Option<u64>| o.map_or_else(|| "not resolved".to_string(), |v| format!("{v:#x}"));
        format!(
            "OS: {}\n\
             DTB/CR3: {:#x}\n\
             KASLR offset: {:#x}\n\
             PsActiveProcessHead: {}\n\
             PsLoadedModuleList: {}\n\
             Kernel base: not surfaced (pending memf-session extension)\n\
             Symbol source: not surfaced (pending memf-session extension)\n",
            c.os,
            c.cr3,
            c.kaslr_offset,
            addr(c.ps_active_process_head),
            addr(c.ps_loaded_module_list),
        )
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
        let artifact = self
            .registry
            .node(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))?
            .artifact
            .clone();
        match artifact {
            Artifact::Dir => Ok(Self::dir_metadata(ino)),
            // Render to report a real size so getattr-then-cat works in tools.
            Artifact::SysOsInfo => Ok(Self::file_metadata(ino, self.render_os_info().len() as u64)),
        }
    }

    fn read_file(&mut self, ino: u64) -> FsResult<Vec<u8>> {
        let artifact = self
            .registry
            .node(ino)
            .ok_or_else(|| FsError::NotFound(format!("inode {ino}")))?
            .artifact
            .clone();
        match artifact {
            Artifact::SysOsInfo => Ok(self.render_os_info().into_bytes()),
            Artifact::Dir => Err(not_supported("read_file on a directory")),
        }
    }

    fn read_file_range(&mut self, ino: u64, offset: u64, len: u64) -> FsResult<Vec<u8>> {
        let data = self.read_file(ino)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data[start..end].to_vec())
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
    use memf_session::OsProfile;

    /// A `MemoryFs` over a trivial real provider (a 1-page LiME dump) with a
    /// directly-constructed Windows analysis context. The provider is not touched
    /// in Phase 1; the ctx drives `sys/os-info.txt`.
    fn mem_fs() -> MemoryFs<LimeProvider> {
        let dump = LimeBuilder::new().add_range(0, &[0u8; 64]).build();
        let provider = LimeProvider::from_bytes(&dump).unwrap();
        let ctx = AnalysisContext {
            os: OsProfile::Windows,
            cr3: 0x1ab000,
            kaslr_offset: 0,
            ps_active_process_head: Some(0xFFFF_F800_DEAD_0000),
            ps_loaded_module_list: Some(0xFFFF_F800_BEEF_0000),
        };
        MemoryFs::new(provider, ctx)
    }

    fn os_info_ino(fs: &mut MemoryFs<LimeProvider>) -> u64 {
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().expect("sys");
        fs.lookup(sys, b"os-info.txt")
            .unwrap()
            .expect("os-info.txt")
    }

    #[test]
    fn os_info_is_a_regular_file_under_sys() {
        let mut fs = mem_fs();
        let ino = os_info_ino(&mut fs);
        assert_eq!(fs.metadata(ino).unwrap().file_type, FsFileType::RegularFile);
    }

    #[test]
    fn os_info_renders_analysis_profile() {
        let mut fs = mem_fs();
        let ino = os_info_ino(&mut fs);
        let text = String::from_utf8(fs.read_file(ino).unwrap()).unwrap();
        assert!(text.contains("OS: Windows"), "got: {text}");
        assert!(text.contains("DTB/CR3: 0x1ab000"), "got: {text}");
        assert!(
            text.contains("PsActiveProcessHead: 0xfffff800dead0000"),
            "got: {text}"
        );
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
