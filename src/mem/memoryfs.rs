#![forbid(unsafe_code)]

//! `MemoryFs` — the `ForensicFs` provider for a memory dump.
//!
//! Phase 1 is the skeleton: a static top-level tree (`sys/`, `proc/`,
//! `forensic/`, `mem/`) served from the [`Registry`], with artifact rendering
//! (`read_file`) and the timeline deferred to later phases. The provider is
//! held now (unused until the Phase 2 walkers) so the type and its mount wiring
//! are stable.

use memf_core::object_reader::ObjectReader;
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_format::PhysicalMemoryProvider;
use memf_session::AnalysisContext;
use memf_symbols::SymbolResolver;

use crate::mem::inode::{Artifact, Registry, ROOT_INO};
use crate::{
    not_supported, ForensicFs, FsDirEntry, FsError, FsFileType, FsMetadata, FsResult, FsTimestamp,
};

/// `ForensicFs` over a memory dump.
pub struct MemoryFs<P: PhysicalMemoryProvider> {
    /// Virtual-address reader (owns the provider via its VAS) used by the
    /// `sys/` and `proc/` walkers; `reader.vas()` backs raw `mem/` reads.
    #[allow(dead_code)]
    reader: ObjectReader<P>,
    /// The bootstrapped analysis context (OS, DTB/CR3, kernel list heads).
    ctx: AnalysisContext,
    registry: Registry,
}

impl<P: PhysicalMemoryProvider> MemoryFs<P> {
    /// Build a memory filesystem over `provider`: the static top-level tree, the
    /// bootstrapped analysis `ctx` (rendered into `sys/os-info.txt`), and an
    /// `ObjectReader` (provider + DTB + `symbols`) for the walker-backed
    /// artifacts.
    ///
    /// Translation is x86-64 4-level paging — the memf binary's default; ARM /
    /// 5-level support is a later refinement (tracked in the Phase 2 plan).
    pub fn new(provider: P, ctx: AnalysisContext, symbols: Box<dyn SymbolResolver>) -> Self {
        let vas = VirtualAddressSpace::new(provider, ctx.cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, symbols);
        Self {
            reader,
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

    /// Render `sys/processes.txt`: run the OS-appropriate memf process walker and
    /// format it, or — on a walker miss/error after a good bootstrap — return a
    /// one-line diagnostic header (never a hard error or silent empty).
    fn render_processes(&self) -> String {
        use memf_session::OsProfile;
        let rows: Result<Vec<ProcRow>, String> = match self.ctx.os {
            OsProfile::Windows => match self.ctx.ps_active_process_head {
                Some(head) => memf_windows::process::walk_processes(&self.reader, head)
                    .map(|ps| ps.into_iter().map(ProcRow::from).collect())
                    .map_err(|e| format!("{e}")),
                None => Err("PsActiveProcessHead not resolved (need --symbols?)".to_string()),
            },
            OsProfile::Linux => memf_linux::process::walk_processes(&self.reader)
                .map(|ps| ps.into_iter().map(ProcRow::from).collect())
                .map_err(|e| format!("{e}")),
            OsProfile::MacOs => Err("not implemented for macOS".to_string()),
        };
        match rows {
            Ok(rows) if !rows.is_empty() => render_process_table(&rows),
            Ok(_) => format!(
                "# pslist: 0 processes (walker returned empty)\n{}",
                render_process_table(&[])
            ),
            Err(why) => format!("# pslist unavailable: {why}\n"),
        }
    }

    /// Render `sys/modules.txt`: the OS-appropriate kernel-module walker, or a
    /// one-line diagnostic header on a walker miss/error (fail-soft).
    fn render_modules(&self) -> String {
        use memf_session::OsProfile;
        let rows: Result<Vec<ModRow>, String> = match self.ctx.os {
            OsProfile::Windows => match self.ctx.ps_loaded_module_list {
                Some(head) => memf_windows::driver::walk_drivers(&self.reader, head)
                    .map(|ds| ds.into_iter().map(ModRow::from).collect())
                    .map_err(|e| format!("{e}")),
                None => Err("PsLoadedModuleList not resolved (need --symbols?)".to_string()),
            },
            OsProfile::Linux => memf_linux::modules::walk_modules(&self.reader)
                .map(|ms| ms.into_iter().map(ModRow::from).collect())
                .map_err(|e| format!("{e}")),
            OsProfile::MacOs => Err("not implemented for macOS".to_string()),
        };
        match rows {
            Ok(rows) if !rows.is_empty() => render_module_table(&rows),
            Ok(_) => format!(
                "# modules: 0 entries (walker returned empty)\n{}",
                render_module_table(&[])
            ),
            Err(why) => format!("# modules unavailable: {why}\n"),
        }
    }

    /// Render `sys/network.txt`: the OS-appropriate connection walker, or a
    /// one-line diagnostic on a walker miss/error (fail-soft).
    ///
    /// Linux uses the self-contained `walk_connections`(+v6). Windows
    /// `walk_tcp_endpoints` needs a TCP partition-table VA that the current memf
    /// bootstrap does not resolve, so Windows surfaces an honest diagnostic
    /// (a real gap, not fabricated content) rather than empty output.
    fn render_network(&self) -> String {
        use memf_session::OsProfile;
        let rows: Result<Vec<NetRow>, String> = match self.ctx.os {
            OsProfile::Linux => match memf_linux::network::walk_connections(&self.reader) {
                Ok(mut conns) => {
                    if let Ok(v6) = memf_linux::network::walk_connections6(&self.reader) {
                        conns.extend(v6);
                    }
                    Ok(conns.into_iter().map(NetRow::from).collect())
                }
                Err(e) => Err(format!("{e}")),
            },
            OsProfile::Windows => Err(
                "Windows TCP partition-table VA not resolved by the current memf \
                 bootstrap (network walk needs a memf-side head, like pslist's)"
                    .to_string(),
            ),
            OsProfile::MacOs => Err("not implemented for macOS".to_string()),
        };
        match rows {
            Ok(rows) if !rows.is_empty() => render_net_table(&rows),
            Ok(_) => format!(
                "# network: 0 connections (walker returned empty)\n{}",
                render_net_table(&[])
            ),
            Err(why) => format!("# network unavailable: {why}\n"),
        }
    }

    /// Render `sys/dmesg.txt` from the Linux kernel ring buffer
    /// (`memf_linux::dmesg::extract_dmesg`), or an honest diagnostic on a
    /// non-Linux dump or a walker miss.
    fn render_dmesg_file(&self) -> String {
        use memf_session::OsProfile;
        if self.ctx.os != OsProfile::Linux {
            return format!("# dmesg unavailable: not a Linux dump ({})\n", self.ctx.os);
        }
        match memf_linux::dmesg::extract_dmesg(&self.reader) {
            Ok(entries) if !entries.is_empty() => {
                let rows: Vec<(u64, String)> = entries
                    .into_iter()
                    .map(|e| (e.timestamp_ns, e.message))
                    .collect();
                render_dmesg(&rows)
            }
            Ok(_) => "# dmesg: empty (log_buf absent or ring buffer empty)\n".to_string(),
            Err(e) => format!("# dmesg unavailable: {e}\n"),
        }
    }
}

impl From<memf_linux::ConnectionInfo> for NetRow {
    fn from(c: memf_linux::ConnectionInfo) -> Self {
        Self {
            protocol: c.protocol.to_string(),
            local: format!("{}:{}", c.local_addr, c.local_port),
            remote: format!("{}:{}", c.remote_addr, c.remote_port),
            state: c.state.to_string(),
            pid: c.pid.map(|p| p.to_string()).unwrap_or_default(),
        }
    }
}

impl From<memf_windows::WinDriverInfo> for ModRow {
    fn from(d: memf_windows::WinDriverInfo) -> Self {
        Self {
            name: d.name,
            base_addr: d.base_addr,
            size: d.size,
            path: d.full_path,
        }
    }
}

impl From<memf_linux::ModuleInfo> for ModRow {
    fn from(m: memf_linux::ModuleInfo) -> Self {
        Self {
            name: m.name,
            base_addr: m.base_addr,
            size: m.size,
            path: String::new(),
        }
    }
}

impl From<memf_windows::WinProcessInfo> for ProcRow {
    fn from(p: memf_windows::WinProcessInfo) -> Self {
        Self {
            pid: p.pid,
            ppid: p.ppid,
            name: p.image_name,
            create_time: p.create_time,
        }
    }
}

impl From<memf_linux::ProcessInfo> for ProcRow {
    fn from(p: memf_linux::ProcessInfo) -> Self {
        Self {
            pid: p.pid,
            ppid: p.ppid,
            name: p.comm,
            create_time: p.start_time,
        }
    }
}

/// One pslist row, normalized across OSes for rendering.
#[derive(Debug, Clone)]
pub(crate) struct ProcRow {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    /// Creation time, OS-native units (Windows FILETIME / Linux ns since boot);
    /// rendered verbatim — interpretation is the examiner's, like memf's output.
    pub create_time: u64,
}

/// Render a pslist as a tab-separated table with a column header. An empty slice
/// yields just the header line (the caller adds a diagnostic comment).
pub(crate) fn render_process_table(rows: &[ProcRow]) -> String {
    let mut out = String::from("PID\tPPID\tCREATE_TIME\tNAME\n");
    for r in rows {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            r.pid, r.ppid, r.create_time, r.name
        ));
    }
    out
}

/// One kernel-module/driver row, normalized across OSes.
#[derive(Debug, Clone)]
pub(crate) struct ModRow {
    pub name: String,
    pub base_addr: u64,
    pub size: u64,
    /// On-disk path (Windows driver) or empty (Linux module).
    pub path: String,
}

/// Render a module list as a tab-separated table with a column header. An empty
/// slice yields just the header line (the caller adds a diagnostic comment).
pub(crate) fn render_module_table(rows: &[ModRow]) -> String {
    let mut out = String::from("NAME\tBASE\tSIZE\tPATH\n");
    for r in rows {
        out.push_str(&format!(
            "{}\t{:#x}\t{}\t{}\n",
            r.name, r.base_addr, r.size, r.path
        ));
    }
    out
}

/// One network-connection row, normalized across OSes.
#[derive(Debug, Clone)]
pub(crate) struct NetRow {
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    /// Owning PID, or empty when not determinable.
    pub pid: String,
}

/// Render a connection list as a tab-separated table with a column header.
pub(crate) fn render_net_table(rows: &[NetRow]) -> String {
    let mut out = String::from("PROTO\tLOCAL\tREMOTE\tSTATE\tPID\n");
    for r in rows {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            r.protocol, r.local, r.remote, r.state, r.pid
        ));
    }
    out
}

/// Render the kernel ring buffer as `[timestamp_ns] message` lines.
pub(crate) fn render_dmesg(entries: &[(u64, String)]) -> String {
    let mut out = String::new();
    for (ts, msg) in entries {
        out.push_str(&format!("[{ts}] {msg}\n"));
    }
    out
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
            Artifact::SysProcesses => Ok(Self::file_metadata(
                ino,
                self.render_processes().len() as u64,
            )),
            Artifact::SysModules => {
                Ok(Self::file_metadata(ino, self.render_modules().len() as u64))
            }
            Artifact::SysNetwork => {
                Ok(Self::file_metadata(ino, self.render_network().len() as u64))
            }
            Artifact::SysDmesg => Ok(Self::file_metadata(
                ino,
                self.render_dmesg_file().len() as u64,
            )),
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
            Artifact::SysProcesses => Ok(self.render_processes().into_bytes()),
            Artifact::SysModules => Ok(self.render_modules().into_bytes()),
            Artifact::SysNetwork => Ok(self.render_network().into_bytes()),
            Artifact::SysDmesg => Ok(self.render_dmesg_file().into_bytes()),
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
        use memf_symbols::isf::IsfResolver;
        let dump = LimeBuilder::new().add_range(0, &[0u8; 64]).build();
        let provider = LimeProvider::from_bytes(&dump).unwrap();
        let ctx = AnalysisContext {
            os: OsProfile::Windows,
            cr3: 0x1ab000,
            kaslr_offset: 0,
            ps_active_process_head: Some(0xFFFF_F800_DEAD_0000),
            ps_loaded_module_list: Some(0xFFFF_F800_BEEF_0000),
        };
        let symbols = Box::new(IsfResolver::from_value(&serde_json::json!({})).unwrap());
        MemoryFs::new(provider, ctx, symbols)
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

    // -- sys/processes.txt (Task 2.1) --

    #[test]
    fn render_process_table_has_header_and_rows() {
        let rows = vec![
            ProcRow {
                pid: 4,
                ppid: 0,
                name: "System".into(),
                create_time: 0,
            },
            ProcRow {
                pid: 668,
                ppid: 4,
                name: "lsass.exe".into(),
                create_time: 132_000_000,
            },
        ];
        let out = render_process_table(&rows);
        let header = out.lines().next().unwrap_or_default();
        assert!(
            header.contains("PID") && header.contains("PPID") && header.contains("NAME"),
            "header: {header:?}"
        );
        assert!(
            out.contains("System") && out.contains("\t4\t"),
            "got: {out}"
        );
        assert!(
            out.contains("668") && out.contains("lsass.exe"),
            "got: {out}"
        );
    }

    #[test]
    fn render_process_table_empty_is_just_header() {
        let out = render_process_table(&[]);
        assert_eq!(out.lines().count(), 1, "empty list → header only: {out:?}");
        assert!(out.contains("PID"));
    }

    #[test]
    fn processes_txt_is_a_regular_file_under_sys() {
        let mut fs = mem_fs();
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().unwrap();
        let p = fs
            .lookup(sys, b"processes.txt")
            .unwrap()
            .expect("processes.txt");
        assert_eq!(fs.metadata(p).unwrap().file_type, FsFileType::RegularFile);
    }

    #[test]
    fn processes_txt_fail_soft_diagnostic_not_empty() {
        // The synthetic provider has no real EPROCESS list, so the walker misses;
        // read_file must return a non-empty diagnostic, never panic or empty.
        let mut fs = mem_fs();
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().unwrap();
        let p = fs.lookup(sys, b"processes.txt").unwrap().unwrap();
        let text = String::from_utf8(fs.read_file(p).unwrap()).unwrap();
        assert!(!text.is_empty(), "must surface a diagnostic, not empty");
        assert!(
            text.contains("pslist"),
            "expected a pslist diagnostic: {text}"
        );
    }

    // -- sys/modules.txt (Task 2.2) --

    #[test]
    fn render_module_table_has_header_and_rows() {
        let rows = vec![
            ModRow {
                name: "ntoskrnl.exe".into(),
                base_addr: 0xfffff800_0000_0000,
                size: 0x800000,
                path: "\\SystemRoot\\ntoskrnl.exe".into(),
            },
            ModRow {
                name: "tcpip.sys".into(),
                base_addr: 0xfffff800_0100_0000,
                size: 0x200000,
                path: String::new(),
            },
        ];
        let out = render_module_table(&rows);
        let header = out.lines().next().unwrap_or_default();
        assert!(
            header.contains("NAME") && header.contains("BASE") && header.contains("SIZE"),
            "header: {header:?}"
        );
        assert!(
            out.contains("ntoskrnl.exe") && out.contains("tcpip.sys"),
            "got: {out}"
        );
    }

    #[test]
    fn render_module_table_empty_is_just_header() {
        let out = render_module_table(&[]);
        assert_eq!(out.lines().count(), 1, "empty → header only: {out:?}");
        assert!(out.contains("NAME"));
    }

    #[test]
    fn modules_txt_is_a_regular_file_under_sys() {
        let mut fs = mem_fs();
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().unwrap();
        let m = fs
            .lookup(sys, b"modules.txt")
            .unwrap()
            .expect("modules.txt");
        assert_eq!(fs.metadata(m).unwrap().file_type, FsFileType::RegularFile);
    }

    #[test]
    fn modules_txt_fail_soft_diagnostic_not_empty() {
        let mut fs = mem_fs();
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().unwrap();
        let m = fs.lookup(sys, b"modules.txt").unwrap().unwrap();
        let text = String::from_utf8(fs.read_file(m).unwrap()).unwrap();
        assert!(!text.is_empty(), "must surface a diagnostic, not empty");
        assert!(
            text.contains("modules"),
            "expected a modules diagnostic: {text}"
        );
    }

    // -- sys/network.txt (Task 2.3) --

    #[test]
    fn render_net_table_has_header_and_rows() {
        let rows = vec![NetRow {
            protocol: "TCPv4".into(),
            local: "10.0.0.5:445".into(),
            remote: "10.0.0.9:51000".into(),
            state: "ESTABLISHED".into(),
            pid: "4".into(),
        }];
        let out = render_net_table(&rows);
        let header = out.lines().next().unwrap_or_default();
        assert!(
            header.contains("PROTO") && header.contains("LOCAL") && header.contains("STATE"),
            "header: {header:?}"
        );
        assert!(
            out.contains("445") && out.contains("ESTABLISHED"),
            "got: {out}"
        );
    }

    #[test]
    fn render_net_table_empty_is_just_header() {
        assert_eq!(render_net_table(&[]).lines().count(), 1);
    }

    #[test]
    fn network_txt_fail_soft_diagnostic_not_empty() {
        let mut fs = mem_fs();
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().unwrap();
        let n = fs
            .lookup(sys, b"network.txt")
            .unwrap()
            .expect("network.txt");
        assert_eq!(fs.metadata(n).unwrap().file_type, FsFileType::RegularFile);
        let text = String::from_utf8(fs.read_file(n).unwrap()).unwrap();
        assert!(!text.is_empty() && text.contains("network"), "got: {text}");
    }

    #[test]
    fn network_txt_windows_uses_pool_scan_not_head_gap() {
        // Windows network must run the symbol-free pool scanners (scan_tcp_*),
        // not surface the old "partition-table VA not resolved" head gap. On the
        // synthetic dump the scanners find nothing → a "0 connections" note.
        let mut fs = mem_fs(); // ctx.os == Windows
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().unwrap();
        let n = fs.lookup(sys, b"network.txt").unwrap().unwrap();
        let text = String::from_utf8(fs.read_file(n).unwrap()).unwrap();
        assert!(
            !text.contains("not resolved"),
            "Windows net must pool-scan, not report a head gap: {text}"
        );
    }

    // -- sys/dmesg.txt (Task 2.5) --

    #[test]
    fn render_dmesg_formats_timestamp_and_message() {
        let entries = vec![
            (0u64, "Linux version 6.1.0".to_string()),
            (1_500_000_000u64, "eth0: link up".to_string()),
        ];
        let out = render_dmesg(&entries);
        assert!(out.contains("Linux version 6.1.0"), "got: {out}");
        assert!(out.contains("eth0: link up"), "got: {out}");
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn render_dmesg_empty_is_empty() {
        assert!(render_dmesg(&[]).is_empty());
    }

    #[test]
    fn dmesg_txt_fail_soft_diagnostic_not_empty() {
        // ctx.os is Windows in mem_fs(); dmesg is Linux-only → honest diagnostic.
        let mut fs = mem_fs();
        let sys = fs.lookup(ROOT_INO, b"sys").unwrap().unwrap();
        let d = fs.lookup(sys, b"dmesg.txt").unwrap().expect("dmesg.txt");
        assert_eq!(fs.metadata(d).unwrap().file_type, FsFileType::RegularFile);
        let text = String::from_utf8(fs.read_file(d).unwrap()).unwrap();
        assert!(!text.is_empty() && text.contains("dmesg"), "got: {text}");
    }
}
