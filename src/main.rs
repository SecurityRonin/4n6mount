#![forbid(unsafe_code)]

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "4n6mount",
    about = "Universal forensic FUSE mount — auto-detects ext4, NTFS, exFAT, HFS+, APFS, \
             ISO9660, EWF/VMDK containers, and zip/7z/tar(.gz/.bz2) archives",
    version
)]
struct Cli {
    /// Image file to mount (positional, required unless exporting/importing)
    image: Option<String>,

    /// Mount point directory (positional)
    mountpoint: Option<String>,

    /// Force filesystem type (auto-detected if omitted)
    #[arg(long)]
    fs: Option<String>,

    /// How to surface recovered deleted files under `deleted/`:
    /// `latest` (newest per name in place, older to $Orphans),
    /// `all` (every instance in $Orphans), or `off`.
    #[arg(long, value_enum, default_value_t = forensic_mount::DeletedMode::Latest)]
    deleted: forensic_mount::DeletedMode,

    /// Symbol file (ISF JSON or PDB) for memory-dump analysis. Optional for a
    /// Windows crash dump whose header carries CR3 + kernel list heads.
    #[arg(long)]
    symbols: Option<String>,

    /// Session directory for COW overlay persistence
    #[arg(long)]
    session: Option<String>,

    /// Resume a previous session
    #[arg(long)]
    resume: bool,

    /// Run as a background daemon
    #[arg(long)]
    daemon: bool,

    /// Known-good hash database for evidence/ filtering
    #[arg(long = "filter-db")]
    filter_dbs: Vec<String>,

    /// Export a session to a tarball
    #[arg(long = "export-session")]
    export_session: Option<String>,

    /// Output path for session export
    #[arg(long)]
    output: Option<String>,

    /// Import a session from a tarball
    #[arg(long = "import-session")]
    import_session: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // Handle export-session
    if let Some(session_dir) = &cli.export_session {
        let output = cli.output.as_deref().unwrap_or_else(|| {
            eprintln!("--output required with --export-session");
            std::process::exit(1);
        });
        forensic_mount::session::export_session(
            std::path::Path::new(session_dir),
            std::path::Path::new(output),
        )
        .unwrap_or_else(|e| {
            eprintln!("Export failed: {e}");
            std::process::exit(1);
        });
        eprintln!("Session exported to {output}");
        return;
    }

    // Handle import-session
    if let Some(tarball) = &cli.import_session {
        let session_dir = cli.session.as_deref().unwrap_or_else(|| {
            eprintln!("--session required with --import-session");
            std::process::exit(1);
        });
        forensic_mount::session::import_session(
            std::path::Path::new(tarball),
            std::path::Path::new(session_dir),
        )
        .unwrap_or_else(|e| {
            eprintln!("Import failed: {e}");
            std::process::exit(1);
        });
        eprintln!("Session imported to {session_dir}");
        return;
    }

    // Mount mode — image and mountpoint required
    let image = cli.image.unwrap_or_else(|| {
        eprintln!("Usage: 4n6mount <image> <mountpoint>");
        std::process::exit(1);
    });
    let mountpoint = cli.mountpoint.unwrap_or_else(|| {
        eprintln!("Usage: 4n6mount <image> <mountpoint>");
        std::process::exit(1);
    });

    // Open image and detect filesystem
    let mut file = std::fs::File::open(&image).unwrap_or_else(|e| {
        eprintln!("Cannot open {image}: {e}");
        std::process::exit(1);
    });

    // Memory-dump path: explicit `--fs memory`, or a recognized dump signature.
    // A memory dump mounts read-only with the Raw layout (its own top level),
    // bypassing the disk overlay entirely.
    let force_memory = matches!(cli.fs.as_deref(), Some("memory" | "mem"));
    let detected_memory = forensic_mount::detect::detect_memory_dump(&mut file)
        .ok()
        .flatten();
    if force_memory || detected_memory.is_some() {
        route_memory_mount(&image, &mountpoint, cli.symbols.as_deref(), cli.daemon);
        return;
    }

    // A forced disk fs type is no longer honored: the engine's `open()`
    // auto-detects the container, partitions, and filesystem. Only `--fs
    // memory`/`mem` (handled above) still forces a route.
    if let Some(x) = &cli.fs {
        eprintln!("note: --fs {x} ignored; auto-detecting (partition-aware)");
    }

    // Hand the image to 4n6mount's open path: it peels an outer compression
    // wrapper (evidence.dd.gz -> dd) via archive-core, then the engine decodes
    // any container (E01/VMDK/QCOW2/VHD/VHDX/DMG), enumerates partitions, and
    // mounts EVERY partition that carries a filesystem — a single-filesystem
    // image at the root (unchanged), a multi-partition disk multiplexed under
    // p1/p2/... subdirectories — failing loud if none is found.
    let forensic_fs =
        forensic_mount::open_image_all(std::path::Path::new(&image)).unwrap_or_else(|e| {
            eprintln!("Cannot mount {image}: {e}");
            std::process::exit(1);
        });

    // Build session if requested
    let session_mgr = cli.session.map(|dir| {
        let session_path = std::path::Path::new(&dir);
        if cli.resume {
            forensic_mount::session::Session::resume(session_path, std::path::Path::new(&image))
                .unwrap_or_else(|e| {
                    eprintln!("Cannot resume session: {e}");
                    std::process::exit(1);
                })
        } else {
            forensic_mount::session::Session::create(session_path, std::path::Path::new(&image))
                .unwrap_or_else(|e| {
                    eprintln!("Cannot create session: {e}");
                    std::process::exit(1);
                })
        }
    });

    let options = forensic_mount::MountOptions {
        read_only: session_mgr.is_none(),
        daemon: cli.daemon,
        fs_name: "4n6mount".to_string(),
        layout: forensic_mount::MountLayout::DiskOverlay,
        deleted_mode: cli.deleted,
    };

    eprintln!("Mounting {image} at {mountpoint}");
    forensic_mount::mount(
        forensic_fs,
        std::path::Path::new(&mountpoint),
        session_mgr,
        &options,
    )
    .unwrap_or_else(|e| {
        eprintln!("Mount failed: {e}");
        std::process::exit(1);
    });
}

/// Build and mount a memory dump as a read-only `Raw`-layout filesystem.
#[cfg(feature = "memory")]
fn route_memory_mount(image: &str, mountpoint: &str, symbols: Option<&str>, daemon: bool) {
    let fs = forensic_mount::build_memory_fs(
        std::path::Path::new(image),
        symbols.map(std::path::Path::new),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let options = forensic_mount::MountOptions {
        read_only: true,
        daemon,
        fs_name: "4n6mount-memory".to_string(),
        layout: forensic_mount::MountLayout::Raw,
        // A memory dump exposes no deleted-file recovery surface.
        deleted_mode: forensic_mount::DeletedMode::Off,
    };
    eprintln!("Mounting memory dump {image} at {mountpoint}");
    forensic_mount::mount(fs, std::path::Path::new(mountpoint), None, &options).unwrap_or_else(
        |e| {
            eprintln!("Mount failed: {e}");
            std::process::exit(1);
        },
    );
}

/// Memory support was not compiled in: fail loud rather than silently misroute.
#[cfg(not(feature = "memory"))]
fn route_memory_mount(_image: &str, _mountpoint: &str, _symbols: Option<&str>, _daemon: bool) {
    eprintln!(
        "This build has no memory-dump support (the `memory` feature was not enabled). \
         Rebuild with `--features memory`."
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mount_args() {
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt/evidence"]);
        assert_eq!(cli.image.unwrap(), "image.dd");
        assert_eq!(cli.mountpoint.unwrap(), "/mnt/evidence");
        assert!(cli.fs.is_none());
        assert!(!cli.daemon);
        assert!(!cli.resume);
    }

    #[test]
    fn parse_mount_with_fs_override() {
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt", "--fs", "ntfs"]);
        assert_eq!(cli.fs.unwrap(), "ntfs");
    }

    #[test]
    fn parse_mount_with_session() {
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt", "--session", "./case-001"]);
        assert_eq!(cli.session.unwrap(), "./case-001");
    }

    #[test]
    fn parse_mount_with_daemon() {
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt", "--daemon"]);
        assert!(cli.daemon);
    }

    #[test]
    fn parse_mount_with_resume() {
        let cli = Cli::parse_from([
            "4n6mount",
            "image.dd",
            "/mnt",
            "--session",
            "./case",
            "--resume",
        ]);
        assert!(cli.resume);
    }

    #[test]
    fn parse_mount_with_symbols() {
        let cli = Cli::parse_from([
            "4n6mount",
            "memory.lime",
            "/mnt",
            "--fs",
            "memory",
            "--symbols",
            "linux.json",
        ]);
        assert_eq!(cli.fs.unwrap(), "memory");
        assert_eq!(cli.symbols.unwrap(), "linux.json");
    }

    #[test]
    fn parse_mount_with_filter_dbs() {
        let cli = Cli::parse_from([
            "4n6mount",
            "image.dd",
            "/mnt",
            "--filter-db",
            "/path/nsrl.db",
            "--filter-db",
            "/path/custom.txt",
        ]);
        assert_eq!(cli.filter_dbs.len(), 2);
    }

    #[test]
    fn parse_export_session() {
        let cli = Cli::parse_from([
            "4n6mount",
            "--export-session",
            "./case-001",
            "--output",
            "case.tar.gz",
        ]);
        assert_eq!(cli.export_session.unwrap(), "./case-001");
        assert_eq!(cli.output.unwrap(), "case.tar.gz");
        assert!(cli.image.is_none());
    }

    #[test]
    fn parse_import_session() {
        let cli = Cli::parse_from([
            "4n6mount",
            "--import-session",
            "case.tar.gz",
            "--session",
            "./case-002",
        ]);
        assert_eq!(cli.import_session.unwrap(), "case.tar.gz");
        assert_eq!(cli.session.unwrap(), "./case-002");
    }

    #[test]
    fn parse_deleted_mode_defaults_to_latest() {
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt"]);
        assert_eq!(cli.deleted, forensic_mount::DeletedMode::Latest);
    }

    #[test]
    fn parse_deleted_mode_all() {
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt", "--deleted", "all"]);
        assert_eq!(cli.deleted, forensic_mount::DeletedMode::All);
    }

    #[test]
    fn parse_deleted_mode_off() {
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt", "--deleted", "off"]);
        assert_eq!(cli.deleted, forensic_mount::DeletedMode::Off);
    }

    #[test]
    fn parse_all_options() {
        let cli = Cli::parse_from([
            "4n6mount",
            "image.E01",
            "/mnt/evidence",
            "--fs",
            "ext4",
            "--session",
            "./case",
            "--resume",
            "--daemon",
            "--filter-db",
            "nsrl.db",
        ]);
        assert_eq!(cli.image.unwrap(), "image.E01");
        assert_eq!(cli.mountpoint.unwrap(), "/mnt/evidence");
        assert_eq!(cli.fs.unwrap(), "ext4");
        assert_eq!(cli.session.unwrap(), "./case");
        assert!(cli.resume);
        assert!(cli.daemon);
        assert_eq!(cli.filter_dbs.len(), 1);
    }
}
