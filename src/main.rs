#![forbid(unsafe_code)]

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "4n6mount",
    about = "Universal forensic FUSE mount — auto-detects ext4, NTFS, exFAT",
    version,
)]
struct Cli {
    /// Image file to mount (positional, required unless exporting/importing)
    image: Option<String>,

    /// Mount point directory (positional)
    mountpoint: Option<String>,

    /// Force filesystem type (auto-detected if omitted)
    #[arg(long)]
    fs: Option<String>,

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

    let fs_type = if let Some(fs_str) = &cli.fs {
        fs_str
            .parse::<forensic_mount::detect::FsType>()
            .unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            })
    } else {
        forensic_mount::detect::detect_filesystem(&mut file).unwrap_or_else(|e| {
            eprintln!("Detection failed: {e}");
            std::process::exit(1);
        })
    };

    eprintln!("Detected filesystem: {fs_type}");

    // Create ForensicFs based on detected type
    let forensic_fs: Box<dyn forensic_mount::ForensicFs + Send> = match fs_type {
        #[cfg(feature = "ext4")]
        forensic_mount::detect::FsType::Ext4 => {
            Box::new(forensic_mount::fs_ext4::Ext4ForensicFs::new(file).unwrap_or_else(|e| {
                eprintln!("Cannot parse ext4: {e}");
                std::process::exit(1);
            }))
        }
        _ => {
            eprintln!(
                "Filesystem type '{fs_type}' is not supported (compiled features may be missing)"
            );
            std::process::exit(1);
        }
    };

    // Build session if requested
    let session_mgr = cli.session.map(|dir| {
        let session_path = std::path::Path::new(&dir);
        if cli.resume {
            forensic_mount::session::Session::resume(
                session_path,
                std::path::Path::new(&image),
            )
            .unwrap_or_else(|e| {
                eprintln!("Cannot resume session: {e}");
                std::process::exit(1);
            })
        } else {
            forensic_mount::session::Session::create(
                session_path,
                std::path::Path::new(&image),
            )
            .unwrap_or_else(|e| {
                eprintln!("Cannot create session: {e}");
                std::process::exit(1);
            })
        }
    });

    let options = forensic_mount::MountOptions {
        read_only: session_mgr.is_none(),
        daemon: cli.daemon,
        fs_name: format!("4n6mount-{fs_type}"),
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
        let cli = Cli::parse_from(["4n6mount", "image.dd", "/mnt", "--session", "./case", "--resume"]);
        assert!(cli.resume);
    }

    #[test]
    fn parse_mount_with_filter_dbs() {
        let cli = Cli::parse_from([
            "4n6mount", "image.dd", "/mnt",
            "--filter-db", "/path/nsrl.db",
            "--filter-db", "/path/custom.txt",
        ]);
        assert_eq!(cli.filter_dbs.len(), 2);
    }

    #[test]
    fn parse_export_session() {
        let cli = Cli::parse_from([
            "4n6mount",
            "--export-session", "./case-001",
            "--output", "case.tar.gz",
        ]);
        assert_eq!(cli.export_session.unwrap(), "./case-001");
        assert_eq!(cli.output.unwrap(), "case.tar.gz");
        assert!(cli.image.is_none());
    }

    #[test]
    fn parse_import_session() {
        let cli = Cli::parse_from([
            "4n6mount",
            "--import-session", "case.tar.gz",
            "--session", "./case-002",
        ]);
        assert_eq!(cli.import_session.unwrap(), "case.tar.gz");
        assert_eq!(cli.session.unwrap(), "./case-002");
    }

    #[test]
    fn parse_all_options() {
        let cli = Cli::parse_from([
            "4n6mount", "image.E01", "/mnt/evidence",
            "--fs", "ext4",
            "--session", "./case",
            "--resume",
            "--daemon",
            "--filter-db", "nsrl.db",
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
