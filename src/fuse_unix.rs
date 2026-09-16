#![forbid(unsafe_code)]

use crate::fusefs::ForensicFuseFs;
use crate::session::Session;
use crate::ForensicFs;
use crate::MountOptions;
use std::io;
use std::path::Path;

/// Mount a `ForensicFs` via FUSE on Unix (macOS / Linux).
///
/// When `options.daemon` is false (default), this blocks until the
/// filesystem is unmounted.  When true, the FUSE event loop runs in a
/// background thread and this function parks the current thread
/// indefinitely.
pub fn mount_unix(
    fs: Box<dyn ForensicFs + Send>,
    mountpoint: &Path,
    session: Option<Session>,
    options: &MountOptions,
) -> io::Result<()> {
    let fuse_fs = ForensicFuseFs::new(fs, session, options.layout, options.deleted_mode);

    let mut fuse_options = vec![fuser::MountOption::FSName(options.fs_name.clone())];
    if options.read_only {
        fuse_options.push(fuser::MountOption::RO);
    }

    if options.daemon {
        let _session = fuser::spawn_mount2(fuse_fs, mountpoint, &fuse_options)?;
        eprintln!(
            "4n6mount: mounted at {} (daemon mode, PID {})",
            mountpoint.display(),
            std::process::id()
        );
        // Block until the process is killed or the fs is unmounted externally.
        loop {
            std::thread::park();
        }
    } else {
        fuser::mount2(fuse_fs, mountpoint, &fuse_options)
    }
}

#[cfg(test)]
mod tests {

    use crate::MountOptions;

    // ----- MountOptions::default() -----

    #[test]
    fn mount_options_default_read_only_is_false() {
        let opts = MountOptions::default();
        assert!(!opts.read_only);
    }

    #[test]
    fn mount_options_default_daemon_is_false() {
        let opts = MountOptions::default();
        assert!(!opts.daemon);
    }

    #[test]
    fn mount_options_default_fs_name() {
        let opts = MountOptions::default();
        assert_eq!(opts.fs_name, "4n6mount");
    }

    // ----- MountOptions custom construction -----

    #[test]
    fn mount_options_custom() {
        let opts = MountOptions {
            read_only: true,
            daemon: true,
            fs_name: "ext4fs".to_string(),
            layout: crate::MountLayout::DiskOverlay,
            deleted_mode: crate::DeletedMode::default(),
        };
        assert!(opts.read_only);
        assert!(opts.daemon);
        assert_eq!(opts.fs_name, "ext4fs");
    }

    #[test]
    fn mount_options_partial_override() {
        let opts = MountOptions {
            read_only: true,
            ..MountOptions::default()
        };
        assert!(opts.read_only);
        assert!(!opts.daemon);
        assert_eq!(opts.fs_name, "4n6mount");
    }
}
