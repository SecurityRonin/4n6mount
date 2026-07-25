//! `open_image_all` must mount **archive** containers (zip/7z/tar) and **logical**
//! containers (ad1/aff4-logical) as browsable filesystems.
//!
//! Regression guard for the mount-smoke failure: the forensic-vfs-engine
//! migration (ADR-0006) left `open_image_all` calling only `Vfs::open_all`,
//! which surfaces an archive/logical container as `fs: None` (its members are
//! treated as nested-evidence candidates, never as a browsable tree). These
//! tests drive the public `open_image_all` end to end — no FUSE — so they run on
//! any host, unlike the CI `mount-smoke` job.

use forensic_mount::{open_image_all, ForensicFs, FsFileType};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// Walk a mounted filesystem from its root along a `/`-separated path.
fn resolve(fs: &mut dyn ForensicFs, path: &str) -> Option<u64> {
    let mut ino = fs.root_ino();
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        ino = fs.lookup(ino, comp.as_bytes()).ok()??;
    }
    Some(ino)
}

#[test]
fn zip_archive_mounts_and_reads_files() {
    let mut fs = open_image_all(&fixture("hello.zip")).expect("zip archive should mount");

    // A file at the archive root reads back verbatim.
    let hello = resolve(&mut *fs, "hello.txt").expect("hello.txt present at root");
    assert_eq!(
        fs.read_file(hello).expect("read hello.txt"),
        b"hello from archive\n"
    );

    // A nested file resolves through an intermediate directory.
    let deep = resolve(&mut *fs, "sub/deep.txt").expect("sub/deep.txt present");
    assert_eq!(
        fs.read_file(deep).expect("read deep.txt"),
        b"deep content\n"
    );

    // The intermediate component is a directory.
    let sub = resolve(&mut *fs, "sub").expect("sub/ present");
    assert!(matches!(
        fs.metadata(sub).expect("metadata sub").file_type,
        FsFileType::Directory
    ));

    // read_dir at the root lists hello.txt.
    let names: Vec<Vec<u8>> = fs
        .read_dir(fs.root_ino())
        .expect("read_dir root")
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.iter().any(|n| n == b"hello.txt"));
}
