//! Extended attributes must reach the FUSE layer from the image.
//!
//! They are evidence: on macOS they carry the quarantine flag, Finder metadata
//! and decmpfs. Until now `ForensicFs` had no xattr method at all, so
//! `fusefs::getxattr` answered `ENODATA` for every real file and an examiner
//! running `xattr -l` was told a file had none — a negative finding produced by
//! the reader rather than by the evidence.
//!
//! `forensic-vfs` already models them as streams (`StreamId::Xattr`,
//! `StreamKind::Xattr`, `data_streams`, `read_at`), so this is a passthrough
//! that was never wired, not a new capability.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use forensic_mount::ForensicFs;

fn images() -> Vec<PathBuf> {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("data");
    ["apfs.img", "hfsplus.img", "exfat.img"]
        .iter()
        .map(|n| d.join(n))
        .filter(|p| p.is_file())
        .collect()
}

/// RED: at least one file in the committed corpus must expose an extended
/// attribute through `ForensicFs`.
///
/// This is deliberately a corpus-wide assertion rather than a per-file one: the
/// claim is that the PATH works, and a single attribute anywhere proves it.
/// Asserting zero would be satisfied by the defect.
#[test]
fn xattrs_reach_the_forensic_fs_layer() {
    let mut total = 0usize;
    let mut examined = 0usize;
    let mut per_image = Vec::new();

    for img in images() {
        let Ok(mut fs) = forensic_mount::open_image(&img) else {
            continue;
        };
        let f: &mut dyn ForensicFs = fs.as_mut();
        let mut found = 0usize;
        let mut stack = vec![f.root_ino()];
        while let Some(ino) = stack.pop() {
            let Ok(entries) = f.read_dir(ino) else { continue };
            for e in entries {
                let n = e.name_str();
                if n == "." || n == ".." {
                    continue;
                }
                examined += 1;
                if let Ok(x) = f.xattrs(e.inode) {
                    found += x.len();
                }
                if matches!(
                    f.metadata(e.inode).map(|m| m.file_type),
                    Ok(forensic_mount::FsFileType::Directory)
                ) {
                    stack.push(e.inode);
                }
            }
        }
        per_image.push(format!("{}: {found}", img.file_name().unwrap().to_string_lossy()));
        total += found;
    }

    eprintln!("  extended attributes found — {}", per_image.join(", "));
    assert!(
        examined > 0,
        "no entries were examined; this test would pass over an empty corpus"
    );
    assert!(
        total > 0,
        "not one extended attribute reached ForensicFs across {} image(s). \
         The readers have them (apfs-core is Tier-1 validated on xattrs) and \
         forensic-vfs models them as streams, so a zero here means the \
         passthrough is still missing.",
        images().len()
    );
}
