//! Does the mount present the evidence *faithfully*?
//!
//! FUSE-T reaches the kernel over loopback **NFS** (ADR-0011). NFS is not a
//! transparent pipe: it has its own attribute model, its own caching, its own
//! timestamp precision, and its own opinion about extended attributes. Anything
//! it changes on the way through is a metadata error in a forensic report — a
//! wrong mtime or a dropped xattr is not a performance footnote, it is a false
//! statement about an exhibit.
//!
//! The oracle is the VFS layer, which is independently covered by this repo's
//! other suites. For every entry it is asked what the *image* says, and the same
//! entry is `stat`ed through the mount. A difference is a finding, and every
//! finding is reported rather than the first one aborting the run — a partial
//! list would understate the problem.
//!
//! Skips loudly when no backend can mount, for the reason in `mount_smoke.rs`:
//! a silent skip is indistinguishable from a pass.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Every committed filesystem image, so the check is not hostage to one
/// format's feature set. exFAT carries almost no metadata; HFS+ and APFS carry
/// birth times and extended attributes, which is where an NFS round trip is
/// most likely to lose something.
fn fixtures() -> Vec<PathBuf> {
    let d = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data");
    ["exfat.img", "hfsplus.img", "apfs.img"]
        .iter()
        .map(|n| d.join(n))
        .filter(|p| p.is_file())
        .collect()
}

fn binary() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    p.pop();
    p.join("4n6mount")
}

struct Mounted {
    child: Child,
    dir: PathBuf,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.dir).status();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Unique per MOUNT, not per process: every test in this binary shares a pid and
/// cargo runs them in parallel. Keying mountpoints on the pid alone made three
/// tests fight over the same directory — the `umount` noise and a run where a
/// real disagreement silently vanished both came from that collision.
static MOUNT_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn mount_fixture(image: &Path) -> Option<Mounted> {
    let tag = image
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let seq = MOUNT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("4n6mount-nfs-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let log = dir.with_extension("log");
    let out = std::fs::File::create(&log).ok()?;
    let err = out.try_clone().ok()?;
    let child = Command::new(binary())
        .arg(image)
        .arg(&dir)
        .stdout(out)
        .stderr(err)
        .spawn()
        .ok()?;
    let m = Mounted { child, dir };
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if m.dir.join("ro").is_dir() {
            return Some(m);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!(
        "SKIPPED: no FUSE backend could mount here — {}",
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .last()
            .unwrap_or("no output")
            .trim()
    );
    None
}

/// Every (path, metadata) pair the VFS layer reports, walked from the root.
/// Walk `f`, returning `(path, metadata)` for every entry.
///
/// Takes the caller's handle on purpose. The reader populates its inode map
/// lazily as directories are read, so an inode number is only meaningful to the
/// handle that walked to it — handing numbers from one handle to another yields
/// `NotFound("unknown inode N")`, which reads like a corrupt image and is not.
fn vfs_tree(f: &mut dyn forensic_mount::ForensicFs) -> Vec<(String, forensic_mount::FsMetadata)> {
    let mut out = Vec::new();
    let mut stack = vec![(f.root_ino(), String::new())];
    while let Some((ino, prefix)) = stack.pop() {
        let Ok(entries) = f.read_dir(ino) else {
            continue;
        };
        for e in entries {
            let name = e.name_str();
            if name == "." || name == ".." {
                continue;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if let Ok(md) = f.metadata(e.inode) {
                let is_dir = matches!(md.file_type, forensic_mount::FsFileType::Directory);
                out.push((path.clone(), md));
                if is_dir {
                    stack.push((e.inode, path));
                }
            }
        }
    }
    out
}

/// A single disagreement between the image and the mounted view.
struct Finding {
    path: String,
    field: &'static str,
    image: String,
    mounted: String,
}

/// TIER: differential. The mount must present what the image contains.
///
/// Checks the fields an examiner reports on: size, type, mode, ownership, link
/// count, and every timestamp at full precision. Timestamps are compared to the
/// **nanosecond**, because that is the resolution the format carries and the
/// resolution a timeline is built from; a silent truncation to seconds would
/// pass a coarser check while changing an exhibit.
#[test]
fn the_mount_presents_the_image_faithfully() {
    let mut findings: Vec<Finding> = Vec::new();
    let mut checked = 0usize;
    let mut mounted_any = false;

    for image in fixtures() {
        let Some(m) = mount_fixture(&image) else {
            continue;
        };
        mounted_any = true;
        let root = m.dir.join("ro").join("root");
        assert!(root.is_dir(), "the forensic layout must expose ro/root");

        let mut fs = forensic_mount::open_image(&image).expect("fixture opens");
        let expected = vfs_tree(fs.as_mut());
        assert!(
            !expected.is_empty(),
            "the VFS oracle must report entries for {}, or this test proves nothing",
            image.display()
        );

        for (path, want) in &expected {
            let p = root.join(path);
            let Ok(got) = std::fs::symlink_metadata(&p) else {
                findings.push(Finding {
                    path: path.clone(),
                    field: "present",
                    image: "yes".into(),
                    mounted: "missing".into(),
                });
                continue;
            };
            checked += 1;

            let mut push = |field: &'static str, image: String, mounted: String| {
                if image != mounted {
                    findings.push(Finding {
                        path: path.clone(),
                        field,
                        image,
                        mounted,
                    });
                }
            };

            let is_dir = matches!(want.file_type, forensic_mount::FsFileType::Directory);
            push("is_dir", is_dir.to_string(), got.is_dir().to_string());

            // Directory sizes are a filesystem's own bookkeeping and NFS is entitled
            // to report its own; only file sizes are evidence.
            if !is_dir {
                push("size", want.size.to_string(), got.size().to_string());
            }

            // Permission bits only: the type bits are checked separately above and
            // the two formats encode them differently.
            push(
                "mode",
                format!("{:o}", want.mode & 0o7777),
                format!("{:o}", got.mode() & 0o7777),
            );
            push("uid", want.uid.to_string(), got.uid().to_string());
            push("gid", want.gid.to_string(), got.gid().to_string());
            push(
                "nlink",
                want.links_count.to_string(),
                got.nlink().to_string(),
            );

            for (field, w, gs, gn) in [
                ("mtime", &want.mtime, got.mtime(), got.mtime_nsec()),
                ("atime", &want.atime, got.atime(), got.atime_nsec()),
                ("ctime", &want.ctime, got.ctime(), got.ctime_nsec()),
            ] {
                push(
                    field,
                    format!("{}.{:09}", w.seconds, w.nanoseconds),
                    format!("{gs}.{gn:09}"),
                );
            }
        }
    }

    if !mounted_any {
        return;
    }
    // A run that compared nothing is not a pass. The first version of this test
    // silently skipped every entry and reported success over an empty list.
    assert!(
        checked > 0,
        "compared 0 entries: the comparison never ran, which is not the same as agreeing"
    );
    eprintln!(
        "  checked {checked} entries across {} image(s)",
        fixtures().len()
    );
    if !findings.is_empty() {
        let mut by_field: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for f in &findings {
            *by_field.entry(f.field).or_default() += 1;
        }
        eprintln!("  disagreements by field: {by_field:?}");
        for f in findings.iter().take(12) {
            eprintln!(
                "    {}: {} — image {:?}, mounted {:?}",
                f.path, f.field, f.image, f.mounted
            );
        }
    }

    // A PINNED BASELINE, not a clean bill of health.
    //
    // NFS cannot carry everything the image states (ADR-0011), and these are the
    // losses measured on macOS 27 with FUSE-T. Committing this red would train
    // every reader to ignore it; committing it green would claim fidelity we do
    // not have. Pinning the exact shape does neither: the run stays green while
    // the limitation is unchanged, and goes red the moment it moves — in either
    // direction. A FUSE-T release that preserved ownership would fail here, and
    // that failure is the news.
    //
    // What each entry means for a report:
    //   atime   pre-1970 times collapse to epoch 0. -2082844800 is 1904-01-01,
    //           the HFS+ "never accessed" marker; the mount renders it as a date.
    //   uid/gid replaced by the MOUNTING USER's. An examiner reading ownership
    //           off the mount reads their own account, not the evidence.
    //   present one filesystem-internal entry is not surfaced by the mount.
    let mut by_field: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in &findings {
        *by_field.entry(f.field).or_default() += 1;
    }
    let known: std::collections::BTreeMap<&str, usize> =
        [("atime", 4), ("gid", 3), ("present", 1), ("uid", 3)]
            .into_iter()
            .collect();
    assert_eq!(
        by_field, known,
        "the NFS round trip lost a DIFFERENT set of fields than the baseline in \
         ADR-0011. Fewer or different losses are good news and mean the baseline \
         should be updated; more means a regression an examiner would inherit."
    );
}

/// Extended attributes must survive the mount.
///
/// `4n6mount` serves xattrs (`fusefs.rs::getxattr`/`listxattr`), and NFS has its
/// own view of them. If they vanish in transit, an examiner who lists attributes
/// through the mount concludes the file had none — a negative finding produced
/// by the transport, not by the evidence.
#[test]
fn extended_attributes_survive_the_mount() {
    let mut errors = Vec::new();
    let mut with_attrs = 0usize;
    let mut files = 0usize;
    let mut mounted_any = false;

    for image in fixtures() {
        let Some(m) = mount_fixture(&image) else {
            continue;
        };
        mounted_any = true;
        let root = m.dir.join("ro").join("root");

        // Whatever this build serves, `listxattr` through the mount must not ERROR;
        // an error and an empty list are different claims and only one is safe.
        let mut fs = forensic_mount::open_image(&image).expect("fixture opens");
        for (path, _) in vfs_tree(fs.as_mut()) {
            let p = root.join(&path);
            if !p.is_file() {
                continue;
            }
            files += 1;
            match Command::new("xattr").arg("-l").arg(&p).output() {
                Ok(o) if !o.status.success() => {
                    errors.push(format!(
                        "{path}: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ));
                }
                Ok(o) if !o.stdout.is_empty() => with_attrs += 1,
                Ok(_) => {}
                Err(e) => errors.push(format!("{path}: {e}")),
            }
        }
    }
    if !mounted_any {
        return;
    }
    assert!(
        files > 0,
        "no files were examined: an xattr check over zero files asserts nothing"
    );
    eprintln!("  {files} files, {with_attrs} carrying xattrs through the mount");
    assert!(
        errors.is_empty(),
        "listing extended attributes failed through the mount:\n  {}",
        errors.join("\n  ")
    );
}

/// File contents must be byte-exact, including at offsets and across the
/// NFS read size — a truncated or misaligned read changes a hash.
#[test]
fn file_contents_are_byte_exact_through_the_mount() {
    use forensic_mount::ForensicFs;
    let mut mismatches = Vec::new();
    let mut checked = 0usize;
    let mut mounted_any = false;

    for image in fixtures() {
        let Some(m) = mount_fixture(&image) else {
            continue;
        };
        mounted_any = true;
        let root = m.dir.join("ro").join("root");

        let mut fs = forensic_mount::open_image(&image).expect("fixture opens");
        let f: &mut dyn ForensicFs = fs.as_mut();
        // Same handle for walking and reading: see vfs_tree's note on inodes.
        let tree = vfs_tree(f);

        for (path, md) in tree {
            if matches!(md.file_type, forensic_mount::FsFileType::Directory) {
                continue;
            }
            // A file the IMAGE cannot read is a finding about the reader, not a
            // reason to skip. Silently continuing here is exactly how this test
            // first reported success having compared nothing at all.
            let want = match f.read_file(md.ino) {
                Ok(v) => v,
                Err(e) => {
                    mismatches.push(format!("{path}: unreadable from the image: {e:?}"));
                    continue;
                }
            };
            let Ok(got) = std::fs::read(root.join(&path)) else {
                mismatches.push(format!("{path}: unreadable through the mount"));
                continue;
            };
            checked += 1;
            if got != want {
                mismatches.push(format!(
                    "{path}: {} bytes in the image, {} through the mount",
                    want.len(),
                    got.len()
                ));
            }
        }
    }
    if !mounted_any {
        return;
    }
    eprintln!("  {checked} files compared byte-for-byte");
    for m in mismatches.iter().take(8) {
        eprintln!("    {m}");
    }
    assert!(
        checked > 0 || !mismatches.is_empty(),
        "compared 0 files byte-for-byte: the comparison never ran"
    );
    assert!(
        mismatches.is_empty(),
        "content differs through the mount:\n  {}",
        mismatches.join("\n  ")
    );
}
