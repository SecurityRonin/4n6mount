//! Repeatable, on-demand end-to-end proof that 4n6mount surfaces **ALL**
//! partitions of a multi-partition disk image — the fix for `open_image` only
//! ever mounting the FIRST filesystem the engine finds (on a Windows GPT disk
//! that is the tiny FAT EFI System Partition, so the NTFS Windows volume was
//! never reachable).
//!
//! [`open_image_all`](forensic_mount::open_image_all) opens every partition and
//! renders the ADR-0010 unified layout `<mount>/<volume>/<fs tree>` at constant
//! depth: every volume is a `<volume>/` directory under a synthetic root —
//! `_partition<index+1>` for a partitioned disk with no label wired, or a single
//! `root` volume for a bare unpartitioned filesystem. This test drives the
//! library `ForensicFs` trait directly — no FUSE — exactly like
//! `e2e_image_read.rs`.
//!
//! Two layers, one file:
//!
//! * **Synthetic unit tests** (always run in CI, no external data) prove
//!   `open_image_all` fails loud on a non-image path rather than fabricating a
//!   mount.
//! * **An env-gated e2e** ([`e2e_multipartition_surfaces_ntfs`]) drives
//!   `open_image_all` against a real multi-partition disk image, asserts several
//!   partitions surface under the synthetic root, finds the NTFS partition, and
//!   reads a real Windows file from it — the load-bearing proof that ntfs-core's
//!   vfs adapter is reachable through 4n6mount's public API via the new `/pN`
//!   layout. Gated on `FN_E2E_IMAGE`; **skips cleanly** when unset/absent.
//!
//! Run the e2e against the extracted Case-001 desktop image (multi-segment E01 —
//! pass the FIRST segment):
//! ```text
//! FN_E2E_IMAGE=/tmp/case001/20200918_0417_DESKTOP-SDN1RPT.E01 \
//!   cargo test --test e2e_multipartition -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_mount::{open_image_all, FsFileType};

// ---------------------------------------------------------------------------
// Synthetic unit tests (CI, no external data)
// ---------------------------------------------------------------------------

/// `open_image_all` on bytes that are not a recognizable container/volume/
/// filesystem must fail loud (an `Err`), never a silent empty mount.
#[test]
fn open_image_all_on_non_image_errors() {
    let dir = std::env::temp_dir().join(format!("4n6mount_mp_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("not-an-image.bin");
    std::fs::write(&path, vec![0x5Au8; 64 * 1024]).unwrap();

    assert!(
        open_image_all(&path).is_err(),
        "open_image_all must fail loud on a non-image file, got Ok"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `open_image_all` on a path that does not exist must fail loud, not panic.
#[test]
fn open_image_all_on_missing_path_errors() {
    let path = std::env::temp_dir().join("4n6mount_mp_definitely_absent_path.img");
    assert!(open_image_all(&path).is_err(), "missing path must Err");
}

/// ADR-0010: a **bare, unpartitioned** filesystem renders as exactly one
/// `<volume>/` directory named `root` (no volume-table `Layer::Volume`, no label
/// wired), and a real file is readable through `<root>/…`. Uses the committed
/// `tests/data/hfsplus.img` fixture, so it runs in CI with no external data.
#[test]
fn open_image_all_bare_volume_renders_single_root_dir() {
    let img = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/hfsplus.img");
    let mut fs = open_image_all(&img).expect("open_image_all must mount the bare HFS+ fixture");
    let root = fs.root_ino();

    let entries = fs.read_dir(root).expect("read_dir(root) must succeed");
    let names: Vec<String> = entries
        .iter()
        .map(forensic_mount::FsDirEntry::name_str)
        .collect();
    assert_eq!(
        names,
        vec!["root".to_string()],
        "a bare unpartitioned filesystem must render exactly one `root` volume, saw {names:?}"
    );
    let vol = &entries[0];
    assert_eq!(
        vol.file_type,
        FsFileType::Directory,
        "the `root` volume entry must be a directory"
    );

    // Read a real file through <root>/… — BFS the volume tree for the first
    // readable regular file and prove size-matched, non-empty content.
    let mut queue: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    queue.push_back(vol.inode);
    visited.insert(vol.inode);
    let mut read_a_file = false;
    'outer: while let Some(ino) = queue.pop_front() {
        let Ok(children) = fs.read_dir(ino) else {
            continue;
        };
        for e in children {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            match e.file_type {
                FsFileType::Directory => {
                    if visited.insert(e.inode) {
                        queue.push_back(e.inode);
                    }
                }
                FsFileType::RegularFile => {
                    let Ok(meta) = fs.metadata(e.inode) else {
                        continue;
                    };
                    if meta.size == 0 {
                        continue;
                    }
                    let bytes = fs
                        .read_file(e.inode)
                        .expect("read_file on a real bare-volume file must succeed");
                    assert_eq!(
                        bytes.len() as u64,
                        meta.size,
                        "read_file byte count for {:?} must equal metadata size",
                        e.name_str()
                    );
                    assert!(!bytes.is_empty());
                    read_a_file = true;
                    break 'outer;
                }
                _ => {}
            }
        }
    }
    assert!(
        read_a_file,
        "must read at least one real file through <root>/… on the bare exFAT fixture"
    );
}

// ---------------------------------------------------------------------------
// Env-gated e2e against a real multi-partition disk image
// ---------------------------------------------------------------------------

/// Root-directory names that positively identify a mounted NTFS partition.
const NTFS_MARKERS: &[&[u8]] = &[
    b"$MFT",
    b"$LogFile",
    b"$Extend",
    b"$Boot",
    b"$Bitmap",
    b"Windows",
    b"Users",
];

/// Directory-tree walk bounds — keep the e2e fast on a multi-GB partition.
const MAX_NODES: usize = 20_000;
const MAX_DEPTH: u32 = 8;
/// Skip absurdly large files ($MFT, hiberfil, pagefile) when choosing one to read.
const MAX_READ_SIZE: u64 = 16 * 1024 * 1024;

/// Drive `open_image_all` against a real multi-partition image: assert several
/// volumes surface under the synthetic root (each a valid `<volume>/` name — a
/// live filesystem label like `System Reserved`, or the `_partition<N>`
/// fallback), locate the NTFS volume, prove its root carries NTFS markers, and
/// read a real regular file from it back — non-empty, size-matched — proving the
/// NTFS vfs adapter is reachable via the ADR-0010 `<volume>/` layout.
///
/// Env-gated on `FN_E2E_IMAGE`; skips cleanly when unset or the file is absent.
#[test]
fn e2e_multipartition_surfaces_ntfs() {
    let Some(img) = std::env::var_os("FN_E2E_IMAGE") else {
        eprintln!("SKIP e2e_multipartition_surfaces_ntfs: set FN_E2E_IMAGE=<path/to/image.E01>");
        return;
    };
    let img = std::path::PathBuf::from(img);
    if !img.is_file() {
        eprintln!(
            "SKIP e2e_multipartition_surfaces_ntfs: {} is not a file",
            img.display()
        );
        return;
    }

    let mut fs = open_image_all(&img).expect("open_image_all must mount a real disk image");
    let root = fs.root_ino();

    // (a) Multiple partitions surface as subdirectories under the synthetic root.
    let parts = fs.read_dir(root).expect("read_dir(root) must succeed");
    let part_names: Vec<String> = parts
        .iter()
        .map(forensic_mount::FsDirEntry::name_str)
        .collect();
    eprintln!(
        "e2e: {} partitions under the synthetic root: {:?}",
        parts.len(),
        part_names
    );
    assert!(
        parts.len() >= 2,
        "a multi-partition disk must surface >= 2 partitions, saw {part_names:?}"
    );
    // ADR-0010 + the live `volume_label()` hook: each volume renders as its
    // filesystem label when the reader extracts one (NTFS `$VOLUME_NAME`, e.g.
    // Case-001 DC01's `System Reserved`), else the positional `_partition<N>`
    // fallback, else `root` for a bare volume. Assert each name is a VALID
    // volume-dir-name — never empty (the old blanket `_partition` prefix no
    // longer holds now that labels light up).
    for n in &part_names {
        assert!(
            !n.is_empty(),
            "a volume dir name must never be empty, saw {part_names:?}"
        );
    }
    // Exact, TSK-oracle-derived names for a KNOWN image, when supplied. Derive
    // each with `fsstat -f ntfs -o <offset> <image>` -> `Volume Name` (unlabeled
    // -> `_partition<index+1>`) and pass them comma-separated, in order. This is
    // the load-bearing showcase assertion — e.g. for Case-001 DC01:
    //   FN_E2E_EXPECT_PARTS="System Reserved,_partition2"
    if let Some(expect) = std::env::var_os("FN_E2E_EXPECT_PARTS") {
        let expected: Vec<String> = expect
            .to_string_lossy()
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        assert_eq!(
            part_names, expected,
            "volume dir names must match the TSK-oracle-derived expectation"
        );
    }
    for e in &parts {
        assert_eq!(
            e.file_type,
            FsFileType::Directory,
            "each partition entry must be a directory: {:?}",
            e.name_str()
        );
    }

    // (b) Find the partition whose root carries NTFS markers.
    let mut ntfs_root: Option<(u64, String)> = None;
    for e in &parts {
        let Ok(entries) = fs.read_dir(e.inode) else {
            continue;
        };
        if entries
            .iter()
            .any(|c| NTFS_MARKERS.contains(&c.name.as_slice()))
        {
            ntfs_root = Some((e.inode, e.name_str()));
            break;
        }
    }
    let (ntfs_ino, ntfs_label) =
        ntfs_root.expect("one partition's root must carry NTFS markers ($MFT/Windows/Users)");
    eprintln!("e2e: NTFS partition surfaced as {ntfs_label:?}");

    // (c) BFS the NTFS partition for the first readable regular file, read it back
    //     through the vfs reader, and assert real, size-matched content.
    let mut queue: std::collections::VecDeque<(u64, String, u32)> =
        std::collections::VecDeque::new();
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    queue.push_back((ntfs_ino, ntfs_label.clone(), 0));
    visited.insert(ntfs_ino);
    let mut nodes = 0usize;

    while let Some((ino, path, depth)) = queue.pop_front() {
        nodes += 1;
        if nodes > MAX_NODES {
            break;
        }
        let Ok(entries) = fs.read_dir(ino) else {
            continue;
        };
        for e in entries {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            let child_path = format!("{path}/{}", e.name_str());
            match e.file_type {
                FsFileType::Directory => {
                    if depth < MAX_DEPTH && visited.insert(e.inode) {
                        queue.push_back((e.inode, child_path, depth + 1));
                    }
                }
                FsFileType::RegularFile => {
                    let Ok(meta) = fs.metadata(e.inode) else {
                        continue;
                    };
                    if meta.size == 0 || meta.size > MAX_READ_SIZE {
                        continue;
                    }
                    let bytes = fs
                        .read_file(e.inode)
                        .expect("read_file on a real NTFS regular file must succeed");
                    assert_eq!(
                        bytes.len() as u64,
                        meta.size,
                        "read_file byte count for {child_path:?} must equal metadata size",
                    );
                    assert!(
                        !bytes.is_empty(),
                        "read_file returned empty for {child_path:?}"
                    );
                    eprintln!(
                        "e2e: VERIFIED NTFS file {child_path:?} through <volume>/ — read {} bytes \
                         == metadata size (first bytes: {:02x?})",
                        bytes.len(),
                        &bytes[..bytes.len().min(16)],
                    );
                    return;
                }
                _ => {}
            }
        }
    }

    panic!(
        "no readable regular file (0 < size <= {MAX_READ_SIZE}) found in the NTFS partition \
         within {nodes} nodes / depth {MAX_DEPTH}"
    );
}
