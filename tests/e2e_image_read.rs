//! Repeatable, on-demand end-to-end proof that 4n6mount reads **real disk-image
//! evidence** through the migrated `forensic-vfs` 0.5 stack: `open_image` decodes
//! the container (ewf → multi-segment E01), the engine walks the volume system
//! (GPT), and a filesystem `vfs` `FileSystem` adapter serves directory listings
//! and file bytes. Nothing FUSE here — it drives the library `ForensicFs` trait
//! ([`open_image`](forensic_mount::open_image)) directly.
//!
//! **Which filesystem gets mounted.** `open_image` → `Vfs::open` mounts "the first
//! filesystem found" (the resolver descends volumes `0..len` and returns the first
//! that a filesystem prober claims). On a GPT Windows disk that is partition 0, the
//! **EFI System Partition (FAT)**, so this e2e verifies real content read through
//! `ewf 0.4.5 → GPT → the FAT vfs-0.5 adapter`. The later NTFS volume is not
//! surfaced by the single-filesystem public API — see the report accompanying this
//! test. The recognizable-root check accepts NTFS markers too, so the same test is
//! a positive NTFS proof the moment it is pointed at an NTFS-first image.
//!
//! Two layers, one file:
//!
//! * **Synthetic unit tests** (always run in CI, no external data) prove
//!   `open_image` fails loud on a non-image path rather than fabricating a mount.
//! * **An env-gated e2e** ([`e2e_real_image_reads_through_vfs`]) drives `open_image`
//!   against a real disk image. It is gated on `FN_E2E_IMAGE` and **skips cleanly**
//!   when the variable is unset or the file is absent (the large images are
//!   gitignored), exactly like the fleet's oracle-gated tests.
//!
//! Run the e2e against the extracted Case-001 desktop image (multi-segment E01 —
//! `open_image` follows `.E02`-`.E04` automatically; pass the FIRST segment):
//! ```text
//! FN_E2E_IMAGE=/tmp/case001/20200918_0417_DESKTOP-SDN1RPT.E01 \
//!   cargo test --test e2e_image_read -- --nocapture
//! ```
//! It asserts the mounted root lists a recognizable filesystem name (proving
//! container + volume + filesystem detection through vfs 0.5), then BFS-walks the
//! tree for the first non-empty regular file and reads its bytes back (proving the
//! vfs-0.5 reader returns real, size-matched content).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_mount::{open_image, FsFileType};

// ---------------------------------------------------------------------------
// Synthetic unit tests (CI, no external data)
// ---------------------------------------------------------------------------

/// `open_image` on bytes that are not a recognizable container/volume/filesystem
/// must fail loud (an `Err`), never return an empty-but-successful mount.
#[test]
fn open_image_on_non_image_errors() {
    let dir = std::env::temp_dir().join(format!("4n6mount_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("not-an-image.bin");
    // 64 KiB of a fixed non-magic byte: no container magic, no volume, no FS.
    std::fs::write(&path, vec![0x5Au8; 64 * 1024]).unwrap();

    let res = open_image(&path);
    assert!(
        res.is_err(),
        "open_image must fail loud on a non-image file, got Ok"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `open_image` on a path that does not exist must fail loud, not panic.
#[test]
fn open_image_on_missing_path_errors() {
    let path = std::env::temp_dir().join("4n6mount_e2e_definitely_absent_path.img");
    assert!(open_image(&path).is_err(), "missing path must Err");
}

// ---------------------------------------------------------------------------
// Env-gated e2e against a real disk image
// ---------------------------------------------------------------------------

/// Root names that positively identify a real filesystem was detected and its
/// root directory decoded — hit any one and the container + volume-system +
/// filesystem path is proven to have worked end-to-end through vfs 0.5. NTFS/
/// Windows markers plus the FAT EFI System Partition's `EFI` directory (the
/// partition-0 filesystem `open_image` actually surfaces on a GPT Windows disk).
const RECOGNIZABLE_ROOT: &[&[u8]] = &[
    // NTFS / Windows volume markers (surfaced on an NTFS-first image).
    b"$MFT",
    b"$LogFile",
    b"$Extend",
    b"$Boot",
    b"$Bitmap",
    b"Windows",
    b"Users",
    // FAT EFI System Partition — partition 0 of a GPT Windows disk.
    b"EFI",
];

/// Directory-tree walk bounds — keep the e2e fast on a multi-GB image while still
/// reaching a real regular file: cap total nodes visited and descent depth.
const MAX_NODES: usize = 5_000;
const MAX_DEPTH: u32 = 6;
/// Skip absurdly large files when choosing one to read (e.g. `$MFT`, hiberfil):
/// reading one would be slow without proving anything a smaller file doesn't.
const MAX_READ_SIZE: u64 = 16 * 1024 * 1024;

/// Drive `open_image` against a real disk image and prove the vfs-0.5 stack reads
/// it: the root lists a recognizable NTFS name, and the first non-empty regular
/// file read back returns real, size-matched content.
///
/// Env-gated: set `FN_E2E_IMAGE` to a disk-image path (first E01 segment for
/// multi-segment sets). Skips cleanly when unset or the file is absent.
#[test]
fn e2e_real_image_reads_through_vfs() {
    let Some(img) = std::env::var_os("FN_E2E_IMAGE") else {
        eprintln!("SKIP e2e_real_image_reads_through_vfs: set FN_E2E_IMAGE=<path/to/image.E01>");
        return;
    };
    let img = std::path::PathBuf::from(img);
    if !img.is_file() {
        eprintln!(
            "SKIP e2e_real_image_reads_through_vfs: {} is not a file",
            img.display()
        );
        return;
    }

    let mut fs = open_image(&img).expect("open_image must mount a real disk image");
    let root = fs.root_ino();

    // 1) Root listing is non-empty and carries a recognizable filesystem name.
    let root_entries = fs.read_dir(root).expect("read_dir(root) must succeed");
    assert!(!root_entries.is_empty(), "root listing must be non-empty");
    let names: Vec<String> = root_entries
        .iter()
        .map(forensic_mount::FsDirEntry::name_str)
        .collect();
    eprintln!("e2e: {} root entries: {:?}", root_entries.len(), names);
    assert!(
        root_entries
            .iter()
            .any(|e| RECOGNIZABLE_ROOT.contains(&e.name.as_slice())),
        "root must contain a recognizable filesystem name (one of {:?}); saw {:?}",
        RECOGNIZABLE_ROOT
            .iter()
            .map(|n| String::from_utf8_lossy(n).to_string())
            .collect::<Vec<_>>(),
        names,
    );

    // 2) BFS the tree (bounded) for the first non-empty regular file, then read it
    //    back through the vfs reader and assert real, size-matched content.
    let mut queue: std::collections::VecDeque<(u64, String, u32)> =
        std::collections::VecDeque::new();
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    queue.push_back((root, String::new(), 0));
    visited.insert(root);
    let mut nodes = 0usize;

    while let Some((ino, path, depth)) = queue.pop_front() {
        nodes += 1;
        if nodes > MAX_NODES {
            eprintln!("e2e: node cap {MAX_NODES} reached before finding a readable file");
            break;
        }
        // A directory we can't list is not a test failure — skip it.
        let Ok(entries) = fs.read_dir(ino) else {
            continue;
        };
        for e in entries {
            // Skip the self/parent links NTFS/FUSE surface.
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
                        .expect("read_file on a real regular file must succeed");
                    assert!(
                        !bytes.is_empty(),
                        "read_file returned empty for {child_path:?} (metadata size {})",
                        meta.size
                    );
                    assert_eq!(
                        bytes.len() as u64,
                        meta.size,
                        "read_file byte count for {child_path:?} must equal metadata size",
                    );
                    eprintln!(
                        "e2e: VERIFIED regular file {child_path:?} — read {} bytes == metadata size \
                         (first bytes: {:02x?}) through the vfs-0.5 filesystem reader",
                        bytes.len(),
                        &bytes[..bytes.len().min(16)],
                    );
                    return;
                }
                _ => {}
            }
        }
    }

    // Reaching here means no readable regular file was found within the bounds.
    // That is a real failure for a populated filesystem (the ESP holds the boot
    // loaders; NTFS is full of files), so fail loud rather than skip — the point
    // is to prove content reads work.
    panic!(
        "no non-empty regular file (0 < size <= {MAX_READ_SIZE}) found within {nodes} nodes / \
         depth {MAX_DEPTH} — the vfs-0.5 reader surfaced no readable file content"
    );
}
