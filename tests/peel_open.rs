//! End-to-end proof that `open_image` transparently peels an outer compression
//! wrapper (`evidence.dd.gz`) via the archive-detour framework and mounts the
//! inner image through the engine — yielding the same filesystem as opening the
//! raw fixture directly.

use std::io::Write;
use std::path::PathBuf;

use forensic_mount::{open_image, ForensicFs};

/// A raw exFAT filesystem fixture the engine mounts directly (offset-0 boot
/// signature). It is small (1 MiB), so gzipping it in-test is cheap.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("exfat.img")
}

/// Read the root directory entry names of a mounted filesystem, sorted.
fn root_names(fs: &mut dyn ForensicFs) -> Vec<String> {
    let root = fs.root_ino();
    let mut names: Vec<String> = fs
        .read_dir(root)
        .expect("read_dir(root)")
        .into_iter()
        .map(|e| e.name_str())
        .filter(|n| n != "." && n != "..")
        .collect();
    names.sort();
    names
}

#[test]
fn open_image_peels_gzip_wrapper_and_mounts_inner() {
    // Control: the raw fixture mounts and lists a non-empty root.
    let mut direct = open_image(&fixture()).expect("raw exfat.img must mount");
    let direct_names = root_names(direct.as_mut());
    assert!(
        !direct_names.is_empty(),
        "raw exfat.img root should list entries"
    );

    // gzip the fixture bytes into `evidence.dd.gz` and open THAT.
    let raw = std::fs::read(fixture()).expect("read fixture");
    let dir = tempfile::tempdir().expect("tempdir");
    let gz_path = dir.path().join("evidence.dd.gz");
    {
        let f = std::fs::File::create(&gz_path).expect("create gz");
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        enc.write_all(&raw).expect("gzip write");
        enc.finish().expect("gzip finish");
    }

    let mut peeled = open_image(&gz_path).expect("evidence.dd.gz must peel and mount");
    let peeled_names = root_names(peeled.as_mut());

    // The peeled mount must present the identical filesystem as the raw fixture.
    assert_eq!(
        peeled_names, direct_names,
        "peeled root listing must match the raw fixture"
    );
}
