#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::filter::CustomDb;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hashes.txt");
    std::fs::write(&path, data).unwrap();
    let _ = CustomDb::load(&path);
});
