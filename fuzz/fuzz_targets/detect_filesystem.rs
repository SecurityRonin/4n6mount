#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::detect::detect_filesystem;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = detect_filesystem(&mut cursor);
});
