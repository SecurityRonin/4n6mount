//! Fuzz the surviving detection entry point in this crate.
//!
//! This target previously fuzzed `detect::detect_filesystem`, which was removed
//! in f355e53 when this crate moved to forensic-vfs-engine for filesystem
//! backends. The target kept pointing at the deleted function, so it had not
//! compiled since — and nothing noticed, because the workflow this repo ran did
//! not build the fuzz targets.
//!
//! `detect_memory_dump` is the detection this crate still owns, and it reads
//! attacker-controlled bytes (LiME / AVML / ELF core / Windows crashdump
//! headers), so it is the right thing to fuzz here. Filesystem detection is now
//! forensic-vfs-engine's to fuzz.
#![no_main]
use forensic_mount::detect::detect_memory_dump;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    // The contract under test is that it RETURNS on any input — never panics,
    // never reads out of bounds. What it decides is not asserted: a random
    // buffer legitimately detects nothing.
    let _ = detect_memory_dump(&mut cursor);
});
