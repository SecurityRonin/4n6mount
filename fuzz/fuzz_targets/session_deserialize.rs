#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::session::{SessionMetadata, OverlayMetadata};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SessionMetadata>(data);
    let _ = serde_json::from_slice::<OverlayMetadata>(data);
});
