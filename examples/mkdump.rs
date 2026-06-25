//! Write a synthetic Windows crash dump to a path, for end-to-end memory-mount
//! smoke testing. Build with `--features memory`.
//!
//! Usage: `cargo run --features memory --example mkdump -- /tmp/crash.dmp`

fn main() {
    let path = std::env::args().nth(1).expect("usage: mkdump <out.dmp>");
    let bytes = memf_format::test_builders::CrashDumpBuilder::new()
        .cr3(0x1ab000)
        .build();
    std::fs::write(&path, &bytes).expect("write dump");
    eprintln!("wrote {} bytes to {path}", bytes.len());
}
