//! Record which `libfuse` this binary actually links.
//!
//! `--fuse-backend fuse-t` and `--list-fuse-backends` both need to know whether
//! FUSE-T is reachable. A cargo feature cannot answer that honestly: a feature
//! is a *request*, and an earlier version of this crate had a `fuse-t` feature
//! that changed nothing but made the probe claim FUSE-T was available while the
//! binary still linked macFUSE — reporting inventory as capability, the exact
//! defect the mount smoke test exists to catch.
//!
//! So ask the linker's own input instead: whatever `pkg-config fuse` resolves
//! to is what `fuser` will link, and if that is FUSE-T the name says so.
fn main() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    let linked = std::process::Command::new("pkg-config")
        .args(["--libs", "fuse"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    // `-lfuse-t` is FUSE-T; `-lfuse` (or osxfuse) is macFUSE.
    let is_fuse_t = linked.split_whitespace().any(|t| t == "-lfuse-t");
    println!(
        "cargo:rustc-env=FUSE_LINKED_LIB={}",
        if is_fuse_t { "fuse-t" } else { "macfuse" }
    );
}
