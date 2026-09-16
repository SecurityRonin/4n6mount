//! Does a mount actually mount?
//!
//! Until now nothing in this repository answered that. `open_image(...)` tests
//! exercise the VFS layer and never touch FUSE, so every FUSE backend shipped
//! unverified — the shape of "L01 Supported" backed by a renamed E01.
//!
//! The invariant under test is deliberately sharp:
//!
//! > **Every backend the probe reports as `available` must actually mount.**
//!
//! Reporting a mechanism as available and then failing to mount with it is
//! worse than reporting it missing. An examiner acts on that word.
//!
//! It runs the shipping binary as a user runs it, rather than calling
//! `mount_unix` in-process, so the thing proven is the thing distributed —
//! argument parsing, backend selection and daemonisation included.
//!
//! Three-way control, per `engineering-execution-discipline`:
//!
//! | case | expectation |
//! |---|---|
//! | **A** a backend is available | mounts, lists, and the listing matches the VFS layer |
//! | **B** available but cannot mount | **MUST FAIL** — this is the positive control |
//! | **C** no backend available | skip, LOUDLY, naming why each is unusable |
//!
//! Case C prints its reasons: a silent skip is indistinguishable from a pass,
//! and that is precisely how a FUSE backend goes years without being exercised.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The exfat fixture already used by the VFS-layer tests.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("exfat.img")
}

/// The binary under test — the one that ships.
fn binary() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop(); // deps/
    p.pop(); // debug|release/
    p.join("4n6mount")
}

/// Root entries the VFS layer reports. This is the oracle: it is covered by the
/// existing suite, so a FUSE view that disagrees with it is the FUSE layer's
/// fault, not the image's.
fn vfs_root_names() -> Vec<String> {
    use forensic_mount::ForensicFs;
    let mut fs = forensic_mount::open_image(&fixture()).expect("fixture must open");
    let f: &mut dyn ForensicFs = fs.as_mut();
    let root = f.root_ino();
    let mut names: Vec<String> = f
        .read_dir(root)
        .expect("read_dir(root)")
        .into_iter()
        .map(|e| e.name_str())
        .filter(|n| n != "." && n != "..")
        .collect();
    names.sort();
    names
}

/// Entries visible through the mounted path, at the filesystem root.
///
/// 4n6mount presents a FORENSIC LAYOUT at the mount point -- `ro/`, `rw/`,
/// `journal/`, `metadata/`, `session/`, `unallocated/` -- and puts the image's
/// own filesystem under `ro/root/`. Comparing the mount point itself against
/// the VFS layer's root therefore compares two different things and can never
/// match; the first version of this test did exactly that and reported a
/// successful mount as a failure.
fn mounted_names(dir: &Path) -> Vec<String> {
    // Prefer the evidence root when the forensic layout is present.
    let evidence = dir.join("ro").join("root");
    let dir = if evidence.is_dir() { &evidence } else { dir };
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n != "." && n != "..")
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

struct Mounted {
    child: Child,
    dir: PathBuf,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        // Always unmount: a leaked FUSE mount wedges the next run and, on a
        // forensic box, leaves an image attached that nobody asked for.
        let _ = Command::new("umount").arg(&self.dir).status();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Mount the fixture with `backend`, waiting until the mountpoint populates.
///
/// Returns the error text on failure so the caller can report WHY, rather than
/// only that something went wrong.
fn try_mount(backend: &str) -> Result<Mounted, String> {
    let dir = std::env::temp_dir().join(format!("4n6mount-smoke-{backend}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;

    let log = dir.with_extension("log");
    let out = std::fs::File::create(&log).map_err(|e| format!("log: {e}"))?;
    let err = out.try_clone().map_err(|e| format!("log dup: {e}"))?;

    let child = Command::new(binary())
        .arg("--fuse-backend")
        .arg(backend)
        .arg(fixture())
        .arg(&dir)
        .stdout(out)
        .stderr(err)
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", binary().display()))?;

    let m = Mounted { child, dir };

    // Poll rather than sleep a fixed time: a fast mount should not cost the
    // suite 20 seconds, and a slow one should not be declared dead early.
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if !mounted_names(&m.dir).is_empty() {
            return Ok(m);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let detail = std::fs::read_to_string(&log).unwrap_or_default();
    Err(detail
        .lines()
        .last()
        .unwrap_or("no output")
        .trim()
        .to_string())
}

/// Live probe of this machine, using the same paths the CLI reports.
fn live_backends() -> Vec<forensic_mount::fuse_backend::BackendStatus> {
    use forensic_mount::fuse_backend::probe;

    let dev_present = std::fs::read_dir("/dev").is_ok_and(|d| {
        d.flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("macfuse"))
    });
    let ver = |p: &str| -> Option<String> {
        let out = Command::new("/usr/bin/defaults")
            .args(["read", p, "CFBundleVersion"])
            .output()
            .ok()?;
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!v.is_empty()).then_some(v)
    };
    let installed = ver(
        "/Library/Filesystems/macfuse.fs/Contents/Extensions/26/macfuse.kext/Contents/Info.plist",
    );
    let staged = ver(
        "/Library/StagedExtensions/Library/Filesystems/macfuse.fs/Contents/Extensions/26/macfuse.kext/Contents/Info.plist",
    );
    let plug = Command::new("/usr/bin/pluginkit")
        .args(["-mAv", "-p", "com.apple.fskit.fsmodule"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let modules: Vec<&str> = plug.lines().filter(|l| l.contains("macfuse")).collect();
    let fuse_t = [
        "/usr/local/lib/libfuse-t.dylib",
        "/usr/local/lib/libfuse-t-1.2.7.dylib",
    ]
    .iter()
    .map(Path::new)
    .find(|p| p.exists());

    probe(
        dev_present,
        staged.as_deref(),
        installed.as_deref(),
        &modules,
        fuse_t,
        option_env!("FUSE_LINKED_LIB").unwrap_or("macfuse") == "fuse-t",
    )
}

fn cli_name(b: forensic_mount::fuse_backend::FuseBackend) -> &'static str {
    use forensic_mount::fuse_backend::FuseBackend as B;
    match b {
        B::Kernel => "kernel",
        B::FsKit => "fskit",
        B::FsKitLocal => "fskit-local",
        B::FuseT => "fuse-t",
        // FuseBackend is #[non_exhaustive]; Auto and anything added later mean
        // "let libfuse decide".
        _ => "auto",
    }
}

/// Every backend reported AVAILABLE must actually mount, and what it shows must
/// match what the VFS layer shows.
///
/// The second half is what makes this more than a liveness check: a mount that
/// succeeds while presenting a different tree is worse than one that fails.
#[test]
fn every_available_backend_really_mounts() {
    let statuses = live_backends();
    let available: Vec<_> = statuses.iter().filter(|s| s.available).collect();

    if available.is_empty() {
        // CASE C — skip, but loudly, naming every reason. A silent skip is
        // indistinguishable from a pass, and that is how a backend ships
        // unexercised for years.
        eprintln!("SKIPPED: no FUSE backend is available on this machine:");
        for s in &statuses {
            eprintln!("  {:?}: {}", s.backend, s.detail);
        }
        return;
    }

    let expected = vfs_root_names();
    assert!(
        !expected.is_empty(),
        "the VFS oracle must list entries, or this test proves nothing"
    );

    let linked = option_env!("FUSE_LINKED_LIB").unwrap_or("macfuse");
    let mut failures = Vec::new();
    for s in available {
        // Only the mechanism this binary links can actually be served; asking
        // for another is now refused by the CLI, so testing it would assert the
        // refusal, not the mount.
        if forensic_mount::fuse_backend::check_selectable(s.backend, linked).is_err() {
            eprintln!(
                "  {:?}: reported available on this machine, but this binary links {linked}",
                s.backend
            );
            continue;
        }
        let name = cli_name(s.backend);
        match try_mount(name) {
            Ok(m) => {
                let got = mounted_names(&m.dir);
                if got == expected {
                    eprintln!(
                        "  {:?}: mounted, {} entries match the VFS layer",
                        s.backend,
                        got.len()
                    );
                } else {
                    failures.push(format!(
                        "{:?}: mounted but the tree differs\n    through FUSE: {got:?}\n    through VFS : {expected:?}",
                        s.backend
                    ));
                }
            }
            // CASE B — the positive control. The probe said available; it was
            // not. That claim is the defect.
            Err(why) => failures.push(format!(
                "{:?}: probe reported AVAILABLE but the mount failed: {why}",
                s.backend
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of the reported-available backends did not mount:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
