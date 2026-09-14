//! Which FUSE mechanism carries the mount.
//!
//! macOS now offers several, and they are not interchangeable — a machine can
//! have one working and another not, for reasons that have nothing to do with
//! the evidence. Choosing explicitly, and being able to say what is available,
//! is the difference between "mount failed" and a diagnosis.
//!
//! | Backend | Kernel code | Provided by | Notes |
//! |---|---|---|---|
//! | [`FuseBackend::Kernel`] | kext, `/dev/macfuse*` | macFUSE | needs staging + Reduced Security |
//! | [`FuseBackend::FsKit`] | none | macFUSE | scheme-based (`macfuse://`), for daemons |
//! | [`FuseBackend::FsKitLocal`] | none | macFUSE | block-resource personality |
//! | [`FuseBackend::FuseT`] | none | FUSE-T | NFS loopback, separate `libfuse-t` |
//!
//! `Kernel`, `FsKit` and `FsKitLocal` are all reached through macFUSE's own
//! `libfuse`, which takes a `backend=` mount option. FUSE-T ships a *different*
//! library implementing the same API, so it is selected by what the binary
//! links, not by an option — which is why [`FuseBackend::FuseT`] reports
//! availability separately rather than being a flag we can simply pass.

use std::path::Path;

/// A FUSE mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FuseBackend {
    /// Let the linked `libfuse` choose (`backend=auto`).
    #[default]
    Auto,
    /// macFUSE kernel extension.
    Kernel,
    /// macFUSE FSKit module, scheme-based.
    FsKit,
    /// macFUSE FSKit module, block-resource personality.
    FsKitLocal,
    /// FUSE-T, over loopback NFS.
    FuseT,
}

impl FuseBackend {
    /// Parse a user-supplied backend name.
    ///
    /// # Errors
    /// Returns the offending value when it is not a known backend, so the
    /// caller can show it rather than saying only "invalid".
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            // "kext" is what the documentation and the community call it; both
            // names reach the same mechanism so neither is a wrong guess.
            "kernel" | "kext" => Ok(Self::Kernel),
            "fskit" => Ok(Self::FsKit),
            "fskit-local" | "fskit_local" => Ok(Self::FsKitLocal),
            "fuse-t" | "fuset" => Ok(Self::FuseT),
            other => Err(format!(
                "unknown FUSE backend {other:?}; expected one of: \
                 auto, kernel (kext), fskit, fskit-local, fuse-t"
            )),
        }
    }

    /// The `backend=` mount option this maps to, if any.
    ///
    /// `None` means the backend is not selected by a mount option — FUSE-T is
    /// chosen by which library the binary links.
    #[must_use]
    pub fn mount_option(self) -> Option<&'static str> {
        match self {
            Self::Auto => Some("backend=auto"),
            Self::Kernel => Some("backend=kernel"),
            Self::FsKit => Some("backend=fskit"),
            Self::FsKitLocal => Some("backend=fskit-local"),
            // FUSE-T is a different library implementing the same API. No
            // mount option reaches it; the binary either links it or does not.
            Self::FuseT => None,
        }
    }
}

/// What this machine can actually mount with, and why not when it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BackendStatus {
    /// The mechanism.
    pub backend: FuseBackend,
    /// Whether it looks usable right now.
    pub available: bool,
    /// Why not, in a form an examiner can act on.
    pub detail: String,
}

/// Probe the machine for usable FUSE mechanisms.
///
/// Pure with respect to the filesystem paths handed in, so the decision logic
/// is testable without installing anything. Real callers pass the live paths.
#[must_use]
pub fn probe(
    dev_macfuse_present: bool,
    staged_kext: Option<&str>,
    installed_kext: Option<&str>,
    fskit_modules: &[&str],
    fuse_t_lib: Option<&Path>,
) -> Vec<BackendStatus> {
    let kernel_detail = if dev_macfuse_present {
        "/dev/macfuse is present; the kernel extension is loaded".to_string()
    } else {
        match (staged_kext, installed_kext) {
            // The mismatch IS the diagnosis: a newly installed kext only loads
            // after it is approved and the machine reboots, which is what
            // stages it. Approving the OLD version changes nothing, so both
            // numbers have to be visible or the state looks like a bare
            // permission failure.
            (Some(st), Some(ins)) if st != ins => format!(
                "kext {ins} is installed but {st} is staged: approve macFUSE in \
                 Privacy & Security, then reboot to stage {ins}"
            ),
            (Some(st), Some(_)) => format!(
                "kext {st} is staged but not loaded; a reboot, or Reduced Security \
                 on Apple silicon, may be required"
            ),
            (None, Some(ins)) => format!(
                "kext {ins} is installed but never approved: approve it in \
                 Privacy & Security, then reboot"
            ),
            _ => "no macFUSE kernel extension is installed".to_string(),
        }
    };

    // The two personalities register as separate modules, so one can be
    // enabled and the other not; reporting them together would claim a
    // capability the machine may not have. Match on the parsed BUNDLE ID, not
    // on the raw line: "fsmodule.macfuse" is a prefix of
    // "fsmodule.macfuse-local", and a real pluginkit line carries a version
    // suffix and tab-separated columns after the identifier.
    let ids: Vec<&str> = fskit_modules.iter().map(|m| bundle_id(m)).collect();
    let scheme = ids
        .iter()
        .any(|id| *id == "io.macfuse.app.fsmodule.macfuse");
    let local = ids
        .iter()
        .any(|id| *id == "io.macfuse.app.fsmodule.macfuse-local");

    vec![
        BackendStatus {
            backend: FuseBackend::Kernel,
            available: dev_macfuse_present,
            detail: kernel_detail,
        },
        BackendStatus {
            backend: FuseBackend::FsKit,
            available: scheme,
            detail: if scheme {
                "FSKit module registered (scheme-based)".to_string()
            } else {
                "FSKit module not registered: launch macfuse.app, then enable it \
                 in System Settings > General > Login Items & Extensions"
                    .to_string()
            },
        },
        BackendStatus {
            backend: FuseBackend::FsKitLocal,
            available: local,
            detail: if local {
                "FSKit module registered (block resources)".to_string()
            } else {
                "FSKit local module not registered".to_string()
            },
        },
        BackendStatus {
            backend: FuseBackend::FuseT,
            available: fuse_t_lib.is_some(),
            detail: match fuse_t_lib {
                Some(p) => format!("FUSE-T library at {}", p.display()),
                None => "FUSE-T is not installed (brew install --cask fuse-t)".to_string(),
            },
        },
    ]
}

/// The bundle identifier from a `pluginkit -mAv` line, or from a bare id.
///
/// A real line looks like:
///
/// ```text
///    io.macfuse.app.fsmodule.macfuse(2.0)\t<uuid>\t<date>\t/path/to.appex
/// ```
///
/// so the identifier is the first whitespace-delimited field with any `(version)`
/// suffix removed. Accepting a bare identifier too keeps callers that already
/// have one from having to fake a line.
fn bundle_id(line: &str) -> &str {
    let first = line.trim().split_whitespace().next().unwrap_or("");
    match first.find('(') {
        Some(i) => &first[..i],
        None => first,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RED: every mechanism must be nameable, because a user who cannot select
    /// one cannot work around a machine where the default is broken.
    #[test]
    fn every_backend_parses_from_its_name() {
        for (name, want) in [
            ("auto", FuseBackend::Auto),
            ("kernel", FuseBackend::Kernel),
            ("kext", FuseBackend::Kernel),
            ("fskit", FuseBackend::FsKit),
            ("fskit-local", FuseBackend::FsKitLocal),
            ("fuse-t", FuseBackend::FuseT),
        ] {
            assert_eq!(FuseBackend::parse(name), Ok(want), "parsing {name:?}");
        }
    }

    /// RED: an unknown name must be refused AND must echo the offending value.
    /// "invalid backend" without the value sends someone hunting for a typo
    /// they cannot see.
    #[test]
    fn an_unknown_backend_name_is_refused_showing_the_value() {
        let e = FuseBackend::parse("macfuse2").expect_err("unknown names are refused");
        assert!(
            e.contains("macfuse2"),
            "the error must show the value, got {e:?}"
        );
    }

    /// RED: the three macFUSE mechanisms map to `backend=` options; FUSE-T does
    /// not, because it is selected by which library is linked.
    #[test]
    fn only_the_macfuse_backends_map_to_a_mount_option() {
        assert_eq!(FuseBackend::Auto.mount_option(), Some("backend=auto"));
        assert_eq!(FuseBackend::Kernel.mount_option(), Some("backend=kernel"));
        assert_eq!(FuseBackend::FsKit.mount_option(), Some("backend=fskit"));
        assert_eq!(
            FuseBackend::FsKitLocal.mount_option(),
            Some("backend=fskit-local")
        );
        assert_eq!(
            FuseBackend::FuseT.mount_option(),
            None,
            "FUSE-T is chosen by linkage, not by a mount option"
        );
    }

    /// RED: a staged kext older than the installed one means the new version
    /// was never approved — the exact state that makes a mount fail with a
    /// permission error that no amount of approving the OLD version fixes.
    #[test]
    fn a_stale_staged_kext_is_reported_as_the_reason() {
        let s = probe(false, Some("5.3.3"), Some("5.4.0"), &[], None);
        let kernel = s
            .iter()
            .find(|b| b.backend == FuseBackend::Kernel)
            .expect("kernel backend is always reported");
        assert!(!kernel.available, "no /dev/macfuse means not usable");
        assert!(
            kernel.detail.contains("5.3.3") && kernel.detail.contains("5.4.0"),
            "the detail must name BOTH versions so the mismatch is visible, got {:?}",
            kernel.detail
        );
    }

    /// RED: with the device node present the kernel backend is usable.
    #[test]
    fn a_present_device_node_means_the_kernel_backend_works() {
        let s = probe(true, Some("5.4.0"), Some("5.4.0"), &[], None);
        assert!(s
            .iter()
            .any(|b| b.backend == FuseBackend::Kernel && b.available));
    }

    /// RED: an FSKit module that is registered is reported per personality.
    #[test]
    fn registered_fskit_modules_are_reported_individually() {
        let s = probe(
            false,
            None,
            None,
            &["io.macfuse.app.fsmodule.macfuse"],
            None,
        );
        let scheme = s.iter().find(|b| b.backend == FuseBackend::FsKit);
        let local = s.iter().find(|b| b.backend == FuseBackend::FsKitLocal);
        assert!(scheme.is_some_and(|b| b.available), "scheme module present");
        assert!(
            local.is_some_and(|b| !b.available),
            "the local personality was NOT registered and must not be claimed"
        );
    }

    /// RED: FUSE-T counts as available only when its library is actually there.
    #[test]
    fn fuse_t_is_available_only_when_its_library_exists() {
        let with = probe(
            false,
            None,
            None,
            &[],
            Some(Path::new("/usr/local/lib/libfuse-t.dylib")),
        );
        assert!(with
            .iter()
            .any(|b| b.backend == FuseBackend::FuseT && b.available));

        let without = probe(false, None, None, &[], None);
        assert!(without
            .iter()
            .any(|b| b.backend == FuseBackend::FuseT && !b.available));
    }

    /// RED: every mechanism is reported, present or not. A probe that omits the
    /// unavailable ones cannot explain why a mount failed.
    #[test]
    fn the_probe_reports_every_mechanism() {
        let s = probe(false, None, None, &[], None);
        for b in [
            FuseBackend::Kernel,
            FuseBackend::FsKit,
            FuseBackend::FsKitLocal,
            FuseBackend::FuseT,
        ] {
            assert!(
                s.iter().any(|x| x.backend == b),
                "{b:?} must be reported even when unavailable"
            );
        }
    }

    /// RED: the prober must handle REAL `pluginkit` output, not the tidy bundle
    /// identifiers a hand-written test imagines.
    ///
    /// The first version of this module matched with `ends_with("fsmodule.macfuse")`,
    /// which is true of a bare identifier and false of an actual pluginkit line:
    ///
    /// ```text
    ///    io.macfuse.app.fsmodule.macfuse(2.0)\t63CF…\t2026-09-14 09:00:33 +0000\t/Library/…
    /// ```
    ///
    /// It passed every synthetic test and then reported the scheme module as
    /// missing on the first real machine it saw. Feeding verbatim tool output is
    /// what makes this test able to catch that.
    #[test]
    fn real_pluginkit_lines_are_understood() {
        let lines = [
            "   io.macfuse.app.fsmodule.macfuse(2.0)\t63CF120B-A09D-464B-81AC-9FD974C5F66E\t2026-09-14 09:00:33 +0000\t/Library/Filesystems/macfuse.fs/Contents/Resources/macfuse.app/Contents/Extensions/io.macfuse.app.fsmodule.macfuse.appex",
            "   io.macfuse.app.fsmodule.macfuse-local(2.0)\tD20E163C-267A-4712-9619-974739FEAA51\t2026-09-14 09:00:33 +0000\t/Library/Filesystems/macfuse.fs/Contents/Resources/macfuse.app/Contents/Extensions/io.macfuse.app.fsmodule.macfuse-local.appex",
        ];
        let s = probe(false, None, None, &lines, None);
        assert!(
            s.iter()
                .any(|b| b.backend == FuseBackend::FsKit && b.available),
            "the scheme module IS registered in this output and must be reported"
        );
        assert!(
            s.iter()
                .any(|b| b.backend == FuseBackend::FsKitLocal && b.available),
            "and so is the local personality"
        );
    }

    /// RED: with ONLY the local personality registered, the scheme module must
    /// not be claimed — the substring trap in the other direction.
    #[test]
    fn only_local_registered_does_not_claim_the_scheme_module() {
        let lines =
            ["   io.macfuse.app.fsmodule.macfuse-local(2.0)\tD20E163C\t2026-09-14\t/x.appex"];
        let s = probe(false, None, None, &lines, None);
        assert!(
            s.iter()
                .any(|b| b.backend == FuseBackend::FsKit && !b.available),
            "the scheme module is absent here and must not be reported available"
        );
        assert!(s
            .iter()
            .any(|b| b.backend == FuseBackend::FsKitLocal && b.available));
    }
}
