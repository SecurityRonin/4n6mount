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
        Err(format!("unimplemented: {s}"))
    }

    /// The `backend=` mount option this maps to, if any.
    ///
    /// `None` means the backend is not selected by a mount option — FUSE-T is
    /// chosen by which library the binary links.
    #[must_use]
    pub fn mount_option(self) -> Option<&'static str> {
        None
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
    _dev_macfuse_present: bool,
    _staged_kext: Option<&str>,
    _installed_kext: Option<&str>,
    _fskit_modules: &[&str],
    _fuse_t_lib: Option<&Path>,
) -> Vec<BackendStatus> {
    Vec::new()
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
        assert!(e.contains("macfuse2"), "the error must show the value, got {e:?}");
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
        assert!(
            s.iter()
                .any(|b| b.backend == FuseBackend::Kernel && b.available)
        );
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
        let with = probe(false, None, None, &[], Some(Path::new("/usr/local/lib/libfuse-t.dylib")));
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
}
