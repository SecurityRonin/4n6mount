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
    /// `macFUSE` `FSKit` module, scheme-based.
    FsKit,
    /// `macFUSE` `FSKit` module, block-resource personality.
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

/// Everything [`probe`] observes about the machine.
///
/// A struct rather than eight positional arguments: four of them are
/// `Option<&str>` or `bool`, so a transposed pair would compile cleanly and
/// quietly invert a diagnosis — `staged_kext` and `installed_kext` in
/// particular, whose whole purpose is to be COMPARED against each other.
#[derive(Debug, Clone, Copy)]
pub struct ProbeEnv<'a> {
    /// What `build.rs` recorded this binary links: `"fuse-t"` or `"macfuse"`.
    pub linked_lib: &'a str,
    /// macOS major version, e.g. `27`; `None` when unknown.
    pub os_major: Option<u32>,
    /// Whether any `/dev/macfuse*` node exists.
    pub dev_macfuse_present: bool,
    /// Version of the STAGED kext, which is the one that loads after a reboot.
    pub staged_kext: Option<&'a str>,
    /// Version of the INSTALLED kext on disk.
    pub installed_kext: Option<&'a str>,
    /// `pluginkit` lines for registered `FSKit` modules.
    pub fskit_modules: &'a [&'a str],
    /// Path to FUSE-T's dylib, if present.
    pub fuse_t_lib: Option<&'a Path>,
    /// Whether this binary links FUSE-T.
    pub linked_fuse_t: bool,
}

/// Probe the machine for usable FUSE mechanisms.
///
/// `os_major` is the macOS major version (e.g. `27`). `None` on a non-macOS
/// host, or when it could not be read — an unknown version asserts no
/// incompatibility, because not knowing is not evidence.
///
/// `available` means **this binary can mount with it right now** — not that the
/// pieces are installed somewhere. The distinction is the whole point: a
/// registered `FSKit` module says nothing about whether the linked `libfuse` will
/// route a mount to it, and FUSE-T's library sitting on disk says nothing about
/// a binary that links macFUSE's `libfuse` instead. Reporting inventory as
/// capability produced three false "available" claims and a mount that failed
/// three times with macFUSE's own error — including for FUSE-T, which proves it
/// was never reached.
///
/// `linked_fuse_t` is what the binary was BUILT against; `fuse_t_lib` only says
/// something is installed, which is reported as context and never as capability.
///
/// Pure with respect to its inputs, so the decision logic is testable without
/// installing anything.
#[must_use]
pub fn probe(env: &ProbeEnv<'_>) -> Vec<BackendStatus> {
    let &ProbeEnv {
        linked_lib,
        os_major,
        dev_macfuse_present,
        staged_kext,
        installed_kext,
        fskit_modules,
        fuse_t_lib,
        linked_fuse_t,
    } = env;
    // The mechanism is fixed at LINK time, so a binary linking FUSE-T cannot
    // use the kernel extension however healthy it looks. Reporting the device
    // node alone as capability is the same inventory-for-capability error the
    // FSKit and FUSE-T arms already avoid.
    let links_macfuse = linked_lib != "fuse-t";

    // MEASURED, not assumed: on macOS 26+ macFUSE's libfuse2 compatibility layer
    // fails for its clients even with the kext loaded, approved, and every
    // /dev/macfuse node present. Three independent programs were tried on macOS
    // 27.0 (build 26A428) and all failed:
    //
    //   4n6mount (fuser 0.16 and 0.18) -> EPERM
    //   minfuse   (40 lines, none of our code) -> Unspecified Error
    //   ewfmount  (libewf, unrelated project) -> macFUSE option-parse error
    //
    // A devfs mount from the same process succeeded throughout, so generic
    // mount permission is not the cause. Reporting Kernel as `available` here
    // promises a mount that cannot happen -- the inventory-for-capability error
    // the FSKit and FUSE-T arms already refuse to make.
    let os_breaks_macfuse = os_major.is_some_and(|v| v >= 26);

    let kernel_detail = if !links_macfuse {
        "this binary links FUSE-T, so the kernel extension cannot be used by it".to_string()
    } else if dev_macfuse_present && os_breaks_macfuse {
        format!(
            "/dev/macfuse is present and the kext is loaded, but macFUSE's libfuse2 \
             layer does not mount on macOS {} -- measured with three independent \
             programs, including two not from this project. Build against FUSE-T \
             instead (see docs/decisions/0011-macos-mounts-via-fuse-t-linkage.md)",
            os_major.unwrap_or(0)
        )
    } else if dev_macfuse_present {
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
    let scheme = ids.contains(&"io.macfuse.app.fsmodule.macfuse");
    let local = ids.contains(&"io.macfuse.app.fsmodule.macfuse-local");

    vec![
        BackendStatus {
            backend: FuseBackend::Kernel,
            available: links_macfuse && dev_macfuse_present && !os_breaks_macfuse,
            detail: kernel_detail,
        },
        BackendStatus {
            // Registered is not routable. Until a mount through the linked
            // libfuse is demonstrated, this is reported as present-not-usable.
            backend: FuseBackend::FsKit,
            available: false,
            detail: if scheme {
                "FSKit module registered (scheme-based), but FSKit is a separate \
                 Apple programming model (FSModule), not a libfuse backend this \
                 binary can link"
                    .to_string()
            } else {
                "FSKit module not registered: launch macfuse.app, then enable it \
                 in System Settings > General > Login Items & Extensions"
                    .to_string()
            },
        },
        BackendStatus {
            backend: FuseBackend::FsKitLocal,
            available: false,
            detail: if local {
                "FSKit module registered (block resources), but not known to be \
                 routable from this build"
                    .to_string()
            } else {
                "FSKit local module not registered".to_string()
            },
        },
        BackendStatus {
            // FUSE-T is a different library implementing the same API, so it is
            // reachable only if this binary was LINKED against it. Its presence
            // on disk is context, never capability.
            backend: FuseBackend::FuseT,
            available: linked_fuse_t,
            detail: match (linked_fuse_t, fuse_t_lib) {
                (true, Some(p)) => format!("linked against FUSE-T at {}", p.display()),
                (true, None) => "built against FUSE-T".to_string(),
                (false, Some(p)) => format!(
                    "FUSE-T is installed at {} but this binary links macFUSE's \
                     libfuse; rebuild against FUSE-T to use it",
                    p.display()
                ),
                (false, None) => "FUSE-T is not installed (brew install --cask fuse-t)".to_string(),
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
    let first = line.split_whitespace().next().unwrap_or("");
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
        let s = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: false,
            staged_kext: Some("5.3.3"),
            installed_kext: Some("5.4.0"),
            fskit_modules: &[],
            fuse_t_lib: None,
            linked_fuse_t: false,
        });
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
        let s = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: true,
            staged_kext: Some("5.4.0"),
            installed_kext: Some("5.4.0"),
            fskit_modules: &[],
            fuse_t_lib: None,
            linked_fuse_t: false,
        });
        assert!(s
            .iter()
            .any(|b| b.backend == FuseBackend::Kernel && b.available));
    }

    /// RED: registration is DETECTED per personality, and reported as presence
    /// rather than as capability.
    ///
    /// `available` means "this binary can mount with it now". A registered
    /// module says nothing about whether the linked `libfuse` routes to `FSKit`, so
    /// detection must show up in the DETAIL while `available` stays false until
    /// a mount is demonstrated. Equating the two produced a probe that claimed
    /// three usable backends and could mount with none of them.
    #[test]
    fn registered_fskit_modules_are_detected_individually() {
        let s = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: false,
            staged_kext: None,
            installed_kext: None,
            fskit_modules: &["io.macfuse.app.fsmodule.macfuse"],
            fuse_t_lib: None,
            linked_fuse_t: false,
        });
        let scheme = s
            .iter()
            .find(|b| b.backend == FuseBackend::FsKit)
            .expect("reported");
        let local = s
            .iter()
            .find(|b| b.backend == FuseBackend::FsKitLocal)
            .expect("reported");
        assert!(
            scheme.detail.contains("registered"),
            "the scheme module IS registered here and the detail must say so: {:?}",
            scheme.detail
        );
        assert!(
            local.detail.contains("not registered"),
            "the local personality is absent and must be reported so: {:?}",
            local.detail
        );
        assert!(
            !scheme.available,
            "registration is not capability; available must stay false"
        );
    }

    /// RED: FUSE-T is available only when this binary was LINKED against it.
    ///
    /// Its library existing on disk proves nothing: FUSE-T is a different
    /// library implementing the same API, so a binary linking macFUSE's libfuse
    /// cannot reach it however many copies are installed. The earlier version of
    /// this probe reported "available" from the file's presence, and the mount
    /// then failed with macFUSE's own error — proof it never reached FUSE-T.
    #[test]
    fn fuse_t_is_available_only_when_linked_not_merely_installed() {
        let installed = Some(Path::new("/usr/local/lib/libfuse-t.dylib"));

        let linked = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: false,
            staged_kext: None,
            installed_kext: None,
            fskit_modules: &[],
            fuse_t_lib: installed,
            linked_fuse_t: true,
        });
        assert!(
            linked
                .iter()
                .any(|b| b.backend == FuseBackend::FuseT && b.available),
            "linked against FUSE-T means usable"
        );

        let merely_installed = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: false,
            staged_kext: None,
            installed_kext: None,
            fskit_modules: &[],
            fuse_t_lib: installed,
            linked_fuse_t: false,
        });
        let s = merely_installed
            .iter()
            .find(|b| b.backend == FuseBackend::FuseT)
            .expect("reported");
        assert!(!s.available, "installed but not linked is NOT available");
        assert!(
            s.detail.contains("rebuild"),
            "and the detail must say what would fix it: {:?}",
            s.detail
        );
    }

    /// RED: every mechanism is reported, present or not. A probe that omits the
    /// unavailable ones cannot explain why a mount failed.
    #[test]
    fn the_probe_reports_every_mechanism() {
        let s = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: false,
            staged_kext: None,
            installed_kext: None,
            fskit_modules: &[],
            fuse_t_lib: None,
            linked_fuse_t: false,
        });
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
        let s = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: false,
            staged_kext: None,
            installed_kext: None,
            fskit_modules: &lines,
            fuse_t_lib: None,
            linked_fuse_t: false,
        });
        let scheme = s
            .iter()
            .find(|b| b.backend == FuseBackend::FsKit)
            .expect("reported");
        let local = s
            .iter()
            .find(|b| b.backend == FuseBackend::FsKitLocal)
            .expect("reported");
        assert!(
            scheme.detail.contains("registered") && !scheme.detail.contains("not registered"),
            "the scheme module IS registered in this output: {:?}",
            scheme.detail
        );
        assert!(
            local.detail.contains("registered") && !local.detail.contains("not registered"),
            "and so is the local personality: {:?}",
            local.detail
        );
    }

    /// RED: with ONLY the local personality registered, the scheme module must
    /// not be claimed — the substring trap in the other direction.
    #[test]
    fn only_local_registered_does_not_claim_the_scheme_module() {
        let lines =
            ["   io.macfuse.app.fsmodule.macfuse-local(2.0)\tD20E163C\t2026-09-14\t/x.appex"];
        let s = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: false,
            staged_kext: None,
            installed_kext: None,
            fskit_modules: &lines,
            fuse_t_lib: None,
            linked_fuse_t: false,
        });
        let scheme = s
            .iter()
            .find(|b| b.backend == FuseBackend::FsKit)
            .expect("reported");
        let local = s
            .iter()
            .find(|b| b.backend == FuseBackend::FsKitLocal)
            .expect("reported");
        assert!(
            scheme.detail.contains("not registered"),
            "only the local personality is present; the scheme module must not be \
             claimed as registered: {:?}",
            scheme.detail
        );
        assert!(
            local.detail.contains("registered") && !local.detail.contains("not registered"),
            "the local personality IS registered: {:?}",
            local.detail
        );
    }

    /// A loaded kext on macOS 26+ must NOT be reported as usable.
    ///
    /// This is the regression that prompted the OS gate: once the kext was
    /// approved and `/dev/macfuse0..63` appeared, the probe began announcing
    /// `Kernel available` on a machine where every mount still returns EPERM.
    /// `mount_smoke` caught it, which is what that test is for.
    #[test]
    fn a_loaded_kext_on_macos_26_plus_is_not_reported_usable() {
        for v in [26u32, 27, 30] {
            let s = probe(&ProbeEnv {
                linked_lib: "macfuse",
                os_major: Some(v),
                dev_macfuse_present: true,
                staged_kext: None,
                installed_kext: None,
                fskit_modules: &[],
                fuse_t_lib: None,
                linked_fuse_t: false,
            });
            let k = s.iter().find(|b| b.backend == FuseBackend::Kernel).unwrap();
            assert!(
                !k.available,
                "macOS {v}: the kext is loaded but macFUSE's libfuse2 layer does \
                 not mount; `available` promises a mount that cannot happen"
            );
            assert!(
                k.detail.contains("FUSE-T"),
                "the detail must name the route that DOES work, not just refuse: {}",
                k.detail
            );
        }
    }

    /// On an older macOS the same inventory IS reported usable.
    ///
    /// Without this the gate would be indistinguishable from simply deleting
    /// kernel support, and an examiner on macOS 14 would be told to rebuild for
    /// no reason.
    #[test]
    fn a_loaded_kext_on_older_macos_is_still_usable() {
        for v in [13u32, 14, 15] {
            let s = probe(&ProbeEnv {
                linked_lib: "macfuse",
                os_major: Some(v),
                dev_macfuse_present: true,
                staged_kext: None,
                installed_kext: None,
                fskit_modules: &[],
                fuse_t_lib: None,
                linked_fuse_t: false,
            });
            let k = s.iter().find(|b| b.backend == FuseBackend::Kernel).unwrap();
            assert!(
                k.available,
                "macOS {v}: macFUSE works here and must be offered"
            );
        }
    }

    /// An unknown OS version asserts no incompatibility.
    ///
    /// Not knowing the version is not evidence that the mechanism is broken, so
    /// the probe falls back to the inventory it can see rather than inventing a
    /// verdict.
    #[test]
    fn an_unknown_os_version_asserts_nothing() {
        let s = probe(&ProbeEnv {
            linked_lib: "macfuse",
            os_major: None,
            dev_macfuse_present: true,
            staged_kext: None,
            installed_kext: None,
            fskit_modules: &[],
            fuse_t_lib: None,
            linked_fuse_t: false,
        });
        let k = s.iter().find(|b| b.backend == FuseBackend::Kernel).unwrap();
        assert!(k.available, "unknown version must not fabricate a failure");
    }
}
