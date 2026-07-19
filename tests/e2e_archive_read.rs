//! Repeatable, on-demand end-to-end proof that 4n6mount reads **real archive
//! member contents correctly** through its own archive-reading path
//! (`archive_core::Archive` — the same reader `open_image` peels evidence with).
//!
//! Two layers, one file:
//!
//! * **Synthetic unit tests** (always run in CI, no external data) exercise the
//!   [`content_matches_extension`] verifier with in-memory fixtures.
//! * **An env-gated e2e** ([`e2e_archive_66pct_content_matches_extension`]) drives
//!   the verifier against a real `.zip` from the fleet test-data catalog. It is
//!   gated on `FN_E2E_ARCHIVE_ZIP` and **skips cleanly** when the variable is
//!   unset or the file is absent (the large `.zip`s are gitignored), exactly like
//!   the fleet's oracle-gated tests.
//!
//! Run the e2e against a catalog `.zip`:
//! ```text
//! FN_E2E_ARCHIVE_ZIP=~/src/issen/tests/data/dfirmadness-szechuan-sauce/case001-pcap.zip \
//!   cargo test --test e2e_archive_read -- --nocapture
//! ```
//! It lists the archive members, picks the file at the 66% position, reads its
//! bytes through `archive_core`, and asserts the content magic matches the file
//! extension — advancing to the next member when a file's type can't be
//! determined (no/unknown extension, or an extension with no known signature).

#![allow(clippy::unwrap_used, clippy::expect_used)]

/// The outcome of checking a file's content bytes against its name's extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The extension is known and the content magic matches it.
    Match,
    /// The extension is known and has a signature, but the content does not match.
    Mismatch,
    /// The type can't be checked: no extension, an unknown extension, or an
    /// extension with no reliable content signature (e.g. `.txt`, `.csv`).
    Undetermined,
}

/// Verify that `bytes` are consistent with the extension of `name`.
///
/// Returns [`Verdict::Undetermined`] when the name has no extension, an unknown
/// extension, or an extension with no reliable content signature (e.g. `.txt`,
/// `.csv`, `.dat`); [`Verdict::Match`]/[`Verdict::Mismatch`] otherwise.
pub fn content_matches_extension(name: &str, bytes: &[u8]) -> Verdict {
    let Some(ext) = extension(name) else {
        return Verdict::Undetermined;
    };
    let Some(magics) = expected_magics(&ext) else {
        return Verdict::Undetermined;
    };
    // Every signature anchors at offset 0; `starts_with` is length-safe (a head
    // shorter than the magic yields false → Mismatch, never a panic).
    if magics.iter().any(|m| bytes.starts_with(m)) {
        Verdict::Match
    } else {
        Verdict::Mismatch
    }
}

/// The lowercased final extension of `name`'s last path component, or `None`
/// when there is none (a bare name, a dotfile like `.bashrc`, or a trailing dot).
fn extension(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (stem, ext) = base.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// The content-magic signatures accepted for a known extension, or `None` when
/// the extension carries no reliable signature (textual/opaque formats). All
/// signatures anchor at offset 0.
fn expected_magics(ext: &str) -> Option<&'static [&'static [u8]]> {
    Some(match ext {
        "png" => &[&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]],
        "jpg" | "jpeg" => &[&[0xFF, 0xD8, 0xFF]],
        "gif" => &[b"GIF87a", b"GIF89a"],
        "bmp" => &[b"BM"],
        "pdf" => &[b"%PDF"],
        "gz" | "tgz" | "gzip" => &[&[0x1F, 0x8B]],
        "bz2" | "tbz2" => &[b"BZh"],
        "xz" => &[&[0xFD, b'7', b'z', b'X', b'Z', 0x00]],
        "zip" | "clbx" | "docx" | "xlsx" | "pptx" | "jar" | "apk" => {
            &[b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]
        }
        "7z" => &[&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]],
        "rar" => &[b"Rar!\x1A\x07"],
        "cab" => &[b"MSCF"],
        "exe" | "dll" | "sys" | "scr" | "ocx" | "cpl" => &[b"MZ"],
        "elf" | "so" => &[&[0x7F, b'E', b'L', b'F']],
        "class" => &[&[0xCA, 0xFE, 0xBA, 0xBE]],
        "evtx" => &[b"ElfFile\x00"],
        "evt" => &[&[0x30, 0x00, 0x00, 0x00, 0x4C, 0x66, 0x4C, 0x65]],
        "sqlite" | "sqlite3" | "db" => &[b"SQLite format 3\x00"],
        "hve" | "regf" => &[b"regf"],
        "lnk" => &[&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]],
        "ico" => &[&[0x00, 0x00, 0x01, 0x00]],
        "cur" => &[&[0x00, 0x00, 0x02, 0x00]],
        "wav" | "avi" => &[b"RIFF"],
        "pcap" => &[
            &[0xD4, 0xC3, 0xB2, 0xA1], // classic pcap (little-endian)
            &[0xA1, 0xB2, 0xC3, 0xD4], // classic pcap (big-endian)
            &[0x0A, 0x0D, 0x0D, 0x0A], // pcapng section header block
        ],
        "pcapng" => &[&[0x0A, 0x0D, 0x0D, 0x0A]],
        "xml" => &[
            b"<?xml",                  // ascii / utf-8
            b"\xEF\xBB\xBF<?xml",      // utf-8 BOM
            &[0xFF, 0xFE, b'<', 0x00], // utf-16 LE BOM + '<'
            &[0xFE, 0xFF, 0x00, b'<'], // utf-16 BE BOM + '<'
        ],
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Synthetic unit tests (CI, no external data)
// ---------------------------------------------------------------------------

/// A real PNG signature over an otherwise-empty body → Match.
#[test]
fn png_magic_matches_png_extension() {
    let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    assert_eq!(content_matches_extension("logo.png", &png), Verdict::Match);
}

/// A `.png` name over garbage bytes → Mismatch (the load-bearing negative case:
/// this is what a wrong-bytes archive read would trip).
#[test]
fn garbage_over_png_extension_mismatches() {
    let garbage = [0u8, 1, 2, 3, 4, 5, 6, 7];
    assert_eq!(
        content_matches_extension("logo.png", &garbage),
        Verdict::Mismatch
    );
}

/// No extension → Undetermined (walk to the next member).
#[test]
fn no_extension_is_undetermined() {
    assert_eq!(
        content_matches_extension("NTUSER", b"regf\x15\x00\x00\x00"),
        Verdict::Undetermined
    );
}

/// A known-but-unmapped extension → Undetermined.
#[test]
fn unknown_extension_is_undetermined() {
    assert_eq!(
        content_matches_extension("blob.xyz", &[0xDE, 0xAD, 0xBE, 0xEF]),
        Verdict::Undetermined
    );
}

/// An extension that exists but has no reliable magic (`.csv`) → Undetermined,
/// even with a UTF-16 BOM present.
#[test]
fn textual_extension_without_signature_is_undetermined() {
    let utf16_bom_csv = [0xFF, 0xFE, b'a', 0x00, b',', 0x00];
    assert_eq!(
        content_matches_extension("report.csv", &utf16_bom_csv),
        Verdict::Undetermined
    );
}

/// `MZ` over `.dll`/`.exe`/`.sys` → Match (PE family).
#[test]
fn mz_magic_matches_pe_extensions() {
    let mz = [b'M', b'Z', 0x90, 0x00];
    assert_eq!(content_matches_extension("driver.sys", &mz), Verdict::Match);
    assert_eq!(content_matches_extension("app.exe", &mz), Verdict::Match);
    assert_eq!(content_matches_extension("lib.dll", &mz), Verdict::Match);
}

/// pcapng magic over `.pcap` → Match (a `.pcap` file is commonly pcapng; both
/// classic-pcap and pcapng magics are accepted). Mirrors the catalog default.
#[test]
fn pcapng_magic_matches_pcap_extension() {
    let pcapng = [0x0A, 0x0D, 0x0D, 0x0A, 0x7C, 0x00, 0x00, 0x00];
    assert_eq!(
        content_matches_extension("case001.pcap", &pcapng),
        Verdict::Match
    );
}

/// EVTX magic (`ElfFile\0`) over `.evtx` → Match; a truncated head → Mismatch.
#[test]
fn evtx_magic_matches_and_short_head_mismatches() {
    let evtx = b"ElfFile\x00\x00\x00\x00\x00";
    assert_eq!(
        content_matches_extension("Security.evtx", evtx),
        Verdict::Match
    );
    assert_eq!(
        content_matches_extension("Security.evtx", b"Elf"),
        Verdict::Mismatch
    );
}

/// `<?xml` over `.xml`, including a UTF-8 BOM prefix → Match.
#[test]
fn xml_declaration_matches_xml_extension() {
    assert_eq!(
        content_matches_extension("doc.xml", b"<?xml version=\"1.0\"?>"),
        Verdict::Match
    );
    let bom_xml = b"\xEF\xBB\xBF<?xml version=\"1.0\"?>";
    assert_eq!(
        content_matches_extension("doc.xml", bom_xml),
        Verdict::Match
    );
}

/// The extension match is case-insensitive.
#[test]
fn extension_match_is_case_insensitive() {
    let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    assert_eq!(content_matches_extension("LOGO.PNG", &png), Verdict::Match);
}

// ---------------------------------------------------------------------------
// Env-gated e2e against a real catalog .zip
// ---------------------------------------------------------------------------

/// Point 4n6mount's archive reader at a real `.zip`, pick the member at the 66%
/// position, read its bytes, and assert the content magic matches the extension
/// — walking forward past members whose type can't be determined.
///
/// Env-gated: set `FN_E2E_ARCHIVE_ZIP` to a `.zip` path. Skips cleanly when the
/// variable is unset or the file is absent.
#[test]
fn e2e_archive_66pct_content_matches_extension() {
    let Some(zip_path) = std::env::var_os("FN_E2E_ARCHIVE_ZIP") else {
        eprintln!(
            "SKIP e2e_archive_66pct_content_matches_extension: set FN_E2E_ARCHIVE_ZIP=<path/to.zip>"
        );
        return;
    };
    let zip_path = std::path::PathBuf::from(zip_path);
    if !zip_path.is_file() {
        eprintln!(
            "SKIP e2e_archive_66pct_content_matches_extension: {} is not a file",
            zip_path.display()
        );
        return;
    }

    let data = std::fs::read(&zip_path).expect("read archive .zip");
    let name = zip_path.file_name().and_then(|s| s.to_str());
    let mut archive = archive_core::Archive::open(&data, name)
        .expect("archive opens")
        .expect("input is a recognized archive");

    // File members only, in archive order (directories have no byte content).
    let files: Vec<(usize, String)> = archive
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.is_dir)
        .map(|(i, e)| (i, e.name.clone()))
        .collect();
    assert!(!files.is_empty(), "archive has at least one file member");

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let start = (0.66_f64 * files.len() as f64).floor() as usize;
    eprintln!(
        "e2e: {} — {} file members, starting at 66% index {}",
        zip_path.display(),
        files.len(),
        start
    );

    // Start at the 66% position but walk the WHOLE archive, wrapping around, so a
    // run of untyped members at the tail (registry hives with no extension, .dat
    // blobs, …) can't false-fail the check: we verify the first member with a
    // determinable type wherever it sits, and only fail on a real content Mismatch.
    let mut tried: Vec<String> = Vec::new();
    let n = files.len();
    for step in 0..n {
        let (index, member_name) = &files[(start + step) % n];
        let bytes = archive.read(*index).expect("read archive member");
        match content_matches_extension(member_name, &bytes) {
            Verdict::Match => {
                eprintln!(
                    "e2e: VERIFIED member #{index} {member_name:?} ({} bytes) — content magic matches extension",
                    bytes.len()
                );
                return;
            }
            Verdict::Mismatch => panic!(
                "member #{index} {member_name:?} content does NOT match its extension \
                 (first bytes: {:02x?}) — archive reader returned wrong content",
                &bytes[..bytes.len().min(16)]
            ),
            Verdict::Undetermined => {
                tried.push(member_name.clone());
            }
        }
    }

    // No member carried an extension we can content-verify (e.g. an archive of
    // registry hives with no/`.dat` extensions, or a raw image). That is NOT a
    // reader failure — a wrong-bytes read of a TYPED member would have tripped
    // `Mismatch` above and panicked — so skip cleanly rather than fail. Point the
    // e2e at an archive with extension-typed members (pcap, PE, evtx, images) to
    // get a positive verification.
    eprintln!(
        "SKIP e2e_archive_66pct_content_matches_extension: no extension-verifiable member \
         (started at 66% index {start}); read {} untyped file(s) OK without error: {:?}",
        tried.len(),
        tried
    );
}
