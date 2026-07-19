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
/// RED stub — the GREEN step implements the magic-vs-extension logic.
pub fn content_matches_extension(_name: &str, _bytes: &[u8]) -> Verdict {
    unimplemented!("GREEN step implements the content-vs-extension verifier")
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

    let mut tried: Vec<String> = Vec::new();
    for (index, member_name) in files.iter().skip(start) {
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

    panic!(
        "no member at/after 66% index {start} had a determinable type to verify; tried {} file(s): {:?}",
        tried.len(),
        tried
    );
}
