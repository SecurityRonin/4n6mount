//! A mount that silently drops evidence is the failure this file exists to
//! prevent.
//!
//! `4n6mount` on macOS links FUSE-T, which serves the mount as loopback NFS and
//! demonstrably does not carry extended attributes or ownership. That is not
//! fixable here — the transport never issues the request. What IS fixable, and
//! what these tests pin, is the tool's obligation to SAY SO.
//!
//! The distinction the notice must preserve:
//!
//! | seen through the mount | what it means |
//! |---|---|
//! | a file with no xattrs | **UNKNOWN** — it may have them |
//! | uid/gid on any entry | the mounting user's, not the image's |
//!
//! An examiner who reads absence as a finding has been misled by the tool, not
//! by the evidence.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_mount::fuse_backend::{fidelity_notice, transport_losses, TransportLoss};

/// The lossy transport must declare BOTH measured losses.
#[test]
fn a_lossy_transport_declares_every_measured_loss() {
    let losses = transport_losses("fuse-t");
    assert!(
        losses.contains(&TransportLoss::ExtendedAttributes),
        "FUSE-T never issues xattr requests; the mount must say so"
    );
    assert!(
        losses.contains(&TransportLoss::Ownership),
        "FUSE-T replaces uid/gid with the mounting user's; the mount must say so"
    );
}

/// Every declared loss carries its measurement and a route that avoids it.
///
/// A loss asserted without evidence is a rumour, and one without an alternative
/// is an obstruction. Both halves are required for the notice to be actionable.
#[test]
fn every_loss_carries_evidence_and_a_route() {
    for l in transport_losses("fuse-t") {
        assert!(!l.what().is_empty(), "a loss must say what is lost");
        assert!(
            l.evidence().len() > 40,
            "a loss must cite how it was measured, not merely assert it: {l:?}"
        );
        assert!(
            !l.lossless_route().is_empty(),
            "a loss must name the route that does not lose it: {l:?}"
        );
    }
}

/// The route named must not point somewhere that does not exist.
///
/// This is a regression pin. The first draft told the examiner to read
/// attributes "from the `metadata/` directory inside this mount". `metadata/`
/// carries no xattr file at all — the promise was false, and a false remedy is
/// worse than the loss it answers, because it sends someone looking instead of
/// telling them to stop.
#[test]
fn the_xattr_route_does_not_promise_the_mount() {
    let route = TransportLoss::ExtendedAttributes.lossless_route();
    assert!(
        route.contains("NOT available anywhere inside this mount"),
        "the xattr route must state plainly that the mount cannot serve them: {route}"
    );
}

/// The notice must be unmissable and must state the UNKNOWN rule.
#[test]
fn the_notice_states_that_absence_is_unknown() {
    let n = fidelity_notice("fuse-t").expect("a lossy transport must produce a notice");
    assert!(
        n.contains("UNKNOWN"),
        "the notice must tell the examiner how to read an absence: {n}"
    );
    assert!(
        n.contains("may HAVE them"),
        "the notice must name the specific wrong inference it prevents: {n}"
    );
    for l in transport_losses("fuse-t") {
        assert!(n.contains(l.what()), "notice omits a declared loss: {l:?}");
    }
}

/// A transport with no measured losses issues no notice.
///
/// Without this the warning would be noise printed on every mount, and a
/// warning that always fires is one nobody reads — the same end state as
/// printing nothing, reached more annoyingly.
#[test]
fn a_lossless_transport_is_silent() {
    assert!(
        transport_losses("macfuse").is_empty(),
        "macFUSE speaks FUSE natively and carries both properties"
    );
    assert!(
        fidelity_notice("macfuse").is_none(),
        "a warning that always fires is one nobody reads"
    );
}
