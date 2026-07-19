# Deletion-Recoverability Corpus — Pre-Registration (results pending)

This file is the pre-registration stub. It is committed **before** any
measurement so the ordering is visible in git history: the three models'
expected outcomes (`predictions.py`) are fixed first, the corpus is built and
measured second, and the scoring is reported last. The predictions are derived
only from the published paper (`../deletion-sok.md` §2.2 and the §3.6 matrix),
not from any measured data.

- Protocol: `../deletion-sok.md` §7 (Pre-Registered Validation Protocol).
- Harness: `manifest.py` (corpus), `run_fs.sh` (build/populate/delete/churn/
  snapshot), `measure.py` (residue measurement via The Sleuth Kit + byte-scan),
  `predictions.py` (the three models, pre-registered), `score.py` (accuracy +
  exact binomial CIs), `run_all.sh` (one-command reproduction).
- Scope of this iteration: the four filesystems mkfs-able on a macOS host
  (FAT, exFAT, HFS+, APFS). Linux filesystems (ext4, XFS, Btrfs, F2FS) require
  a Linux runner and are deferred with a documented protocol.

Results, the measured table, and the scored verdict are filled in after the run.
