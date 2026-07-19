#!/usr/bin/env bash
# One-command reproduction of the macOS arm of the SoK §7 deletion-recoverability
# protocol: for each testable filesystem, build a real image, populate a fixed
# manifest, delete it, churn, snapshot at T0/T1/T2, then measure and score.
#
# Host requirements (macOS): hdiutil, newfs_msdos/newfs_exfat/newfs_hfs,
# diskutil, and The Sleuth Kit (fls/istat/icat) as the independent oracle.
# No sudo required (image-backed disks attach unprivileged).
#
# Usage: ./run_all.sh [workroot]   (default /tmp/delexp)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${1:-/tmp/delexp}"
rm -rf "$ROOT"; mkdir -p "$ROOT"

echo "== host =="; sw_vers 2>/dev/null | tr '\n' ' '; echo; uname -m; fls -V

for FS in fat exfat hfsplus apfs; do
  echo "== $FS =="
  python3 "$HERE/manifest.py" emit "$FS" "$ROOT/stage-$FS"
  bash "$HERE/run_fs.sh" "$FS" "$ROOT/$FS" "$ROOT/stage-$FS"
  python3 "$HERE/measure.py" "$FS" "$ROOT/$FS" "$ROOT/stage-$FS"
done

echo "== scoring =="
( cd "$HERE" && python3 score.py "$ROOT" )
echo
echo "Artifacts: $ROOT/{fs}/measured_{fs}.json  +  $ROOT/score_results.json"
echo "(raw t0/t1/t2 images stay under $ROOT and are NOT committed)"
