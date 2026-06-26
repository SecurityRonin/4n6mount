#!/usr/bin/env bash
# Linux FUSE mount smoke test: for each row in manifest.tsv, mount the fixture,
# read the known file through the mount, and assert its contents.
#
# Usage: scripts/smoke/smoke.sh <4n6mount-binary> <fixtures-dir>
set -uo pipefail

BIN="${1:?path to 4n6mount binary}"
FIX="${2:?fixtures dir}"
MANIFEST="$(cd "$(dirname "$0")" && pwd)/manifest.tsv"
pass=0; fail=0

while IFS=$'\t' read -r name fixture flag layout subpath expected; do
  case "$name" in ''|\#*) continue;; esac
  mnt="$(mktemp -d)"; log="/tmp/4n6smoke_${name}.log"
  "$BIN" "$FIX/$fixture" "$mnt" --fs "$flag" --daemon >"$log" 2>&1 || true
  for _ in $(seq 1 30); do mountpoint -q "$mnt" && break; sleep 0.5; done

  if [ "$layout" = disk ]; then readpath="$mnt/ro/$subpath"; else readpath="$mnt/$subpath"; fi
  if grep -qF "$expected" "$readpath" 2>/dev/null; then
    echo "PASS  $name  ($readpath contains '$expected')"; pass=$((pass+1))
  else
    echo "FAIL  $name  — '$expected' not found at $readpath"
    echo "      mount ls: $(ls -A "$mnt" 2>&1 | tr '\n' ' ')"
    echo "      log: $(tail -n 2 "$log" 2>/dev/null | tr '\n' ' ')"
    fail=$((fail+1))
  fi

  fusermount3 -u "$mnt" 2>/dev/null || fusermount -u "$mnt" 2>/dev/null || sudo umount "$mnt" 2>/dev/null || true
  rmdir "$mnt" 2>/dev/null || true
done < "$MANIFEST"

echo "=== FUSE smoke: $pass passed, $fail failed ==="
exit "$fail"
