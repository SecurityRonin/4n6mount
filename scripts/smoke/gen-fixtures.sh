#!/usr/bin/env bash
# Mint the non-committed mount-smoke fixtures (Linux only — uses real format
# tools so the authoring engine is an independent oracle). Each file-bearing
# fixture contains hello.txt = "hello from <fmt>" + sub/deep.txt. Committed
# fixtures (exfat/hfsplus/apfs/crash.dmp) are copied from tests/data.
#
# Usage: scripts/smoke/gen-fixtures.sh [OUTDIR]   (default: ./fixtures)
set -euo pipefail

OUT="${1:-fixtures}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$OUT"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# Committed fixtures (Apple-driver / synthetic) — copied as-is.
for f in exfat.img hfsplus.img apfs.img crash.dmp; do
  cp "$REPO/tests/data/$f" "$OUT/$f"
done

# Build a small known tree: hello.txt + sub/deep.txt.
mktree() { # $1=dir  $2=hello-content
  rm -rf "$1"; mkdir -p "$1/sub"
  printf '%s\n' "$2" > "$1/hello.txt"
  printf 'deep content\n' > "$1/sub/deep.txt"
}

# --- archives (real zip/7z/tar) ---
mktree "$W/zip"  "hello from zip";    ( cd "$W/zip"  && zip -qr "$OUT/test.zip" . )
mktree "$W/7z"   "hello from sevenz"; 7z a -bso0 -bsp0 "$OUT/test.7z" "$W/7z/." >/dev/null
mktree "$W/gz"   "hello from targz";  tar czf "$OUT/test.tar.gz"  -C "$W/gz" .
mktree "$W/bz"   "hello from tarbz2"; tar cjf "$OUT/test.tar.bz2" -C "$W/bz" .

# --- ISO 9660 (genisoimage bakes the tree directly, no mount needed) ---
mktree "$W/iso"  "hello from iso";    genisoimage -quiet -r -J -o "$OUT/test.iso" "$W/iso"

# --- filesystem images via real mkfs + a loopback mount to write the file ---
mkfs_with_file() { # $1=out.img  $2=mkfs-cmd  $3=mount-args  $4=hello-content
  dd if=/dev/zero of="$1" bs=1M count=24 status=none
  eval "$2 \"$1\"" >/dev/null 2>&1
  local m; m="$(mktemp -d)"
  sudo mount $3 "$1" "$m"
  printf '%s\n' "$4" | sudo tee "$m/hello.txt" >/dev/null
  sudo mkdir -p "$m/sub"; printf 'deep content\n' | sudo tee "$m/sub/deep.txt" >/dev/null
  sync; sudo umount "$m"; rmdir "$m"
}
mkfs_with_file "$OUT/ext4.img" "mkfs.ext4 -F -q" "-o loop"        "hello from ext4"
mkfs_with_file "$OUT/ntfs.img" "mkntfs -F -Q"    "-t ntfs-3g -o loop" "hello from ntfs"

# --- EWF (.E01): acquire a raw ext4 image whose inner FS holds hello.txt ---
mkfs_with_file "$W/ewf-inner.raw" "mkfs.ext4 -F -q" "-o loop" "hello from ewf"
ewfacquire -u -t "$OUT/test" -f encase6 -c deflate:none -S 1GiB "$W/ewf-inner.raw" >/dev/null 2>&1

# --- VMDK: convert a raw ext4 image (inner FS holds hello.txt) ---
mkfs_with_file "$W/vmdk-inner.raw" "mkfs.ext4 -F -q" "-o loop" "hello from vmdk"
qemu-img convert -O vmdk "$W/vmdk-inner.raw" "$OUT/test.vmdk"

echo "=== minted fixtures in $OUT ==="
ls -la "$OUT"
