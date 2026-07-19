#!/usr/bin/env bash
# Create a real filesystem in a raw disk image on macOS (no sudo), populate a
# fixed manifest, delete it, apply churn, and snapshot the raw bytes at
# T0 (post-populate) / T1 (post-delete) / T2 (post-churn).
#
# Usage: run_fs.sh <fat|exfat|hfsplus|apfs> <workdir> <stagedir>
#
# Everything lives under /tmp (per the fleet test-data provenance standard:
# extracted/derived working copies never under ~/src). Images are large and
# are NOT committed; only the small manifest.json + measured JSON are.
set -u
FS="$1"; WORK="$2"; STAGE="$3"
IMG="$WORK/disk.img"
MNT="$WORK/mnt"
VOL="EXPVOL"
rm -rf "$WORK"; mkdir -p "$WORK" "$MNT"

log(){ echo "[$FS] $*"; }

DEV=""
detach(){ [ -n "$DEV" ] && hdiutil detach "$DEV" >/dev/null 2>&1; DEV=""; }
trap detach EXIT

attach(){
  DEV=$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$IMG" 2>/dev/null | head -1 | awk '{print $1}')
  RDEV=${DEV/disk/rdisk}
}

mount_dev(){ # $1 = device to mount (whole disk or synthesized volume)
  diskutil mount -mountPoint "$MNT" "$1" >/dev/null 2>&1
}
unmount_dev(){ diskutil unmount "$MNT" >/dev/null 2>&1 || umount "$MNT" 2>/dev/null; }

snapshot(){ sync; cp "$IMG" "$WORK/$1.img"; log "snapshot $1 -> $WORK/$1.img"; }

# ---- format ----------------------------------------------------------------
dd if=/dev/zero of="$IMG" bs=1m count=160 2>/dev/null
attach
APFS_VOLDEV=""
case "$FS" in
  fat)      newfs_msdos -F 32 -v "$VOL" "$RDEV" >/dev/null 2>&1 ;;
  exfat)    newfs_exfat -v "$VOL" "$RDEV" >/dev/null 2>&1 ;;
  hfsplus)  newfs_hfs -v "$VOL" "$RDEV" >/dev/null 2>&1 ;;
  apfs)
    # partitionDisk lays GPT + APFS container + volume and auto-mounts it.
    diskutil partitionDisk "$DEV" GPT APFS "$VOL" 100% >/dev/null 2>&1
    APFS_VOLDEV=$(diskutil list "$DEV" | awk '/Apple_APFS_ISC/{next} /Apple_APFS/{print $NF; exit}')
    ;;
  *) log "unknown fs"; exit 2 ;;
esac

MOUNTTGT="$DEV"
if [ "$FS" = "apfs" ]; then
  # find the synthesized APFS volume mountpoint
  MP=$(diskutil info "$VOL" 2>/dev/null | awk -F': *' '/Mount Point/{print $2}')
  MNT="$MP"
else
  mount_dev "$DEV" || { log "mount failed"; exit 3; }
fi
log "formatted + mounted at $MNT"

populate_common(){
  # Copy every non-fragmented manifest file to its real relpath in one call.
  # Order: contiguous large file lands first on the near-empty disk.
  python3 - "$STAGE" "$MNT" <<'PY'
import json,os,shutil,sys
m=json.load(open(sys.argv[1]+"/manifest.json")); root=sys.argv[2]
for fid in ("contig","short83","lfn","unicode","deep"):
    f=m["files"][fid]; dst=os.path.join(root,f["relpath"])
    os.makedirs(os.path.dirname(dst) or root, exist_ok=True)
    shutil.copyfile(os.path.join(sys.argv[1],fid+".dat"), dst)
PY
  sync
  # APFS is copy-on-write over a shared container and TSK cannot read its map
  # (L2 is not measured for APFS), so the fill-to-fragment dance adds no
  # measurement value and risks ENOSPC — write frag directly there.
  if [ "$FS" = "apfs" ]; then
    cp "$STAGE/frag.dat" "$MNT/fragmented_blob.bin"; sync; return
  fi
  # Force real fragmentation: the driver prefers any contiguous free run, so we
  # must first eliminate every contiguous run >= the frag size. Fill the bulk
  # with one big filler, top off with 64 KB fillers to ENOSPC, delete alternate
  # 64 KB fillers (leaving 64 KB holes separated by live fillers), then write the
  # 128 KB frag file: with no contiguous 128 KB free it must span >=2 holes.
  AVAIL=$(df -k "$MNT" | awk 'NR==2{print $4}')
  BIG=$(( AVAIL - 3000 ))            # leave ~3 MB for the 64 KB-filler zone
  [ "$BIG" -gt 0 ] && dd if=/dev/urandom of="$MNT/bigfill.bin" bs=1k count="$BIG" 2>/dev/null
  sync
  i=0
  while dd if=/dev/urandom of="$MNT/sf_$(printf %03d $i).bin" bs=64k count=1 2>/dev/null; do
    [ -s "$MNT/sf_$(printf %03d $i).bin" ] || { rm -f "$MNT/sf_$(printf %03d $i).bin"; break; }
    i=$((i+1)); [ "$i" -ge 60 ] && break
  done
  sync
  j=0; while [ "$j" -lt "$i" ]; do rm -f "$MNT/sf_$(printf %03d $j).bin"; j=$((j+2)); done  # odd holes
  sync
  cp "$STAGE/frag.dat" "$MNT/fragmented_blob.bin"; sync
  rm -f "$MNT"/sf_*.bin "$MNT/bigfill.bin"; sync   # remove all scaffolding
}
populate_common
log "populated"; ls -laR "$MNT" 2>/dev/null | grep -c '' >/dev/null

# ---- T0 --------------------------------------------------------------------
unmount_dev; snapshot t0

# ---- delete ----------------------------------------------------------------
if [ "$FS" = "apfs" ]; then
  diskutil mount "$VOL" >/dev/null 2>&1; MNT=$(diskutil info "$VOL" 2>/dev/null | awk -F': *' '/Mount Point/{print $2}')
else
  attach; mount_dev "$DEV"
fi
python3 - "$STAGE" "$MNT" <<'PY'
import json,sys,os
m=json.load(open(sys.argv[1]+"/manifest.json")); root=sys.argv[2]
for f in m["files"].values():
    p=os.path.join(root,f["relpath"])
    try: os.remove(p)
    except OSError as e: print("del-miss",p,e)
PY
sync; unmount_dev; snapshot t1
log "deleted manifest files"

# ---- churn (overwrite pressure) --------------------------------------------
if [ "$FS" = "apfs" ]; then
  diskutil mount "$VOL" >/dev/null 2>&1; MNT=$(diskutil info "$VOL" 2>/dev/null | awk -F': *' '/Mount Point/{print $2}')
else
  attach; mount_dev "$DEV"
fi
# many small files + a couple of large writes then deletes, to churn allocator
for i in $(seq 1 40); do dd if=/dev/urandom of="$MNT/churn_$i.tmp" bs=8k count=4 2>/dev/null; done
sync
for i in $(seq 1 40); do rm -f "$MNT/churn_$i.tmp"; done
dd if=/dev/urandom of="$MNT/churn_big1.tmp" bs=1m count=8 2>/dev/null
dd if=/dev/urandom of="$MNT/churn_big2.tmp" bs=1m count=8 2>/dev/null
sync; rm -f "$MNT/churn_big1.tmp" "$MNT/churn_big2.tmp"; sync
unmount_dev; snapshot t2
log "churned"
detach
log "done: t0/t1/t2 images in $WORK"
