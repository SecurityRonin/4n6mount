#!/usr/bin/env python3
"""Measure per-(file, layer, time-point) deletion residue from raw images.

Independent oracle: The Sleuth Kit (fls/istat/icat) drives the structure-aware
L1/L2 measurement for the formats it supports (FAT, exFAT, HFS+). Raw byte-scan
of per-chunk content markers drives L3 (content survival) filesystem-agnostically
and also carries L1/L3 for APFS, which mainline TSK cannot parse.

Outcome vocabularies (shared with predictions.py / score.py):
  L1 name    : full | partial | none
  L2 map     : sufficient | partial | none
  L3 content : match | partial | none

Operational definitions (documented in RESULTS.md):
  L1  fls -rd recovers the deleted entry's name (TSK formats). full == recovered
      name equals original; partial == a truncated/mangled/first-char-lost form
      recovered (e.g. FAT 8.3 tombstone `_B.TXT`); none == not recovered.
      APFS: byte-scan for the name in UTF-8 / UTF-16LE.
  L2  icat reconstructs content *using only the recovered map*. sufficient ==
      icat output hash == manifest hash (map alone yielded correct full content);
      partial == icat non-empty with 0<chunk-coverage<all (e.g. FAT contiguity
      guess recovers a fragmented file only up to its first extent); none ==
      icat empty / errors / istat lists no data units. The fragmented file is the
      L2 discriminator: only a *retained* map (exFAT stream extent, HFS+ extent
      record) reproduces it; FAT's zeroed chain forces a contiguity assumption
      that fails. APFS: not measured here (no TSK map reader) -> "na".
  L3  per-chunk markers surviving in the raw image / total chunks. match == all;
      partial == some; none == zero. Fragmentation-robust and map-independent.
"""
import hashlib
import json
import re
import subprocess
import sys
import os

TSK_FS = {"fat", "exfat", "hfsplus"}


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, **kw)


def chunk_coverage(raw: bytes, nonce: str, n_chunks: int):
    found = 0
    for i in range(n_chunks):
        if (f"{nonce}#{i:05d}#".encode()) in raw:
            found += 1
    return found


def l3_class(found, total):
    if found == 0:
        return "none"
    return "match" if found >= total else "partial"


# ---- TSK helpers -----------------------------------------------------------
def fls_deleted(img):
    """Return list of (inode, recovered_path) for deleted entries."""
    r = sh(["fls", "-rdp", img])
    out = []
    for line in r.stdout.decode(errors="replace").splitlines():
        # e.g. "r/r * 8:\tSECRET_report.txt"  or  "r/r * 8(realloc):\tname"
        m = re.match(r"^[^\t]*\*\s*([0-9]+)(?:-[0-9]+-[0-9]+)?(?:\([^)]*\))?:\t(.*)$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def fls_live(img):
    r = sh(["fls", "-rp", img])
    out = []
    for line in r.stdout.decode(errors="replace").splitlines():
        if "*" in line.split("\t")[0]:
            continue
        m = re.match(r"^[^\t]*\s([0-9]+)(?:-[0-9]+-[0-9]+)?:\t(.*)$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def istat_nblocks(img, inode):
    r = sh(["istat", img, str(inode)])
    txt = r.stdout.decode(errors="replace")
    # capture integers appearing after a blocks/sectors header
    nums = 0
    grab = False
    for line in txt.splitlines():
        if re.search(r"(Sectors|Blocks|Direct Blocks|Data Fork Blocks)\s*:", line):
            grab = True
            continue
        if grab:
            toks = re.findall(r"\b\d+\b", line)
            if toks:
                nums += len(toks)
            elif line.strip() == "" and nums:
                break
    return nums


def icat_hash(img, inode):
    r = sh(["icat", img, str(inode)])
    data = r.stdout
    if not data:
        return None, b""
    return hashlib.sha256(data).hexdigest(), data


def name_match_class(orig_name, recovered):
    """full/partial/none by comparing a recovered name to the original."""
    if recovered is None:
        return "none"
    base = recovered.rsplit("/", 1)[-1]
    if base == orig_name:
        return "full"
    # FAT 8.3 short-name tombstone: first char lost -> `_...`; or 8.3-mangled.
    stem = orig_name.rsplit(".", 1)[0]
    if base and (base[1:] and (base[1:] in orig_name.upper() or base[1:] in orig_name)):
        return "partial"
    # any nonempty recovered token that shares the tail
    if base and stem[1:6].upper() and stem[1:6].upper() in base.upper():
        return "partial"
    return "partial" if base else "none"


def apfs_name_class(raw, name):
    if name.encode() in raw or name.encode("utf-16-le") in raw:
        return "full"
    # partial: stem present
    stem = name.rsplit(".", 1)[0]
    if stem.encode() in raw or stem.encode("utf-16-le") in raw:
        return "partial"
    return "none"


def measure(fs, workdir, stagedir):
    man = json.load(open(os.path.join(stagedir, "manifest.json")))
    files = man["files"]
    result = {"fs": fs, "files": {}}

    # map original names -> inode from the T0 live listing (TSK formats)
    live_inode = {}
    if fs in TSK_FS:
        for ino, path in fls_live(os.path.join(workdir, "t0.img")):
            live_inode[path.rstrip("/")] = ino

    for tp in ("t1", "t2"):
        img = os.path.join(workdir, f"{tp}.img")
        raw = open(img, "rb").read()
        deleted = fls_deleted(img) if fs in TSK_FS else []
        # index deleted recovered names by inode and by basename
        del_by_ino = {ino: p for ino, p in deleted}
        for fid, meta in files.items():
            n_ch = meta["n_chunks"]
            found = chunk_coverage(raw, meta["nonce"], n_ch)
            l3 = l3_class(found, n_ch)

            rec = result["files"].setdefault(fid, {"class": meta["class"], "name": meta["name"]})
            entry = {"l3": l3, "l3_chunks": f"{found}/{n_ch}"}

            if fs in TSK_FS:
                ino = live_inode.get(meta["relpath"])
                recovered = del_by_ino.get(ino) if ino else None
                if recovered is None:
                    # fall back: match a deleted entry by basename tail
                    for di, dp in deleted:
                        if dp.rsplit("/", 1)[-1].lstrip("_") and \
                           meta["name"].rsplit(".", 1)[0][1:5] in dp.upper():
                            recovered, ino = dp, di
                            break
                entry["l1"] = name_match_class(meta["name"], recovered)
                entry["l1_recovered"] = recovered
                # L2 via icat vs manifest hash
                if ino:
                    h, data = icat_hash(img, ino)
                    if h is None:
                        entry["l2"] = "none"
                    elif h == meta["sha256"]:
                        entry["l2"] = "sufficient"
                    else:
                        cov = chunk_coverage(data, meta["nonce"], n_ch)
                        entry["l2"] = "partial" if cov > 0 else "none"
                    entry["l2_icat_ok"] = (h == meta["sha256"])
                    entry["istat_blocks"] = istat_nblocks(img, ino)
                else:
                    entry["l2"] = "none"
                    entry["l1"] = entry.get("l1", "none")
            else:  # APFS: byte-scan only
                entry["l1"] = apfs_name_class(raw, meta["name"])
                entry["l2"] = "na"
            result["files"][fid][tp] = entry

    with open(os.path.join(workdir, f"measured_{fs}.json"), "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[{fs}] measured -> {workdir}/measured_{fs}.json")
    # brief console summary
    for fid, r in result["files"].items():
        t1 = r["t1"]
        print(f"  {fid:9s} {r['class']:20s} L1={t1['l1']:8s} L2={t1['l2']:11s} "
              f"L3={t1['l3']:6s} ({t1['l3_chunks']})")


if __name__ == "__main__":
    measure(sys.argv[1], sys.argv[2], sys.argv[3])
