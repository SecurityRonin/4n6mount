#!/usr/bin/env python3
"""Pre-registered expected-outcome classes for the three competing models.

These are derived ONLY from the paper as published — §2.2 (the two-axis model,
E1–E4) and the §3.6 master matrix — NOT from any measurement. Committed before
the scoring step so the pre-registration ordering is visible in git history.

Vocabularies (must match measure.py):
  L1 name    : full | partial | none
  L2 map     : sufficient | partial | none
  L3 content : match | partial | none

Three models, one expected class per (fs, file-class, layer) cell:
  T  two_axis  — §2.2 update-strategy (Axis A) + name-payload handling (Axis B),
                 E1–E4, applied per file-class.
  A  axis_a    — Axis-A-only baseline: in-place vs out-of-place, nothing else.
  C  carrier   — Carrier-category baseline: the category exists in the format
                 => residue expected (the no-model "everything survives" default).

APFS L2 is not measured on this host (mainline TSK has no APFS map reader), so
every model's APFS-L2 prediction is emitted as "na" and excluded from scoring.
"""

FS_LIST = ["fat", "exfat", "hfsplus", "apfs"]
LAYERS = ["l1", "l2", "l3"]
# file-class attributes used by the rules
FILES = {
    "short83": {"name83": True,  "contiguous": True},
    "lfn":     {"name83": False, "contiguous": True},
    "unicode": {"name83": False, "contiguous": True},
    "deep":    {"name83": False, "contiguous": True},
    "contig":  {"name83": False, "contiguous": True},
    "frag":    {"name83": False, "contiguous": False},
}
IN_PLACE = {"fat", "exfat", "hfsplus"}   # Axis A
OUT_OF_PLACE = {"apfs"}


def carrier(fs, fid, layer):
    """Category exists => recoverable. All three categories exist in all four
    formats, so the no-model default predicts the best class everywhere."""
    if fs == "apfs" and layer == "l2":
        return "na"
    return {"l1": "full", "l2": "sufficient", "l3": "match"}[layer]


def axis_a(fs, fid, layer):
    """In-place: structures modified where they live -> record (name+map) marked
    free but retained -> residue present. Out-of-place: no live structure
    overwritten -> superseded structures linger until reclaim -> at T1 (no
    reclaim) residue also present. Axis A alone cannot see tombstone vs.
    record-removal, policy zeroing, or chain loss, so it predicts full residue
    for both classes."""
    if fs == "apfs" and layer == "l2":
        return "na"
    return {"l1": "full", "l2": "sufficient", "l3": "match"}[layer]


def two_axis(fs, fid, layer):
    """§2.2 E1–E4 + §3.6, per file-class."""
    f = FILES[fid]
    if fs == "fat":
        # tombstone slots: 8.3 loses first byte (E1) -> partial; LFN payload
        # persists -> full. Chain zeroed (E3): contiguous recovers (sufficient),
        # fragmented breaks the contiguity assumption -> partial. L3 idle (E4).
        if layer == "l1":
            return "partial" if f["name83"] else "full"
        if layer == "l2":
            return "sufficient" if f["contiguous"] else "partial"
        return "match"
    if fs == "exfat":
        # InUse bit, no 0xE5 tombstone: full name residue for every class (E1).
        # FirstCluster+DataLength persist; NoFatChain=1 (contiguous) => complete
        # extent (sufficient); fragmented NoFatChain=0 chain fate driver-
        # dependent [I] -> partial. L3 idle.
        if layer == "l1":
            return "full"
        if layer == "l2":
            return "sufficient" if f["contiguous"] else "partial"
        return "match"
    if fs == "hfsplus":
        # record-removal from the live catalog B-tree (E2): live name/map degrade;
        # the journal window is expected to carry stale nodes -> some residue.
        # Committed lean: partial (journal-window-dependent). L3 idle.
        if layer == "l1":
            return "partial"
        if layer == "l2":
            return "partial"
        return "match"
    if fs == "apfs":
        # out-of-place COW: at T1 (no reclaim) checkpoints/stale nodes retain the
        # dropped records -> name residue present (full); content idle (match).
        # L2 not measurable here.
        if layer == "l1":
            return "full"
        if layer == "l2":
            return "na"
        return "match"
    raise ValueError(fs)


MODELS = {"two_axis": two_axis, "axis_a": axis_a, "carrier": carrier}


def all_predictions():
    preds = {}
    for fs in FS_LIST:
        for fid in FILES:
            for layer in LAYERS:
                cell = f"{fs}|{fid}|{layer}"
                preds[cell] = {name: fn(fs, fid, layer) for name, fn in MODELS.items()}
    return preds


if __name__ == "__main__":
    import json
    print(json.dumps(all_predictions(), indent=2))
