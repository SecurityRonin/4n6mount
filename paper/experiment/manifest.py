#!/usr/bin/env python3
"""Fixed deletion-corpus manifest + deterministic content generator.

Shared by the populate step (`emit`) and the measurement step. Each file's
content is a concatenation of 512-byte *chunks*, and every chunk carries a
unique, greppable marker `<nonce>#NNNNN#`. Per-chunk markers make L3 content
survival measurable by raw byte-scan even when the filesystem fragments the
file (each surviving chunk is found independently of block order), and they are
filesystem-agnostic, so APFS (which The Sleuth Kit cannot parse) is measured on
the same L1/L3 footing as the TSK-supported formats.

The file classes span the residue-relevant axes of the SoK §7 protocol:
resident/inline vs. non-resident, single-extent vs. deliberately fragmented,
short (8.3) vs. long (LFN) vs. Unicode names, and shallow vs. deep paths.
"""
import hashlib
import json
import os
import sys

CHUNK = 512  # bytes per marked chunk == typical FAT/exFAT sector granularity

# id -> (relative path, byte size, file-class label)
# Deterministic nonces (fixed, not random) so the corpus is reproducible.
FILES = [
    ("short83",  "AB.TXT",                              CHUNK,        "tiny-short-8.3"),
    ("lfn",      "evidence_report_final_copy.txt",      CHUNK,        "tiny-longname-LFN"),
    ("unicode",  "秘密資料.txt",        CHUNK,        "tiny-unicode-name"),
    ("deep",     "d1/d2/d3/d4/nested_secret.txt",       CHUNK,        "tiny-deep-path"),
    ("contig",   "big_contiguous_blob.bin",             256 * CHUNK,  "large-contiguous"),
    ("frag",     "fragmented_blob.bin",                 256 * CHUNK,  "large-fragmented"),
]

NONCES = {
    "short83": "N0short83aaaaaaa",
    "lfn":     "N1lfnbbbbbbbbbbb",
    "unicode": "N2unicodeccccccc",
    "deep":    "N3deepdddddddddd",
    "contig":  "N4contigeeeeeeee",
    "frag":    "N5fragffffffffff",
}


def gen_content(nonce: str, size: int) -> bytes:
    """Deterministic content: 512B chunks each prefixed `<nonce>#NNNNN#`,
    the remainder filled from sha256(nonce||idx) so bytes are high-entropy and
    unique per file, and the whole is reproducible from the nonce alone."""
    out = bytearray()
    idx = 0
    while len(out) < size:
        marker = f"{nonce}#{idx:05d}#".encode()
        block = bytearray(marker)
        seed = f"{nonce}:{idx}".encode()
        while len(block) < CHUNK:
            seed = hashlib.sha256(seed).digest()
            block.extend(seed)
        out.extend(block[:CHUNK])
        idx += 1
    return bytes(out[:size])


def chunk_markers(nonce: str, size: int):
    n = (size + CHUNK - 1) // CHUNK
    return [f"{nonce}#{i:05d}#".encode() for i in range(n)]


def build_manifest(fs: str):
    m = {"fs": fs, "chunk": CHUNK, "files": {}}
    for fid, relpath, size, cls in FILES:
        nonce = NONCES[fid]
        content = gen_content(nonce, size)
        m["files"][fid] = {
            "id": fid,
            "relpath": relpath,
            "name": relpath.rsplit("/", 1)[-1],
            "size": size,
            "class": cls,
            "nonce": nonce,
            "sha256": hashlib.sha256(content).hexdigest(),
            "n_chunks": len(chunk_markers(nonce, size)),
        }
    return m


def emit(fs: str, stagedir: str):
    """Write staged content files + manifest.json into stagedir."""
    os.makedirs(stagedir, exist_ok=True)
    m = build_manifest(fs)
    for fid, meta in m["files"].items():
        content = gen_content(meta["nonce"], meta["size"])
        with open(os.path.join(stagedir, fid + ".dat"), "wb") as f:
            f.write(content)
    with open(os.path.join(stagedir, "manifest.json"), "w") as f:
        json.dump(m, f, indent=2, ensure_ascii=False)
    print(f"emitted {len(m['files'])} files + manifest.json to {stagedir}")


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "emit":
        emit(sys.argv[2], sys.argv[3])
    else:
        print("usage: manifest.py emit <fs> <stagedir>", file=sys.stderr)
        sys.exit(2)
