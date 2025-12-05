#!/usr/bin/env python3
"""
stitch_artifacts.py

Usage:
    python stitch_artifacts.py /path/to/output_artifacts [--outdir output_artifacts/stitched] [--min-overlap 32] [--max-overlap 4096]

What it does:
 - Scans all files directly in the given artifacts directory.
 - Computes simple metadata (size, sample header, entropy).
 - Computes pairwise suffix-prefix exact overlaps (up to max_overlap bytes).
 - Greedily merges the pair with the largest overlap >= min_overlap, repeating until no pair meets threshold.
 - Writes merged files into outdir and a manifest CSV describing merges.

Note: This is a heuristic assembler. Always manually inspect stitched outputs.
"""
from __future__ import annotations
import argparse, os, math, csv
from pathlib import Path
from collections import Counter, namedtuple

FileMeta = namedtuple('FileMeta', ['path','size','header_hex','entropy'])

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    L = len(data)
    return -sum((v/L) * math.log2(v/L) for v in c.values())

def sample_header_hex(data: bytes, n=16) -> str:
    return data[:n].hex()

def read_files_from_dir(d: Path):
    files = []
    for p in sorted(d.iterdir()):
        if p.is_file():
            b = p.read_bytes()
            files.append((p, b))
    return files

def max_suffix_prefix_overlap(a: bytes, b: bytes, max_overlap:int):
    """
    Return the length of the largest suffix of a that is equal to a prefix of b (<= max_overlap).
    Implemented with a simple loop (fast enough for moderate sizes).
    """
    max_ol = 0
    # limit possible overlap by lengths
    limit = min(len(a), len(b), max_overlap)
    # search from large to small for early exit on large overlap (important)
    for l in range(limit, 0, -1):
        if a[-l:] == b[:l]:
            return l
    return 0

def greedy_assemble(files_bytes, min_overlap=32, max_overlap=4096):
    """
    files_bytes: list of (Path or id, bytes)
    returns list of assembled (name, bytes, sources)
    """
    # store as list of dicts for mutability
    fragments = [{'id': i, 'name': str(path), 'bytes': b, 'sources': [str(path)]} for i,(path,b) in enumerate(files_bytes)]
    next_id = len(fragments)
    while True:
        best = None  # (ol_len, i, j)
        n = len(fragments)
        if n < 2:
            break
        # compute pairwise overlaps
        for i in range(n):
            ai = fragments[i]['bytes']
            if len(ai) < min_overlap:
                continue
            for j in range(n):
                if i == j: 
                    continue
                bj = fragments[j]['bytes']
                if len(bj) < min_overlap:
                    continue
                ol = max_suffix_prefix_overlap(ai, bj, max_overlap)
                if ol >= min_overlap:
                    if best is None or ol > best[0]:
                        best = (ol, i, j)
        if not best:
            break
        ol, i, j = best
        A = fragments[i]
        B = fragments[j]
        merged_bytes = A['bytes'] + B['bytes'][ol:]
        merged_sources = A['sources'] + B['sources']
        merged_name = f"merged_{next_id}"
        print(f"Merging {A['name']} + {B['name']} with overlap {ol} -> {merged_name}")
        # remove i and j (ensure remove larger index first)
        for idx in sorted([i,j], reverse=True):
            fragments.pop(idx)
        fragments.append({'id': next_id, 'name': merged_name, 'bytes': merged_bytes, 'sources': merged_sources})
        next_id += 1
    return fragments

def main():
    ap = argparse.ArgumentParser(description="Attempt to stitch artifact fragments by suffix-prefix overlap.")
    ap.add_argument("artifacts_dir", help="Directory containing artifact files (single-level).")
    ap.add_argument("--outdir", "-o", help="Directory to save stitched outputs (default: output_artifacts/stitched)", default="output_artifacts/stitched")
    ap.add_argument("--min-overlap", type=int, default=32, help="Minimum overlap in bytes to consider a valid merge (default 32)")
    ap.add_argument("--max-overlap", type=int, default=4096, help="Max overlap to search for (default 4096)")
    args = ap.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    if not artifacts_dir.exists():
        print("Error: artifacts dir not found:", artifacts_dir); return
    files = read_files_from_dir(artifacts_dir)
    if not files:
        print("No files found in", artifacts_dir); return

    # metadata
    metas = []
    files_bytes = []
    for p,b in files:
        metas.append(FileMeta(path=str(p), size=len(b), header_hex=sample_header_hex(b,16), entropy=entropy(b)))
        files_bytes.append((p,b))

    # print quick summary
    print("Found files:", len(files_bytes))
    for m in metas:
        print(f"{m.path} size={m.size} entropy={m.entropy:.3f} header={m.header_hex}")

    # greedy assembly
    assembled = greedy_assemble(files_bytes, min_overlap=args.min_overlap, max_overlap=args.max_overlap)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for idx,frag in enumerate(assembled, start=1):
        outpath = outdir / f"stitched_{idx:03d}.bin"
        with outpath.open("wb") as f:
            f.write(frag['bytes'])
        manifest.append({'out_file': str(outpath), 'size': len(frag['bytes']), 'sources': ";".join(frag['sources'])})
        print("Wrote", outpath, "size", len(frag['bytes']), "sources", frag['sources'])

    # write manifest CSV
    import csv
    manifest_path = outdir / "stitch_manifest.csv"
    with manifest_path.open("w", newline='', encoding='utf-8') as mf:
        writer = csv.DictWriter(mf, fieldnames=['out_file','size','sources'])
        writer.writeheader()
        for r in manifest:
            writer.writerow(r)
    print("Finished. Manifest:", manifest_path)

if __name__ == "__main__":
    main()

