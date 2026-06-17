#!/usr/bin/env python3
"""
Convert flawfinder --csv output to CodeChecker plist format.

Usage:
    flawfinder --minlevel=1 --csv --columns <src_dir> | \
        python3 flawfinder_to_plist.py - <output_dir>
    python3 flawfinder_to_plist.py fw.csv <output_dir>

CodeChecker store only accepts Apple plist files produced by CodeChecker analyze.
This script generates compatible plist files so flawfinder findings appear in the
CodeChecker dashboard alongside clangsa/cppcheck results.
"""
import csv
import hashlib
import os
import plistlib
import sys


SEV_MAP = {"5": "error", "4": "error", "3": "warning", "2": "warning", "1": "note"}


def convert(csv_path: str, out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)

    src = sys.stdin if csv_path == "-" else open(csv_path, newline="")
    by_file: dict[str, list] = {}

    try:
        reader = csv.reader(src)
        header = next(reader)
        # CSV columns (flawfinder 2.x):
        # File,Line,Column,DefaultLevel,Level,Category,Name,Warning,...
        idx = {name: i for i, name in enumerate(header)}
        fi = idx["File"]
        li = idx["Line"]
        ci = idx["Column"]
        lvi = idx["Level"]
        cati = idx["Category"]
        nmi = idx["Name"]
        wni = idx["Warning"]

        for row in reader:
            if len(row) <= wni:
                continue
            fp = row[fi].strip()
            by_file.setdefault(fp, []).append(row)
    finally:
        if csv_path != "-":
            src.close()

    total = 0
    for fp, rows in by_file.items():
        diagnostics = []
        for row in rows:
            try:
                ln = int(row[li])
                col = int(row[ci])
            except ValueError:
                continue
            cat = row[cati].strip()
            name = row[nmi].strip()
            warn = row[wni].strip()
            level = row[lvi].strip()
            desc = f"({cat}) {name}: {warn}"
            h = hashlib.md5(
                f"{fp}:{ln}:{col}:{name}".encode()
            ).hexdigest()
            loc = {"file": 0, "line": ln, "col": col}
            diagnostics.append({
                "check_name": f"flawfinder.{cat}.{name}",
                "description": desc,
                "category": cat,
                "type": SEV_MAP.get(level, "warning"),
                "issue_hash_content_of_line_in_context": h,
                "location": loc,
                "path": [{"kind": "event", "message": desc, "location": loc}],
            })
        if not diagnostics:
            continue
        slug = hashlib.md5(fp.encode()).hexdigest()[:12]
        out_path = os.path.join(out_dir, f"fw_{slug}.plist")
        with open(out_path, "wb") as f:
            plistlib.dump(
                {"clang_version": "flawfinder", "files": [fp], "diagnostics": diagnostics},
                f,
            )
        total += len(diagnostics)

    print(
        f"flawfinder_to_plist: {total} findings across {len(by_file)} file(s) -> {out_dir}",
        flush=True,
    )
    return total


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <fw.csv|-> <output_dir>", file=sys.stderr)
        sys.exit(1)
    n = convert(sys.argv[1], sys.argv[2])
    sys.exit(0 if n > 0 else 1)
