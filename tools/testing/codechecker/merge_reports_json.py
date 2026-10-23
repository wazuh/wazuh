#!/usr/bin/env python3
"""
Merge CodeChecker reports.json files.

Usage: merge_reports_json.py <source.json> <dest.json>

Appends the reports list from <source.json> into <dest.json>, deduplicating
by report_hash so re-running the diff never creates duplicates.  Both files
must follow the CodeChecker {"version": 1, "reports": [...]} schema.

If <dest.json> does not exist yet, the source is copied verbatim.
"""
import json
import os
import sys


def load(path):
    if not os.path.isfile(path):
        return {"version": 1, "reports": []}
    with open(path) as fh:
        return json.load(fh)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <source.json> <dest.json>", file=sys.stderr)
        sys.exit(1)

    src_path, dst_path = sys.argv[1], sys.argv[2]
    src = load(src_path)
    dst = load(dst_path)

    seen = {r.get("report_hash") for r in dst["reports"] if r.get("report_hash")}
    added = 0
    for r in src.get("reports", []):
        h = r.get("report_hash")
        if h and h in seen:
            continue
        dst["reports"].append(r)
        if h:
            seen.add(h)
        added += 1

    os.makedirs(os.path.dirname(os.path.abspath(dst_path)), exist_ok=True)
    with open(dst_path, "w") as fh:
        json.dump(dst, fh)

    print(f"merge_reports_json: added {added} report(s) from {src_path} -> {dst_path}")


if __name__ == "__main__":
    main()
