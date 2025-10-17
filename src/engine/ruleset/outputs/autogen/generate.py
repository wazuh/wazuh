#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from pathlib import Path
from typing import List, Set
try:
    import yaml  # PyYAML
except ImportError:
    print("ERROR: This script requires PyYAML. Please install it with 'pip install pyyaml'.", file=sys.stderr)
    sys.exit(1)


TEMPLATE = """name: output/indexer-{name}/0

metadata:
  module: wazuh
  title: Indexer output event for {name}
  description: Output integrations events to wazuh-indexer
  compatibility: >
    This decoder has been tested on Wazuh version 5.0
  versions:
    - ""
  author:
    name: Wazuh, Inc.
    date: 2024/12/01
  references:
    - ""

check:
  - wazuh.decoders: array_contains_any({decoders})

outputs:
  - wazuh-indexer:
      index: wazuh-events-{name}
"""


def read_decoders_from_manifest(manifest_path: Path) -> List[str]:
    with manifest_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    decs = data.get("decoders", [])
    if decs is None:
        decs = []
    if not isinstance(decs, list):
        raise ValueError(f"'decoders' in {manifest_path} is not a list.")
    # Filter out empty strings and strip whitespace
    out = []
    for d in decs:
        if isinstance(d, str):
            s = d.strip()
            if s:
                # remove prefix "decoder/"
                if s.startswith("decoder/"):
                    s = s[len("decoder/") :]
                # Remove "/0" suffix if present
                if s.endswith("/0"):
                    s = s[: -len("/0")]
                out.append(s)
    return out


def collect_decoders(dirs: List[Path]) -> List[str]:
    all_decoders: Set[str] = set()
    missing = []
    for d in dirs:
        manifest = d / "manifest.yml"
        if not manifest.is_file():
            missing.append(str(manifest))
            continue
        try:
            for dec in read_decoders_from_manifest(manifest):
                all_decoders.add(dec)
        except Exception as e:
            print(f"Warning: Could not read decoders from {manifest}: {e}", file=sys.stderr)
    if missing:
        for m in missing:
            print(f"Warning: Manifest file not found: {m}", file=sys.stderr)
    return sorted(all_decoders)


def build_placeholder(decoders: List[str]) -> str:
    # "<$DECODER_PLACEHOLDER>" → lista de decoders entre comillas y separadas por coma.
    # Ej: "decoder/a/0","decoder/b/0"
    return ",".join(f"\"{d}\"" for d in decoders)


def main():
    parser = argparse.ArgumentParser(
        description="Generate an indexer output asset for Wazuh based on decoders from provided manifest.yml files."
    )
    parser.add_argument("-n", "--name", required=True, help="Name of the indexer output asset.")
    parser.add_argument("folders", nargs="+", help="List of integration folders containing manifest.yml files.")
    parser.add_argument("-o", "--outdir", default=".", help="Output directory for the generated indexer output file.")
    args = parser.parse_args()

    name = args.name.strip()
    if not name:
        print("ERROR: --name cannot be empty.", file=sys.stderr)
        sys.exit(2)

    dirs = [Path(p).resolve() for p in args.folders]
    decoders = collect_decoders(dirs)

    if not decoders:
        print("ERROR: No decoders found in the provided manifest files.", file=sys.stderr)
        sys.exit(3)

    dec_placeholder = build_placeholder(decoders)
    content = TEMPLATE.format(name=name, decoders=dec_placeholder)

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / f"indexer-{name}.yml"
    outfile.write_text(content, encoding="utf-8")

    print(f"Generated indexer output file at: {outfile}")


if __name__ == "__main__":
    main()
