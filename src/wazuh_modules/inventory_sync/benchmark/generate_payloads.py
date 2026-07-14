#!/usr/bin/env python3
"""
generate_payloads.py — Synthetic DataValue payload generator.

Builds JSON payloads whose serialized size is approximately the requested
number of bytes.  Used for `--payload-size` style scenarios (e.g. large_payload).

CLI:

    python3 generate_payloads.py --size 65536 --count 1 -o payload_64k.json
    python3 generate_payloads.py --size 4096  --count 100 -o payloads/

Library:

    from generate_payloads import build_payload
    payload = build_payload(target_bytes=65536, kind="package")
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import string
import sys
from pathlib import Path


def _random_string(n: int) -> str:
    """Cheap, deterministic-enough printable string of length n."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


KINDS = ("package", "system", "hotfix", "fim_file", "sca_check")


def _state_block() -> dict:
    return {"document_version": 1, "modified_at": "2024-01-15T10:30:00Z"}


def build_payload(target_bytes: int, kind: str = "package") -> dict:
    """
    Build a payload whose JSON encoding is approximately `target_bytes` long.

    Each kind matches the `dynamic: strict` mapping of its target index
    (templates in src/external/indexer-plugins/*.json). Only fields present
    in the real mapping are emitted — any extra field would trigger HTTP 400
    "mapping set to strict, dynamic introduction of [X]".

    Mapping per kind:
      - "package":   wazuh-states-inventory-packages   (package.*)
      - "system":    wazuh-states-inventory-system     (host.*)
      - "hotfix":    wazuh-states-inventory-hotfixes   (package.hotfix.*)
      - "fim_file":  wazuh-states-fim-files            (file.*)
      - "sca_check": wazuh-states-sca                  (check.*, policy.*)

    The padded string is always a field already present in the mapping
    (typically a description) so the result remains 400-safe even at very
    small sizes.
    """
    sha1 = _random_string(40).lower()
    base: dict = {
        "checksum": {"hash": {"sha1": sha1}},
        "state":    _state_block(),
    }

    if kind == "package":
        base["package"] = {
            "architecture": "amd64",
            "category":     "libs",
            "description":  "",
            "installed":    "2024-01-15T10:30:00Z",
            "multiarch":    "same",
            "name":         f"pkg-{_random_string(8)}",
            "path":         "/usr/bin/synthetic",
            "priority":     "optional",
            "size":         1024,
            "source":       "synthetic",
            "type":         "deb",
            "vendor":       "Synthetic",
            "version":      "1.0.0",
        }
        body_field = base["package"]
        body_key   = "description"
    elif kind == "system":
        base["host"] = {
            "architecture": "x86_64",
            "hostname":     f"host-{_random_string(8)}",
            "os": {
                "build":        "5.15.0-91-generic",
                "codename":     "jammy",
                "distribution": {"release": "22.04"},
                "full":         "",
                "kernel": {
                    "name":    "Linux",
                    "release": "5.15.0-91-generic",
                    "version": "#101-Ubuntu",
                },
                "major":    "22",
                "minor":    "04",
                "name":     "Ubuntu",
                "patch":    "3",
                "platform": "ubuntu",
                "type":     "linux",
                "version":  "22.04.3",
            },
        }
        body_field = base["host"]["os"]
        body_key   = "full"
    elif kind == "hotfix":
        base["package"] = {"hotfix": {"name": f"KB{_random_string(7)}"}}
        # No long string field exists in this mapping; pad via hotfix.name.
        body_field = base["package"]["hotfix"]
        body_key   = "name"
    elif kind == "fim_file":
        base["file"] = {
            "attributes":  "regular file",
            "device":      "8,1",
            "gid":         "0",
            "group":       "root",
            "hash": {
                "md5":    "d41d8cd98f00b204e9800998ecf8427e",
                "sha1":   sha1,
                "sha256": _random_string(64).lower(),
            },
            "inode":       "131072",
            "mtime":       "2024-01-15T10:30:00Z",
            "owner":       "root",
            "path":        f"/etc/synthetic-{_random_string(6)}",
            "permissions": "0640",
            "size":        1024,
            "uid":         "0",
        }
        body_field = base["file"]
        body_key   = "path"
    elif kind == "sca_check":
        base["policy"] = {
            "id":          "cis_ubuntu_22-04",
            "name":        "CIS Ubuntu 22.04 Benchmark",
            "file":        "cis_ubuntu22-04.yml",
            "description": "",
            "references":  "https://www.cisecurity.org/benchmark/ubuntu_linux",
        }
        base["check"] = {
            "id":          f"chk-{_random_string(5)}",
            "name":        "Ensure permissions on /etc/passwd are configured",
            "description": "",
            "rationale":   "",
            "remediation": "chmod 0644 /etc/passwd",
            "condition":   "all",
            "rules":       "f:/etc/passwd -> mode=0644;",
            "result":      "passed",
            "reason":      "All rules matched",
            "references":  "CIS",
        }
        body_field = base["check"]
        body_key   = "description"
    else:
        raise ValueError(f"unknown kind: {kind} (valid: {', '.join(KINDS)})")

    # Iteratively pad the chosen string field until the JSON serializes close
    # to target_bytes (within 8 bytes).
    encoded = json.dumps(base, separators=(",", ":"))
    if len(encoded) >= target_bytes:
        return base

    pad_needed = target_bytes - len(encoded)
    body_field[body_key] = _random_string(pad_needed)

    # Tail-trim if we overshot due to escaping
    while len(json.dumps(base, separators=(",", ":"))) > target_bytes and body_field[body_key]:
        body_field[body_key] = body_field[body_key][:-1]

    return base


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate synthetic DataValue payloads.")
    p.add_argument("--size",  type=int, required=True,
                   help="Target JSON size in bytes per payload")
    p.add_argument("--count", type=int, default=1,
                   help="How many payloads to emit (default: 1)")
    p.add_argument("--kind",  choices=list(KINDS), default="package",
                   help="Payload shape (default: package). Each kind matches "
                        "the dynamic:strict mapping of its destination index.")
    p.add_argument("-o", "--output", type=str, required=True,
                   help="Output file (if count==1) or directory (if count>1).")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.count <= 0:
        print("count must be >= 1", file=sys.stderr)
        return 2

    if args.count == 1:
        payload = build_payload(args.size, args.kind)
        Path(args.output).write_text(json.dumps(payload, indent=2))
        print(f"Wrote {args.output} (~{args.size}B)")
    else:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        for i in range(args.count):
            payload = build_payload(args.size, args.kind)
            (out_dir / f"payload_{args.kind}_{i:04d}.json").write_text(
                json.dumps(payload, indent=2)
            )
        print(f"Wrote {args.count} payloads into {out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
