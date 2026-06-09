#!/usr/bin/env python3
"""Build a GitHub Actions matrix of integration test modules whose declared
paths match the files changed in a pull request.

Glob patterns honour gitignore-style semantics:
  - ``**``  matches any number of path segments (including zero).
  - ``*``   matches any characters except ``/``.
  - ``?``   matches a single character except ``/``.
  - ``[abc]`` / ``[!abc]`` character classes.

This is portable across Python versions, unlike ``pathlib.PurePath.match``,
which only learnt to honour ``**`` recursively in Python 3.13.

Inputs are taken from environment variables:
  - MODULES_CONFIG: path to the JSON file describing the modules.
  - BASE_SHA / HEAD_SHA: commits to diff. If either is empty, the script
    emits ``none_matrix`` and exits without consulting git.
  - NONE_MATRIX: JSON value to emit when no module matches. The shape must
    be compatible with the consumer workflow's matrix (same keys as the
    matched entries).
  - FIELD_DEFAULTS: optional JSON object with default values applied to
    each matched entry for fields the module did not declare. Used to
    keep every matrix entry uniform.
  - GITHUB_OUTPUT: file to append outputs to.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Iterable


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    i, n = 0, len(pattern)
    out: list[str] = ["^"]
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                j = i + 2
                if j < n and pattern[j] == "/":
                    # `prefix/**/suffix` also matches `prefix/suffix`.
                    out.append("(?:.*/)?")
                    i = j + 1
                else:
                    out.append(".*")
                    i = j
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] == "!":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape(c))
                i += 1
            else:
                cls = pattern[i + 1 : j]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append(f"[{cls}]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def _matches(pattern: str, files: Iterable[str]) -> bool:
    rx = _glob_to_regex(pattern)
    return any(rx.match(fp) for fp in files)


def _emit(output_path: str, matrix: dict, any_matched: bool) -> None:
    with open(output_path, "a", encoding="utf-8") as fp:
        fp.write(f"matrix={json.dumps(matrix, separators=(',', ':'))}\n")
        fp.write(f"any_matched={'true' if any_matched else 'false'}\n")


def main() -> int:
    base_sha = os.environ.get("BASE_SHA", "").strip()
    head_sha = os.environ.get("HEAD_SHA", "").strip()
    modules_config = os.environ["MODULES_CONFIG"]
    none_matrix = json.loads(os.environ["NONE_MATRIX"])
    field_defaults = json.loads(os.environ.get("FIELD_DEFAULTS", "{}"))
    github_output = os.environ["GITHUB_OUTPUT"]

    if not base_sha or not head_sha:
        print("BASE_SHA or HEAD_SHA not provided; emitting none-matrix.", file=sys.stderr)
        _emit(github_output, none_matrix, False)
        return 0

    diff = subprocess.run(
        ["git", "diff", "--name-only", base_sha, head_sha],
        capture_output=True,
        text=True,
        check=True,
    )
    changed = [line for line in diff.stdout.splitlines() if line]
    print(f"Changed files ({len(changed)}):", file=sys.stderr)
    for fp in changed:
        print(f"  {fp}", file=sys.stderr)

    with open(modules_config, encoding="utf-8") as fp:
        config = json.load(fp)

    matched: list[dict] = []
    for module in config["modules"]:
        name = module["name"]
        matched_pattern: str | None = None
        for pattern in module.get("paths", []):
            if _matches(pattern, changed):
                matched_pattern = pattern
                break
        if matched_pattern is None:
            continue
        print(f"Module '{name}' matched via pattern '{matched_pattern}'", file=sys.stderr)

        base_entry = {k: v for k, v in module.items() if k not in ("paths", "tiers")}
        for k, v in field_defaults.items():
            base_entry.setdefault(k, v)

        for tier in module.get("tiers", ["0 1"]):
            entry = dict(base_entry)
            entry["shard_name"] = f"tier-{tier.replace(' ', '-')}"
            entry["pytest_tier_args"] = " ".join(f"--tier {t}" for t in tier.split())
            matched.append(entry)

    if matched:
        _emit(github_output, {"include": matched}, True)
    else:
        print("No module matched the changed files; emitting none-matrix.", file=sys.stderr)
        _emit(github_output, none_matrix, False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
