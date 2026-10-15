#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Decide which tracked files carry an SPDX license line, and which one.

Scope:
  src/engine/**                                   -> AGPL-3.0-or-later
  src/shared_modules/{utils,manager_config,
      keystore,indexer_connector,common}/**       -> GPL-2.0-only OR AGPL-3.0-or-later
  everything else                                 -> out of scope

Usage:
  spdx_scope.py [--repo DIR] classify <path>...
  spdx_scope.py [--repo DIR] list   [--scope agpl|dual]
  spdx_scope.py [--repo DIR] apply  [--scope agpl|dual]
  spdx_scope.py [--repo DIR] census [--scope agpl|dual]
  spdx_scope.py [--repo DIR] check  -     (NUL-separated repo-relative paths on stdin)
"""

import argparse
import io
import os
import posixpath
import re
import subprocess
import sys
from typing import Dict, Iterator, List, Optional, Tuple

AGPL = "AGPL-3.0-or-later"
DUAL = "GPL-2.0-only OR AGPL-3.0-or-later"

ENGINE_PREFIX = "src/engine/"
DUAL_DIRS = ("utils", "manager_config", "keystore", "indexer_connector", "common")
DUAL_PREFIXES = tuple("src/shared_modules/%s/" % d for d in DUAL_DIRS)

SLASH_EXT = {".cpp", ".cc", ".c", ".hpp", ".h", ".proto", ".go", ".fbs"}
HASH_EXT = {".py", ".sh", ".cmake", ".pl"}
HASH_NAMES = {"CMakeLists.txt", "Dockerfile"}
HASH_PATHS = {
    ENGINE_PREFIX + "internal_packages/debs/SPECS/" + n
    for n in ("postinst", "preinst", "prerm", "postrm", "rules")
}

GENERATED_SUFFIXES = (
    ".pb.h", ".pb.cc", ".pb.go", "_pb2.py", "_pb2.pyi", "_pb2_grpc.py", "_generated.h",
)
FIXTURE_DIRS = {"data", "fixtures", "test_data", "testdata"}
FIXTURE_ROOT = ENGINE_PREFIX + "test/"
THIRD_PARTY = {
    ENGINE_PREFIX + "tools/engine-bench/src/engine_bench/scripts/flamegraph.pl",
    ENGINE_PREFIX + "tools/engine-bench/src/engine_bench/scripts/stackcollapse-perf.pl",
    "src/shared_modules/utils/makeUnique.h",
}
UNLISTED_EXT = {
    ".js", ".ts", ".rb", ".lua", ".bash", ".zsh", ".ps1", ".bat", ".rs", ".java", ".kt",
    ".c++", ".cxx", ".hh", ".hxx", ".inc", ".ipp", ".tcc", ".m4",
}

SCAN_LINES = 30
# Only a comment line counts (`//`, `#`, `/*` or ` *`): the token inside a string literal is not an identifier.
_ID_RE = re.compile(r"^\s*(?://|#|/?\*)\s*SPDX-License-Identifier:\s*(.+?)\s*(\*/)?\s*$")
_CODING_RE = re.compile(r"^[ \t\f]*#.*?coding[:=]")


class SpdxError(Exception):
    """A file already carries a different SPDX identifier."""


def _expected_identifier(path: str) -> Optional[str]:
    if path.startswith(ENGINE_PREFIX):
        return AGPL
    if path.startswith(DUAL_PREFIXES):
        return DUAL
    return None


def _comment_style(path: str) -> Optional[str]:
    base = posixpath.basename(path)
    if path in HASH_PATHS or base in HASH_NAMES:
        return "#"
    ext = posixpath.splitext(base)[1]
    if ext in SLASH_EXT:
        return "//"
    if ext in HASH_EXT:
        return "#"
    return None


def classify(path: str, content: Optional[bytes]) -> Optional[Tuple[str, str]]:
    """Return (identifier, comment) for a file in scope, None otherwise.

    content=None classifies by path only (a file that does not exist on disk)."""
    ident = _expected_identifier(path)
    if ident is None:
        return None
    comment = _comment_style(path)
    if comment is None:
        return None
    if content is not None and not content.strip():
        return None
    base = posixpath.basename(path)
    if base.endswith(GENERATED_SUFFIXES):
        return None
    if path in THIRD_PARTY:
        return None
    if path.startswith(FIXTURE_ROOT):
        dirs = path[len(FIXTURE_ROOT):].split("/")[:-1]
        if any(d in FIXTURE_DIRS for d in dirs):
            return None
    return ident, comment


def find_identifier(content: bytes, limit: Optional[int] = SCAN_LINES) -> Optional[str]:
    """Identifier of the first SPDX comment line within the first `limit` lines (all lines if None), if any."""
    lines = content.split(b"\n") if limit is None else content.split(b"\n", limit)[:limit]
    for raw in lines:
        line = raw.rstrip(b"\r").decode("utf-8", "replace")
        m = _ID_RE.search(line)
        if m:
            return m.group(1)
    return None


def apply_to_bytes(path: str, content: bytes) -> bytes:
    """Insert the SPDX line; unchanged if present, SpdxError if it differs."""
    cls = classify(path, content)
    if cls is None:
        return content
    ident, comment = cls
    found = find_identifier(content)
    if found is not None:
        if found == ident:
            return content
        raise SpdxError("%s: found SPDX identifier %r, expected %r" % (path, found, ident))
    late = find_identifier(content, None)
    if late is not None:
        # An identifier below the scanned lines: never add a second one.
        raise SpdxError("%s: SPDX identifier %r after line %d, expected it within the first lines" % (path, late, SCAN_LINES))

    lines = content.splitlines(True)
    idx = 0
    if lines and lines[0].startswith(b"#!"):
        idx = 1
    if path.endswith(".py"):
        # PEP 263: the encoding declaration must stay on line 1 or 2.
        for n in (0, 1):
            if n < len(lines) and _CODING_RE.match(lines[n].decode("latin-1")):
                idx = max(idx, n + 1)

    new = ("%s SPDX-License-Identifier: %s\n" % (comment, ident)).encode("utf-8")
    if path.endswith(".go"):
        new += b"\n"
    head = b"".join(lines[:idx])
    if head and not head.endswith(b"\n"):
        head += b"\n"  # preceding line lacked a terminator (file is only that line)
    return head + new + b"".join(lines[idx:])


# --------------------------------------------------------------------------- repo


def _toplevel() -> str:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True,
                         stdout=subprocess.PIPE).stdout
    return out.decode().strip()


def _tracked(repo: str) -> List[str]:
    out = subprocess.run(["git", "-C", repo, "ls-files", "-z"], check=True,
                         stdout=subprocess.PIPE).stdout
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def _regular_files(repo: str) -> Iterator[Tuple[str, str]]:
    for rel in _tracked(repo):
        full = os.path.join(repo, rel)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        yield rel, full


def _read(full: str) -> bytes:
    with open(full, "rb") as fh:
        return fh.read()


def _scope_ok(path: str, scope: Optional[str]) -> bool:
    if scope is None:
        return True
    return _expected_identifier(path) == (AGPL if scope == "agpl" else DUAL)


def _in_scope(repo: str, scope: Optional[str]) -> Iterator[Tuple[str, str, bytes, str, str]]:
    for rel, full in _regular_files(repo):
        if not _scope_ok(rel, scope):
            continue
        content = _read(full)
        cls = classify(rel, content)
        if cls is not None:
            yield rel, full, content, cls[0], cls[1]


# --------------------------------------------------------------------------- modes


def cmd_classify(repo: str, args: argparse.Namespace) -> int:
    for path in args.paths:
        # Normalise "./x", absolute and "a/../b" spellings to the repo-relative form the scope rules use.
        if os.path.isabs(path):
            path = os.path.relpath(path, repo)
        path = posixpath.normpath(path.replace(os.sep, "/"))
        full = os.path.join(repo, path)
        try:
            content = _read(full)
        except OSError:
            content = None
        cls = classify(path, content)
        print("%s\tnone" % path if cls is None else "%s\t%s\t%s" % (path, cls[0], cls[1]))
    return 0


def cmd_list(repo: str, args: argparse.Namespace) -> int:
    for rel, _full, _c, _i, _s in _in_scope(repo, args.scope):
        print(rel)
    return 0


def cmd_apply(repo: str, args: argparse.Namespace) -> int:
    applied = unchanged = 0
    errors = 0
    for rel, full, content, _i, _s in _in_scope(repo, args.scope):
        try:
            new = apply_to_bytes(rel, content)
        except SpdxError as exc:
            print(str(exc), file=sys.stderr)
            errors += 1
            continue
        if new == content:
            unchanged += 1
        else:
            with open(full, "wb") as fh:  # truncating an existing file keeps its mode
                fh.write(new)
            applied += 1
    print("applied %d, unchanged %d" % (applied, unchanged))
    return 1 if errors else 0


def _is_unlisted_code(path: str, content: bytes) -> bool:
    base = posixpath.basename(path)
    ext = posixpath.splitext(base)[1]
    if ext:
        return ext in UNLISTED_EXT
    return content.startswith(b"#!")


def cmd_census(repo: str, args: argparse.Namespace) -> int:
    missing: List[str] = []
    wrong: List[str] = []
    excluded: List[str] = []
    unlisted: List[str] = []
    for rel, full in _regular_files(repo):
        exp = _expected_identifier(rel)
        if exp is None:
            continue
        content = _read(full)
        cls = classify(rel, content)
        found = find_identifier(content)
        if cls is not None:
            if not _scope_ok(rel, args.scope):
                continue
            if found is None:
                missing.append(rel)
            elif found != cls[0]:
                wrong.append("%s\tfound %s, expected %s" % (rel, found, cls[0]))
        else:
            # Only files excluded by a rule (generated, third party, fixture, empty) count;
            # prose such as COPYING quotes the identifier legitimately.
            if (_scope_ok(rel, args.scope) and found in (AGPL, DUAL)
                    and _comment_style(rel) is not None):
                excluded.append("%s\t%s" % (rel, found))
            if exp == AGPL and _scope_ok(rel, args.scope) and _is_unlisted_code(rel, content):
                unlisted.append(rel)
    for title, items in (("missing:", missing), ("wrong:", wrong),
                         ("excluded-with-identifier:", excluded), ("unlisted-code:", unlisted)):
        print(title)
        for item in items:
            print(item)
    print("summary: missing=%d wrong=%d excluded-with-identifier=%d unlisted-code=%d"
          % (len(missing), len(wrong), len(excluded), len(unlisted)))
    return 1 if (missing or wrong or excluded) else 0


CHECK_HINT = ("add the line with `python3 .github/scripts/spdx_scope.py apply`, or list third-party "
              "files in `THIRD_PARTY` of `.github/scripts/spdx_scope.py`")


def cmd_check(repo: str, args: argparse.Namespace) -> int:
    """Verify the SPDX line of the given paths; out-of-scope, deleted, non-regular and symlinks are ignored."""
    out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="surrogateescape",
                           newline="\n", write_through=True)
    raw = sys.stdin.buffer.read()
    checked = failed = 0
    for item in raw.split(b"\0"):
        if not item:
            continue
        path = posixpath.normpath(item.decode("utf-8", "surrogateescape").replace(os.sep, "/"))
        full = os.path.join(repo, path)
        # A symlink, a gitlink (a directory) or a deleted path has no regular file to read.
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        try:
            content = _read(full)
        except OSError:
            continue
        cls = classify(path, content)
        if cls is None:
            continue
        checked += 1
        found = find_identifier(content)
        if found is None:
            print("%s: missing %s" % (path, cls[0]), file=out)
            failed += 1
        elif found != cls[0]:
            print("%s: wrong %s (expected %s)" % (path, found, cls[0]), file=out)
            failed += 1
    print("checked %d, failed %d" % (checked, failed), file=out)
    if failed:
        print(CHECK_HINT, file=out)
    out.detach()
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo", default=None, help="repository root (default: git toplevel)")
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("classify")
    p.add_argument("paths", nargs="+")
    for name in ("list", "apply", "census"):
        p = sub.add_parser(name)
        p.add_argument("--scope", choices=("agpl", "dual"), default=None)
    p = sub.add_parser("check")
    p.add_argument("source", choices=("-",), help="'-': read NUL-separated paths from stdin")
    args = parser.parse_args(argv)
    repo = args.repo or _toplevel()
    handlers = {"classify": cmd_classify, "list": cmd_list, "apply": cmd_apply,
                "census": cmd_census, "check": cmd_check}
    return handlers[args.mode](repo, args)


if __name__ == "__main__":
    sys.exit(main())
