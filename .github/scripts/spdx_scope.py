#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Decide which tracked files carry an SPDX license line, and which one.

Scope:
  src/engine/**                                   -> AGPL-3.0-or-later
  src/shared_modules/{utils,manager_config,
      keystore,indexer_connector,common}/**       -> GPL-2.0-only OR AGPL-3.0-or-later
  everything else                                 -> out of scope

In scope, code whose comment style is known (`//` or `#`, by extension, name or shebang) is checked
for its identifier. Code the script cannot write a comment for (.lua, .bat, .m4, .inc, or a shebang
other than sh/bash/dash/ksh/zsh/python/perl/ruby/make/awk) is `unsupported`: `check` and `apply`
fail on it and name it; add its comment style here or exclude the file. Excluded files stay ignored.

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

SLASH_EXT = {
    ".cpp", ".cc", ".c", ".hpp", ".h", ".proto", ".go", ".fbs",
    ".js", ".ts", ".rs", ".java", ".kt", ".c++", ".cxx", ".hh", ".hxx", ".ipp", ".tcc",
}
HASH_EXT = {".py", ".sh", ".cmake", ".pl", ".rb", ".bash", ".zsh", ".ps1"}
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
# Code extensions whose comment syntax the script cannot write.
UNLISTED_EXT = {".lua", ".bat", ".m4", ".inc"}
# Shebang interpreters whose comments are `#`.
HASH_INTERPRETERS = {"sh", "bash", "dash", "ksh", "zsh", "python", "perl", "ruby", "make", "awk"}


class _Unsupported:
    """Sentinel returned by classify() for in-scope code with no known comment style."""

    def __repr__(self) -> str:
        return "UNSUPPORTED"


UNSUPPORTED = _Unsupported()

SCAN_LINES = 30
# Only a comment line counts (`//`, `#`, `/*` or ` *`): the token inside a string literal is not an identifier.
_ID_RE = re.compile(r"^\s*(?://|#|/?\*)\s*SPDX-License-Identifier:\s*(.+?)\s*(\*/)?\s*$")
# Encoding declaration on line 1 or 2. Deliberately wider than PEP 263 to cover Ruby too (any case, blanks before the
# separator): a comment taken for a declaration only moves the SPDX line one line down.
_CODING_RE = re.compile(r"^[ \t\f]*#.*?coding[ \t]*[:=]", re.IGNORECASE)
_VERSION_SUFFIX_RE = re.compile(r"[0-9.]+$")
_UTF8_BOM = b"\xef\xbb\xbf"
# UTF-32 BOMs first: the UTF-32-LE BOM starts with the UTF-16-LE one.
_WIDE_CODECS = ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe", "utf-16-le"),
                (b"\xfe\xff", "utf-16-be"))
_WIDE_BOMS = tuple(bom for bom, _codec in _WIDE_CODECS)


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


def _interpreter(content: Optional[bytes]) -> Optional[str]:
    """Interpreter named by the shebang of `content` (versions stripped), None without a shebang."""
    if not content or not content.startswith(b"#!"):
        return None
    # split() without a separator also drops the "\r" of a CRLF first line.
    first = content.split(b"\n", 1)[0][2:].decode("latin-1").split()
    if not first:
        return ""
    name = posixpath.basename(first[0])
    if name == "env":
        name = _env_command(first[1:])
    return _VERSION_SUFFIX_RE.sub("", name)


def _env_command(args: List[str]) -> str:
    """Command run by `env <args>` in a shebang, for the simple forms only: `env <command> …` and `env -S <command> …`.
    Anything else (assignments, other options, quoting) gives "env", so the file is not taken for a script of a known
    interpreter: its comment syntax cannot be told reliably."""
    if args and args[0] == "-S":
        args = args[1:]
    if not args or args[0].startswith("-") or "=" in args[0] or any(q in args[0] for q in "\"'\\"):
        return "env"
    return posixpath.basename(args[0])


def _unsupported_label(path: str, content: Optional[bytes]) -> str:
    ext = posixpath.splitext(posixpath.basename(path))[1]
    if ext in UNLISTED_EXT:
        return ext
    return "#!%s" % _interpreter(content)


def unsupported_message(path: str, content: Optional[bytes]) -> str:
    return "%s: unsupported code type (%s)" % (path, _unsupported_label(path, content))


def classify(path: str, content: Optional[bytes]):
    """Return (identifier, comment) for a file in scope, None otherwise, UNSUPPORTED for in-scope code
    whose comment style is unknown (not for excluded files).

    content=None classifies by path only (a file that does not exist on disk)."""
    ident = _expected_identifier(path)
    if ident is None:
        return None
    unsupported = False
    comment = _comment_style(path)
    if comment is None:
        ext = posixpath.splitext(posixpath.basename(path))[1]
        if ext in UNLISTED_EXT:
            unsupported = True
        elif not ext and (interp := _interpreter(content)) is not None:
            if interp in HASH_INTERPRETERS:
                comment = "#"
            else:
                unsupported = True
        else:
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
    return UNSUPPORTED if unsupported else (ident, comment)


def _decode(content: bytes) -> str:
    """Text of a file: UTF-16/UTF-32 when it starts with their BOM, UTF-8 otherwise (a UTF-8 BOM is dropped)."""
    for bom, codec in _WIDE_CODECS:
        if content.startswith(bom):
            return content[len(bom):].decode(codec, "replace")
    if content.startswith(_UTF8_BOM):
        content = content[len(_UTF8_BOM):]
    return content.decode("utf-8", "replace")


def find_identifier(content: bytes, limit: Optional[int] = SCAN_LINES) -> Optional[str]:
    """Identifier of the first SPDX comment line within the first `limit` lines (all lines if None), if any."""
    text = _decode(content)
    lines = text.split("\n") if limit is None else text.split("\n", limit)[:limit]
    for raw in lines:
        line = raw.rstrip("\r")
        m = _ID_RE.search(line)
        if m:
            return m.group(1)
    return None


def apply_to_bytes(path: str, content: bytes) -> bytes:
    """Insert the SPDX line; unchanged if present, SpdxError if it differs."""
    cls = classify(path, content)
    if cls is None:
        return content
    if cls is UNSUPPORTED:
        raise SpdxError("%s: %s" % (unsupported_message(path, content), UNSUPPORTED_HINT))
    ident, comment = cls
    found = find_identifier(content)
    if found is not None:
        if found == ident:
            return content
        raise SpdxError("%s: found SPDX identifier %r, expected %r" % (path, found, ident))
    if content.startswith(_WIDE_BOMS):
        # The line would be written in UTF-8 in front of a UTF-16/UTF-32 text: refuse instead of corrupting the file.
        # (an identifier already written there by hand is accepted above: find_identifier decodes these encodings)
        raise SpdxError("%s: UTF-16/UTF-32 file: add the SPDX line by hand in the file's own encoding" % path)
    late = find_identifier(content, None)
    if late is not None:
        # An identifier below the scanned lines: never add a second one.
        raise SpdxError("%s: SPDX identifier %r after line %d, expected it within the first lines" % (path, late, SCAN_LINES))

    bom = _UTF8_BOM if content.startswith(_UTF8_BOM) else b""
    lines = content[len(bom):].splitlines(True)
    idx = 0
    if lines and lines[0].startswith(b"#!") and not lines[0].startswith(b"#!["):
        idx = 1  # a shebang stays first; `#![` is a Rust inner attribute, not a shebang
    ext = posixpath.splitext(posixpath.basename(path))[1]
    keeps_coding = ext in (".py", ".rb") or (not ext and _interpreter(content) in ("python", "ruby"))
    if keeps_coding:
        # Python (PEP 263) and Ruby read an encoding declaration only on line 1, or line 2 after a shebang: keep it there,
        # also for extension-less scripts.
        for n in (0, 1):
            if n < len(lines) and _CODING_RE.match(lines[n].decode("latin-1")):
                idx = max(idx, n + 1)

    new = ("%s SPDX-License-Identifier: %s\n" % (comment, ident)).encode("utf-8")
    if path.endswith(".go"):
        new += b"\n"
    head = b"".join(lines[:idx])
    if head and not head.endswith(b"\n"):
        head += b"\n"  # preceding line lacked a terminator (file is only that line)
    return bom + head + new + b"".join(lines[idx:])  # a UTF-8 BOM stays the first bytes of the file


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


def _in_scope(repo: str, scope: Optional[str]) -> Iterator[Tuple[str, str, bytes, object, Optional[str]]]:
    """(path, full path, content, identifier, comment); identifier is UNSUPPORTED (comment None) for unsupported code."""
    for rel, full in _regular_files(repo):
        if not _scope_ok(rel, scope):
            continue
        content = _read(full)
        cls = classify(rel, content)
        if cls is UNSUPPORTED:
            yield rel, full, content, UNSUPPORTED, None
        elif cls is not None:
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
        if cls is None:
            print("%s\tnone" % path)
        elif cls is UNSUPPORTED:
            print("%s\tunsupported" % path)
        else:
            print("%s\t%s\t%s" % (path, cls[0], cls[1]))
    return 0


def cmd_list(repo: str, args: argparse.Namespace) -> int:
    for rel, _full, _c, ident, _s in _in_scope(repo, args.scope):
        if ident is not UNSUPPORTED:
            print(rel)
    return 0


def cmd_apply(repo: str, args: argparse.Namespace) -> int:
    applied = unchanged = unsupported = 0
    errors = 0
    for rel, full, content, ident, _s in _in_scope(repo, args.scope):
        if ident is UNSUPPORTED:
            print("%s: %s" % (unsupported_message(rel, content), UNSUPPORTED_HINT), file=sys.stderr)
            unsupported += 1
            continue
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
    print("applied %d, unchanged %d, unsupported %d" % (applied, unchanged, unsupported))
    return 1 if (errors or unsupported) else 0


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
        if cls is UNSUPPORTED:
            if _scope_ok(rel, args.scope):
                unlisted.append(rel)
        elif cls is not None:
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
    for title, items in (("missing:", missing), ("wrong:", wrong),
                         ("excluded-with-identifier:", excluded), ("unlisted-code:", unlisted)):
        print(title)
        for item in items:
            print(item)
    print("summary: missing=%d wrong=%d excluded-with-identifier=%d unlisted-code=%d"
          % (len(missing), len(wrong), len(excluded), len(unlisted)))
    return 1 if (missing or wrong or excluded) else 0


UNSUPPORTED_HINT = ("add its comment style to .github/scripts/spdx_scope.py or exclude the file")
CHECK_HINT = ("add the line with `python3 .github/scripts/spdx_scope.py apply`, or list third-party "
              "files in `THIRD_PARTY` of `.github/scripts/spdx_scope.py`; for an `unsupported code "
              "type`, add its comment style to the script or exclude the file (`apply` cannot fix it)")


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
        if cls is UNSUPPORTED:
            print("%s: %s" % (unsupported_message(path, content), UNSUPPORTED_HINT), file=out)
            failed += 1
            continue
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
