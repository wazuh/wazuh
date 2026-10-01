#!/usr/bin/env python3
"""Validate the external dependencies inventory and export it for the build scripts.

    deps.py check [--inventory PATH] [--src DIR] [--no-make]
    deps.py flatten [--inventory PATH]

`check` prints one `ERROR: <name>: <message>` line per problem to stderr and exits 1 if
there is any, 0 otherwise. `flatten` prints the inventory as bash associative arrays
(EXT_URL, EXT_SHA256, ...) for build_external.sh, whose builder images have no python3.
"""

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = REPO / "packages" / "externals" / "dependencies.json"
PATCHES_DIR = REPO / "packages" / "externals" / "patches"

TARGETS = {"agent", "manager"}
PLATFORMS = {"linux", "darwin", "windows", "aix", "solaris", "hpux", "el5", "freebsd", "netbsd", "openbsd"}
SOURCES = {"upstream", "snapshot"}
FORMATS = {"tar.gz", "tar.bz2", "tar.xz", "zip", "file"}
URL_PLACEHOLDERS = {"version", "version_us", "version_dash", "version_concat", "revision"}
REQUIRED = {
    "name": str, "version": str, "revision": str, "source": str, "url": str, "format": str, "strip": int,
    "patches": list, "targets": list, "platforms": list, "purl": str, "license": str, "author": str,
    "homepage": str,
}
OPTIONAL = {
    "upstream_sha256": str, "snapshot_sha256": str, "target_dir": str, "prebuilt": bool, "scan": bool,
    "reason": str, "notes": str,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# (target, platform) -> extra make arguments; windows needs the MinGW cross-compiler.
MAKE_COMBOS = {
    ("manager", "linux"): ["TARGET=manager"],
    ("agent", "linux"): ["TARGET=agent"],
    ("agent", "darwin"): ["TARGET=agent", "uname_S=Darwin"],
    ("agent", "windows"): ["TARGET=winagent"],
}
MINGW_CC = "i686-w64-mingw32-gcc"

# Entries built outside build_external.sh: the field that must match the version pinned by their build.
PINS = {
    "libbpf-bootstrap": ("revision", "packages/externals/ebpf/build_ebpf.sh", re.compile(r'^LIBBPF_TAG="([^"]+)"', re.M)),
    "cpython": ("version", "framework/.python-version", re.compile(r"^(\S+)\s*$")),
}


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def external_res(src_dir, warnings):
    """Return {(target, platform): set(names)} as computed by `make print-EXTERNAL_RES`."""
    result = {}
    for combo, args in MAKE_COMBOS.items():
        if combo == ("agent", "windows") and not shutil.which(MINGW_CC):
            warnings.append(f"windows not checked (no {MINGW_CC})")
            continue
        proc = subprocess.run(["make", "-s", "-C", str(src_dir), "print-EXTERNAL_RES", *args],
                              capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"make print-EXTERNAL_RES {' '.join(args)} failed: {proc.stderr.strip()}")
        result[combo] = set(proc.stdout.split())
    return result


def _check_cpe(cpe):
    parts = cpe.split(":")
    if len(parts) != 13 or parts[:3] != ["cpe", "2.3", "a"]:
        return f"malformed CPE {cpe!r} (expected 13 components starting with cpe:2.3:a:)"
    if parts[5] != "*":
        return f"CPE {cpe!r} carries version {parts[5]!r}; versions belong in `version`"
    return None


def _check_url(url):
    if not url.startswith(("https://", "http://")):
        return f"`url` must be an http(s) URL, got {url!r}"
    unknown = sorted(set(re.findall(r"\{([^}]*)\}", url)) - URL_PLACEHOLDERS)
    if unknown:
        return f"`url` uses unknown placeholder(s) {', '.join(unknown)}"
    return None


def _check_pin(entry, repo_root):
    field, rel, pattern = PINS[entry["name"]]
    path = Path(repo_root) / rel
    try:
        match = pattern.search(path.read_text(encoding="utf-8"))
    except OSError:
        return f"cannot read {rel} to check `{field}`"
    if not match:
        return f"no version pin found in {rel}"
    if entry.get(field) != match.group(1):
        return f"`{field}` is {entry.get(field)!r} but {rel} pins {match.group(1)!r}"
    return None


def _check_entry(entry, patches_dir, repo_root):
    name = entry.get("name", "<unnamed>")
    errors = []

    def err(message):
        errors.append(f"{name}: {message}")

    for field, kind in REQUIRED.items():
        if field not in entry:
            err(f"missing field `{field}`")
        elif not isinstance(entry[field], kind) or (kind is int and isinstance(entry[field], bool)):
            err(f"`{field}` must be {kind.__name__}")
    for field, kind in OPTIONAL.items():
        if field in entry and not isinstance(entry[field], kind):
            err(f"`{field}` must be {kind.__name__}")
    for field in sorted(set(entry) - set(REQUIRED) - set(OPTIONAL) - {"cpe"}):
        err(f"unknown field `{field}`")

    source = entry.get("source")
    if source not in SOURCES:
        err(f"`source` must be one of {sorted(SOURCES)}")
    required_sha = {"upstream": "upstream_sha256", "snapshot": "snapshot_sha256"}.get(source)
    if required_sha and required_sha not in entry:
        err(f"{source} entry needs `{required_sha}`")
    for field in ("upstream_sha256", "snapshot_sha256"):
        if isinstance(entry.get(field), str) and not SHA256_RE.match(entry[field]):
            err(f"`{field}` is not a lowercase sha256")
    if isinstance(entry.get("url"), str):
        problem = _check_url(entry["url"])
        if problem:
            err(problem)
    if isinstance(entry.get("format"), str) and entry["format"] not in FORMATS:
        err(f"`format` must be one of {sorted(FORMATS)}")
    if isinstance(entry.get("strip"), int) and not isinstance(entry["strip"], bool) and entry["strip"] < 0:
        err("`strip` must be >= 0")

    for field, allowed in (("targets", TARGETS), ("platforms", PLATFORMS)):
        values = entry.get(field)
        if isinstance(values, list):
            if not values:
                err(f"`{field}` is empty")
            for value in sorted(set(values) - allowed, key=str):
                err(f"unknown {field[:-1]} {value!r}")

    if "cpe" not in entry:
        err("missing field `cpe`")
    else:
        cpe = entry["cpe"]
        cpes = cpe if isinstance(cpe, list) else [cpe]
        if cpe is None:
            if entry.get("scan", True):
                err("`cpe: null` requires `scan: false`")
        elif not cpes or not all(isinstance(c, str) for c in cpes):
            err("`cpe` must be a string, a non-empty list of strings or null")
        else:
            for c in cpes:
                problem = _check_cpe(c)
                if problem:
                    err(problem)
    if entry.get("scan") is False and not entry.get("reason"):
        err("`scan: false` requires `reason`")

    for patch in entry.get("patches", []) if isinstance(entry.get("patches"), list) else []:
        if not (Path(patches_dir) / patch).is_file():
            err(f"patch {patch!r} not found under {patches_dir}")

    if name in PINS:
        problem = _check_pin(entry, repo_root)
        if problem:
            err(problem)
    return errors


def validate(doc, external=None, patches_dir=PATCHES_DIR, repo_root=REPO):
    """Return a list of `<name>: <message>` errors; empty means valid."""
    if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("entries"), list):
        return ["<inventory>: expected {\"schema\": 1, \"entries\": [...]}"]
    entries = [e for e in doc["entries"] if isinstance(e, dict)]
    if len(entries) != len(doc["entries"]):
        return ["<inventory>: every entry must be an object"]
    names = [e.get("name") for e in entries]
    errors = []
    for dup in sorted({n for n in names if isinstance(n, str) and names.count(n) > 1}):
        errors.append(f"{dup}: duplicate name")
    str_names = [n for n in names if isinstance(n, str)]
    if str_names != sorted(str_names):
        errors.append("<inventory>: entries must be sorted by `name`")
    for entry in entries:
        errors.extend(_check_entry(entry, patches_dir, repo_root))

    for (target, platform), expected in sorted((external or {}).items()):
        declared = {e["name"] for e in entries
                    if isinstance(e.get("name"), str) and target in e.get("targets", []) and platform in e.get("platforms", [])}
        for extra in sorted(declared - expected):
            errors.append(f"{extra}: declared for {target}/{platform} but not in EXTERNAL_RES")
        for missing in sorted(expected - declared):
            errors.append(f"{missing}: in EXTERNAL_RES for {target}/{platform} but missing from inventory")
    return errors


def expand_url(url, version, revision):
    """Same substitutions as the URL templates always had, plus {revision}."""
    major, minor, patch = (version.split(".") + ["0", "0", "0"])[:3]
    concat = "%d%02d%02d00" % tuple(int(x) if x.isdigit() else 0 for x in (major, minor, patch))
    for key, value in (("version_concat", concat), ("version_us", version.replace(".", "_")),
                       ("version_dash", version.replace(".", "-")), ("version", version), ("revision", revision)):
        url = url.replace("{" + key + "}", value)
    return url


def flatten(doc):
    """Return bash `declare -A` lines describing every entry of a valid inventory."""
    columns = {
        "EXT_URL": lambda e: expand_url(e["url"], e["version"], e["revision"]),
        "EXT_SHA256": lambda e: e.get("upstream_sha256") or e["snapshot_sha256"],
        "EXT_SOURCE": lambda e: e["source"],
        "EXT_VERSION": lambda e: e["version"],
        "EXT_FORMAT": lambda e: e["format"],
        "EXT_STRIP": lambda e: str(e["strip"]),
        "EXT_TARGET": lambda e: e.get("target_dir", e["name"]),
        "EXT_PATCHES": lambda e: " ".join(e["patches"]),
        "EXT_PLATFORMS": lambda e: " ".join(e["platforms"]),
    }
    lines = []
    for var, value in columns.items():
        items = " ".join(f"[{shlex.quote(e['name'])}]={shlex.quote(value(e))}" for e in doc["entries"])
        lines.append(f"declare -A {var}=({items})")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="validate the inventory")
    check.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    check.add_argument("--src", default=str(REPO / "src"))
    check.add_argument("--no-make", action="store_true", help="skip the EXTERNAL_RES comparison")
    flat = sub.add_parser("flatten", help="print the inventory as bash associative arrays")
    flat.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    args = parser.parse_args(argv)

    try:
        doc = load(args.inventory)
    except (OSError, ValueError) as exc:
        print(f"ERROR: <inventory>: cannot read {args.inventory}: {exc}", file=sys.stderr)
        return 1

    if args.command == "flatten":
        errors = validate(doc)
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if errors:
            return 1
        sys.stdout.write(flatten(doc))
        return 0

    warnings = []
    external = None
    if not args.no_make:
        try:
            external = external_res(args.src, warnings)
        except RuntimeError as exc:
            print(f"ERROR: <inventory>: {exc}", file=sys.stderr)
            return 1
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    errors = validate(doc, external)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
