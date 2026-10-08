#!/usr/bin/env python3
"""Validate the external dependencies inventory and export it for the build scripts.

    deps.py check [--inventory PATH] [--src DIR] [--no-make]
    deps.py flatten [--inventory PATH]
    deps.py readme [--inventory PATH] [--readme PATH] [--check]
    deps.py sbom [--inventory PATH | --manifest URL|PATH] [--requirements PATH] [--output PATH]
    deps.py manifest --pool DIR [--inventory PATH] [--wazuh-commit SHA] [--workflow-run ID]
    deps.py plan [--inventory PATH] [--pool URL]
    deps.py verify --local DIR [--pool URL]
    deps.py mirror --dest DIR [--local DIR] [--pool URL] [--target T] [--platform DIR] [--inventory PATH]
    deps.py pool-check [--inventory PATH] [--pool URL]
    deps.py lock [--inventory PATH] [--check] [--output PATH]
    deps.py key [--inventory PATH] [NAME ...]
    deps.py key-paths

`check` prints one `ERROR: <name>: <message>` line per problem to stderr and exits 1 if
there is any, 0 otherwise. `flatten` prints the inventory as bash associative arrays
(EXT_URL, EXT_SHA256, ...) for build_external.sh, since not every builder image has python3.
`readme` rewrites the dependency table of README.md, `sbom` prints a CycloneDX 1.5 SBOM,
`manifest` writes the manifest.json of every ref built into a pool directory, and `plan`
prints the entries whose ref is not in the pool yet, which are the ones to build. `mirror`
lays out the refs a target needs, from a local pool tree and the pool; `verify` checks the
refs of a local pool tree against what the pool serves; `pool-check` checks that every ref
of the lock is in the pool with the inputs it was keyed on.
`lock` writes src/deps.lock.mk, the pool ref of every entry (`<name>/<version>-<key>`), or with
--check fails if it is stale. `key` prints `<ref> <inputs sha256>` per entry, and `key-paths` the
repository paths that go into the keys.
"""

import argparse
import concurrent.futures
import difflib
import hashlib
import http.client
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = REPO / "packages" / "externals" / "dependencies.json"
PATCHES_DIR = REPO / "packages" / "externals" / "patches"
OVERLAYS_DIR = REPO / "packages" / "externals" / "overlay"
README = REPO / "README.md"
REQUIREMENTS = REPO / "framework" / "requirements.txt"
MIRROR = "https://packages.wazuh.com/deps"
POOL = f"{MIRROR}/pool"
TABLE_BEGIN, TABLE_END = "<!-- deps-table:begin -->", "<!-- deps-table:end -->"
# Fields that define what is built; metadata (license, CPE, notes) can be fixed without a new pool entry.
CONTENT_FIELDS = ("version", "revision", "source", "url", "upstream_sha256", "snapshot_sha256", "patches", "overlay",
                  "subdir", "targets", "platforms")

# Pool key: a hash of everything that decides the bytes of a pool entry, computable without network.
# Raising KEY_EPOCH rebuilds every entry.
KEY_EPOCH = 1
# `url` is left out: a mirror with the same sha256 serves the same bytes.
KEY_FIELDS = tuple(f for f in CONTENT_FIELDS if f != "url") + ("format", "strip")
LOCK = REPO / "src" / "deps.lock.mk"
BUILDER_IMAGES = REPO / "packages" / "externals" / "builder-images.json"
# What fetches, cuts, overlays, patches and packs the source tree of every entry not built by its own script.
SOURCE_RECIPE = ("packages/externals/build_external.sh", "packages/externals/generate_external.sh",
                 "packages/externals/consolidate.sh")
# How every entry with binaries is compiled: the whole external CMakeLists.txt, since its blocks cannot be told
# apart per library, plus the `# deps-recipe` blocks with the CMake options and compilers the Makefile passes.
BUILD_RECIPE = ("src/external/CMakeLists.txt", "src/CMakeLists.txt#deps-recipe", "src/Makefile#deps-recipe")
# Entries built by their own scripts. cpython also compiles libwazuhext, so it keeps the build and platform
# recipes; libbpf-bootstrap is built on a GitHub runner by build_ebpf.sh alone.
OWN_RECIPE = {
    "cpython": ("framework/cpython/compile.sh", "framework/cpython/custom/**", "framework/requirements.txt",
                "framework/.python-version", "src/Makefile#cpython-recipe"),
    "libbpf-bootstrap": ("packages/externals/ebpf/build_ebpf.sh", "src/syscheckd/src/ebpf/src/modern.bpf.c"),
}
KEY_INPUT_FILES = ("packages/externals/dependencies.json", "packages/externals/builder-images.json",
                   "packages/externals/patches/**", "packages/externals/overlay/**")
# Links libwazuhext and carries the framework wheels.
PYTHON_ENTRY = "cpython"

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
    "upstream_sha256": str, "snapshot_sha256": str, "prebuilt": bool, "scan": bool,
    "reason": str, "notes": str, "overlay": str, "subdir": str, "links": list, "built": bool, "binaries": list,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# A directory name under packages/externals/overlay/; never "." or "..".
OVERLAY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")

# (target, platform) -> extra make arguments; windows needs the MinGW cross-compiler.
MAKE_COMBOS = {
    ("manager", "linux"): ["TARGET=manager", "uname_S=Linux"],
    ("agent", "linux"): ["TARGET=agent", "uname_S=Linux"],
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


def _check_entry(entry, patches_dir, repo_root, overlays_dir=OVERLAYS_DIR):
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
        # A snapshot is a published tree; only the mirror serves it.
        if source == "snapshot" and not entry["url"].startswith(f"{MIRROR}/"):
            err(f"snapshot entry must point under {MIRROR}/, where its published tree lives")
    # pkg:<type>/<namespace>/<name>@<version>; a "/" inside the version must be percent-encoded.
    if isinstance(entry.get("purl"), str) and not re.match(r"^pkg:[a-z]+/[^@]+@[^/@]+$", entry["purl"]):
        err(f"`purl` {entry['purl']!r} is not pkg:<type>/<name>@<version> with an encoded version")
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
    for field in ("overlay", "subdir"):
        if entry.get(field) == "":
            err(f"`{field}` must not be empty")
    overlay = entry.get("overlay")
    if isinstance(overlay, str) and overlay:
        if not OVERLAY_RE.match(overlay):
            err(f"`overlay` {overlay!r} is not a directory name")
        elif not any(p.is_file() for p in (Path(overlays_dir) / overlay).rglob("*")):
            err(f"overlay {overlay!r} not found or empty under {overlays_dir}")
    subdir = entry.get("subdir")
    # Checked on the raw string: Path() drops "." segments and a trailing "/".
    if isinstance(subdir, str) and subdir and (subdir.startswith("/") or {"", ".", ".."} & set(subdir.split("/"))):
        err(f"`subdir` {subdir!r} must be a relative path without empty, . or .. segments")

    binaries = entry.get("binaries")
    if isinstance(binaries, list) and isinstance(entry.get("platforms"), list):
        for value in sorted(set(binaries) - set(entry["platforms"])):
            err(f"`binaries` names {value!r}, which is not in `platforms`")
        if entry.get("built", True) is False:
            err("an entry with `built: false` has no `binaries`")
    links = entry.get("links")
    if isinstance(links, list):
        if not all(isinstance(link, str) for link in links):
            err("`links` must be a list of entry names")
        else:
            for dup in sorted({link for link in links if links.count(link) > 1}):
                err(f"`links` repeats {dup!r}")
            if name in links:
                err("`links` names the entry itself")
            if links and entry.get("built", True) is False:
                err("an entry with `built: false` has no binary to link")

    if name in PINS:
        problem = _check_pin(entry, repo_root)
        if problem:
            err(problem)
    return errors


# CMake target names that differ from the inventory name (prefixes `ext_` / suffix `_external` already removed).
CMAKE_NAMES = {"abseilcpp": "abseil-cpp", "pcre2": "libpcre2", "audit": "audit-userspace", "yamlcpp": "yaml-cpp",
               "maxminddb": "libmaxminddb", "cjson": "cJSON", "expected_lite": "expected-lite", "minizip": "zlib",
               "openssl_ssl": "openssl", "openssl_crypto": "openssl"}


def _cmake_name(target):
    base = re.sub(r"^ext_|_external$", "", target)
    return CMAKE_NAMES.get(base, base)


# Libraries a manager build leaves out of libwazuhext, which cpython links: agent-only and macOS-only ones.
WAZUHEXT_NOT_MANAGER = {"dbus", "lua", "rpm", "popt", "audit-userspace", "procps", "libplist"}


def _cmake_commands(cmake_text):
    """(command, [arguments]) for every command call, comments removed and parentheses balanced."""
    text = re.sub(r"#[^\n]*", "", cmake_text)
    for match in re.finditer(r"\b(\w+)\s*\(", text):
        depth, i = 1, match.end()
        while depth and i < len(text):
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        yield match.group(1), text[match.end():i - 1].split()


def cmake_links(cmake_text):
    """({entry: linked entries} from the ExternalProject_Add DEPENDS, entries that go into libwazuhext)."""
    graph, wazuhext = {}, set()
    for command, args in _cmake_commands(cmake_text):
        if command == "ExternalProject_Add" and args:
            owner, linked, in_depends = _cmake_name(args[0]), set(), False
            for arg in args[1:]:
                if re.fullmatch(r"[A-Z][A-Z0-9_]*", arg):
                    in_depends = arg == "DEPENDS"
                elif in_depends:
                    if not re.fullmatch(r"ext_\w+|\w+_external", arg):
                        raise ValueError(f"{owner}: DEPENDS {arg} in src/external/CMakeLists.txt cannot be resolved")
                    linked.add(_cmake_name(arg))
            if linked - {owner}:
                graph.setdefault(owner, set()).update(linked - {owner})
        elif command in ("set", "list") and "WAZUHEXT_WHOLE_LIBS" in args[:2]:
            for arg in args[args.index("WAZUHEXT_WHOLE_LIBS") + 1:]:
                if not re.fullmatch(r"ext_\w+|openssl_\w+", arg):
                    raise ValueError(f"WAZUHEXT_WHOLE_LIBS item {arg} in src/external/CMakeLists.txt cannot be resolved")
                wazuhext.add(_cmake_name(arg))
    return graph, wazuhext


# Pool platform directories of each inventory platform, as `make deps` names them in PRECOMPILED_RES.
POOL_PLATFORMS = {"linux": ("linux/amd64", "linux/aarch64"), "darwin": ("darwin/amd64", "darwin/aarch64"),
                  "windows": ("windows",)}
ALL_POOL_PLATFORMS = tuple(d for dirs in POOL_PLATFORMS.values() for d in dirs)
IMAGE_RE = re.compile(r"^ghcr\.io/wazuh/[a-z0-9_]+@sha256:[0-9a-f]{64}$|^unpinned:\S+$")


def check_builder_images(images):
    """Errors in builder-images.json: one digest per linux target/arch and for windows, runners and Xcode for darwin."""
    errors = []
    expected = [("linux", t, a) for t in ("agent", "manager") for a in ("amd64", "arm64")] + [("windows", "agent")]
    for path in expected:
        value = images
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if not isinstance(value, str) or not IMAGE_RE.match(value):
            errors.append(f"<builder-images>: {'.'.join(path)} must be ghcr.io/wazuh/<image>@sha256:<digest>")
    darwin = images.get("darwin") if isinstance(images, dict) else None
    if not (isinstance(darwin, dict) and isinstance(darwin.get("runners"), list) and darwin["runners"]
            and all(isinstance(r, str) for r in darwin["runners"]) and isinstance(darwin.get("xcode"), str)
            and re.fullmatch(r"\d+\.\d+(\.\d+)?", darwin["xcode"])):
        errors.append("<builder-images>: darwin needs `runners` (list) and `xcode` (a version such as 15.4)")
    return errors


def _check_links(entries, repo_root):
    names = {e["name"] for e in entries}
    links = {e["name"]: e.get("links", []) for e in entries if isinstance(e.get("links"), list)}
    errors = [f"{name}: `links` names unknown entry {link!r}"
              for name, linked in sorted(links.items()) for link in linked if link not in names]
    state = {}

    def visit(name, path):
        if state.get(name) == "done":
            return
        if state.get(name) == "open":
            errors.append(f"{name}: `links` cycle {' -> '.join(path[path.index(name):] + [name])}")
            return
        state[name] = "open"
        for link in links.get(name, []):
            if link in names:
                visit(link, path + [name])
        state[name] = "done"

    for name in sorted(links):
        visit(name, [])
    cmake = Path(repo_root) / "src" / "external" / "CMakeLists.txt"
    if cmake.is_file():
        graph, wazuhext = cmake_links(cmake.read_text(encoding="utf-8"))
        # An entry missing from the inventory is reported against EXTERNAL_RES, not here.
        for name in sorted(names - {PYTHON_ENTRY}):
            expected = graph.get(name, set()) & names
            if set(links.get(name, [])) & names != expected:
                errors.append(f"{name}: `links` is {sorted(links.get(name, []))} but the DEPENDS in "
                              f"src/external/CMakeLists.txt give {sorted(expected)}")
        if PYTHON_ENTRY in names:
            expected = (wazuhext - WAZUHEXT_NOT_MANAGER) & names
            if set(links.get(PYTHON_ENTRY, [])) & names != expected:
                errors.append(f"{PYTHON_ENTRY}: `links` is {sorted(links.get(PYTHON_ENTRY, []))} but the manager's "
                              f"WAZUHEXT_WHOLE_LIBS give {sorted(expected)}")
    return errors


def validate(doc, external=None, patches_dir=PATCHES_DIR, repo_root=REPO, overlays_dir=OVERLAYS_DIR):
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
        errors.extend(_check_entry(entry, patches_dir, repo_root, overlays_dir))
    if not errors:
        errors.extend(_check_links(entries, repo_root))
    images = Path(repo_root) / BUILDER_IMAGES.relative_to(REPO)
    if images.is_file():
        errors.extend(check_builder_images(load(images)))

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
    entries = doc["entries"]
    columns = {
        "EXT_URL": lambda e: expand_url(e["url"], e["version"], e["revision"]),
        "EXT_SHA256": lambda e: e["upstream_sha256" if e["source"] == "upstream" else "snapshot_sha256"],
        "EXT_SOURCE": lambda e: e["source"],
        "EXT_VERSION": lambda e: e["version"],
        "EXT_FORMAT": lambda e: e["format"],
        "EXT_STRIP": lambda e: str(e["strip"]),
        "EXT_TARGET": lambda e: e["name"],
        "EXT_PATCHES": lambda e: " ".join(e["patches"]),
        "EXT_OVERLAY": lambda e: e.get("overlay", ""),
        "EXT_SUBDIR": lambda e: e.get("subdir", ""),
        "EXT_PLATFORMS": lambda e: " ".join(e["platforms"]),
    }
    lines = []
    for var, value in columns.items():
        items = " ".join(f"[{shlex.quote(e['name'])}]={shlex.quote(value(e))}" for e in entries)
        lines.append(f"declare -A {var}=({items})")
    return "\n".join(lines) + "\n"


def readme_table(doc):
    rows = [("Software", "Version", "Author", "License")]
    rows += [(f"[{e['name']}]({e['homepage']})", e["version"], e["author"], e["license"])
             for e in sorted(doc["entries"], key=lambda e: e["name"].lower())]
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    line = lambda cells: "| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths)) + " |"
    return "\n".join([line(rows[0]), line(["-" * w for w in widths]), *map(line, rows[1:])])


def render_readme(text, doc):
    begin, end = text.find(TABLE_BEGIN), text.find(TABLE_END)
    if begin < 0 or end < begin:
        raise ValueError(f"README has no {TABLE_BEGIN} ... {TABLE_END} block")
    return text[:begin + len(TABLE_BEGIN)] + "\n" + readme_table(doc) + "\n" + text[end:]


def read_requirements(path, warnings=None):
    """Return (normalized name, version) for every `name==version` line; other lines are reported."""
    pins = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            name, sep, version = line.partition("==")
            if not sep:
                # An unpinned requirement has no version to scan; older branches still carry some.
                if warnings is not None:
                    warnings.append(f"{path}: {line!r} is not pinned with ==; left out of the SBOM")
                continue
            pins.append((re.sub(r"[-_.]+", "-", name.strip()).lower(), version.strip()))
    return pins


def sbom(entries, requirements):
    components = []
    for e in entries:
        component = {"bom-ref": e["name"], "type": "library", "name": e["name"], "version": e["version"]}
        cpes = e.get("cpe") if isinstance(e.get("cpe"), list) else [e.get("cpe")]
        if cpes[0]:
            component["cpe"] = cpes[0]
        component["purl"] = e["purl"]
        component["licenses"] = [{"license": {"name": e["license"]}}]
        component["properties"] = [{"name": "syft:location:0:path", "value": "packages/externals/dependencies.json"}]
        # Syft and Grype read additional CPEs from this property only.
        component["properties"] += [{"name": "syft:cpe23", "value": c} for c in cpes[1:]]
        components.append(component)
    for name, version in requirements:
        components.append({"bom-ref": f"pypi:{name}", "type": "library", "name": name, "version": version,
                           "purl": f"pkg:pypi/{name}@{version}",
                           "properties": [{"name": "syft:location:0:path", "value": "framework/requirements.txt"}]})
    components.sort(key=lambda c: c["bom-ref"])
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def patch_hashes(entries, patches_dir=PATCHES_DIR):
    return {patch: hashlib.sha256((Path(patches_dir) / patch).read_bytes()).hexdigest()
            for e in entries for patch in e.get("patches", [])}


def overlay_hashes(entries, overlays_dir=OVERLAYS_DIR):
    """{"<overlay>/<path>": sha256} of every file in the overlays of `entries`, hidden files included."""
    result = {}
    for e in entries:
        if e.get("overlay"):
            root = Path(overlays_dir) / e["overlay"]
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                result[f"{e['overlay']}/{path.relative_to(root).as_posix()}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _text_sha256(path):
    """sha256 with CRLF read as LF in text files, so a Windows checkout computes the same keys."""
    data = Path(path).read_bytes()
    return hashlib.sha256(data if b"\0" in data else data.replace(b"\r\n", b"\n")).hexdigest()


def _recipe(specs, repo):
    """{spec: sha256 | {path: sha256}} for files, `dir/**` globs and `file#marker` blocks."""
    result = {}
    for spec in specs:
        rel, _, marker = spec.partition("#")
        path = Path(repo) / rel
        if rel.endswith("/**"):
            root = path.parent
            files = sorted(p for p in root.rglob("*") if p.is_file())
            if not files:
                raise ValueError(f"key input {rel} has no files")
            result[spec] = {p.relative_to(root).as_posix(): _text_sha256(p) for p in files}
        elif marker:
            text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            blocks = re.findall(rf"^# {re.escape(marker)}: begin\n(.*?)^# {re.escape(marker)}: end$", text, re.M | re.S)
            begins = len(re.findall(rf"^# {re.escape(marker)}: begin$", text, re.M))
            ends = len(re.findall(rf"^# {re.escape(marker)}: end$", text, re.M))
            if not blocks or not begins == ends == len(blocks):
                raise ValueError(f"key input {rel} needs matching `# {marker}: begin/end` lines")
            result[spec] = hashlib.sha256("\0".join(blocks).encode()).hexdigest()
        else:
            if not path.is_file():
                raise ValueError(f"key input {rel} not found")
            result[spec] = _text_sha256(path)
    return result


def _platform_recipe(entry, images):
    """Builder of each platform the entry is built on: image digests for linux/windows, runner and Xcode for darwin."""
    result = {}
    for platform in sorted(entry["platforms"]):
        if platform not in images:
            raise ValueError(f"{entry['name']}: no builder for {platform} in {BUILDER_IMAGES.name}")
        builders = images[platform]
        result[platform] = {t: builders[t] for t in sorted(entry["targets"]) if t in builders} \
            if platform == "linux" else builders
    return result


def keys(doc, repo=REPO):
    """{name: (key, inputs_hash)}: the pool key of every entry and the full sha256 of its inputs."""
    entries = {e["name"]: e for e in doc["entries"]}
    images = load(Path(repo) / BUILDER_IMAGES.relative_to(REPO))
    source, build = _recipe(SOURCE_RECIPE, repo), _recipe(BUILD_RECIPE, repo)
    patches_dir = Path(repo) / PATCHES_DIR.relative_to(REPO)
    overlays_dir = Path(repo) / OVERLAYS_DIR.relative_to(REPO)
    result, open_ = {}, set()

    def compute(name):
        if name in result:
            return result[name][1]
        if name in open_:
            raise ValueError(f"{name}: `links` cycle")
        open_.add(name)
        entry = entries[name]
        built = entry.get("built", True)
        inputs = {
            "epoch": KEY_EPOCH,
            "entry": dict({f: entry[f] for f in KEY_FIELDS if f in entry}, built=built),
            "patches": {p: _text_sha256(patches_dir / p) for p in entry.get("patches", [])},
            "overlay": {k: _text_sha256(overlays_dir / k) for k in overlay_hashes([entry], overlays_dir)},
            "links": {link: compute(link) for link in sorted(entry.get("links", []))},
        }
        if name in OWN_RECIPE:
            inputs["own"] = _recipe(OWN_RECIPE[name], repo)
        else:
            inputs["source"] = source
        if built and name != "libbpf-bootstrap":
            inputs["build"] = build
            inputs["platforms"] = _platform_recipe(entry, images)
        digest = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        open_.discard(name)
        result[name] = (digest[:8], digest)
        return digest

    for name in entries:
        compute(name)
    return result


def ref(entry, key):
    return f"{entry['name']}/{entry['version']}-{key}"


def key_paths():
    """Every repository path or glob that goes into some key; workflow `paths:` filters must cover them."""
    specs = set(SOURCE_RECIPE) | set(BUILD_RECIPE) | set(KEY_INPUT_FILES) | {s for own in OWN_RECIPE.values() for s in own}
    return sorted({s.partition("#")[0] for s in specs})


def lock_text(doc, repo=REPO):
    computed = keys(doc, repo)
    lines = ["# Generated by packages/externals/deps.py lock from dependencies.json; do not edit."]
    lines += [f"DEP_REF_{e['name']} := {ref(e, computed[e['name']][0])}" for e in sorted(doc["entries"], key=lambda e: e["name"])]
    return "\n".join(lines) + "\n"


def _files(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and p.name != "manifest.json"}


# The cpython sources tarball `make deps` downloads on each platform (CPYTHON_ARCHIVE in src/Makefile).
CPYTHON_ARCHIVES = {"linux/amd64": "cpython_x86_64.tar.gz", "linux/aarch64": "cpython_arm64.tar.gz"}


def _cpython_wheels(where, requirements, run_platforms):
    """({sources tarball: {wheel: sha256}}, errors): the wheels each cpython sources tarball ships, which must
    be the same name==version set on every architecture and match framework/requirements.txt. Every platform
    of the run needs its tarball, under the name `make deps` asks for."""
    wheels, pins, errors = {}, {}, []
    present = {p.name for p in (where / "sources").glob("*")}
    errors += [f"sources/{name}: not a cpython archive `make deps` downloads"
               for name in sorted(present - set(CPYTHON_ARCHIVES.values()))]
    errors += [f"no sources/{name} for {platform}" for platform, name in CPYTHON_ARCHIVES.items()
               if platform in run_platforms and name not in present]
    for tarball in sorted((where / "sources").glob("cpython_*.tar.gz")):
        found = {}
        with tarfile.open(tarball) as archive:
            for member in archive:
                if member.isfile() and re.fullmatch(r"cpython/Dependencies/[^/]+\.whl", member.name):
                    found[member.name.rsplit("/", 1)[1]] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
        wheels[tarball.name] = found
        pins[tarball.name] = {(re.sub(r"[-_.]+", "-", m.group(1)).lower(), m.group(2))
                              for m in (re.match(r"^([^-]+)-([^-]+)-", w) for w in found) if m}
    if not wheels:
        return {}, errors or ["no sources/cpython_<arch>.tar.gz"]
    wanted = set(read_requirements(requirements))
    for name, shipped in pins.items():
        if shipped != wanted:
            errors.append(f"{name}: wheels differ from {Path(requirements).name}: missing "
                          f"{sorted('=='.join(p) for p in wanted - shipped)}, extra {sorted('=='.join(p) for p in shipped - wanted)}")
    return wheels, errors


def manifest_pool(doc, pool_dir, wazuh_commit=None, workflow_run=None, repo=REPO, run_platforms=ALL_POOL_PLATFORMS,
                  only=None, toolchain=None):
    """Write <ref>/manifest.json for every ref built into pool_dir (or only those of the `only` entries);
    return the errors that stop a publish.

    An entry with binaries must carry one for every platform of `binaries` (default `platforms`) that
    `run_platforms` built; a ref with an error gets no manifest. `toolchain` is a directory of <leg>.txt
    files describing what each build leg installed on the fly; it is recorded as is.
    """
    computed = keys(doc, repo)
    entries = {e["name"]: e for e in doc["entries"]}
    refs = {ref(entries[n], k): n for n, (k, _) in computed.items()}
    images = json.dumps(load(Path(repo) / BUILDER_IMAGES.relative_to(REPO)))
    unpinned = sorted(set(re.findall(r'"(unpinned:[^"]+)"', images)))
    if toolchain and not Path(toolchain).is_dir():
        raise ValueError(f"--toolchain {toolchain} is not a directory")
    if only is not None and (not only or only - {e["name"] for e in doc["entries"]}):
        raise ValueError(f"--only needs entries of the inventory, got {sorted(only) or 'none'}")
    tools = {p.stem: p.read_text(encoding="utf-8").splitlines()
             for p in sorted(Path(toolchain).glob("*.txt"))} if toolchain else {}
    errors = []
    for where in sorted(p for p in Path(pool_dir).glob("*/*") if p.is_dir()):
        if only is not None and where.parent.name not in only:
            continue
        name = refs.get(where.relative_to(pool_dir).as_posix())
        if name is None:
            errors.append(f"<pool>: {where.relative_to(pool_dir).as_posix()} is not a ref of the lock")
            continue
        files = _files(where)
        platforms = {f.rsplit("/", 1)[0] for f in files if not f.startswith("sources/")}
        entry = entries[name]
        problems = []
        if name not in OWN_RECIPE and not any(f.startswith("sources/") for f in files):
            problems.append("no sources/")
        if entry.get("built", True):
            expected = {d for p in entry.get("binaries", entry["platforms"]) for d in POOL_PLATFORMS.get(p, ())}
            # build_ebpf.sh builds every architecture in one job, so a run that has it has them all.
            missing = sorted((expected if name == "libbpf-bootstrap" else expected & set(run_platforms)) - platforms)
            if missing:
                problems.append(f"no {', '.join(missing)} tarball")
        elif platforms:
            problems.append(f"`built: false`, but it has {', '.join(sorted(platforms))}")
        extra = {}
        if name == PYTHON_ENTRY:
            requirements = Path(repo) / REQUIREMENTS.relative_to(REPO)
            wheels, wheel_problems = _cpython_wheels(where, requirements, run_platforms)
            problems += wheel_problems
            extra = {"wheels": wheels, "requirements_sha256": _text_sha256(requirements)}
        if problems:
            errors.extend(f"{name}: {problem}" for problem in problems)
            continue
        result = {"schema": 2, "ref": where.relative_to(pool_dir).as_posix(), "inputs_hash": computed[name][1],
                  "entry": entries[name],
                  "links": {link: ref(entries[link], computed[link][0]) for link in entries[name].get("links", [])},
                  "wazuh_commit": wazuh_commit, "workflow_run": workflow_run, "unpinned": unpinned, **extra,
                  "toolchain": tools, "files": files}
        (where / "manifest.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return errors


def load_manifest(source):
    try:
        if re.match(r"^https?://", source):
            with urllib.request.urlopen(source, timeout=60) as response:
                return json.load(response)
        return load(source)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"no manifest at {source}: {exc}") from exc


def _published_manifest(url):
    """The manifest.json at url as a dict, "missing" when the pool does not have it, or the error that stopped it.

    Server and network errors are retried; a 403/404 is not, since it is how a missing key looks."""
    for delay in (1, 2, 4, None):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            # CloudFront answers 403 for a key that does not exist.
            if exc.code in (403, 404):
                return "missing"
            if exc.code < 500:
                return exc
            error = exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, FileNotFoundError):
                return "missing"
            error = exc
        except ValueError as exc:
            return exc
        except (OSError, http.client.HTTPException) as exc:
            error = exc
        if delay:
            time.sleep(delay)
    return error


def pool_status(doc, pool=POOL, repo=REPO):
    """{name: None if published as keyed, "missing", or an error message}."""
    computed = keys(doc, repo)
    entries = {e["name"]: e for e in doc["entries"]}

    def fetch(name):
        return _published_manifest(f"{pool}/{ref(entries[name], computed[name][0])}/manifest.json")

    with concurrent.futures.ThreadPoolExecutor(8) as executor:
        got = dict(zip(entries, executor.map(fetch, entries)))
    status = {}
    for name in sorted(entries):
        published, where = got[name], f"{pool}/{ref(entries[name], computed[name][0])}"
        if published == "missing":
            status[name] = "missing"
        elif not isinstance(published, dict):
            status[name] = f"cannot read {where}/manifest.json: {published}"
        elif published.get("inputs_hash") != computed[name][1]:
            status[name] = f"{where} was built from other inputs (inputs_hash differs)"
        else:
            status[name] = None
    return status


def pool_check(doc, pool=POOL, repo=REPO):
    """Refs of the lock missing from the pool, or published with other inputs than the ones they are keyed on."""
    computed, entries = keys(doc, repo), {e["name"]: e for e in doc["entries"]}
    return [f"{name}: {pool}/{ref(entries[name], computed[name][0])} is not published" if problem == "missing"
            else f"{name}: {problem}" for name, problem in pool_status(doc, pool, repo).items() if problem]


def _fetch(url, timeout=300, retries=0):
    """Bytes at url; with retries, server and network errors are retried, a 4xx is not."""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code < 500 or attempt == retries:
                raise
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            if isinstance(getattr(exc, "reason", None), FileNotFoundError) or attempt == retries:
                raise
        time.sleep(2 ** attempt)


def lock_refs(path=LOCK):
    """{name: ref} from src/deps.lock.mk."""
    return dict(re.findall(r"^DEP_REF_(\S+) := (\S+)$", Path(path).read_text(encoding="utf-8"), re.M))


def verify(local_pool, pool=POOL):
    """Differences between the refs of a local pool tree and what the pool serves (inputs and every file)."""
    errors, jobs = [], []
    refs = sorted(p for p in Path(local_pool).glob("*/*") if (p / "manifest.json").is_file())
    if not refs:
        return [f"<pool>: no ref with a manifest.json under {local_pool}"]
    for where in refs:
        rel = where.relative_to(local_pool).as_posix()
        local = load(where / "manifest.json")
        try:
            published = json.loads(_fetch(f"{pool}/{rel}/manifest.json", 60))
        except (OSError, ValueError, http.client.HTTPException) as exc:
            errors.append(f"{rel}: cannot read the published manifest.json: {exc}")
            continue
        if published.get("inputs_hash") != local.get("inputs_hash"):
            errors.append(f"{rel}: published with other inputs (inputs_hash differs)")
            continue
        jobs += [(f"{rel}/{path}", digest) for path, digest in published.get("files", {}).items()]

    def check(job):
        path, digest = job
        try:
            data = _fetch(f"{pool}/{path}")
        except (OSError, http.client.HTTPException) as exc:
            return f"{path}: {exc}"
        return None if hashlib.sha256(data).hexdigest() == digest else f"{path}: sha256 differs from the manifest"

    with concurrent.futures.ThreadPoolExecutor(8) as executor:
        errors += [e for e in executor.map(check, jobs) if e]
    return errors


def mirror(doc, dest, local=None, pool=POOL, target=None, platform=None, repo=REPO, lock=LOCK, without=()):
    """Lay out under `dest` every ref of the lock `target` needs on `platform`: copied from `local` when it has
    it, downloaded from `pool` otherwise, in both cases with the inputs it is keyed on. Returns the refs found
    nowhere."""
    if platform and platform not in ALL_POOL_PLATFORMS:
        raise ValueError(f"platform must be one of {', '.join(ALL_POOL_PLATFORMS)}, got {platform!r}")
    if local and Path(local).resolve() == Path(dest).resolve():
        raise ValueError("--dest must not be the --local tree")
    computed, locked = keys(doc, repo), lock_refs(lock)
    inventory_platform = platform.split("/")[0] if platform else None
    wanted = []
    for e in doc["entries"]:
        targets = {"winagent": "agent"}.get(target, target)
        if e["name"] in without or (target and (targets not in e["targets"]
                                                or (inventory_platform and inventory_platform not in e["platforms"]))):
            continue
        rel, keyed = locked.get(e["name"]), ref(e, computed[e["name"]][0])
        if rel != keyed:
            raise ValueError(f"{e['name']}: the lock has {rel}, the inventory gives {keyed}; run deps.py lock")
        wanted.append((rel, computed[e["name"]][1]))
    missing = []
    for rel, inputs_hash in wanted:
        out = Path(dest) / rel
        shutil.rmtree(out, ignore_errors=True)
        if local and (Path(local) / rel / "manifest.json").is_file():
            if load(Path(local) / rel / "manifest.json").get("inputs_hash") != inputs_hash:
                raise ValueError(f"{rel}: {local} has it built from other inputs (inputs_hash differs)")
            shutil.copytree(Path(local) / rel, out, copy_function=os.link)
            continue
        manifest = _published_manifest(f"{pool}/{rel}/manifest.json")
        if manifest == "missing":
            missing.append(rel)
            continue
        if not isinstance(manifest, dict):
            raise ValueError(f"{rel}: cannot read {pool}/{rel}/manifest.json: {manifest}")
        if manifest.get("inputs_hash") != inputs_hash:
            raise ValueError(f"{rel}: {pool} has it built from other inputs (inputs_hash differs)")
        out.mkdir(parents=True, exist_ok=True)
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for path, digest in manifest["files"].items():
            if not (path.startswith("sources/") or (platform and path.startswith(f"{platform}/"))):
                continue
            try:
                data = _fetch(f"{pool}/{rel}/{path}", retries=3)
            except (OSError, http.client.HTTPException) as exc:
                raise ValueError(f"{rel}/{path}: listed in its manifest.json but not served: {exc}") from exc
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(f"{rel}/{path}: sha256 differs from its manifest")
            (out / path).parent.mkdir(parents=True, exist_ok=True)
            (out / path).write_bytes(data)
    return missing


def _report(errors):
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {name: sub.add_parser(name, help=text) for name, text in (
        ("check", "validate the inventory"), ("flatten", "print the inventory as bash associative arrays"),
        ("readme", "rewrite the dependency table of README.md"), ("sbom", "print a CycloneDX SBOM"),
        ("manifest", "write the manifest.json of every ref built into a pool directory"),
        ("plan", "print the entries whose ref is not published yet"),
        ("pool-check", "check that every ref of the lock is published in the pool"),
        ("verify", "check the refs of a local pool tree against the pool"),
        ("mirror", "lay out the pool refs a target needs, from a local tree and the pool"),
        ("lock", "write src/deps.lock.mk"), ("key", "print the pool ref and inputs hash of entries"),
        ("key-paths", "print the repository paths that go into the keys"),
        ("builder-image", "print a value of builder-images.json, e.g. `linux manager amd64` or `darwin xcode`"))}
    for command in commands.values():
        command.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    commands["check"].add_argument("--src", default=str(REPO / "src"))
    commands["check"].add_argument("--no-make", action="store_true", help="skip the EXTERNAL_RES comparison")
    commands["readme"].add_argument("--readme", default=str(README))
    commands["readme"].add_argument("--check", action="store_true", help="fail instead of rewriting")
    commands["sbom"].add_argument("--manifest", help="take the entries from a set manifest (URL or path)")
    commands["sbom"].add_argument("--requirements", default=str(REQUIREMENTS))
    commands["sbom"].add_argument("--output")
    commands["sbom"].add_argument("--target", choices=sorted(TARGETS), help="keep only the entries built for this target")
    commands["manifest"].add_argument("--pool", required=True, help="directory with <name>/<version>-<key>/ refs")
    commands["manifest"].add_argument("--platforms", default=",".join(ALL_POOL_PLATFORMS),
                                      help="comma-separated platform directories this run built")
    commands["manifest"].add_argument("--only", nargs="*", help="write only the refs of these entries")
    commands["manifest"].add_argument("--toolchain", help="directory of <leg>.txt files with what each leg installed")
    commands["manifest"].add_argument("--wazuh-commit")
    commands["manifest"].add_argument("--workflow-run")
    commands["plan"].add_argument("--pool", default=POOL)
    commands["pool-check"].add_argument("--pool", default=POOL)
    commands["verify"].add_argument("--local", required=True, help="pool tree whose refs were published")
    commands["verify"].add_argument("--pool", default=POOL)
    commands["mirror"].add_argument("--dest", required=True)
    commands["mirror"].add_argument("--local", help="pool tree built by this run, preferred over the pool")
    commands["mirror"].add_argument("--pool", default=POOL)
    commands["mirror"].add_argument("--target", choices=["agent", "manager", "winagent"])
    commands["mirror"].add_argument("--platform", help="pool platform directory, e.g. linux/amd64 or windows")
    commands["mirror"].add_argument("--lock", default=str(LOCK))
    commands["mirror"].add_argument("--without", nargs="*", default=[], help="entries left out, e.g. cpython")
    commands["lock"].add_argument("--check", action="store_true", help="fail instead of rewriting")
    commands["lock"].add_argument("--output", default=str(LOCK))
    commands["key"].add_argument("names", nargs="*")
    commands["builder-image"].add_argument("path", nargs="+")
    args = parser.parse_args(argv)
    if args.command == "key-paths":
        print("\n".join(key_paths()))
        return 0
    if args.command == "builder-image":
        value = load(BUILDER_IMAGES)
        for key in args.path:
            value = value.get(key) if isinstance(value, dict) else None
        if not isinstance(value, str):
            return _report([f"<builder-images>: {'.'.join(args.path)} is not a value of {BUILDER_IMAGES.name}"])
        print(value)
        return 0

    try:
        doc = None if args.command == "verify" or (args.command == "sbom" and args.manifest) \
            else load(args.inventory)
    except (OSError, ValueError) as exc:
        print(f"ERROR: <inventory>: cannot read {args.inventory}: {exc}", file=sys.stderr)
        return 1
    # sbom also reads other branches' inventories, whose version pins are not this tree's.
    if doc is not None and args.command not in ("check", "sbom"):
        errors = validate(doc)
        if errors:
            return _report(errors)

    try:
        if args.command == "flatten":
            sys.stdout.write(flatten(doc))
        elif args.command == "readme":
            text = Path(args.readme).read_text(encoding="utf-8")
            new = render_readme(text, doc)
            if args.check:
                if new != text:
                    sys.stderr.writelines(difflib.unified_diff(text.splitlines(True), new.splitlines(True),
                                                               args.readme, "generated from the inventory"))
                    return _report([f"<inventory>: {args.readme} differs from the inventory; run deps.py readme"])
            elif new != text:
                Path(args.readme).write_text(new, encoding="utf-8")
        elif args.command == "sbom":
            entries = load_manifest(args.manifest)["entries"] if args.manifest else doc["entries"]
            if args.target:
                if any("targets" not in e for e in entries):
                    raise ValueError("--target needs `targets` in every entry")
                entries = [e for e in entries if args.target in e["targets"]]
            warnings = []
            text = json.dumps(sbom(entries, read_requirements(args.requirements, warnings)), indent=2) + "\n"
            for warning in warnings:
                print(f"WARNING: {warning}", file=sys.stderr)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        elif args.command == "manifest":
            return _report(manifest_pool(doc, args.pool, args.wazuh_commit, args.workflow_run,
                                         run_platforms=[p for p in args.platforms.split(",") if p],
                                         only=set(args.only) if args.only is not None else None,
                                         toolchain=args.toolchain))
        elif args.command == "plan":
            status = pool_status(doc, args.pool)
            errors = [f"{name}: {problem}" for name, problem in status.items() if problem not in (None, "missing")]
            if errors:
                return _report(errors)
            print(" ".join(name for name, problem in status.items() if problem == "missing"))
        elif args.command == "verify":
            return _report(verify(args.local, args.pool))
        elif args.command == "mirror":
            missing = mirror(doc, args.dest, args.local, args.pool, args.target, args.platform, lock=args.lock,
                             without=set(args.without))
            return _report([f"{rel}: not in {args.local or 'the local tree'} nor in {args.pool}" for rel in missing])
        elif args.command == "lock":
            new = lock_text(doc)
            path = Path(args.output)
            old = path.read_text(encoding="utf-8") if path.is_file() else ""
            if args.check:
                if new != old:
                    sys.stderr.writelines(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                               str(path), "generated from the inventory"))
                    return _report([f"<inventory>: {path} is stale; run deps.py lock"])
            elif new != old:
                path.write_text(new, encoding="utf-8")
        elif args.command == "key":
            computed = keys(doc)
            entries = {e["name"]: e for e in doc["entries"]}
            for name in args.names or sorted(entries):
                if name not in entries:
                    raise ValueError(f"no entry {name!r}")
                print(ref(entries[name], computed[name][0]), computed[name][1])
        elif args.command == "pool-check":
            return _report(pool_check(doc, args.pool))
        else:
            warnings = []
            external = None if args.no_make else external_res(args.src, warnings)
            images = json.dumps(load(BUILDER_IMAGES))
            if "unpinned:" in images:
                warnings.append(f"{BUILDER_IMAGES.name} has unpinned builders; pool keys do not identify their images")
            for warning in warnings:
                print(f"WARNING: {warning}", file=sys.stderr)
            return _report(validate(doc, external))
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        return _report([f"<inventory>: {exc}"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
