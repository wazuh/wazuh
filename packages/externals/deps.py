#!/usr/bin/env python3
"""Validate the external dependencies inventory and export it for the build scripts.

    deps.py check [--inventory PATH] [--src DIR] [--no-make]
    deps.py flatten [--inventory PATH]
    deps.py readme [--inventory PATH] [--readme PATH] [--check]
    deps.py sbom [--inventory PATH | --manifest URL|PATH] [--requirements PATH] [--output PATH]
    deps.py manifest --deps-version N [--python --built-against SET [--requirements PATH]]
                     [--inventory PATH] [--wazuh-commit SHA] [--workflow-run ID] [--files DIR]
    deps.py drift [--inventory PATH] [--manifest URL|PATH] [--python-manifest URL|PATH]

`check` prints one `ERROR: <name>: <message>` line per problem to stderr and exits 1 if
there is any, 0 otherwise. `flatten` prints the inventory as bash associative arrays
(EXT_URL, EXT_SHA256, ...) for build_external.sh, whose builder images have no python3.
`readme` rewrites the dependency table of README.md, `sbom` prints a CycloneDX 1.5 SBOM,
`manifest` prints the manifest.json of a published set (the external libraries, or with
--python the embedded Python and its wheels), and `drift` compares the inventory with the
manifests of the sets src/Makefile's DEPS_VERSION and PYTHON_DEPS_VERSION point at.
"""

import argparse
import difflib
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = REPO / "packages" / "externals" / "dependencies.json"
PATCHES_DIR = REPO / "packages" / "externals" / "patches"
README = REPO / "README.md"
REQUIREMENTS = REPO / "framework" / "requirements.txt"
MIRROR = "https://packages.wazuh.com/deps"
TABLE_BEGIN, TABLE_END = "<!-- deps-table:begin -->", "<!-- deps-table:end -->"
# Fields that define what a set contains; metadata (license, CPE, notes) can be fixed without a new set.
CONTENT_FIELDS = ("version", "revision", "source", "url", "upstream_sha256", "snapshot_sha256", "patches",
                  "targets", "platforms")
# Built by 5_builderpackage_embedded-python.yml and published in the PYTHON_DEPS_VERSION set.
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
    "reason": str, "notes": str,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

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
        "EXT_SHA256": lambda e: e["upstream_sha256" if e["source"] == "upstream" else "snapshot_sha256"],
        "EXT_SOURCE": lambda e: e["source"],
        "EXT_VERSION": lambda e: e["version"],
        "EXT_FORMAT": lambda e: e["format"],
        "EXT_STRIP": lambda e: str(e["strip"]),
        "EXT_TARGET": lambda e: e["name"],
        "EXT_PATCHES": lambda e: " ".join(e["patches"]),
        "EXT_PLATFORMS": lambda e: " ".join(e["platforms"]),
    }
    lines = []
    for var, value in columns.items():
        items = " ".join(f"[{shlex.quote(e['name'])}]={shlex.quote(value(e))}" for e in doc["entries"])
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


def manifest(doc, deps_version, wazuh_commit=None, workflow_run=None, files_dir=None, python=None,
             patches_dir=PATCHES_DIR):
    """Manifest of an externals set, or with python={"built_against", "requirements"} of a Python set."""
    files = {}
    if files_dir:
        root = Path(files_dir)
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = {"schema": 1, "deps_version": deps_version, "wazuh_commit": wazuh_commit, "workflow_run": workflow_run}
    if python is None:
        result["entries"] = [e for e in doc["entries"] if e["name"] != PYTHON_ENTRY]
        # A patch edited in place keeps its name; its hash is what the set was built with.
        result["patches"] = patch_hashes(result["entries"], patches_dir)
    else:
        result["built_against"] = python["built_against"]
        result["entries"] = [e for e in doc["entries"] if e["name"] == PYTHON_ENTRY]
        result["requirements"] = [f"{name}=={version}" for name, version in python["requirements"]]
    result["files"] = files
    return result


def load_manifest(source):
    try:
        if re.match(r"^https?://", source):
            with urllib.request.urlopen(source, timeout=60) as response:
                return json.load(response)
        return load(source)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"no manifest at {source}: {exc}") from exc


def drift(doc, published, python=False, patches_dir=PATCHES_DIR):
    """Return the differences in content fields between the inventory and a set manifest."""
    ours = {e["name"]: e for e in doc["entries"] if (e["name"] == PYTHON_ENTRY) == python}
    theirs = {e["name"]: e for e in published.get("entries", [])}
    errors = [f"{n}: in the inventory but not in the set manifest" for n in sorted(set(ours) - set(theirs))]
    errors += [f"{n}: in the set manifest but not in the inventory" for n in sorted(set(theirs) - set(ours))]
    for name in sorted(set(ours) & set(theirs)):
        for field in CONTENT_FIELDS:
            if ours[name].get(field) != theirs[name].get(field):
                errors.append(f"{name}: `{field}` is {ours[name].get(field)!r} here but "
                              f"{theirs[name].get(field)!r} in the set manifest")
    if not python:
        built = published.get("patches", {})
        for patch, digest in sorted(patch_hashes(ours.values(), patches_dir).items()):
            if built.get(patch) != digest:
                errors.append(f"{patch.split('/')[0]}: patch {patch} differs from the one the set was built with")
    return errors


def drift_python(doc, published, requirements, deps_version_value):
    """Differences between the inventory, the framework requirements and the Python set manifest."""
    errors = drift(doc, published, python=True)
    if published.get("built_against") != deps_version_value:
        errors.append(f"{PYTHON_ENTRY}: the Python set was built against {published.get('built_against')!r}, "
                      f"but DEPS_VERSION is {deps_version_value!r}; rebuild it")
    pins = {f"{name}=={version}" for name, version in requirements}
    shipped = set(published.get("requirements", []))
    errors += [f"{PYTHON_ENTRY}: {pin} is in framework/requirements.txt but not in the Python set" for pin in sorted(pins - shipped)]
    errors += [f"{PYTHON_ENTRY}: {pin} is in the Python set but not in framework/requirements.txt" for pin in sorted(shipped - pins)]
    return errors


def deps_version(src_dir, variable="DEPS_VERSION"):
    match = re.search(rf"^{variable}\s*=\s*(\S+)", (Path(src_dir) / "Makefile").read_text(encoding="utf-8"), re.M)
    if not match:
        raise RuntimeError(f"no {variable} in {src_dir}/Makefile")
    return match.group(1)


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
        ("manifest", "print the manifest.json of a published set"),
        ("drift", "compare the inventory with the manifests of DEPS_VERSION and PYTHON_DEPS_VERSION"))}
    for command in commands.values():
        command.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    commands["check"].add_argument("--src", default=str(REPO / "src"))
    commands["check"].add_argument("--no-make", action="store_true", help="skip the EXTERNAL_RES comparison")
    commands["readme"].add_argument("--readme", default=str(README))
    commands["readme"].add_argument("--check", action="store_true", help="fail instead of rewriting")
    commands["sbom"].add_argument("--manifest", help="take the entries from a set manifest (URL or path)")
    commands["sbom"].add_argument("--requirements", default=str(REQUIREMENTS))
    commands["sbom"].add_argument("--output")
    commands["manifest"].add_argument("--deps-version", required=True)
    commands["manifest"].add_argument("--wazuh-commit")
    commands["manifest"].add_argument("--workflow-run")
    commands["manifest"].add_argument("--files", help="directory whose files are hashed into `files`")
    commands["manifest"].add_argument("--python", action="store_true", help="manifest of an embedded Python set")
    commands["manifest"].add_argument("--built-against", help="with --python: DEPS_VERSION the Python set was built with")
    commands["manifest"].add_argument("--requirements", default=str(REQUIREMENTS))
    commands["drift"].add_argument("--manifest", help="default: the mirror manifest of src/Makefile's DEPS_VERSION")
    commands["drift"].add_argument("--python-manifest",
                                   help="default: the mirror manifest of src/Makefile's PYTHON_DEPS_VERSION")
    commands["drift"].add_argument("--requirements", default=str(REQUIREMENTS))
    commands["drift"].add_argument("--src", default=str(REPO / "src"))
    args = parser.parse_args(argv)

    try:
        doc = None if getattr(args, "manifest", None) and args.command == "sbom" else load(args.inventory)
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
            warnings = []
            text = json.dumps(sbom(entries, read_requirements(args.requirements, warnings)), indent=2) + "\n"
            for warning in warnings:
                print(f"WARNING: {warning}", file=sys.stderr)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        elif args.command == "manifest":
            python = None
            if args.python:
                if not args.built_against:
                    raise ValueError("--python needs --built-against")
                python = {"built_against": args.built_against, "requirements": read_requirements(args.requirements)}
            result = manifest(doc, args.deps_version, args.wazuh_commit, args.workflow_run, args.files, python)
            sys.stdout.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        elif args.command == "drift":
            externals_version = deps_version(args.src)
            externals = args.manifest or f"{MIRROR}/{externals_version}/manifest.json"
            python = args.python_manifest or f"{MIRROR}/{deps_version(args.src, 'PYTHON_DEPS_VERSION')}/manifest.json"
            errors = drift(doc, load_manifest(externals))
            errors += drift_python(doc, load_manifest(python), read_requirements(args.requirements), externals_version)
            return _report(errors)
        else:
            warnings = []
            external = None if args.no_make else external_res(args.src, warnings)
            for warning in warnings:
                print(f"WARNING: {warning}", file=sys.stderr)
            return _report(validate(doc, external))
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        return _report([f"<inventory>: {exc}"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
