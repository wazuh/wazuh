#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate THIRD-PARTY-NOTICES and the README third-party table.

Modes (see components.json for the manifest, texts/ for inline license texts):

  notices --artefact manager|standalone --external src/external -o FILE
  readme  --check|--write README.md
  wheels  DIR -o FILE        licenses of the .whl files in DIR
  venv    SITE_PACKAGES -o FILE   licenses of the distributions installed there
  check   --external src/external [--notices FILE]

Standard library only, Python >= 3.8, deterministic output.
"""
import argparse
import email.parser
import importlib.metadata
import io
import json
import os
import re
import sys
import tarfile
import textwrap
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "components.json")
BASE = HERE  # directory that texts/ paths are relative to (manifest dir)
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
BEGIN = "<!-- third-party:begin -->"
END = "<!-- third-party:end -->"
HEADING = "## Software and libraries used"
FIRST_PARTY = {
    "api-communication", "engine-suite", "engine-test-utils",
    "engine-metrics", "engine-helper-test", "engine-it",
}
LICENSE_RE = re.compile(r"^(licen[sc]e|copying|notice)", re.I)
SEP = "=" * 78
SUB = "-" * 78


class GenError(Exception):
    pass


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def clean(text):
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"


def decode(data):
    return clean(data.decode("utf-8", errors="replace"))


ARTEFACTS = ("manager", "standalone", "agent", "readme-only")
REQUIRED = ("name", "version", "spdx", "author", "homepage")


def load_manifest():
    """Return the validated manifest: components, external_ignore, python_overrides."""
    try:
        with open(MANIFEST, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise GenError("cannot load manifest %s: %s" % (MANIFEST, e))
    comps = doc.get("components")
    if not isinstance(comps, list) or not comps:
        raise GenError("manifest has no components")
    for i, c in enumerate(comps):
        who = c.get("name") if isinstance(c, dict) and c.get("name") else \
            "component #%d" % (i + 1)
        if not isinstance(c, dict):
            raise GenError("%s is not an object" % who)
        for key in REQUIRED:
            v = c.get(key)
            if not isinstance(v, str) or not v.strip():
                raise GenError("component %s: missing or empty '%s'" % (who, key))
        arts = c.get("artefacts")
        if not isinstance(arts, list) or not arts:
            raise GenError("component %s: 'artefacts' must be a non-empty list"
                           % who)
        bad = [a for a in arts if a not in ARTEFACTS]
        if bad:
            raise GenError("component %s: unknown artefact %s (allowed: %s)"
                           % (who, ", ".join(map(str, bad)), ", ".join(ARTEFACTS)))
    ignore = doc.get("external_ignore", [])
    for e in ignore:
        if not isinstance(e, dict) or not e.get("dir") or not e.get("reason"):
            raise GenError("external_ignore entries need 'dir' and 'reason'")
    return {"components": comps, "external_ignore": ignore,
            "python_overrides": doc.get("python_overrides", {})}


def python_overrides():
    return {norm(k): v for k, v in load_manifest()["python_overrides"].items()}


def comp_dir(comp):
    """Directory of src/external that backs the component (or None)."""
    d = comp.get("dir")
    if d:
        return d
    files = comp.get("files") or []
    if files:
        return files[0].split("/")[0]
    return None


def read_text(path, what):
    try:
        with open(path, "rb") as f:
            return decode(f.read())
    except OSError:
        raise GenError("missing file for %s: %s" % (what, path))


def tar_open(path):
    try:
        return tarfile.open(path, "r:*")
    except (OSError, tarfile.TarError) as e:
        raise GenError("cannot open archive %s: %s" % (path, e))


def tar_member(tar, member, what):
    cands = [member, member[2:] if member.startswith("./") else "./" + member]
    for c in cands:
        try:
            fobj = tar.extractfile(c)
        except KeyError:
            continue
        if fobj is not None:
            return decode(fobj.read())
    raise GenError("missing member for %s: %s" % (what, member))


# --------------------------------------------------------------------------
# Python distributions
# --------------------------------------------------------------------------
def license_id(meta):
    expr = (meta.get("License-Expression") or "").strip()
    if expr:
        return expr
    lic = (meta.get("License") or "").strip()
    if lic and "\n" not in lic and len(lic) <= 80 and lic.upper() != "UNKNOWN":
        return lic
    cls = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or []
           if c.startswith("License ::")]
    cls = [c for c in cls if c and c != "OSI Approved"]
    if cls:
        return " OR ".join(cls)
    return "unknown"


def parse_meta(raw):
    return email.parser.Parser().parsestr(raw.decode("utf-8", errors="replace"))


def is_license_path(rel):
    """rel: path inside a *.dist-info directory (posix separators)."""
    parts = rel.split("/")
    if parts[0].lower() in ("licenses", "license_files") and len(parts) > 1:
        return True
    return len(parts) == 1 and bool(LICENSE_RE.match(parts[0]))


def dist_block(name, version, spdx, homepage, texts, where, vendored_in=None):
    return {
        "name": name if not vendored_in else "%s (vendored in %s)" % (name, vendored_in),
        "version": version, "spdx": spdx, "homepage": homepage,
        "included": where, "texts": texts,
    }


def meta_fields(meta):
    return (meta.get("Name") or "unknown", meta.get("Version") or "unknown",
            license_id(meta), meta.get("Home-page") or "")


def collect_from_files(files, read, overrides, where):
    """files: iterable of posix paths relative to site-packages.
    read(path) -> bytes. One block per *.dist-info, any depth."""
    infos = {}
    for p in files:
        parts = p.split("/")
        for i, part in enumerate(parts[:-1]):
            if part.endswith(".dist-info"):
                infos.setdefault("/".join(parts[:i + 1]), []).append(
                    "/".join(parts[i + 1:]))
                break
    blocks = []
    for di in sorted(infos):
        rels = infos[di]
        if "METADATA" not in rels:
            continue
        meta = parse_meta(read(di + "/METADATA"))
        name, ver, spdx, home = meta_fields(meta)
        if norm(name) in FIRST_PARTY:
            continue
        texts = []
        for rel in sorted(r for r in rels if is_license_path(r)):
            texts.append((rel, decode(read(di + "/" + rel))))
        if not texts:
            ov = overrides.get(norm(name))
            if ov is None:
                raise GenError("distribution without license file or "
                               "override: %s %s (%s)" % (name, ver, di))
            else:
                texts.append((os.path.basename(ov),
                              read_text(os.path.join(BASE, ov), name)))
        vendored = di.split("/")[0] if "/" in di else None
        blocks.append(dist_block(name, ver, spdx, home, texts, where, vendored))
    blocks.sort(key=lambda b: (norm(b["name"].split(" ")[0]), b["version"],
                               b["name"]))
    return blocks


def python_bundle_blocks(comp, external):
    spec = comp["python-bundle"]
    archive = os.path.join(external, spec["archive"])
    tar = tar_open(archive)
    prefix = spec["site_packages"]
    prefix = prefix[2:] if prefix.startswith("./") else prefix
    names = {}
    for m in tar.getmembers():
        if not m.isfile():
            continue
        n = m.name[2:] if m.name.startswith("./") else m.name
        if n.startswith(prefix + "/"):
            names[n[len(prefix) + 1:]] = m.name

    def read(p):
        f = tar.extractfile(names[p])
        return f.read()

    blocks = collect_from_files(sorted(names), read, python_overrides(),
                                "manager")
    tar.close()
    return blocks


def wheel_blocks(wheel_dir):
    seen = {}
    overrides = python_overrides()
    for fn in sorted(os.listdir(wheel_dir)):
        if not fn.endswith(".whl"):
            continue
        try:
            zf = zipfile.ZipFile(os.path.join(wheel_dir, fn))
        except (OSError, zipfile.BadZipFile) as e:
            raise GenError("unreadable wheel %s: %s" % (fn, e))
        with zf:
            names = zf.namelist()
            blocks = collect_from_files(
                names, lambda p, z=zf: z.read(p), overrides,
                "wazuh-internal-tools")
        for b in blocks:
            key = (norm(b["name"].split(" ")[0]), b["version"], b["name"])
            if key not in seen:
                seen[key] = b
    return [seen[k] for k in sorted(seen)]


def venv_blocks(site):
    site = os.path.abspath(site)
    if not os.path.isdir(site):
        raise GenError("not a directory: %s" % site)
    files = []
    for dp, dn, fn in os.walk(site):
        dn.sort()
        rel = os.path.relpath(dp, site)
        for f in sorted(fn):
            files.append(f if rel == "." else (rel + "/" + f).replace(os.sep, "/"))
    # importlib.metadata over exactly this directory (top-level distributions)
    top = {}
    for d in importlib.metadata.distributions(path=[site]):
        di = getattr(d, "_path", None)
        if di is not None:
            top[os.path.basename(str(di))] = d
    # top-level dist-infos known to importlib, plus nested ones (vendored)
    selected = []
    for f in files:
        if ".dist-info/" not in f:
            continue
        head = f.split(".dist-info/")[0]
        if "/" in head or (head + ".dist-info") in top:
            selected.append(f)

    def read(p):
        with open(os.path.join(site, p), "rb") as fh:
            return fh.read()

    return collect_from_files(selected, read, python_overrides(),
                              "wazuh-internal-tools")


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def render_block(b):
    out = [SEP, "%s %s" % (b["name"], b["version"]), SEP,
           "License:     %s" % b["spdx"]]
    if b.get("homepage"):
        out.append("Homepage:    %s" % b["homepage"])
    out.append("Included in: %s" % b["included"])
    out.append("")
    texts = b["texts"]
    for label, text in texts:
        if len(texts) > 1 or label:
            out.append("%s\n[ %s ]\n%s" % (SUB, label, SUB))
        out.append(text)
    return "\n".join(out)


def render_document(title, intro, blocks):
    head = [title, "", textwrap.fill(intro.strip(), 78, break_on_hyphens=False),
            "", "Contents", ""]
    for i, b in enumerate(blocks, 1):
        head.append("%3d. %s %s (%s)" % (i, b["name"], b["version"], b["spdx"]))
    head.append("")
    return "\n".join(head) + "\n" + "\n".join(render_block(b) for b in blocks)


def component_block(comp, external, tar_cache):
    texts = []
    for rel in comp.get("files", []):
        texts.append((rel, read_text(os.path.join(external, rel), comp["name"])))
    for rel in comp.get("inline", []):
        texts.append((rel, read_text(os.path.join(BASE, rel), comp["name"])))
    if "tarball" in comp:
        spec = comp["tarball"]
        arch = os.path.join(external, spec["archive"])
        tar = tar_cache.get(arch)
        if tar is None:
            tar = tar_cache[arch] = tar_open(arch)
        texts.append(("%s:%s" % (spec["archive"], spec["member"]),
                      tar_member(tar, spec["member"], comp["name"])))
    if not texts:
        raise GenError("no license text source for %s" % comp["name"])
    return {
        "name": comp["name"], "version": comp["version"], "spdx": comp["spdx"],
        "homepage": comp.get("homepage", ""),
        "included": ", ".join(comp["artefacts"]), "texts": texts,
    }


def check_notice_files(comp, external):
    d = comp_dir(comp)
    if not d:
        return
    path = os.path.join(external, d)
    if not os.path.isdir(path):
        raise GenError("directory of %s is not a directory: %s" % (comp["name"], path))
    declared = {os.path.basename(f) for f in comp.get("files", [])}
    for f in sorted(os.listdir(path)):
        if f.upper().startswith("NOTICE") and f not in declared:
            raise GenError("undeclared NOTICE file for %s: %s/%s"
                           % (comp["name"], d, f))


def check_external_coverage(manifest, external):
    if not os.path.isdir(external):
        raise GenError("not a directory: %s" % external)
    known = {comp_dir(c) for c in manifest["components"]}
    known |= {e["dir"] for e in manifest["external_ignore"]}
    for d in sorted(os.listdir(external)):
        if os.path.isdir(os.path.join(external, d)) and d not in known:
            raise GenError("directory %s/%s is neither a component dir nor in "
                           "external_ignore" % (external, d))


INTRO_WHAT = {
    "manager": "the Wazuh manager",
    "standalone": "the Wazuh engine standalone bundle",
}


def build_notices(artefact, external):
    manifest = load_manifest()
    check_external_coverage(manifest, external)
    comps = [c for c in manifest["components"] if artefact in c["artefacts"]]
    comps.sort(key=lambda c: (c["name"].lower(), c["name"]))
    tar_cache = {}
    blocks = []
    try:
        for c in comps:
            check_notice_files(c, external)
            blocks.append(component_block(c, external, tar_cache))
            if "python-bundle" in c and artefact == "manager":
                blocks.extend(python_bundle_blocks(c, external))
    finally:
        for t in tar_cache.values():
            t.close()
    intro = (
        "This file lists the third-party software distributed with %s and "
        "its license texts. It is generated by "
        "src/engine/tools/third-party-notices/generate.py from "
        "components.json and the license files under src/external; do not "
        "edit it by hand. Each entry says which artefact carries it."
        % INTRO_WHAT[artefact])
    return render_document("THIRD-PARTY-NOTICES (artefact: %s)" % artefact,
                           intro, blocks)


# --------------------------------------------------------------------------
# README table
# --------------------------------------------------------------------------
def readme_table():
    comps = sorted(load_manifest()["components"], key=lambda c: (c["name"].lower(), c["name"]))
    cols = ["Software", "Version", "Author", "License"]
    rows = []
    for c in comps:
        name = "[%s](%s)" % (c["name"], c["homepage"]) if c.get("homepage") else c["name"]
        rows.append([name, c["version"], c["author"],
                     c.get("readme_license") or c["spdx"]])
    w = [max(len(cols[i]), max(len(r[i]) for r in rows)) for i in range(4)]

    def line(cells):
        return "| " + " | ".join(x.ljust(w[i]) for i, x in enumerate(cells)) + " |"

    out = [line(cols), "| " + " | ".join("-" * w[i] for i in range(4)) + " |"]
    out += [line(r) for r in rows]
    return "\n".join(out), len(rows)


def readme_apply(text):
    table, n = readme_table()
    block = "%s\n%s\n%s" % (BEGIN, table, END)
    if BEGIN in text and END in text:
        pre, rest = text.split(BEGIN, 1)
        _, post = rest.split(END, 1)
        return pre + block + post, n
    lines = text.split("\n")
    try:
        h = next(i for i, l in enumerate(lines) if l.strip() == HEADING)
    except StopIteration:
        raise GenError("README has no markers and no '%s' heading" % HEADING)
    i = h + 1
    while i < len(lines) and not lines[i].startswith("|"):
        i += 1
    j = i
    while j < len(lines) and lines[j].startswith("|"):
        j += 1
    if i == j:
        raise GenError("no table found under '%s'" % HEADING)
    return "\n".join(lines[:i] + block.split("\n") + lines[j:]), n


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def write_out(path, text):
    if not text.endswith("\n"):
        text += "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def cmd_notices(a):
    write_out(a.output, build_notices(a.artefact, a.external))


def cmd_readme(a):
    with open(a.readme, encoding="utf-8") as f:
        old = f.read()
    new, n = readme_apply(old)
    if a.write:
        if new != old:
            with open(a.readme, "w", encoding="utf-8", newline="\n") as f:
                f.write(new)
        print("README: %d rows" % n)
        return 0
    if BEGIN not in old or new != old:
        print("README third-party table is out of date (run: readme --write)",
              file=sys.stderr)
        return 1
    print("README ok: %d rows" % n)
    return 0


def intro_py(kind):
    return ("Python packages installed in the wazuh-internal-tools package "
            "(%s). The first-party distributions (%s) are excluded."
            % (kind, ", ".join(sorted(FIRST_PARTY))))


def cmd_wheels(a):
    write_out(a.output, render_document(
        "THIRD-PARTY-NOTICES (wazuh-internal-tools, wheels)",
        intro_py("from its wheels"), wheel_blocks(a.dir)))


def cmd_venv(a):
    write_out(a.output, render_document(
        "THIRD-PARTY-NOTICES (wazuh-internal-tools, venv)",
        intro_py("from its virtual environment"), venv_blocks(a.site_packages)))


def cmd_check(a):
    path = a.notices or os.path.join(ROOT, "THIRD-PARTY-NOTICES")
    expected = build_notices("manager", a.external)
    if not expected.endswith("\n"):
        expected += "\n"
    try:
        with open(path, encoding="utf-8") as f:
            actual = f.read()
    except OSError:
        raise GenError("cannot read %s" % path)
    if actual != expected:
        print("%s is out of date (run: notices --artefact manager)" % path,
              file=sys.stderr)
        return 1
    print("%s ok" % path)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("notices")
    s.add_argument("--artefact", choices=["manager", "standalone"], required=True)
    s.add_argument("--external", required=True)
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_notices)
    s = sub.add_parser("readme")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    s.add_argument("readme")
    s.set_defaults(fn=cmd_readme)
    s = sub.add_parser("wheels")
    s.add_argument("dir")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_wheels)
    s = sub.add_parser("venv")
    s.add_argument("site_packages")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_venv)
    s = sub.add_parser("check")
    s.add_argument("--external", required=True)
    s.add_argument("--notices")
    s.set_defaults(fn=cmd_check)
    p.add_argument("--manifest", help="alternative components.json (tests)")
    a = p.parse_args(argv)
    if a.manifest:
        global MANIFEST, BASE
        MANIFEST = os.path.abspath(a.manifest)
        BASE = os.path.dirname(MANIFEST)
    try:
        return a.fn(a) or 0
    except GenError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
