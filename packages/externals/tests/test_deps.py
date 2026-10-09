# Run: python3 -m pytest packages/externals/tests -q

import copy
import fnmatch
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "deps.py"
INVENTORY = HERE.parent / "dependencies.json"
SRC = HERE.parents[2] / "src"

spec = importlib.util.spec_from_file_location("deps", SCRIPT)
deps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deps)

SHA = "a" * 64


def entry(name, **overrides):
    base = {
        "name": name, "version": "1.0.0", "revision": f"v1.0.0-{name}", "source": "upstream",
        "url": f"https://example.com/{name}-{{version}}.tar.gz", "upstream_sha256": SHA,
        "format": "tar.gz", "strip": 1, "patches": [], "targets": ["agent", "manager"],
        "platforms": ["linux"], "cpe": f"cpe:2.3:a:{name}:{name}:*:*:*:*:*:*:*:*",
        "purl": f"pkg:generic/{name}@1.0.0", "license": "MIT", "author": "upstream",
        "homepage": f"https://example.com/{name}",
    }
    base.update(overrides)
    return base


CMAKE_GRAPH, WAZUHEXT = deps.cmake_links((SRC / "external" / "CMakeLists.txt").read_text(encoding="utf-8"))
CMAKE_GRAPH = dict(CMAKE_GRAPH, cpython=WAZUHEXT - deps.WAZUHEXT_NOT_MANAGER)


def doc(*entries):
    """Entries without `links` get the ones src/external/CMakeLists.txt gives among the entries present."""
    names = {e["name"] for e in entries}
    for e in entries:
        if "links" not in e and CMAKE_GRAPH.get(e["name"], set()) & names:
            e["links"] = sorted(CMAKE_GRAPH[e["name"]] & names)
    return {"schema": 1, "entries": list(entries)}


def minimal():
    return doc(entry("curl"), entry("openssl"), entry("zlib"))


def errors(document, external=None, patches_dir=None, repo_root=None, overlays_dir=None):
    return deps.validate(document, external, patches_dir or HERE, repo_root or deps.REPO, overlays_dir or HERE)


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def without(item, field):
    del item[field]
    return item


SNAPSHOT_URL = f"{deps.MIRROR}/99-37702/libraries/sources/geo_db.tar.gz"
PROCPS_CPES = ["cpe:2.3:a:procps_project:procps:*:*:*:*:*:*:*:*", "cpe:2.3:a:procps-ng_project:procps-ng:*:*:*:*:*:*:*:*"]
ALL = {"curl", "openssl", "zlib"}


@pytest.mark.parametrize("make_doc,external,expected", [
    pytest.param(minimal, None, [], id="valid"),
    pytest.param(minimal, {("agent", "linux"): ALL, ("manager", "linux"): ALL}, [], id="external-res-match"),
    pytest.param(minimal, {("agent", "linux"): {"curl", "openssl"}},
                 ["zlib: declared for agent/linux but not in EXTERNAL_RES"], id="external-res-extra"),
    pytest.param(minimal, {("manager", "linux"): ALL | {"sqlite"}},
                 ["sqlite: in EXTERNAL_RES for manager/linux but missing from inventory"], id="external-res-missing"),
    pytest.param(lambda: doc(entry("zlib"), entry("zlib")), None, ["zlib: duplicate name"], id="duplicate"),
    pytest.param(lambda: doc(entry("zlib"), entry("curl")), None,
                 ["<inventory>: entries must be sorted by `name`"], id="unsorted"),
    pytest.param(lambda: doc(without(entry("zlib"), "upstream_sha256")), None,
                 ["zlib: upstream entry needs `upstream_sha256`"], id="upstream-sha"),
    pytest.param(lambda: doc(without(entry("geo_db", source="snapshot", url=SNAPSHOT_URL), "upstream_sha256")), None,
                 ["geo_db: snapshot entry needs `snapshot_sha256`"], id="snapshot-sha"),
    pytest.param(lambda: doc(entry("zlib", upstream_sha256="a" * 63)), None,
                 ["zlib: `upstream_sha256` is not a lowercase sha256"], id="bad-sha"),
    pytest.param(lambda: doc(entry("geo_db", source="snapshot", snapshot_sha256=SHA, url=SNAPSHOT_URL)), None, [],
                 id="snapshot-on-mirror"),
    pytest.param(lambda: doc(entry("rpm", source="snapshot", snapshot_sha256=SHA,
                                   url="https://github.com/rpm-software-management/rpm/archive/rpm-{version}-release.tar.gz")),
                 None, [f"rpm: snapshot entry must point under {deps.MIRROR}/, where its published tree lives"],
                 id="snapshot-off-mirror"),
    pytest.param(lambda: doc(entry("jemalloc", cpe=None, scan=False)), None,
                 ["jemalloc: `scan: false` requires `reason`"], id="scan-false-reason"),
    pytest.param(lambda: doc(entry("jemalloc", cpe=None)), None,
                 ["jemalloc: `cpe: null` requires `scan: false`"], id="null-cpe"),
    pytest.param(lambda: doc(entry("curl", cpe="cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*")), None,
                 ["curl: CPE 'cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*' carries version '8.12.1'; versions belong in `version`"],
                 id="cpe-version"),
    pytest.param(lambda: doc(entry("procps", cpe=PROCPS_CPES)), None, [], id="cpe-list"),
    pytest.param(lambda: doc(entry("procps", cpe="cpe:2.3:a:procps_project:procps:*:*:*:*:*:*:*")), None,
                 ["procps: malformed CPE 'cpe:2.3:a:procps_project:procps:*:*:*:*:*:*:*'"
                  " (expected 13 components starting with cpe:2.3:a:)"], id="cpe-malformed"),
    pytest.param(lambda: doc(entry("zlib", strip="1", colour="blue")), None,
                 ["zlib: `strip` must be int", "zlib: unknown field `colour`"], id="types-unknown-field"),
    pytest.param(lambda: doc(entry("zlib", build=1, subpins={})), None,
                 ["zlib: unknown field `build`", "zlib: unknown field `subpins`"], id="removed-fields"),
    pytest.param(lambda: doc(entry("zlib", targets=["server"], platforms=["beos"])), None,
                 ["zlib: unknown target 'server'", "zlib: unknown platform 'beos'"], id="target-platform"),
    pytest.param(lambda: doc(entry("zlib", format="rar", strip=-1)), None,
                 ["zlib: `format` must be one of ['file', 'tar.bz2', 'tar.gz', 'tar.xz', 'zip']", "zlib: `strip` must be >= 0"],
                 id="format-strip"),
    pytest.param(lambda: doc(entry("pcre2", url="gh:PCRE2Project/pcre2:pcre2-{version}")), None,
                 ["pcre2: `url` must be an http(s) URL, got 'gh:PCRE2Project/pcre2:pcre2-{version}'"], id="url-scheme"),
    pytest.param(lambda: doc(entry("zlib", url="https://x/{foo}.tar.gz")), None,
                 ["zlib: `url` uses unknown placeholder(s) foo"], id="url-placeholder"),
    pytest.param(lambda: doc(entry("date", url="https://x/{revision}.tar.gz")), None, [], id="url-revision"),
    pytest.param(lambda: doc(entry("llhttp", purl="pkg:github/nodejs/llhttp@release%2Fv9.4.2")), None, [], id="purl"),
    pytest.param(lambda: doc(entry("llhttp", purl="pkg:github/nodejs/llhttp@release/v9.4.2")), None,
                 ["llhttp: `purl` 'pkg:github/nodejs/llhttp@release/v9.4.2'"
                  " is not pkg:<type>/<name>@<version> with an encoded version"],
                 id="purl-unencoded"),
])
def test_validate(make_doc, external, expected):
    assert errors(make_doc(), external) == expected


def test_patch_missing(tmp_path):
    result = errors(doc(entry("date", patches=["date/0001-fix.patch"])), patches_dir=tmp_path)
    assert result == [f"date: patch 'date/0001-fix.patch' not found under {tmp_path}"]


def test_patch_present(tmp_path):
    (tmp_path / "date").mkdir()
    (tmp_path / "date" / "0001-fix.patch").write_text("")
    assert errors(doc(entry("date", patches=["date/0001-fix.patch"])), patches_dir=tmp_path) == []


def pin_root(tmp_path, libbpf_tag="v1.7.0", python="3.12.14"):
    (tmp_path / "packages/externals/ebpf").mkdir(parents=True)
    (tmp_path / "packages/externals/ebpf/build_ebpf.sh").write_text(f'#!/bin/sh\nLIBBPF_TAG="{libbpf_tag}"\n')
    (tmp_path / "framework").mkdir()
    (tmp_path / "framework/.python-version").write_text(f"{python}\n")
    return tmp_path


def test_libbpf_tag_mismatch(tmp_path):
    root = pin_root(tmp_path, libbpf_tag="v1.6.0")
    result = errors(doc(entry("libbpf-bootstrap", version="1.7.0", revision="v1.7.0")), repo_root=root)
    assert result == ["libbpf-bootstrap: `revision` is 'v1.7.0' but packages/externals/ebpf/build_ebpf.sh pins 'v1.6.0'"]
    assert errors(doc(entry("libbpf-bootstrap", revision="v1.6.0")), repo_root=root) == []


def test_python_version_mismatch(tmp_path):
    root = pin_root(tmp_path, python="3.12.13")
    result = errors(doc(entry("cpython", version="3.12.14")), repo_root=root)
    assert result == ["cpython: `version` is '3.12.14' but framework/.python-version pins '3.12.13'"]


def test_pin_file_missing(tmp_path):
    result = errors(doc(entry("cpython", version="3.12.14")), repo_root=tmp_path)
    assert result == ["cpython: cannot read framework/.python-version to check `version`"]


def test_cli_exit_codes(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(minimal()))
    bad = tmp_path / "bad.json"
    broken = minimal()
    broken["entries"][0]["cpe"] = "cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*"
    bad.write_text(json.dumps(broken))
    assert run("check", "--no-make", "--inventory", str(good)).returncode == 0
    result = run("check", "--no-make", "--inventory", str(bad))
    assert result.returncode == 1 and "ERROR: curl: CPE" in result.stderr
    assert run().returncode == 2


def overlay_tree(root, name, files):
    for rel, content in files.items():
        (root / name / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / name / rel).write_text(content)
    return root


@pytest.mark.parametrize("field,value,message", [
    ("overlay", "", "`overlay` must not be empty"),
    ("overlay", "../patches", "`overlay` '../patches' is not a directory name"),
    ("overlay", ".", "`overlay` '.' is not a directory name"),
    ("overlay", "..", "`overlay` '..' is not a directory name"),
    ("overlay", "absent", "overlay 'absent' not found or empty under {root}"),
    ("overlay", "empty", "overlay 'empty' not found or empty under {root}"),
    ("subdir", "", "`subdir` must not be empty"),
    ("subdir", "../x", "`subdir` '../x' must be a relative path without empty, . or .. segments"),
    ("subdir", "/x", "`subdir` '/x' must be a relative path without empty, . or .. segments"),
    ("subdir", ".", "`subdir` '.' must be a relative path without empty, . or .. segments"),
    ("subdir", "proc/.", "`subdir` 'proc/.' must be a relative path without empty, . or .. segments"),
])
def test_overlay_schema(field, value, message, tmp_path):
    root = overlay_tree(tmp_path, "rpm", {"sub/.keep": ""})
    (root / "empty" / "sub").mkdir(parents=True)
    assert errors(doc(entry("rpm", overlay="rpm", subdir="proc")), overlays_dir=root) == []
    result = errors(doc(entry("rpm", **{"overlay": "rpm", "subdir": "proc", field: value})), overlays_dir=root)
    assert result == ["rpm: " + message.format(root=root)]


def test_repo_inventory():
    assert run("check", "--no-make", "--inventory", str(INVENTORY)).returncode == 0
    entries = deps.load(INVENTORY)["entries"]
    assert [e["name"] for e in entries if e["source"] == "snapshot"] == ["geo_db"]
    assert [e["name"] for e in entries if e["source"] == "upstream" and "snapshot_sha256" in e] == []
    for e in entries:
        assert all((deps.PATCHES_DIR / p).is_file() for p in e["patches"]), e["name"]
        assert not e.get("overlay") or any(p.is_file() for p in (deps.OVERLAYS_DIR / e["overlay"]).rglob("*")), e["name"]


def test_patch_headers():
    patches = sorted(deps.PATCHES_DIR.rglob("*.patch"))
    assert patches and any(p.parent.name == "rpm" for p in patches)
    for patch in patches:
        text = patch.read_text()
        header = re.split(r"^(?:diff |--- )", text, maxsplit=1, flags=re.M)[0]
        for label in ("Why", "Upstream", "Remove when"):
            assert re.search(rf"^{label}:[ \t]*\S", header, re.M), f"{patch}: no {label}: before the first diff"
        if patch.parent.name == "rpm":
            assert "f85845c26cc8" in text and "CVE-" not in text, patch


@pytest.mark.skipif(shutil.which("make") is None or not (SRC / "Makefile").is_file(), reason="needs make and src/Makefile")
def test_repo_external_res(tmp_path):
    result = run("check", "--inventory", str(INVENTORY), "--src", str(SRC))
    assert result.returncode == 0, result.stderr
    trimmed = deps.load(INVENTORY)
    trimmed["entries"] = [e for e in trimmed["entries"] if e["name"] != "zlib"]
    path = tmp_path / "trimmed.json"
    path.write_text(json.dumps(trimmed))
    result = run("check", "--inventory", str(path), "--src", str(SRC))
    assert result.returncode == 1 and "zlib: in EXTERNAL_RES" in result.stderr


def bash_lookup(env_text, *expressions, tmp_path):
    env = tmp_path / "deps.env"
    env.write_text(env_text)
    script = f"source {env}; " + "; ".join(f"printf '%s\\n' \"{x}\"" for x in expressions)
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout.splitlines()


def test_flatten_expands_urls():
    document = doc(entry("asio", version="1.38.2", url="https://x/asio-{version_dash}.tar.gz"),
                   entry("date", revision="8a93211", url="https://x/{revision}.tar.gz"),
                   entry("sqlite", version="3.51.1", url="https://x/sqlite-{version_concat}-{version_us}.tar.gz"))
    text = deps.flatten(document)
    assert "[asio]=https://x/asio-1-38-2.tar.gz" in text
    assert "[date]=https://x/8a93211.tar.gz" in text
    assert "[sqlite]=https://x/sqlite-3510100-3_51_1.tar.gz" in text


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_flatten_sources_in_bash(tmp_path):
    result = run("flatten", "--inventory", str(INVENTORY))
    assert result.returncode == 0, result.stderr
    values = bash_lookup(result.stdout, "${EXT_SHA256[geo_db]}", "${EXT_TARGET[nlohmann]}", "${EXT_FORMAT[nlohmann]}",
                         "${EXT_SHA256[zlib]}", "${#EXT_URL[@]}", tmp_path=tmp_path)
    entries = {e["name"]: e for e in deps.load(INVENTORY)["entries"]}
    assert values == [entries["geo_db"]["snapshot_sha256"], "nlohmann", "file", entries["zlib"]["upstream_sha256"],
                      str(len(entries))]


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_flatten_quotes(tmp_path):
    odd = "https://x/it's $HOME `id` {version}.tar.gz"
    text = deps.flatten(doc(entry("zlib", url=odd)))
    assert bash_lookup(text, "${EXT_URL[zlib]}", "${EXT_TARGET[zlib]}", tmp_path=tmp_path) == [
        "https://x/it's $HOME `id` 1.0.0.tar.gz", "zlib"]


def test_flatten_rejects_invalid(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc(entry("zlib", format="rar"))))
    result = run("flatten", "--inventory", str(bad))
    assert result.returncode == 1 and result.stdout == "" and "ERROR: zlib:" in result.stderr


README_TEXT = "# Wazuh\n\n<!-- deps-table:begin -->\nold\n<!-- deps-table:end -->\n\n* tail\n"


def test_readme_roundtrip(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(README_TEXT)
    inventory = tmp_path / "deps.json"
    inventory.write_text(json.dumps(minimal()))
    assert run("readme", "--inventory", str(inventory), "--readme", str(readme)).returncode == 0
    text = readme.read_text()
    assert text.startswith("# Wazuh\n\n<!-- deps-table:begin -->\n| Software") and text.endswith("<!-- deps-table:end -->\n\n* tail\n")
    assert "| [zlib](https://example.com/zlib)       | 1.0.0   | upstream | MIT     |" in text
    assert run("readme", "--inventory", str(inventory), "--readme", str(readme), "--check").returncode == 0


def test_readme_check_detects_edit(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(deps.render_readme(README_TEXT, minimal()).replace("zlib)       | 1.0.0", "zlib)       | 9.9.9"))
    inventory = tmp_path / "deps.json"
    inventory.write_text(json.dumps(minimal()))
    result = run("readme", "--inventory", str(inventory), "--readme", str(readme), "--check")
    assert result.returncode == 1 and "-| [zlib](https://example.com/zlib)       | 9.9.9" in result.stderr


def test_readme_needs_markers():
    with pytest.raises(ValueError, match="deps-table:begin"):
        deps.render_readme("# no table\n", minimal())


def test_sbom_real_tree(tmp_path):
    out1, out2 = tmp_path / "a.json", tmp_path / "b.json"
    assert run("sbom", "--output", str(out1)).returncode == 0
    assert run("sbom", "--output", str(out2)).returncode == 0
    assert out1.read_bytes() == out2.read_bytes()
    bom = json.loads(out1.read_text())
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.5")
    refs = [c["bom-ref"] for c in bom["components"]]
    assert refs == sorted(refs) and len(set(refs)) == len(refs)
    pypi = [c for c in bom["components"] if c["purl"].startswith("pkg:pypi/")]
    requirements = deps.read_requirements(deps.REQUIREMENTS)
    assert len(pypi) == len(requirements) and len(bom["components"]) == len(requirements) + len(deps.load(INVENTORY)["entries"])
    cpython = next(c for c in bom["components"] if c["bom-ref"] == "cpython")
    assert cpython["cpe"].startswith("cpe:2.3:a:python:python:*")
    assert all("version" in c and c["properties"][0]["name"] == "syft:location:0:path" for c in bom["components"])


def test_sbom_from_manifest(tmp_path):
    published = tmp_path / "manifest.json"
    published.write_text(json.dumps({"entries": [entry("zlib", cpe=None, scan=False, reason="none")]}))
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("# comment\nPyYAML==6.0.1\n")
    result = run("sbom", "--manifest", str(published), "--requirements", str(requirements))
    bom = json.loads(result.stdout)
    assert [c["bom-ref"] for c in bom["components"]] == ["pypi:pyyaml", "zlib"]
    assert "cpe" not in bom["components"][1]


def test_sbom_target(tmp_path):
    inventory = tmp_path / "deps.json"
    inventory.write_text(json.dumps(doc(entry("rpm", targets=["agent"]), entry("zlib"), entry("rocksdb", targets=["manager"]))))
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("PyYAML==6.0.1\n")
    result = run("sbom", "--inventory", str(inventory), "--requirements", str(requirements), "--target", "manager")
    assert [c["bom-ref"] for c in json.loads(result.stdout)["components"]] == ["pypi:pyyaml", "rocksdb", "zlib"]
    published = tmp_path / "manifest.json"
    published.write_text(json.dumps({"entries": [{k: v for k, v in entry("zlib").items() if k != "targets"}]}))
    result = run("sbom", "--manifest", str(published), "--requirements", str(requirements), "--target", "manager")
    assert result.returncode == 1 and "--target needs `targets` in every entry" in result.stderr


def test_sbom_skips_unpinned_requirements(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("PyYAML==6.0.1\nchardet>=3.0.4\n")
    inventory = tmp_path / "deps.json"
    inventory.write_text(json.dumps(doc(entry("zlib"))))
    result = run("sbom", "--inventory", str(inventory), "--requirements", str(requirements))
    assert result.returncode == 0 and "WARNING:" in result.stderr and "chardet>=3.0.4" in result.stderr
    assert [c["bom-ref"] for c in json.loads(result.stdout)["components"]] == ["pypi:pyyaml", "zlib"]


def test_sbom_skips_validation(tmp_path):
    inventory = tmp_path / "deps.json"
    inventory.write_text(json.dumps(doc(entry("cpython", version="3.0.0"))))
    assert run("check", "--no-make", "--inventory", str(inventory)).returncode == 1
    result = run("sbom", "--inventory", str(inventory))
    assert result.returncode == 0 and json.loads(result.stdout)["components"][0]["version"] == "3.0.0"


def test_flatten_checksum_follows_source():
    item = entry("procps", source="snapshot", snapshot_sha256="b" * 64)
    assert "[procps]=" + "b" * 64 in deps.flatten(doc(item))


def test_sbom_extra_cpes():
    item = entry("procps", cpe=["cpe:2.3:a:procps_project:procps:*:*:*:*:*:*:*:*",
                                "cpe:2.3:a:procps-ng_project:procps-ng:*:*:*:*:*:*:*:*"])
    component = deps.sbom([item], [])["components"][0]
    assert component["cpe"].startswith("cpe:2.3:a:procps_project")
    assert {"name": "syft:cpe23", "value": "cpe:2.3:a:procps-ng_project:procps-ng:*:*:*:*:*:*:*:*"} in component["properties"]


def test_linux_combos_force_uname():
    assert all("uname_S=Linux" in args for (target, platform), args in deps.MAKE_COMBOS.items() if platform == "linux")


# Literal copies: a field dropped from deps.py must fail here, not just lose its case.
CONTENT = ("version", "revision", "source", "url", "upstream_sha256", "snapshot_sha256", "patches", "overlay", "subdir",
           "targets", "platforms")
KEY = ("version", "revision", "source", "upstream_sha256", "snapshot_sha256", "patches", "overlay", "subdir", "targets",
       "platforms", "format", "strip")


def test_field_lists():
    assert (deps.CONTENT_FIELDS, deps.KEY_FIELDS) == (CONTENT, KEY)


BUILD_EXTERNAL = HERE.parent / "build_external.sh"


def shell_functions(*names):
    """The bodies of build_external.sh functions, to test them without running the leg."""
    text = BUILD_EXTERNAL.read_text()
    bodies = []
    for name in names:
        match = re.search(rf"^{name}\(\) \{{(?: [^\n]*\}}\n|\n.*?^\}}\n)", text, re.M | re.S)
        assert match, f"{name}() not found in {BUILD_EXTERNAL}"
        bodies.append(match.group(0))
    return "".join(bodies)


def tarball(path, members, compress="gz"):
    with tarfile.open(path, f"w:{compress}") as archive:
        for member, content in members.items():
            info = tarfile.TarInfo(member)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return path


def fetch(tmp_path, dep):
    env = tmp_path / "deps.env"
    env.write_text(deps.flatten(doc(dep)))
    script = shell_functions("log", "err", "download", "extract", "sha256_of", "fetch_dep")
    script += f"source {shlex.quote(str(env))}\nfetch_dep {dep['name']}\n"
    external = tmp_path / "external"
    external.mkdir(exist_ok=True)
    # Own process group: a regression that copies the wrong tree is killed whole on timeout.
    proc = subprocess.Popen(["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True,
                            env={"PATH": os.environ["PATH"], "WAZUH_SRC": str(tmp_path),
                                 "EXTERNAL_DIR": str(external), "DOWNLOAD_DIR": str(tmp_path / "dl")})
    try:
        stdout, stderr = proc.communicate(timeout=20)
    except BaseException:
        # Also on Ctrl-C: the new session does not get the terminal's SIGINT.
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr), external / dep["name"]


def sha_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


needs_shell = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("curl")), reason="needs bash and curl")


@needs_shell
def test_fetch_dep_checks_sha256(tmp_path):
    archive = tarball(tmp_path / "zlib-1.0.0.tar.gz", {"zlib-1.0.0/zlib.h": b"zlib\n"})
    result, tree = fetch(tmp_path, entry("zlib", url=archive.as_uri(), upstream_sha256=sha_of(archive)))
    assert result.returncode == 0, result.stderr
    assert (tree / "zlib.h").read_text() == "zlib\n"
    result, tree = fetch(tmp_path, entry("zlib", url=archive.as_uri(), upstream_sha256="b" * 64))
    assert result.returncode != 0 and "sha256 mismatch for zlib" in result.stderr


@pytest.mark.skipif(shutil.which("unzip") is None, reason="needs unzip")
def test_fetch_dep_broken_zip(tmp_path):
    archive = tmp_path / "zlib.zip"
    archive.write_bytes(b"not a zip")
    result, tree = fetch(tmp_path, entry("zlib", url=archive.as_uri(), upstream_sha256=sha_of(archive), format="zip",
                                         strip=0))
    assert result.returncode != 0 and not tree.exists()


@needs_shell
@pytest.mark.skipif(shutil.which("zip") is None, reason="needs zip")
def test_fetch_dep_zip_without_top_directory(tmp_path):
    (tmp_path / "flat").mkdir()
    (tmp_path / "flat" / "zlib.h").write_text("flat\n")
    archive = tmp_path / "zlib.zip"
    subprocess.run(["zip", "-qj", str(archive), str(tmp_path / "flat" / "zlib.h")], check=True)
    result, tree = fetch(tmp_path, entry("zlib", url=archive.as_uri(), upstream_sha256=sha_of(archive), format="zip"))
    assert result.returncode != 0 and "no directory to strip" in result.stderr and not tree.exists()


def fetch_procps(tmp_path, **overrides):
    """procps from pkg-1/{proc/a.c,x}, cut to proc/, overlaid and patched."""
    archive = tarball(tmp_path / "procps-1.tar.gz", {"pkg-1/proc/a.c": b"upstream\n", "pkg-1/x": b"x\n"})
    externals = tmp_path / "packages" / "externals"
    overlay_tree(externals / "overlay", "procps", {"a.c": "overlay\n", "sub/b.h": "b\n", ".keep": ""})
    overlay_tree(externals / "patches", "procps", {"0001.patch": "Why: test\n\ndiff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n"
                                                                  "@@ -1 +1 @@\n-overlay\n+patched\n"})
    item = entry("procps", url=archive.as_uri(), upstream_sha256=sha_of(archive), subdir="proc", overlay="procps",
                 patches=["procps/0001.patch"])
    return fetch(tmp_path, dict(item, **overrides))


@needs_shell
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_fetch_dep_subdir_overlay_patch(tmp_path):
    result, tree = fetch_procps(tmp_path)
    assert result.returncode == 0, result.stderr
    assert sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*")) == [".keep", "a.c", "sub", "sub/b.h"]
    assert (tree / "a.c").read_text() == "patched\n"
    assert "keeping proc/ of procps" in result.stdout and "copying overlay/procps/ over procps" in result.stdout


@needs_shell
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_fetch_dep_patch_does_not_apply(tmp_path):
    externals = tmp_path / "packages" / "externals"
    overlay_tree(externals / "patches", "procps", {"0002.patch": "Why: test\n\ndiff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n"
                                                                  "@@ -1 +1 @@\n-nothing like this\n+patched\n"})
    result, tree = fetch_procps(tmp_path, patches=["procps/0002.patch"])
    assert result.returncode != 0 and "patch procps/0002.patch does not apply to procps" in result.stderr
    assert not tree.exists()


@needs_shell
def test_fetch_dep_missing_subdir(tmp_path):
    result, tree = fetch_procps(tmp_path, subdir="nope")
    assert result.returncode != 0 and "nope/ not found" in result.stderr and not tree.exists()


@needs_shell
def test_fetch_dep_missing_overlay(tmp_path):
    result, tree = fetch_procps(tmp_path, overlay="absent")
    assert result.returncode != 0 and "cannot copy overlay/absent/" in result.stderr and not tree.exists()


PUBLISH = HERE.parent / "publish_pool.sh"
# A stand-in for the AWS CLI: objects live under $FAKE_S3/store, every call is logged. With FAKE_RACE set,
# the first put-object of a manifest.json finds that content already there, as if another run wrote it.
FAKE_AWS = r'''#!/bin/bash
key="" body="" out="" cond=no prefix=""
op="$2"; shift 2
while [ $# -gt 0 ]; do
    case "$1" in
        --key) key="$2"; shift 2 ;; --body) body="$2"; shift 2 ;; --bucket) shift 2 ;;
        --prefix) prefix="$2"; key="$2"; shift 2 ;; --query|--output) shift 2 ;;
        --if-none-match) cond=yes; shift 2 ;; help) echo "--if-none-match"; exit 0 ;;
        *) out="$1"; shift ;;
    esac
done
echo "${op} ${key} cond=${cond}" >> "${FAKE_S3}/calls.log"
obj="${FAKE_S3}/store/${key}"
case "${op}" in
    put-object)
        if [ -n "${FAKE_RACE:-}" ] && [[ "${key}" == */manifest.json ]] && [ ! -e "${FAKE_S3}/raced" ]; then
            touch "${FAKE_S3}/raced"; mkdir -p "$(dirname "${obj}")"; printf '%s' "${FAKE_RACE}" > "${obj}"
        fi
        if [ -f "${obj}" ]; then echo "An error occurred (PreconditionFailed)" >&2; exit 254; fi
        mkdir -p "$(dirname "${obj}")" && cp "${body}" "${obj}" ;;
    get-object)
        if [ -n "${FAKE_GET_FAILS:-}" ] && [[ "${key}" == *"${FAKE_GET_FAILS}"* ]]; then
            # A download cut halfway leaves part of the object behind.
            head -c 3 "${obj}" > "${out}"; echo "An error occurred (connection reset)" >&2; exit 254
        fi
        cp "${obj}" "${out}" 2>/dev/null || { echo "An error occurred (NoSuchKey)" >&2; exit 254; } ;;
    list-objects-v2)
        keys="$(cd "${FAKE_S3}/store" 2>/dev/null && find . -type f | sed 's|^\./||' | grep "^${prefix}" | sort | paste -sd '\t' -)"
        echo "${keys:-None}" ;;
esac
'''

needs_publish = pytest.mark.skipif(not all(shutil.which(tool) for tool in ("bash", "sha256sum", "python3")),
                                   reason="needs bash, sha256sum and python3")

CURL_FILES = {"sources/curl.tar.gz": b"curl src\n", "linux/amd64/curl.tar.gz": b"curl bin\n"}
ZLIB_FILES = {"sources/zlib.tar.gz": b"zlib src\n"}


def pool_tree(root, refs_files, document=None, inputs_hash=None):
    """root/<ref>/<rel> for every file plus the manifest.json consolidate.sh writes. Returns {name: ref}."""
    document = document or deps.load(deps.DEFAULT_INVENTORY)
    computed, refs = deps.keys(document), keyed_refs(document)
    for name, files in refs_files.items():
        pool_files(root / refs[name], files)
        manifest = {"schema": 2, "ref": refs[name], "inputs_hash": (inputs_hash or {}).get(name, computed[name][1]),
                    "files": {rel: hashlib.sha256(content).hexdigest() for rel, content in files.items()}}
        (root / refs[name] / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return refs


def run_publish(tmp_path, pool_dir, store=None, race=None, get_fails=None):
    fake = tmp_path / "fake"
    (fake / "bin").mkdir(parents=True, exist_ok=True)
    (fake / "bin" / "aws").write_text(FAKE_AWS)
    (fake / "bin" / "aws").chmod(0o755)
    for key, content in (store or {}).items():
        (fake / "store" / key).parent.mkdir(parents=True, exist_ok=True)
        (fake / "store" / key).write_bytes(content)
    env = {"PATH": f"{fake / 'bin'}:{os.environ['PATH']}", "FAKE_S3": str(fake)}
    if race is not None:
        env["FAKE_RACE"] = race
    if get_fails:
        env["FAKE_GET_FAILS"] = get_fails
    result = subprocess.run(["bash", str(PUBLISH), str(pool_dir), "bucket"], capture_output=True, text=True,
                            env=env, timeout=60)
    log = (fake / "calls.log").read_text().splitlines() if (fake / "calls.log").exists() else []
    return result, [line.split() for line in log], fake / "store"


def puts(calls, prefix=""):
    return [c[1] for c in calls if c[0] == "put-object" and c[1].startswith(prefix)]


@needs_publish
def test_publish_pool_uploads(tmp_path):
    refs = pool_tree(tmp_path / "pool", {"curl": CURL_FILES, "zlib": ZLIB_FILES})
    result, calls, store = run_publish(tmp_path, tmp_path / "pool")
    assert result.returncode == 0, result.stderr
    assert all(c[2] == "cond=yes" for c in calls if c[0] == "put-object")
    for name in ("curl", "zlib"):
        uploaded = puts(calls, f"deps/pool/{refs[name]}/")
        assert uploaded[-1] == f"deps/pool/{refs[name]}/manifest.json" and len(uploaded) == len(set(uploaded))
    local = sorted(p.relative_to(tmp_path / "pool") for p in (tmp_path / "pool").rglob("*") if p.is_file())
    remote = sorted(p.relative_to(store / "deps/pool") for p in (store / "deps/pool").rglob("*") if p.is_file())
    assert local == remote and len(local) == 5
    assert all((tmp_path / "pool" / p).read_bytes() == (store / "deps/pool" / p).read_bytes() for p in local)
    assert "published 2 refs, 0 already in the pool" in result.stdout


def published_manifest(tmp_path, name, **overrides):
    refs = pool_tree(tmp_path / "pool", {name: CURL_FILES})
    manifest = json.loads((tmp_path / "pool" / refs[name] / "manifest.json").read_text())
    return refs[name], json.dumps(dict(manifest, **overrides)).encode()


@needs_publish
def test_publish_pool_already_published(tmp_path):
    ref, manifest = published_manifest(tmp_path, "curl", files={})
    result, calls, _ = run_publish(tmp_path, tmp_path / "pool", store={f"deps/pool/{ref}/manifest.json": manifest})
    assert result.returncode == 0, result.stderr
    assert puts(calls) == [] and f"{ref} is already published" in result.stdout


@needs_publish
def test_publish_pool_other_inputs(tmp_path):
    ref, manifest = published_manifest(tmp_path, "curl", inputs_hash="0" * 64)
    result, calls, _ = run_publish(tmp_path, tmp_path / "pool", store={f"deps/pool/{ref}/manifest.json": manifest})
    assert result.returncode != 0 and f"{ref} is published with other inputs" in result.stderr
    assert puts(calls) == []


@needs_publish
def test_publish_pool_resume_same(tmp_path):
    refs = pool_tree(tmp_path / "pool", {"curl": CURL_FILES})
    key = f"deps/pool/{refs['curl']}/sources/curl.tar.gz"
    result, calls, store = run_publish(tmp_path, tmp_path / "pool", store={key: CURL_FILES["sources/curl.tar.gz"]})
    assert result.returncode == 0, result.stderr
    assert ["get-object", key, "cond=no"] in calls
    published = store / f"deps/pool/{refs['curl']}/manifest.json"
    assert published.read_bytes() == (tmp_path / "pool" / refs["curl"] / "manifest.json").read_bytes()


@needs_publish
def test_publish_pool_adopt(tmp_path):
    refs = pool_tree(tmp_path / "pool", {"curl": CURL_FILES})
    key = f"deps/pool/{refs['curl']}/sources/curl.tar.gz"
    result, _, store = run_publish(tmp_path, tmp_path / "pool", store={key: b"earlier build\n"})
    assert result.returncode == 0, result.stderr
    assert "uploaded by an earlier run with other bytes; keeping it" in result.stdout
    manifest = json.loads((store / f"deps/pool/{refs['curl']}/manifest.json").read_text())
    assert manifest["files"]["sources/curl.tar.gz"] == hashlib.sha256(b"earlier build\n").hexdigest()
    assert manifest["files"]["linux/amd64/curl.tar.gz"] == hashlib.sha256(CURL_FILES["linux/amd64/curl.tar.gz"]).hexdigest()
    assert (store / key).read_bytes() == b"earlier build\n"


@needs_publish
def test_publish_pool_manifest_race(tmp_path):
    ref, manifest = published_manifest(tmp_path, "curl")
    result, _, store = run_publish(tmp_path, tmp_path / "pool", race=manifest.decode())
    assert result.returncode == 0, result.stderr
    assert f"{ref} was published meanwhile by another run" in result.stdout
    assert (store / f"deps/pool/{ref}/manifest.json").read_bytes() == manifest


@needs_publish
def test_publish_pool_tampered(tmp_path):
    refs = pool_tree(tmp_path / "pool", {"curl": CURL_FILES})
    (tmp_path / "pool" / refs["curl"] / "sources/curl.tar.gz").write_bytes(b"tampered\n")
    result, _, store = run_publish(tmp_path, tmp_path / "pool")
    assert result.returncode != 0 and f"{refs['curl']}/sources/curl.tar.gz does not match its manifest" in result.stderr
    assert not (store / f"deps/pool/{refs['curl']}/manifest.json").exists()


def verify_pools(tmp_path, **inputs_hash):
    """A local pool tree and a file:// pool that serves a copy of it, with `inputs_hash` overrides."""
    refs = pool_tree(tmp_path / "local", {"curl": CURL_FILES, "zlib": ZLIB_FILES})
    pool_tree(tmp_path / "pool", {"curl": CURL_FILES, "zlib": ZLIB_FILES}, inputs_hash=inputs_hash)
    return refs, tmp_path / "local", (tmp_path / "pool").as_uri()


def test_verify_pool_ok(tmp_path):
    _, local, pool = verify_pools(tmp_path)
    assert deps.verify(local, pool) == []
    result = run("verify", "--local", str(local), "--pool", pool)
    assert result.returncode == 0, result.stderr


def test_verify_pool_hash(tmp_path):
    refs, local, pool = verify_pools(tmp_path, zlib="0" * 64)
    assert deps.verify(local, pool) == [f"{refs['zlib']}: published with other inputs (inputs_hash differs)"]
    result = run("verify", "--local", str(local), "--pool", pool)
    assert result.returncode == 1 and "other inputs" in result.stderr


def test_verify_pool_file(tmp_path):
    refs, local, pool = verify_pools(tmp_path)
    (tmp_path / "pool" / refs["curl"] / "linux/amd64/curl.tar.gz").write_bytes(b"tampered\n")
    assert deps.verify(local, pool) == [f"{refs['curl']}/linux/amd64/curl.tar.gz: sha256 differs from the manifest"]


def subset(*names):
    document = copy.deepcopy(deps.load(deps.DEFAULT_INVENTORY))
    document["entries"] = [e for e in document["entries"] if e["name"] in names]
    return document


def platform_files(name):
    return {f"{where}/{name}.tar.gz": f"{name} {where}\n".encode() for where in ("sources", "linux/amd64", "windows")}


def tree(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def test_mirror_local_and_pool(tmp_path):
    document = subset("curl", "openssl", "zlib")
    refs = pool_tree(tmp_path / "local", {"curl": platform_files("curl")}, document)
    pool_tree(tmp_path / "pool", {"openssl": platform_files("openssl"), "zlib": platform_files("zlib")}, document)
    dest = tmp_path / "dest"
    missing = deps.mirror(document, dest, tmp_path / "local", (tmp_path / "pool").as_uri(), "agent", "linux/amd64")
    assert missing == []
    assert tree(dest / refs["curl"]) == tree(tmp_path / "local" / refs["curl"])
    for name in ("openssl", "zlib"):
        assert tree(dest / refs[name]) == [f"linux/amd64/{name}.tar.gz", "manifest.json", f"sources/{name}.tar.gz"]
        assert (dest / refs[name] / f"sources/{name}.tar.gz").read_bytes() == f"{name} sources\n".encode()
        manifest = json.loads((dest / refs[name] / "manifest.json").read_text())
        assert manifest == json.loads((tmp_path / "pool" / refs[name] / "manifest.json").read_text())


def test_mirror_missing(tmp_path):
    document = subset("curl", "openssl", "zlib")
    refs = pool_tree(tmp_path / "local", {"curl": platform_files("curl")}, document)
    pool_tree(tmp_path / "pool", {"zlib": platform_files("zlib")}, document)
    missing = deps.mirror(document, tmp_path / "dest", tmp_path / "local", (tmp_path / "pool").as_uri(), "agent",
                          "linux/amd64")
    assert missing == [refs["openssl"]]


def test_mirror_bad_sha(tmp_path):
    document = subset("curl", "openssl", "zlib")
    refs = pool_tree(tmp_path / "pool", {name: platform_files(name) for name in ("curl", "openssl", "zlib")}, document)
    (tmp_path / "pool" / refs["zlib"] / "sources/zlib.tar.gz").write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="sha256 differs from its manifest"):
        deps.mirror(document, tmp_path / "dest", None, (tmp_path / "pool").as_uri(), "agent", "linux/amd64")


def test_mirror_target_filter(tmp_path):
    document, pool = deps.load(deps.DEFAULT_INVENTORY), tmp_path.as_uri()
    entries = {e["name"]: e for e in document["entries"]}

    def names(target, platform):
        return {rel.split("/")[0] for rel in deps.mirror(document, tmp_path / "dest", None, pool, target, platform)}

    agent = names("agent", "linux/amd64")
    assert agent == {n for n, e in entries.items() if "agent" in e["targets"] and "linux" in e["platforms"]}
    assert "curl" in agent and not {"rocksdb", "cpython"} & agent
    assert "cpython" in names("manager", "linux/amd64")
    windows = names("winagent", "windows")
    assert windows and all("windows" in entries[n]["platforms"] and "agent" in entries[n]["targets"] for n in windows)


def test_smoke_build_uses_pool():
    text = (HERE.parent / "smoke_build.sh").read_text(encoding="utf-8")
    assert 'DEPS_POOL_URL="file://${DEPS_DIR}/pool"' in text
    assert "exit 1" not in text[:text.index('make -C "${SRC_DIR}" deps')]


def spec_path(spec):
    return spec.partition("#")[0]


def copy_key_paths(dest):
    """A tree with only the files deps.key_paths() names: keys() must not need anything else."""
    for rel in deps.key_paths():
        src, dst = deps.REPO / rel, Path(dest) / rel
        if rel.endswith("/**"):
            shutil.copytree(src.parent, dst.parent)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)


@pytest.fixture
def key_repo(tmp_path):
    copy_key_paths(tmp_path)
    return tmp_path, copy.deepcopy(deps.load(deps.DEFAULT_INVENTORY))


def changed(before, after):
    return {name for name in before if before[name][0] != after[name][0]}


def with_dependents(document, names):
    """`names` plus every entry that links one of them, transitively."""
    result = set(names)
    while True:
        more = {e["name"] for e in document["entries"] if set(e.get("links", [])) & result} - result
        if not more:
            return result
        result |= more


def edited(document, name, **fields):
    result = copy.deepcopy(document)
    for e in result["entries"]:
        if e["name"] == name:
            e.update(fields)
    return result


def append_byte(path):
    with open(path, "ab") as handle:
        handle.write(b"x")


def recipe_files(repo):
    specs = set(deps.SOURCE_RECIPE) | set(deps.BUILD_RECIPE) | {s for own in deps.OWN_RECIPE.values() for s in own}
    for rel in sorted({spec_path(s) for s in specs}):
        path = Path(repo) / rel
        yield from sorted(p for p in path.parent.rglob("*") if p.is_file()) if rel.endswith("/**") else [path]


def test_key_deterministic(key_repo):
    repo, document = key_repo
    reference = deps.keys(document, deps.REPO)
    entries = {e["name"]: e for e in document["entries"]}
    expected = sorted(f"{deps.ref(entries[n], k)} {h}" for n, (k, h) in reference.items())
    assert len(expected) == 49
    for seed in ("1", "2"):
        result = subprocess.run([sys.executable, str(SCRIPT), "key"], capture_output=True, text=True, cwd=repo,
                                env=dict(os.environ, PYTHONHASHSEED=seed))
        assert result.returncode == 0, result.stderr
        assert sorted(result.stdout.splitlines()) == expected
    for path in recipe_files(repo):
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert deps.keys(document, repo) == reference


@pytest.mark.parametrize("field", ["version", "upstream_sha256", "targets", "platforms"])
def test_key_own_inputs(field, key_repo):
    repo, document = key_repo
    zlib = next(e for e in document["entries"] if e["name"] == "zlib")
    value = {"version": "9.9.9", "upstream_sha256": "b" * 64,
             "targets": [t for t in zlib["targets"] if t != "agent"],
             "platforms": [p for p in zlib["platforms"] if p != "windows"]}[field]
    assert value != zlib[field]
    before = deps.keys(document, repo)
    after = deps.keys(edited(document, "zlib", **{field: value}), repo)
    assert changed(before, after) == {"zlib", "curl", "date", "rpm", "cpython"}


def test_key_patch_and_overlay(key_repo):
    repo, document = key_repo
    rxcpp = next(e for e in document["entries"] if e["name"] == "RxCpp")
    before = deps.keys(document, repo)
    append_byte(repo / "packages/externals/patches" / rxcpp["patches"][0])
    after = deps.keys(document, repo)
    assert changed(before, after) == {"RxCpp"}
    append_byte(next(p for p in (repo / "packages/externals/overlay/popt").rglob("*") if p.is_file()))
    expected = with_dependents(document, {"popt"})
    assert "rpm" in expected
    assert changed(after, deps.keys(document, repo)) == expected


def edit_spec(repo, spec):
    """Edit a file, or the n-th block (`file#marker:n`, first by default) of a marked file."""
    if "#" in spec:
        rel, _, marker = spec.partition("#")
        marker, _, nth = marker.partition(":")
        path = repo / rel
        parts = path.read_text(encoding="utf-8").split(f"# {marker}: end")
        index = int(nth or 0)
        assert len(parts) > index + 1, spec
        parts[index] += "# edited\n"
        path.write_text(f"# {marker}: end".join(parts), encoding="utf-8")
    else:
        append_byte(repo / spec)


@pytest.mark.parametrize("spec", ["packages/externals/build_external.sh", "packages/externals/generate_external.sh",
                                  "packages/externals/consolidate.sh"])
def test_key_source_recipe(spec, key_repo):
    repo, document = key_repo
    before = deps.keys(document, repo)
    edit_spec(repo, spec)
    own = set(deps.OWN_RECIPE)
    expected = with_dependents(document, {e["name"] for e in document["entries"]} - own)
    assert "nlohmann" in expected and "libbpf-bootstrap" not in expected
    assert changed(before, deps.keys(document, repo)) == expected


@pytest.mark.parametrize("spec", ["src/external/CMakeLists.txt", "src/CMakeLists.txt#deps-recipe",
                                  "src/Makefile#deps-recipe:0", "src/Makefile#deps-recipe:1", "KEY_EPOCH"])
def test_key_common_recipe(spec, key_repo, monkeypatch):
    repo, document = key_repo
    before = deps.keys(document, repo)
    if spec == "KEY_EPOCH":
        monkeypatch.setattr(deps, "KEY_EPOCH", deps.KEY_EPOCH + 1)
    else:
        edit_spec(repo, spec)
    built = {e["name"] for e in document["entries"] if e.get("built", True)}
    if spec == "KEY_EPOCH":
        # Raising KEY_EPOCH rebuilds every entry, including the ones without a recipe.
        expected = {e["name"] for e in document["entries"]}
    else:
        expected = built - {"libbpf-bootstrap"}
    assert changed(before, deps.keys(document, repo)) == expected


def test_key_platform_recipe(key_repo):
    repo, document = key_repo
    images_path = repo / "packages/externals/builder-images.json"
    before = deps.keys(document, repo)
    images = json.loads(images_path.read_text(encoding="utf-8"))
    images["windows"]["agent"] = "ghcr.io/wazuh/compile_windows_agent@sha256:" + "c" * 64
    images_path.write_text(json.dumps(images), encoding="utf-8")
    windows = {e["name"] for e in document["entries"] if e.get("built", True) and "windows" in e["platforms"]}
    assert windows
    assert changed(before, deps.keys(document, repo)) == with_dependents(document, windows)


@pytest.mark.parametrize("field,value", [("license", "Other"), ("cpe", None), ("notes", "edited"),
                                         ("homepage", "https://example.com/curl"),
                                         ("url", "https://example.com/curl-{version}.tar.gz")])
def test_key_ignores_metadata(field, value, key_repo):
    repo, document = key_repo
    before = deps.keys(document, repo)
    assert changed(before, deps.keys(edited(document, "curl", **{field: value}), repo)) == set()


@pytest.mark.parametrize("name,expected", [
    ("openssl", {"openssl", "curl", "date", "rpm", "cpython"}),
    ("curl", {"curl", "date", "cpython"}),
    ("bzip2", {"bzip2", "rocksdb", "cpython"}),
    ("abseil-cpp", {"abseil-cpp", "re2"}),
])
def test_key_propagation(name, expected, key_repo):
    repo, document = key_repo
    before = deps.keys(document, repo)
    assert changed(before, deps.keys(edited(document, name, version="9.9.9"), repo)) == expected


@pytest.mark.parametrize("spec,expected", [
    ("framework/cpython/compile.sh", {"cpython"}),
    ("framework/requirements.txt", {"cpython"}),
    ("src/Makefile#cpython-recipe", {"cpython"}),
    ("packages/externals/ebpf/build_ebpf.sh", {"libbpf-bootstrap"}),
    ("src/syscheckd/src/ebpf/src/modern.bpf.c", {"libbpf-bootstrap"}),
    ("framework/cpython/custom/Setup.local", {"cpython"}),
    ("framework/.python-version", {"cpython"}),
])
def test_key_own_recipe(spec, expected, key_repo):
    repo, document = key_repo
    before = deps.keys(document, repo)
    rel, _, marker = spec.partition("#")
    if marker:
        path = repo / rel
        text = path.read_text(encoding="utf-8")
        assert f"# {marker}: end" in text
        path.write_text(text.replace(f"# {marker}: end", f"# edited\n# {marker}: end"), encoding="utf-8")
    else:
        append_byte(repo / rel)
    assert changed(before, deps.keys(document, repo)) == expected


def test_key_paths_cover(tmp_path):
    document = deps.load(deps.DEFAULT_INVENTORY)
    copy_key_paths(tmp_path)
    assert deps.keys(document, tmp_path) == deps.keys(document, deps.REPO)
    for rel in deps.key_paths():
        if rel.endswith("/**"):
            assert (deps.REPO / rel).parent.is_dir(), rel
        else:
            assert (deps.REPO / rel).is_file(), rel


def test_ref_format():
    document = deps.load(deps.DEFAULT_INVENTORY)
    computed = deps.keys(document)
    for e in document["entries"]:
        pattern = rf"^{re.escape(e['name'])}/{re.escape(e['version'])}-[0-9a-f]{{8}}$"
        assert re.match(pattern, deps.ref(e, computed[e["name"]][0])), e["name"]


@pytest.mark.parametrize("entries,message", [
    ([entry("aaa", links=["nope"])], "aaa: `links` names unknown entry 'nope'"),
    ([entry("aaa", links=["aaa"])], "aaa: `links` names the entry itself"),
    ([entry("aaa", built=False, links=["bbb"]), entry("bbb")], "aaa: an entry with `built: false` has no binary to link"),
    ([entry("aaa", links=["bbb", "bbb"]), entry("bbb")], "aaa: `links` repeats 'bbb'"),
], ids=["unknown", "self", "built-false", "repeated"])
def test_links_errors(entries, message):
    assert message in errors(doc(*entries))


def test_links_cycle():
    document = doc(entry("aaa", links=["bbb"]), entry("bbb", links=["aaa"]))
    assert "aaa: `links` cycle aaa -> bbb -> aaa" in errors(document)
    with pytest.raises(ValueError, match="`links` cycle"):
        deps.keys(document)


def test_links_match_cmake():
    document = copy.deepcopy(deps.load(deps.DEFAULT_INVENTORY))
    assert [e for e in deps.validate(document) if "`links`" in e] == []
    rocksdb = next(e for e in document["entries"] if e["name"] == "rocksdb")
    rocksdb["links"].remove("bzip2")
    assert any(e.startswith("rocksdb:") and "DEPENDS" in e for e in deps.validate(document))


@pytest.mark.parametrize("change", [lambda links: links + ["jemalloc"], lambda links: [l for l in links if l != "openssl"]],
                         ids=["extra", "missing"])
def test_links_cpython_wazuhext(change):
    document = copy.deepcopy(deps.load(deps.DEFAULT_INVENTORY))
    cpython = next(e for e in document["entries"] if e["name"] == "cpython")
    cpython["links"] = sorted(change(cpython["links"]))
    assert any("cpython: `links`" in e and "WAZUHEXT_WHOLE_LIBS" in e for e in deps.validate(document))


def test_lock_roundtrip(tmp_path):
    lock = tmp_path / "deps.lock.mk"
    assert run("lock", "--output", str(lock)).returncode == 0
    first = lock.read_text(encoding="utf-8")
    assert run("lock", "--output", str(lock)).returncode == 0
    assert lock.read_text(encoding="utf-8") == first
    lines = first.splitlines()
    assert len(lines) == 50 and lines[0].startswith("#")
    names = [line.split()[0].removeprefix("DEP_REF_") for line in lines[1:]]
    assert names == sorted(names)


def test_lock_check_stale(tmp_path):
    lock = tmp_path / "deps.lock.mk"
    assert run("lock", "--output", str(lock)).returncode == 0
    assert run("lock", "--check", "--output", str(lock)).returncode == 0
    lines = lock.read_text(encoding="utf-8").splitlines(True)
    lines[1] = lines[1].rstrip("\n") + "0\n"
    lock.write_text("".join(lines), encoding="utf-8")
    result = run("lock", "--check", "--output", str(lock))
    assert result.returncode == 1
    assert lines[1].rstrip("\n") in result.stderr


@pytest.mark.skipif(shutil.which("make") is None, reason="needs make")
def test_lock_make_parses(tmp_path):
    lock = tmp_path / "deps.lock.mk"
    assert run("lock", "--output", str(lock)).returncode == 0
    result = subprocess.run(["make", "-f", str(lock), "-p"], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode in (0, 2), result.stderr
    assert re.search(r"^DEP_REF_libbpf-bootstrap := libbpf-bootstrap/", result.stdout, re.M)
    assert re.search(r"^DEP_REF_curl := curl/", result.stdout, re.M)


def test_builder_images_macos_runners():
    workflow = (deps.REPO / ".github/workflows/5_builderpackage_externals.yml").read_text(encoding="utf-8")
    runners = set(re.findall(r"system: macos,.*runner: ([\w.-]+)", workflow))
    assert runners and runners == set(deps.load(deps.BUILDER_IMAGES)["darwin"]["runners"])


@pytest.mark.parametrize("path,value", [(("linux", "agent", "amd64"), "ghcr.io/wazuh/x:5.0.0"),
                                        (("windows", "agent"), None), (("darwin", "runners"), [])])
def test_builder_images_format(path, value):
    images = copy.deepcopy(deps.load(deps.BUILDER_IMAGES))
    node = images
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    assert deps.check_builder_images(images)
    assert deps.check_builder_images(deps.load(deps.BUILDER_IMAGES)) == []


@pytest.mark.parametrize("text,expected", [
    ("ExternalProject_Add(a_external\n  DEPENDS b_external)\n", {"a": {"b"}}),
    ("ExternalProject_Add(a_external\n  DEPENDS\n  b_external # why\n  ext_c\n  BUILD_COMMAND x)\n", {"a": {"b", "c"}}),
    ("add_custom_target(z_external)\nExternalProject_Add(a_external DEPENDS b_external)\n", {"a": {"b"}}),
])
def test_cmake_links_parser(text, expected):
    assert deps.cmake_links(text)[0] == expected


def test_cmake_links_variable():
    with pytest.raises(ValueError, match="cannot be resolved"):
        deps.cmake_links("ExternalProject_Add(a_external DEPENDS ${DEPS})\n")


def test_validate_builder_images(tmp_path):
    images = tmp_path / "packages/externals/builder-images.json"
    images.parent.mkdir(parents=True)
    images.write_text(json.dumps({"linux": {}}), encoding="utf-8")
    assert any(e.startswith("<builder-images>:") for e in errors(minimal(), repo_root=tmp_path))


def test_key_platform_recipe_linux(key_repo):
    repo, document = key_repo
    images_path = repo / "packages/externals/builder-images.json"
    before = deps.keys(document, repo)
    images = json.loads(images_path.read_text(encoding="utf-8"))
    images["linux"]["manager"]["amd64"] = "ghcr.io/wazuh/pkg_rpm_manager_builder_amd64@sha256:" + "d" * 64
    images_path.write_text(json.dumps(images), encoding="utf-8")
    manager = {e["name"] for e in document["entries"] if e.get("built", True) and e["name"] != "libbpf-bootstrap"
               and "linux" in e["platforms"] and "manager" in e["targets"]}
    assert "rocksdb" in manager and "dbus" not in manager
    assert changed(before, deps.keys(document, repo)) == with_dependents(document, manager)


@pytest.mark.parametrize("field,value", [("format", "zip"), ("strip", 2)])
def test_key_format_strip(field, value, key_repo):
    repo, document = key_repo
    before = deps.keys(document, repo)
    assert changed(before, deps.keys(edited(document, "nlohmann", **{field: value}), repo)) == {"nlohmann"}


def test_key_binary_crlf_kept(key_repo):
    repo, document = key_repo
    blob = repo / "framework/cpython/custom/blob.bin"
    blob.write_bytes(b"\0\r\n")
    before = deps.keys(document, repo)
    blob.write_bytes(b"\0\n")
    assert changed(before, deps.keys(document, repo)) == {"cpython"}


def test_key_paths_literal():
    assert deps.key_paths() == sorted([
        "framework/.python-version", "framework/cpython/compile.sh", "framework/cpython/custom/**",
        "framework/requirements.txt", "packages/externals/build_external.sh", "packages/externals/builder-images.json",
        "packages/externals/consolidate.sh", "packages/externals/dependencies.json", "packages/externals/ebpf/build_ebpf.sh",
        "packages/externals/generate_external.sh", "packages/externals/overlay/**", "packages/externals/patches/**",
        "src/CMakeLists.txt", "src/Makefile", "src/external/CMakeLists.txt", "src/syscheckd/src/ebpf/src/modern.bpf.c"])


def test_recipe_unpaired_marker(key_repo):
    repo, document = key_repo
    path = repo / "src/Makefile"
    path.write_text(path.read_text(encoding="utf-8").replace("# deps-recipe: begin\n", "", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="matching"):
        deps.keys(document, repo)


@pytest.mark.parametrize("text", ["ExternalProject_Add(a_external DEPENDS sqlite3)\n",
                                  'ExternalProject_Add(a_external DEPENDS "b_external")\n',
                                  "set(WAZUHEXT_WHOLE_LIBS ext_zlib ${MORE})\n"])
def test_cmake_links_unresolved(text):
    with pytest.raises(ValueError, match="cannot be resolved"):
        deps.cmake_links(text)


LOCK_REFS = dict(re.findall(r"^DEP_REF_(\S+) := (\S+)$", (SRC / "deps.lock.mk").read_text(encoding="utf-8"), re.M))
needs_make_pool = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("make", "curl", "gunzip"))
    or (platform.system(), platform.machine()) != ("Linux", "x86_64"), reason="needs make, curl and gunzip on Linux x86_64")


def make_src(tmp_path, pool, *goal_and_extra, dry_run=False, url=None):
    """Run src/Makefile and the real lock from a scratch src/ against a file:// pool, or `url`."""
    src = tmp_path / "src"
    (src / "external").mkdir(parents=True, exist_ok=True)
    for name in ("Makefile", "deps.lock.mk"):
        shutil.copy(SRC / name, src / name)
    args = ["make", "-s"] + (["-n"] if dry_run else []) + ["-C", str(src), *goal_and_extra, f"DEPS_POOL_URL={url or pool.as_uri()}"]
    return subprocess.run(args, capture_output=True, text=True, timeout=60), src / "external"


def pool_entry(pool, name, sources=False, precompiled=False):
    """Publish <name>/FROM, saying which tarball it came from, under the lock's ref of <name>."""
    for wanted, where in ((sources, "sources"), (precompiled, "linux/amd64")):
        if wanted:
            (pool / LOCK_REFS[name] / where).mkdir(parents=True)
            tarball(pool / LOCK_REFS[name] / where / f"{name}.tar.gz", {f"{name}/FROM": where.encode()})


@needs_make_pool
def test_make_pool_precompiled(tmp_path):
    pool_entry(tmp_path / "pool", "cJSON", sources=True, precompiled=True)
    result, external = make_src(tmp_path, tmp_path / "pool", "external/cJSON.tar.gz")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (external / "cJSON" / "FROM").read_text() == "linux/amd64"


@needs_make_pool
def test_make_pool_fallback_sources(tmp_path):
    pool_entry(tmp_path / "pool", "cJSON", sources=True)
    result, external = make_src(tmp_path, tmp_path / "pool", "external/cJSON.tar.gz")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (external / "cJSON" / "FROM").read_text() == "sources"
    assert [p.name for p in external.iterdir()] == ["cJSON"]


@needs_make_pool
@pytest.mark.parametrize("extra", [(), ("EXTERNAL_SRC_ONLY=yes",)])
def test_make_pool_missing(extra, tmp_path):
    (tmp_path / "pool").mkdir()
    result, external = make_src(tmp_path, tmp_path / "pool", "external/cJSON.tar.gz", *extra)
    assert result.returncode != 0 and "Dependency cJSON failed installation" in result.stdout + result.stderr
    assert not list(external.glob("cJSON*"))


@needs_make_pool
def test_make_pool_no_ref(tmp_path):
    pool_entry(tmp_path / "pool", "cJSON", sources=True)
    result, _ = make_src(tmp_path, tmp_path / "pool", "external/cJSON.tar.gz", "DEP_REF_cJSON=")
    assert result.returncode != 0 and "cJSON: no DEP_REF_cJSON in deps.lock.mk" in result.stderr


@needs_make_pool
def test_make_pool_cpython_tzdata_urls(tmp_path):
    pool = tmp_path / "pool"
    result, _ = make_src(tmp_path, pool, "external/cpython.tar.gz", "external/tzdata.tar.gz", dry_run=True)
    assert result.returncode == 0, result.stderr
    for url in (f"{LOCK_REFS['cpython']}/sources/cpython_x86_64.tar.gz", f"{LOCK_REFS['cpython']}/linux/amd64/cpython.tar.gz",
                f"{LOCK_REFS['tzdata']}/sources/tzdata.tar.gz"):
        assert f"{pool.as_uri()}/{url}" in result.stdout


def pool_mirror(root, **inputs_hash):
    """A file:// pool with the manifest.json of every ref the inventory keys; `name=None` leaves one out."""
    document = deps.load(deps.DEFAULT_INVENTORY)
    computed = deps.keys(document)
    entries = {e["name"]: e for e in document["entries"]}
    for name, (key, digest) in computed.items():
        digest = inputs_hash.get(name, digest)
        if digest is not None:
            where = root / deps.ref(entries[name], key)
            where.mkdir(parents=True)
            (where / "manifest.json").write_text(json.dumps({"inputs_hash": digest}))
    return document, root.as_uri()


@pytest.mark.parametrize("override,expected", [({}, None), ({"curl": None}, "is not published"),
                                               ({"curl": "0" * 64}, "inputs_hash differs")], ids=["ok", "missing", "hash"])
def test_pool_check(override, expected, tmp_path):
    document, pool = pool_mirror(tmp_path, **override)
    assert len(document["entries"]) == 49
    result = deps.pool_check(document, pool)
    if expected is None:
        assert result == []
    else:
        assert len(result) == 1 and result[0].startswith("curl: ") and expected in result[0]


def test_pool_check_cli(tmp_path):
    _, pool = pool_mirror(tmp_path, zlib=None)
    result = run("pool-check", "--pool", pool)
    assert result.returncode == 1 and "zlib:" in result.stderr


WORKFLOWS = deps.REPO / ".github/workflows"
EXTERNALS_WORKFLOW = WORKFLOWS / "5_builderpackage_externals.yml"
LOCK_WORKFLOW = WORKFLOWS / "5_codequality_externals-lock.yml"


def covered(rel, patterns):
    return any(rel.startswith(p[:-2]) if p.endswith("/**") else fnmatch.fnmatch(rel, p) for p in patterns)


def paths_blocks(text):
    """The items of every `paths:` list of a workflow, unquoted."""
    blocks, lines = [], text.splitlines()
    for i, line in enumerate(lines):
        key = re.match(r"^( *)paths:\s*$", line)
        if not key:
            continue
        items = []
        for nxt in lines[i + 1:]:
            if not nxt.strip() or nxt.lstrip().startswith("#"):
                continue
            item = re.match(r"""^( *)- *(['"]?)(.*?)\2\s*(?:#.*)?$""", nxt)
            if not item or len(item.group(1)) < len(key.group(1)):
                break
            items.append(item.group(3))
        blocks.append(items)
    return blocks


def jobs(text):
    body = text[re.search(r"^jobs:\n", text, re.M).end():]
    return dict(re.findall(r"^  ([\w-]+):\n((?:(?:    .*|)\n)*)", body, re.M))


def job_steps(job):
    """Each step of a job as {"name", "if", "uses", "run", "text"}."""
    steps_block = job[re.search(r"^    steps:\n", job, re.M).end():]
    steps = []
    for text in re.split(r"^(?=      - )", steps_block, flags=re.M)[1:]:
        text = "        " + text[8:]
        fields = {key: (m.group(1).strip() if (m := re.search(rf"^        {key}: (.*)$", text, re.M)) else None)
                  for key in ("name", "if", "uses", "run")}
        if fields["run"] == "|":
            body = re.search(r"^        run: \|\n((?:(?: {10}.*|)\n)*)", text, re.M).group(1)
            fields["run"] = "\n".join(line[10:] for line in body.splitlines()) + "\n"
        fields["text"] = text
        steps.append(fields)
    return steps


def job_needs(job):
    needs = re.search(r"^    needs: \[?([^\]\n]*)\]?$", job, re.M)
    return [n.strip() for n in needs.group(1).split(",")] if needs else []


def test_build_workflow_paths():
    blocks = paths_blocks(EXTERNALS_WORKFLOW.read_text(encoding="utf-8"))
    assert len(blocks) == 1, "the workflow needs one pull_request paths list"
    required = deps.key_paths() + ["src/deps.lock.mk", EXTERNALS_WORKFLOW.relative_to(deps.REPO).as_posix()]
    assert [rel for rel in required if not covered(rel, blocks[0])] == []


def test_lock_workflow_paths():
    text = LOCK_WORKFLOW.read_text(encoding="utf-8")
    trigger = re.search(r"^on:\n  pull_request:\n    types: \[([^\]]*)\]\n", text, re.M)
    assert trigger and "ready_for_review" in [t.strip() for t in trigger.group(1).split(",")]
    blocks = paths_blocks(text)
    assert len(blocks) == 1, "the workflow needs one pull_request paths list"
    required = deps.key_paths() + ["src/deps.lock.mk", "README.md", LOCK_WORKFLOW.relative_to(deps.REPO).as_posix()]
    assert [rel for rel in required if not covered(rel, blocks[0])] == []
    assert not covered("src/foo.c", blocks[0])
    steps = [step for job in jobs(text).values() for step in job_steps(job)]
    for command in ("deps.py lock --check", "deps.py pool-check", "deps.py check", "deps.py readme --check"):
        assert [step for step in steps if step["run"] and command in step["run"]], command
    assert not (WORKFLOWS / "5_codequality_externals-drift.yml").exists()


def test_workflows_skip_drafts():
    guard = "    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}\n"
    assert guard in jobs(EXTERNALS_WORKFLOW.read_text(encoding="utf-8"))["check"]
    assert guard in jobs(LOCK_WORKFLOW.read_text(encoding="utf-8"))["check-lock"]


def test_workflows_filter_lock():
    missing = [path.name for path in sorted(WORKFLOWS.glob("*.yml"))
               for block in paths_blocks(path.read_text(encoding="utf-8"))
               if "src/Makefile" in block and "src/deps.lock.mk" not in block]
    assert missing == []


def docker_commands(run_body):
    return re.findall(r"docker run(?:[^\n]*\\\n)*[^\n]*", run_body)


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_workflow_images_by_digest(tmp_path):
    text = EXTERNALS_WORKFLOW.read_text(encoding="utf-8")
    assert [s for s in ("pull_image_from_ghcr.sh", "docker_image_tag", "deps_version") if s in text.lower()] == []
    docker_jobs = 0
    for name, job in jobs(text).items():
        steps = job_steps(job)
        runs_docker = [i for i, step in enumerate(steps)
                       if step["run"] and ("docker " in step["run"] or "generate_external.sh" in step["run"])]
        for step in steps:
            for command in docker_commands(step["run"] or ""):
                assert re.search(r'"[^"]+:\$\{BUILDER_TAG\}"', command) and "ghcr.io" not in command, (name, command)
        if not runs_docker:
            continue
        docker_jobs += 1
        pulls = [i for i, step in enumerate(steps) if step["run"] and "pull_builder_image.sh" in step["run"]]
        assert pulls and pulls[0] < runs_docker[0], name
    assert docker_jobs == 3

    log = tmp_path / "docker.log"
    bin_dir = fake_tools(tmp_path / "bin", {"docker": f'echo "$*" >> {shlex.quote(str(log))}; cat > /dev/null'})
    github_env = tmp_path / "github_env"
    github_env.write_text("EARLIER=1\n")
    result = subprocess.run(["bash", str(HERE.parent / "pull_builder_image.sh"), "pkg_rpm_manager_builder_amd64",
                             "linux", "manager", "amd64"], capture_output=True, text=True, timeout=60,
                            env=dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", GHCR_TOKEN="token",
                                     GITHUB_ACTOR="actor", GITHUB_ENV=str(github_env)))
    assert result.returncode == 0, result.stdout + result.stderr
    image = run("builder-image", "linux", "manager", "amd64").stdout.strip()
    digest = re.fullmatch(r"\S+@sha256:([0-9a-f]{64})", image).group(1)
    assert log.read_text().splitlines() == ["login ghcr.io -u actor --password-stdin", f"pull {image}",
                                           f"tag {image} pkg_rpm_manager_builder_amd64:{digest[:12]}"]
    assert github_env.read_text() == f"EARLIER=1\nBUILDER_TAG={digest[:12]}\n"


def test_publish_gated():
    workflow = jobs(EXTERNALS_WORKFLOW.read_text(encoding="utf-8"))
    publish = workflow["publish"]
    assert re.search(r"^    if: vars\.DEPS_POOL_PUBLISH == 'true'$", publish, re.M)
    assert re.search(r"^    environment: deps-publish$", publish, re.M)
    assert re.search(r"^    concurrency:\n(?:      .*\n)*?      cancel-in-progress: false$", publish, re.M)
    assert "smoke-build" in job_needs(publish)
    steps = job_steps(publish)
    role = [i for i, step in enumerate(steps) if (step["uses"] or "").startswith("aws-actions/configure-aws-credentials")]
    downloads = [i for i, step in enumerate(steps) if re.search(r"/download_(s3_artifact|package)$", step["uses"] or "")]
    assert len(role) == 1 and downloads and max(downloads) < role[0]
    assert job_needs(workflow["verify"]) == ["publish"]


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_build_workflow_plan_outputs(tmp_path):
    check = jobs(EXTERNALS_WORKFLOW.read_text(encoding="utf-8"))["check"]
    outputs = re.search(r"^    outputs:\n((?:      .*\n)+)", check, re.M).group(1)
    assert dict(re.findall(r"^      (\w+): \$\{\{ steps\.plan\.outputs\.(\w+) \}\}$", outputs, re.M)) == \
        {name: name for name in ("missing", "legs", "ebpf", "cpython")}
    body = next(step["run"] for step in job_steps(check) if step["name"] == "Plan the refs to build")
    bin_dir = fake_tools(tmp_path / "bin", {"python3": 'echo "${PLAN}"'})
    for plan, legs, ebpf, cpython in (("", "false", "false", "false"), ("curl date cpython", "true", "false", "true"),
                                      ("cpython libbpf-bootstrap", "false", "true", "true")):
        output = tmp_path / "github_output"
        output.write_text("")
        result = subprocess.run(["bash", "-c", body], capture_output=True, text=True, timeout=20,
                                env=dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", PLAN=plan,
                                         GITHUB_OUTPUT=str(output)))
        assert result.returncode == 0, result.stderr
        assert output.read_text().splitlines() == [f"missing={plan}", f"legs={legs}", f"ebpf={ebpf}",
                                                   f"cpython={cpython}"], plan


@needs_make_pool
def test_make_pool_http_404(tmp_path):
    """Over HTTP a missing tarball is a 404 page, which must not be saved as the tarball."""
    import functools
    import http.server
    import threading
    pool = tmp_path / "pool"
    pool.mkdir()

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(pool)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        result, external = make_src(tmp_path, pool, "external/cJSON.tar.gz", url=url)
        assert result.returncode != 0 and "Dependency cJSON failed installation" in result.stdout + result.stderr
        assert not list(external.glob("cJSON*"))
        pool_entry(pool, "cJSON", sources=True)
        result, external = make_src(tmp_path, pool, "external/cJSON.tar.gz", url=url)
        assert result.returncode == 0, result.stdout + result.stderr
        assert (external / "cJSON" / "FROM").read_text() == "sources"
        assert [p.name for p in external.iterdir()] == ["cJSON"]
    finally:
        server.shutdown()


@needs_make_pool
@pytest.mark.parametrize("extra", [(), ("PYTHON_SOURCE=yes",), ("EXTERNAL_SRC_ONLY=yes",)])
def test_make_pool_cpython_branches(extra, tmp_path):
    """Each cpython rule fetches its sources from the cpython ref and fails loudly without them."""
    (tmp_path / "pool").mkdir()
    result, _ = make_src(tmp_path, tmp_path / "pool", "external/cpython.tar.gz", *extra, dry_run=True)
    assert f"{(tmp_path / 'pool').as_uri()}/{LOCK_REFS['cpython']}/sources/cpython_x86_64.tar.gz" in result.stdout
    result, external = make_src(tmp_path, tmp_path / "pool", "external/cpython.tar.gz", *extra)
    assert result.returncode != 0 and "Dependency cpython failed installation" in result.stdout + result.stderr
    assert not list(external.glob("cpython*"))


def serve(handler_cls):
    import http.server
    import threading
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_pool_check_http(tmp_path, monkeypatch):
    """403 (how CloudFront answers a missing key) is `not published`; 5xx is retried, then an error."""
    import http.server
    document = deps.load(deps.DEFAULT_INVENTORY)
    computed = deps.keys(document)
    entries = {e["name"]: e for e in document["entries"]}
    paths = {f"/{deps.ref(entries[n], k)}/manifest.json": n for n, (k, _) in computed.items()}
    hits = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            name = paths.get(self.path)
            hits[name] = hits.get(name, 0) + 1
            if name == "curl":
                self.send_response(403)
                self.end_headers()
            elif name == "zlib":
                self.send_response(503)
                self.end_headers()
            else:
                body = json.dumps({"inputs_hash": computed[name][1]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    monkeypatch.setattr(deps.time, "sleep", lambda seconds: None)
    server, url = serve(Handler)
    try:
        errors = deps.pool_check(document, url)
    finally:
        server.shutdown()
    assert [e.split(":")[0] for e in errors] == ["curl", "zlib"]
    assert "is not published" in errors[0] and "cannot read" in errors[1]
    assert hits["curl"] == 1 and hits["zlib"] == 4


def keyed_refs(document=None):
    """{name: ref} as deps.keys() computes them for this tree, which is what src/deps.lock.mk holds when fresh."""
    document = document or deps.load(deps.DEFAULT_INVENTORY)
    entries = {e["name"]: e for e in document["entries"]}
    return {name: deps.ref(entries[name], key) for name, (key, _) in deps.keys(document).items()}


def pool_files(pool, files):
    for rel, content in files.items():
        (pool / rel).parent.mkdir(parents=True, exist_ok=True)
        (pool / rel).write_bytes(content)


def test_manifest_pool(tmp_path):
    document, refs = deps.load(deps.DEFAULT_INVENTORY), keyed_refs()
    pool_files(tmp_path, {f"{refs['curl']}/sources/curl.tar.gz": b"s", f"{refs['curl']}/linux/amd64/curl.tar.gz": b"b",
                          f"{refs['nlohmann']}/sources/nlohmann.tar.gz": b"n"})
    assert deps.manifest_pool(document, tmp_path, "c" * 40, "123", run_platforms=["linux/amd64"]) == []
    result = json.loads((tmp_path / refs["curl"] / "manifest.json").read_text())
    assert (result["schema"], result["ref"], result["inputs_hash"]) == (2, refs["curl"], deps.keys(document)["curl"][1])
    assert result["links"] == {"openssl": refs["openssl"], "zlib": refs["zlib"]}
    assert result["files"] == {"linux/amd64/curl.tar.gz": hashlib.sha256(b"b").hexdigest(),
                               "sources/curl.tar.gz": hashlib.sha256(b"s").hexdigest()}
    assert (result["wazuh_commit"], result["workflow_run"], result["entry"]["name"]) == ("c" * 40, "123", "curl")
    assert (tmp_path / refs["nlohmann"] / "manifest.json").is_file()
    # A second run must not list the manifests it wrote.
    assert deps.manifest_pool(document, tmp_path, run_platforms=["linux/amd64"]) == []
    assert "manifest.json" not in json.loads((tmp_path / refs["curl"] / "manifest.json").read_text())["files"]


@pytest.mark.parametrize("name,files,platforms,expected", [
    ("curl", ["sources"], ["linux/amd64"], ["curl: no linux/amd64 tarball"]),
    ("curl", ["sources", "linux/amd64"], ["linux/amd64", "windows"], ["curl: no windows tarball"]),
    ("curl", ["linux/amd64"], ["linux/amd64"], ["curl: no sources/"]),
    ("nlohmann", ["sources", "linux/amd64"], deps.ALL_POOL_PLATFORMS, ["nlohmann: `built: false`, but it has linux/amd64"]),
    # bzip2 is not compiled for Windows (`binaries`), so a run that built windows does not require it.
    ("bzip2", ["sources", "linux/amd64"], ["linux/amd64", "windows"], []),
], ids=["no-platform-tarball", "every-run-platform", "no-sources", "unbuilt-with-platform", "binaries-exception"])
def test_manifest_pool_contents(name, files, platforms, expected, tmp_path):
    ref = keyed_refs()[name]
    pool_files(tmp_path, {f"{ref}/{where}/{name}.tar.gz": b"x" for where in files})
    assert deps.manifest_pool(deps.load(deps.DEFAULT_INVENTORY), tmp_path, run_platforms=platforms) == expected
    assert (tmp_path / ref / "manifest.json").exists() == (not expected)


def test_manifest_pool_unknown_ref(tmp_path):
    pool_files(tmp_path, {"curl/0.0.0-deadbeef/sources/curl.tar.gz": b"s"})
    result = deps.manifest_pool(deps.load(deps.DEFAULT_INVENTORY), tmp_path)
    assert len(result) == 1 and "curl/0.0.0-deadbeef" in result[0]
    assert not (tmp_path / "curl/0.0.0-deadbeef/manifest.json").exists()


def test_plan_cli(tmp_path):
    _, pool = pool_mirror(tmp_path / "a", curl=None, date=None)
    result = run("plan", "--pool", pool)
    assert (result.returncode, result.stdout) == (0, "curl date\n"), result.stderr
    _, pool = pool_mirror(tmp_path / "b", curl=None, zlib="0" * 64)
    result = run("plan", "--pool", pool)
    assert result.returncode == 1 and "zlib" in result.stderr and result.stdout == ""


GENERATE_EXTERNAL = HERE.parent / "generate_external.sh"
needs_zip = pytest.mark.skipif(not all(shutil.which(tool) for tool in ("bash", "zip", "unzip")),
                               reason="needs bash, zip and unzip")


def zip_file(path, members):
    with zipfile.ZipFile(path, "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)


def generate_pack(tmp_path, zips, toolchain=None):
    """Run only the pack step of generate_external.sh over external_artifacts/<zip> on an rpm-amd64 manager leg."""
    artifacts = tmp_path / "out" / "external_artifacts"
    artifacts.mkdir(parents=True)
    for name, members in zips.items():
        zip_file(artifacts / name, members)
    if toolchain is not None:
        (artifacts / "toolchain.txt").write_text(toolchain)
    body = subprocess.run(["sed", "-n", "/# Re-pack the per-dep zips/,$p", str(GENERATE_EXTERNAL)],
                          capture_output=True, text=True, check=True).stdout
    assert body, f"no pack step in {GENERATE_EXTERNAL}"
    script = tmp_path / "pack.sh"
    script.write_text(f"set -e\nSYSTEM=rpm ARCHITECTURE=amd64 TARGET=manager OUTDIR={shlex.quote(str(tmp_path / 'out'))} "
                      f"WAZUH_PATH={shlex.quote(str(deps.REPO))}\n" + body)
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60), tmp_path / "out"


@needs_zip
def test_generate_pack_pool_layout(tmp_path):
    result, out = generate_pack(tmp_path, {"curl_src.zip": {"curl/a.c": "c"},
                                           "curl_rpm_amd64.zip": {"curl/lib/.libs/libcurl.a": "a"},
                                           "rocksdb_rpm_amd64.zip": {"rocksdb/a.c": "c"}},
                                toolchain="leg: rpm-amd64-manager\ncmake: cmake version 3.31.6\n")
    assert result.returncode == 0, result.stdout + result.stderr
    curl = out / "pool" / LOCK_REFS["curl"]
    with tarfile.open(curl / "sources" / "curl.tar.gz") as archive:
        assert archive.getnames() == ["curl", "curl/a.c"]
    with tarfile.open(curl / "linux" / "amd64" / "curl.tar.gz") as archive:
        assert "curl/lib/.libs/libcurl.a" in archive.getnames()
    assert not list((out / "pool").rglob("linux/amd64/rocksdb.tar.gz"))
    with tarfile.open(out / "externals-rpm-amd64-manager.tar.gz") as archive:
        names = archive.getnames()
        toolchain = archive.extractfile("toolchain/rpm-amd64-manager.txt").read()
    assert f"pool/{LOCK_REFS['curl']}/linux/amd64/curl.tar.gz" in names
    assert all(n.startswith(("pool", "toolchain")) for n in names)
    assert toolchain == b"leg: rpm-amd64-manager\ncmake: cmake version 3.31.6\n"


@needs_zip
def test_generate_pack_unknown_dep(tmp_path):
    result, _ = generate_pack(tmp_path, {"nosuch_src.zip": {"nosuch/a.c": "c"}})
    assert result.returncode != 0 and "no DEP_REF_nosuch" in result.stderr


@needs_zip
def test_generate_pack_nothing_built(tmp_path):
    result, out = generate_pack(tmp_path, {})
    assert result.returncode == 0, result.stderr
    assert tarfile.open(out / "externals-rpm-amd64-manager.tar.gz").getnames() == ["pool", "toolchain"]


@pytest.fixture
def consolidate_repo(tmp_path):
    """A scratch tree with consolidate.sh, deps.py and a lock regenerated from it, so refs and keys agree."""
    repo = tmp_path / "repo"
    copy_key_paths(repo)
    for name in ("deps.py", "consolidate.sh"):
        shutil.copy(HERE.parent / name, repo / "packages" / "externals" / name)
    (repo / "src").mkdir(exist_ok=True)
    result = subprocess.run([sys.executable, str(repo / "packages/externals/deps.py"), "lock"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    refs = dict(re.findall(r"^DEP_REF_(\S+) := (\S+)$", (repo / "src/deps.lock.mk").read_text(encoding="utf-8"), re.M))
    return repo, refs


def leg_tarball(path, files):
    path.parent.mkdir(parents=True, exist_ok=True)
    return tarball(path, {f"pool/{rel}": content for rel, content in files.items()})


def consolidate(repo, tmp_path):
    return subprocess.run(["bash", str(repo / "packages/externals/consolidate.sh"), str(tmp_path / "legs"),
                           str(tmp_path / "ebpf"), str(tmp_path / "out")], capture_output=True, text=True, timeout=60)


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_consolidate_merge(consolidate_repo, tmp_path):
    repo, refs = consolidate_repo
    curl = refs["curl"]
    for target in ("manager", "agent"):
        platform_tar = tarball(tmp_path / f"{target}-curl.tar.gz", {"curl/lib/libcurl.a": target.encode()}).read_bytes()
        files = {f"{curl}/sources/curl.tar.gz": f"sources-{target}".encode(), f"{curl}/linux/amd64/curl.tar.gz": platform_tar}
        if target == "agent":
            files.update({f"{refs['zlib']}/sources/zlib.tar.gz": b"z", f"{refs['zlib']}/linux/amd64/zlib.tar.gz": b"za"})
        leg_tarball(tmp_path / "legs" / target / f"externals-rpm-amd64-{target}.tar.gz", files)
    for arch in ("amd64", "aarch64"):
        (tmp_path / "ebpf" / arch).mkdir(parents=True)
        tarball(tmp_path / "ebpf" / arch / "libbpf-bootstrap.tar.gz", {"libbpf-bootstrap/x.o": arch.encode()})
    result = consolidate(repo, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    pool = tmp_path / "out" / "pool"
    assert (pool / curl / "sources/curl.tar.gz").read_bytes() == b"sources-manager"
    with tarfile.open(pool / curl / "linux/amd64/curl.tar.gz") as archive:
        assert archive.extractfile("curl/lib/libcurl.a").read() == b"agent"
    for arch in ("amd64", "aarch64"):
        assert (pool / refs["libbpf-bootstrap"] / f"linux/{arch}/libbpf-bootstrap.tar.gz").is_file()
    assert sorted(p.parent.relative_to(pool).as_posix() for p in pool.rglob("manifest.json")) == \
        sorted([curl, refs["libbpf-bootstrap"], refs["zlib"]])


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_consolidate_fails_on_manifest_error(consolidate_repo, tmp_path):
    repo, refs = consolidate_repo
    leg_tarball(tmp_path / "legs" / "externals-rpm-amd64-agent.tar.gz",
                {f"{refs['nlohmann']}/sources/nlohmann.tar.gz": b"s",
                 f"{refs['nlohmann']}/linux/amd64/nlohmann.tar.gz": b"b"})
    result = consolidate(repo, tmp_path)
    assert result.returncode != 0 and "nlohmann" in result.stderr


def build_selection(deps_build):
    """Run build_external.sh's in_build/built_here and its build-or-pool loop with every dep on the leg."""
    body = subprocess.run(["sed", "-n", '/^in_build() /p; /^built_here() /p; /^pool_goals=""/,/^done/p',
                           str(BUILD_EXTERNAL)], capture_output=True, text=True, check=True).stdout
    assert body.count("()") == 2 and "pool_goals=" in body
    script = ("on_leg() { return 0; }\nfetch_dep() { echo \"fetch:$1\"; }\nerr() { echo \"$*\" >&2; }\n"
              'DEPS_FOR_LEG="cpython libbpf-bootstrap curl zlib"\n' f"DEPS_BUILD={shlex.quote(deps_build)}\n" + body +
              'echo "goals:[${pool_goals}]"\nfor n in ${DEPS_FOR_LEG}; do built_here "$n" && echo "built:$n"; done; true\n')
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_build_external_selection():
    assert build_selection("curl") == ["fetch:curl", "goals:[ external/zlib.tar.gz]", "built:curl"]
    assert build_selection("") == ["fetch:curl", "fetch:zlib", "goals:[]", "built:curl", "built:zlib"]


def test_binaries_must_be_platforms():
    document = copy.deepcopy(deps.load(deps.DEFAULT_INVENTORY))
    bzip2 = next(e for e in document["entries"] if e["name"] == "bzip2")
    bzip2["binaries"] = ["linux", "aix"]
    assert "bzip2: `binaries` names 'aix', which is not in `platforms`" in deps.validate(document)


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_consolidate_without_legs(consolidate_repo, tmp_path):
    repo, _ = consolidate_repo
    (tmp_path / "legs").mkdir()
    result = consolidate(repo, tmp_path)
    assert result.returncode != 0 and "no externals-" in result.stderr


def test_mirror_twice_and_unserved_file(tmp_path):
    d = subset("curl", "openssl", "zlib")
    pool_tree(tmp_path / "local", {"curl": platform_files("curl")}, d)
    pool_tree(tmp_path / "pool", {n: platform_files(n) for n in ("openssl", "zlib")}, d)
    args = (tmp_path / "local", (tmp_path / "pool").as_uri(), "agent", "linux/amd64")
    assert deps.mirror(d, tmp_path / "dest", *args) == []
    assert deps.mirror(d, tmp_path / "dest", *args) == []
    zlib = next((tmp_path / "pool" / "zlib").iterdir())
    (zlib / "sources" / "zlib.tar.gz").unlink()
    with pytest.raises(ValueError, match="listed in its manifest.json but not served"):
        deps.mirror(d, tmp_path / "dest2", None, (tmp_path / "pool").as_uri(), "agent", "linux/amd64")


@needs_publish
def test_publish_pool_get_fails_after_412(tmp_path):
    """Two keys already uploaded with other bytes; reading the second one fails. The publish must stop
    instead of recording the sha256 of the first one (or of a partial download) for the second."""
    refs = pool_tree(tmp_path / "pool", {"curl": CURL_FILES})
    prefix = f"deps/pool/{refs['curl']}"
    store = {f"{prefix}/linux/amd64/curl.tar.gz": b"older bin\n", f"{prefix}/sources/curl.tar.gz": b"older src\n"}
    result, calls, store_dir = run_publish(tmp_path, tmp_path / "pool", store=store, get_fails="/sources/")
    assert ["get-object", f"{prefix}/linux/amd64/curl.tar.gz", "cond=no"] in calls
    assert result.returncode != 0
    assert not (store_dir / f"{prefix}/manifest.json").exists()


@needs_publish
@pytest.mark.parametrize("layout", ["missing", "empty", "one_level_up", "ref_without_manifest"])
def test_publish_pool_nothing_to_publish(layout, tmp_path):
    pool = tmp_path / "pool"
    if layout == "empty":
        pool.mkdir()
    elif layout == "one_level_up":
        pool_tree(pool, {"curl": CURL_FILES})
        pool = pool / "curl"
    elif layout == "ref_without_manifest":
        refs = pool_tree(pool, {"curl": CURL_FILES})
        (pool / refs["curl"] / "manifest.json").unlink()
    result, calls, _ = run_publish(tmp_path, pool)
    assert result.returncode != 0 and puts(calls) == []


@needs_publish
def test_publish_pool_listed_file_missing(tmp_path):
    refs = pool_tree(tmp_path / "pool", {"curl": CURL_FILES})
    (tmp_path / "pool" / refs["curl"] / "linux/amd64/curl.tar.gz").unlink()
    result, calls, _ = run_publish(tmp_path, tmp_path / "pool")
    assert result.returncode != 0 and "do not match its manifest.json" in result.stderr and puts(calls) == []


@needs_publish
def test_publish_pool_orphan_object(tmp_path):
    """An object a former run left under the ref, and this run does not have, would be served as a tarball."""
    refs = pool_tree(tmp_path / "pool", {"curl": CURL_FILES})
    store = {f"deps/pool/{refs['curl']}/windows/curl.tar.gz": b"stray\n"}
    result, calls, _ = run_publish(tmp_path, tmp_path / "pool", store=store)
    assert result.returncode != 0 and "windows/curl.tar.gz is in the pool but not in" in result.stderr
    assert puts(calls) == []


@needs_publish
def test_publish_pool_race_other_inputs(tmp_path):
    ref, manifest = published_manifest(tmp_path, "curl", inputs_hash="0" * 64)
    result, _, _ = run_publish(tmp_path, tmp_path / "pool", race=manifest.decode())
    assert result.returncode != 0 and "published meanwhile with other inputs" in result.stderr


def test_verify_pool_nothing_local(tmp_path):
    assert deps.verify(tmp_path / "nothing", (tmp_path / "pool").as_uri())[0].startswith("<pool>: no ref")


def test_mirror_bad_platform_and_same_dest(tmp_path):
    d = subset("curl", "openssl", "zlib")
    with pytest.raises(ValueError, match="platform must be one of"):
        deps.mirror(d, tmp_path / "dest", None, (tmp_path / "pool").as_uri(), "agent", "linux/x86_64")
    with pytest.raises(ValueError, match="must not be the --local tree"):
        deps.mirror(d, tmp_path / "same", tmp_path / "same", (tmp_path / "pool").as_uri(), "agent", "linux/amd64")


def test_mirror_refs_from_lock(tmp_path):
    lock = tmp_path / "deps.lock.mk"
    text = (SRC / "deps.lock.mk").read_text(encoding="utf-8")
    lock.write_text(re.sub(r"^DEP_REF_zlib := \S+$", "DEP_REF_zlib := zlib/0.0.0-deadbeef", text, flags=re.M),
                    encoding="utf-8")
    with pytest.raises(ValueError, match=r"^zlib: .*zlib/0\.0\.0-deadbeef.*run deps\.py lock"):
        deps.mirror(subset("curl", "openssl", "zlib"), tmp_path / "dest", None, (tmp_path / "pool").as_uri(), "agent",
                    "linux/amd64", lock=lock)


def test_mirror_inputs_hash(tmp_path):
    document = subset("curl", "openssl", "zlib")
    pool_tree(tmp_path / "pool", {n: platform_files(n) for n in ("curl", "openssl", "zlib")}, document,
              inputs_hash={"zlib": "0" * 64})
    with pytest.raises(ValueError, match="other inputs"):
        deps.mirror(document, tmp_path / "dest", None, (tmp_path / "pool").as_uri(), "agent", "linux/amd64")
    pool_tree(tmp_path / "good", {n: platform_files(n) for n in ("openssl", "zlib")}, document)
    pool_tree(tmp_path / "local", {"curl": platform_files("curl")}, document, inputs_hash={"curl": "0" * 64})
    with pytest.raises(ValueError, match="other inputs"):
        deps.mirror(document, tmp_path / "dest", tmp_path / "local", (tmp_path / "good").as_uri(), "agent",
                    "linux/amd64")


def test_mirror_retries(tmp_path, monkeypatch):
    import http.server
    document = subset("curl", "openssl", "zlib")
    root = tmp_path / "pool"
    refs = pool_tree(root, {n: platform_files(n) for n in ("curl", "zlib")}, document)
    flaky = {f"/{refs['zlib']}/manifest.json", f"/{refs['zlib']}/sources/zlib.tar.gz"}
    hits = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            hits[self.path] = hits.get(self.path, 0) + 1
            path = root / self.path.lstrip("/")
            if self.path in flaky and hits[self.path] == 1:
                self.send_response(503)
                self.end_headers()
            elif not path.is_file():
                self.send_response(404)
                self.end_headers()
            else:
                body = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    monkeypatch.setattr(deps.time, "sleep", lambda seconds: None)
    server, url = serve(Handler)
    try:
        missing = deps.mirror(document, tmp_path / "dest", None, url, "agent", "linux/amd64")
    finally:
        server.shutdown()
    assert missing == [refs["openssl"]]
    assert all(hits[path] == 2 for path in flaky)
    assert hits[f"/{refs['openssl']}/manifest.json"] == 1
    assert tree(tmp_path / "dest" / refs["zlib"]) == ["linux/amd64/zlib.tar.gz", "manifest.json", "sources/zlib.tar.gz"]
    assert sha_of(tmp_path / "dest" / refs["zlib"] / "sources/zlib.tar.gz") == sha_of(root / refs["zlib"] / "sources/zlib.tar.gz")


def test_mirror_without(tmp_path):
    document = deps.load(deps.DEFAULT_INVENTORY)
    refs = pool_tree(tmp_path / "pool", {"cpython": {"sources/cpython_x86_64.tar.gz": b"s",
                                                     "linux/amd64/cpython.tar.gz": b"b"}}, document)
    pool = (tmp_path / "pool").as_uri()
    assert refs["cpython"] not in deps.mirror(document, tmp_path / "with", None, pool, "manager", "linux/amd64")
    assert (tmp_path / "with" / refs["cpython"] / "linux/amd64/cpython.tar.gz").is_file()
    missing = deps.mirror(document, tmp_path / "dest", None, pool, "manager", "linux/amd64", without={"cpython"})
    assert missing and not any(rel.startswith("cpython/") for rel in missing)
    assert not (tmp_path / "dest" / "cpython").exists()
    result = run("mirror", "--dest", str(tmp_path / "cli"), "--pool", pool, "--target", "manager", "--platform",
                 "linux/amd64", "--without", "cpython")
    assert result.returncode == 1 and "ERROR: curl/" in result.stderr and "cpython" not in result.stderr
    assert not (tmp_path / "cli" / "cpython").exists()


def test_manifest_only(tmp_path):
    refs = keyed_refs()
    pool_files(tmp_path, {f"{refs[n]}/{rel}": b"x" for n in ("curl", "zlib")
                          for rel in (f"sources/{n}.tar.gz", f"linux/amd64/{n}.tar.gz")})
    (tmp_path / refs["zlib"] / "manifest.json").write_bytes(b'{"earlier": true}\n')
    assert deps.manifest_pool(deps.load(deps.DEFAULT_INVENTORY), tmp_path, run_platforms=["linux/amd64"],
                              only={"curl"}) == []
    assert json.loads((tmp_path / refs["curl"] / "manifest.json").read_text())["entry"]["name"] == "curl"
    assert (tmp_path / refs["zlib"] / "manifest.json").read_bytes() == b'{"earlier": true}\n'
    (tmp_path / refs["curl"] / "manifest.json").unlink()
    result = run("manifest", "--pool", str(tmp_path), "--platforms", "linux/amd64", "--only", "zlib")
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / refs["curl"] / "manifest.json").exists()
    assert json.loads((tmp_path / refs["zlib"] / "manifest.json").read_text())["entry"]["name"] == "zlib"


WHEELS = {"x86_64": ("PyYAML-6.0.1-cp312-cp312-manylinux_2_17_x86_64.whl", "typing_extensions-4.12.2-py3-none-any.whl"),
          "arm64": ("PyYAML-6.0.1-cp312-cp312-manylinux_2_17_aarch64.whl", "typing_extensions-4.12.2-py3-none-any.whl")}


def cpython_pool(repo, pool, wheels):
    """The cpython ref keyed on `repo`, with sources/cpython_<arch>.tar.gz shipping `wheels[arch]`."""
    document = deps.load(deps.DEFAULT_INVENTORY)
    cpython = next(e for e in document["entries"] if e["name"] == "cpython")
    where = pool / deps.ref(cpython, deps.keys(document, repo)["cpython"][0])
    for arch, names in wheels.items():
        (where / "sources").mkdir(parents=True, exist_ok=True)
        tarball(where / "sources" / f"cpython_{arch}.tar.gz",
                {"cpython/Python/ceval.c": b"c", **{f"cpython/Dependencies/{w}": f"{arch} {w}".encode() for w in names}})
    pool_files(where, {"linux/amd64/cpython.tar.gz": b"a", "linux/aarch64/cpython.tar.gz": b"b"})
    return document, where


def test_manifest_cpython_wheels(tmp_path):
    repo = tmp_path / "repo"
    copy_key_paths(repo)
    requirements = repo / "framework/requirements.txt"
    requirements.write_text("PyYAML==6.0.1\ntyping-extensions==4.12.2\n", encoding="utf-8")
    platforms = ["linux/amd64", "linux/aarch64"]

    document, where = cpython_pool(repo, tmp_path / "ok", WHEELS)
    assert deps.manifest_pool(document, tmp_path / "ok", repo=repo, run_platforms=platforms) == []
    result = json.loads((where / "manifest.json").read_text())
    assert result["wheels"] == {f"cpython_{arch}.tar.gz": {w: hashlib.sha256(f"{arch} {w}".encode()).hexdigest()
                                                           for w in names} for arch, names in WHEELS.items()}
    assert result["requirements_sha256"] == deps._text_sha256(requirements)

    document, where = cpython_pool(repo, tmp_path / "short", dict(WHEELS, arm64=WHEELS["arm64"][:1]))
    errors = deps.manifest_pool(document, tmp_path / "short", repo=repo, run_platforms=platforms)
    assert len(errors) == 1 and "cpython_arm64.tar.gz" in errors[0] and "typing-extensions==4.12.2" in errors[0]
    assert not (where / "manifest.json").exists()

    document, where = cpython_pool(repo, tmp_path / "extra",
                                   dict(WHEELS, x86_64=WHEELS["x86_64"] + ("six-1.16.0-py2.py3-none-any.whl",)))
    errors = deps.manifest_pool(document, tmp_path / "extra", repo=repo, run_platforms=platforms)
    assert len(errors) == 1 and "cpython_x86_64.tar.gz" in errors[0] and "extra ['six==1.16.0']" in errors[0]
    assert not (where / "manifest.json").exists()

    document, where = cpython_pool(repo, tmp_path / "none", {})
    errors = deps.manifest_pool(document, tmp_path / "none", repo=repo, run_platforms=platforms)
    assert errors == ["cpython: no sources/cpython_x86_64.tar.gz for linux/amd64",
                      "cpython: no sources/cpython_arm64.tar.gz for linux/aarch64"]
    assert not (where / "manifest.json").exists()

    bumped = {arch: (names[0].replace("6.0.1", "6.0.2"), names[1]) for arch, names in WHEELS.items()}
    document, where = cpython_pool(repo, tmp_path / "version", bumped)
    errors = deps.manifest_pool(document, tmp_path / "version", repo=repo, run_platforms=platforms)
    assert len(errors) == 2 and all("pyyaml==6.0.1" in e and "pyyaml==6.0.2" in e for e in errors), errors
    assert not (where / "manifest.json").exists()

    nested = "simple/six/six-1.16.0-py2.py3-none-any.whl"
    document, where = cpython_pool(repo, tmp_path / "nested", dict(WHEELS, x86_64=WHEELS["x86_64"] + (nested,)))
    assert deps.manifest_pool(document, tmp_path / "nested", repo=repo, run_platforms=platforms) == []
    assert sorted(json.loads((where / "manifest.json").read_text())["wheels"]["cpython_x86_64.tar.gz"]) == \
        sorted(WHEELS["x86_64"])


def test_manifest_cpython_archive_names(tmp_path):
    repo = tmp_path / "repo"
    copy_key_paths(repo)
    (repo / "framework/requirements.txt").write_text("PyYAML==6.0.1\ntyping-extensions==4.12.2\n", encoding="utf-8")
    both = ["linux/amd64", "linux/aarch64"]
    for case, arches in (("aarch64", ("x86_64", "aarch64")), ("amd64", ("amd64", "arm64"))):
        wheels = {arch: WHEELS["arm64" if arch in ("aarch64", "arm64") else "x86_64"] for arch in arches}
        document, where = cpython_pool(repo, tmp_path / case, wheels)
        errors = deps.manifest_pool(document, tmp_path / case, repo=repo, run_platforms=both)
        assert f"cpython: sources/cpython_{case}.tar.gz: not a cpython archive `make deps` downloads" in errors, errors
        assert not (where / "manifest.json").exists()

    document, where = cpython_pool(repo, tmp_path / "x86_64", {"x86_64": WHEELS["x86_64"]})
    assert deps.manifest_pool(document, tmp_path / "x86_64", repo=repo, run_platforms=both) == [
        "cpython: no sources/cpython_arm64.tar.gz for linux/aarch64"]
    assert not (where / "manifest.json").exists()
    assert deps.manifest_pool(document, tmp_path / "x86_64", repo=repo, run_platforms=["linux/amd64"]) == []
    assert list(json.loads((where / "manifest.json").read_text())["wheels"]) == ["cpython_x86_64.tar.gz"]


def test_manifest_toolchain(tmp_path):
    refs = keyed_refs()
    pool_files(tmp_path / "pool", {f"{refs['curl']}/sources/curl.tar.gz": b"s",
                                   f"{refs['curl']}/linux/amd64/curl.tar.gz": b"b"})
    (tmp_path / "toolchain").mkdir()
    (tmp_path / "toolchain" / "rpm-amd64-agent.txt").write_text("leg: rpm-amd64-agent\ncc: cc (GCC) 4.8.5\n")
    (tmp_path / "toolchain" / "README").write_text("not a leg\n")
    document, manifest = deps.load(deps.DEFAULT_INVENTORY), tmp_path / "pool" / refs["curl"] / "manifest.json"
    assert deps.manifest_pool(document, tmp_path / "pool", run_platforms=["linux/amd64"], toolchain=tmp_path / "toolchain") == []
    assert json.loads(manifest.read_text())["toolchain"] == {"rpm-amd64-agent": ["leg: rpm-amd64-agent",
                                                                                 "cc: cc (GCC) 4.8.5"]}
    assert deps.manifest_pool(document, tmp_path / "pool", run_platforms=["linux/amd64"]) == []
    assert json.loads(manifest.read_text())["toolchain"] == {}


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_consolidate_toolchain(consolidate_repo, tmp_path):
    repo, refs = consolidate_repo
    legs = {"manager": {f"{refs['curl']}/sources/curl.tar.gz": b"s", f"{refs['curl']}/linux/amd64/curl.tar.gz": b"b"},
            "agent": {f"{refs['zlib']}/sources/zlib.tar.gz": b"z", f"{refs['zlib']}/linux/amd64/zlib.tar.gz": b"zb"}}
    for target, files in legs.items():
        (tmp_path / "legs").mkdir(exist_ok=True)
        tarball(tmp_path / "legs" / f"externals-rpm-amd64-{target}.tar.gz",
                {**{f"pool/{rel}": content for rel, content in files.items()},
                 f"toolchain/rpm-amd64-{target}.txt": f"leg: rpm-amd64-{target}\n".encode()})
    result = consolidate(repo, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    manifests = sorted((tmp_path / "out" / "pool").rglob("manifest.json"))
    assert [p.parent.relative_to(tmp_path / "out" / "pool").as_posix() for p in manifests] == [refs["curl"], refs["zlib"]]
    for path in manifests:
        assert json.loads(path.read_text())["toolchain"] == {f"rpm-amd64-{t}": [f"leg: rpm-amd64-{t}"]
                                                             for t in ("agent", "manager")}


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_consolidate_ebpf_only(consolidate_repo, tmp_path):
    repo, refs = consolidate_repo
    for arch in ("amd64", "aarch64"):
        (tmp_path / "ebpf" / arch).mkdir(parents=True)
        tarball(tmp_path / "ebpf" / arch / "libbpf-bootstrap.tar.gz", {"libbpf-bootstrap/x.o": arch.encode()})
    result = consolidate(repo, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((tmp_path / "out" / "pool" / refs["libbpf-bootstrap"] / "manifest.json").read_text())
    assert sorted(manifest["files"]) == ["linux/aarch64/libbpf-bootstrap.tar.gz", "linux/amd64/libbpf-bootstrap.tar.gz"]
    assert manifest["toolchain"] == {}

    amd64 = tmp_path / "amd64"
    (amd64 / "ebpf" / "amd64").mkdir(parents=True)
    tarball(amd64 / "ebpf" / "amd64" / "libbpf-bootstrap.tar.gz", {"libbpf-bootstrap/x.o": b"amd64"})
    result = consolidate(repo, amd64)
    assert result.returncode != 0 and "no linux/aarch64 tarball" in result.stderr, result.stdout + result.stderr
    assert not (amd64 / "out" / "pool" / refs["libbpf-bootstrap"] / "manifest.json").exists()


def test_manifest_libbpf_all_architectures(tmp_path):
    document, ebpf = deps.load(deps.DEFAULT_INVENTORY), keyed_refs()["libbpf-bootstrap"]
    pool_files(tmp_path, {f"{ebpf}/linux/amd64/libbpf-bootstrap.tar.gz": b"a"})
    for run_platforms in ([], ["linux/amd64"]):
        assert deps.manifest_pool(document, tmp_path, run_platforms=run_platforms) == [
            "libbpf-bootstrap: no linux/aarch64 tarball"], run_platforms
        assert not (tmp_path / ebpf / "manifest.json").exists()
    pool_files(tmp_path, {f"{ebpf}/linux/aarch64/libbpf-bootstrap.tar.gz": b"b"})
    assert deps.manifest_pool(document, tmp_path, run_platforms=[]) == []
    assert (tmp_path / ebpf / "manifest.json").is_file()


def test_manifest_only_and_toolchain_args(tmp_path):
    refs = keyed_refs()
    pool_files(tmp_path / "pool", {f"{refs['zlib']}/sources/zlib.tar.gz": b"z", f"{refs['zlib']}/linux/amd64/zlib.tar.gz": b"b"})
    for extra, message in ((["--only", "nosuch"], "--only needs entries of the inventory"), (["--only"], "got none"),
                           (["--toolchain", str(tmp_path / "missing")], "is not a directory")):
        result = run("manifest", "--pool", str(tmp_path / "pool"), "--platforms", "linux/amd64", *extra)
        assert result.returncode == 1 and message in result.stderr, (extra, result.stderr)
        assert not list((tmp_path / "pool").rglob("manifest.json")), extra
    document = deps.load(deps.DEFAULT_INVENTORY)
    for only in (set(), {"zlib", "nosuch"}):
        with pytest.raises(ValueError, match="--only"):
            deps.manifest_pool(document, tmp_path / "pool", run_platforms=["linux/amd64"], only=only)
    assert not list((tmp_path / "pool").rglob("manifest.json"))


def test_builder_image_cli():
    images = deps.load(deps.BUILDER_IMAGES)
    result = run("builder-image", "linux", "manager", "amd64")
    assert (result.returncode, result.stdout) == (0, images["linux"]["manager"]["amd64"] + "\n"), result.stderr
    assert re.fullmatch(r"ghcr\.io/wazuh/\S+@sha256:[0-9a-f]{64}\n", result.stdout)
    result = run("builder-image", "darwin", "xcode")
    assert (result.returncode, result.stdout) == (0, "15.4\n"), result.stderr
    for path in (("darwin",), ("darwin", "runners"), ("linux", "nosuch")):
        result = run("builder-image", *path)
        assert result.returncode == 1 and result.stdout == "" and "ERROR:" in result.stderr, path


@pytest.mark.parametrize("xcode,valid", [("unpinned:runner-default", False), ("", False), ("15", False),
                                         ("15.4", True), ("16.2.1", True)])
def test_builder_images_xcode(xcode, valid):
    images = copy.deepcopy(deps.load(deps.BUILDER_IMAGES))
    images["darwin"]["xcode"] = xcode
    assert (deps.check_builder_images(images) == []) == valid


COMPILE_SH = deps.REPO / "framework/cpython/compile.sh"


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_compile_sh_skips_cpython(tmp_path):
    block = re.search(r"^    if \$BUILD_CPYTHON; then\n.*?^    fi\n", COMPILE_SH.read_text(encoding="utf-8"), re.M | re.S)
    assert block and "print-EXTERNAL_RES" in block.group(0), f"no deps download block in {COMPILE_SH}"
    sed = re.search(r"print-EXTERNAL_RES \| (sed -E '[^']*')\)", block.group(0))
    assert sed, block.group(0)
    for given, expected in (("cJSON cpython libffi", ["cJSON", "libffi"]), ("cpython", []),
                            ("cpython cJSON", ["cJSON"]), ("a cpythonx b", ["a", "cpythonx", "b"])):
        result = subprocess.run(["bash", "-c", sed.group(1)], input=given, capture_output=True, text=True, check=True)
        assert result.stdout.split() == expected, given
    log = tmp_path / "make.log"
    for flag, expected in (("true", ["-s -C /wazuh/src print-EXTERNAL_RES",
                                     "-C /wazuh/src PYTHON_SOURCE=y deps -j EXTERNAL_RES=cJSON libffi"]),
                           ("false", ["-C /wazuh/src PYTHON_SOURCE=y deps -j"])):
        script = ("set -euo pipefail\n"
                  f'make() {{ printf "%s\\n" "$*" >> {shlex.quote(str(log))}; '
                  '[ "${*: -1}" != print-EXTERNAL_RES ] || echo "cJSON cpython libffi"; }\n'
                  f"WAZUH_ROOT_DIR=/wazuh\nBUILD_CPYTHON={flag}\ndownload() {{\n{block.group(0)}}}\ndownload\n")
        log.unlink(missing_ok=True)
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert log.read_text().splitlines() == expected, flag


def fake_tools(bin_dir, tools):
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name, body in tools.items():
        (bin_dir / name).write_text(f"#!{shutil.which('bash')}\n{body}\n")
        (bin_dir / name).chmod(0o755)
    return bin_dir


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_build_external_toolchain_block(tmp_path):
    text = BUILD_EXTERNAL.read_text(encoding="utf-8")
    block = re.search(r'^\{\n(?:(?!^\{\n).)*?^\} > "\$\{ARTIFACTS_DIR\}/toolchain\.txt"\n', text, re.M | re.S)
    assert block, f"no toolchain block in {BUILD_EXTERNAL}"
    lists = re.findall(r"^(?:APT|YUM|BREW)_TOOLS=.*\n", text, re.M)
    assert len(lists) == 3, lists
    yum_tools = shlex.split(re.search(r'^YUM_TOOLS=(".*")$', text, re.M).group(1))[0].split()
    brew_tools = shlex.split(re.search(r'^BREW_TOOLS=(".*")$', text, re.M).group(1))[0].split()
    script = tmp_path / "toolchain.sh"
    script.write_text("".join(lists) + block.group(0))
    head = {"head": f'exec {shutil.which("head")} "$@"'}
    compiler = fake_tools(tmp_path / "gcc-14.3.0", {"gcc": 'echo "gcc (GCC) 14.3.0"'})
    rpm_bin = fake_tools(tmp_path / "rpm", dict(head, cc='echo "cc (GCC) 4.8.5"', **{"c++": 'echo "c++ (GCC) 4.8.5"'},
                                                cmake='echo "cmake version 3.31.6"', yum="exit 1",
                                                rpm='for p in "${@:2}"; do echo "$p-1.0"; done'))
    brew_bin = fake_tools(tmp_path / "brew", dict(head, brew='echo "brew $*"'))

    def leg(bin_dir, **env):
        result = subprocess.run([shutil.which("bash"), str(script)], capture_output=True, text=True, timeout=20,
                                env={"PATH": str(bin_dir), "ARTIFACTS_DIR": str(tmp_path), "SYSTEM": "rpm",
                                     "ARCHITECTURE_TARGET": "amd64", "BUILD_TARGET": "agent", **env})
        assert result.returncode == 0, result.stderr
        return (tmp_path / "toolchain.txt").read_text().splitlines()

    lines = leg(rpm_bin, CC=str(compiler / "gcc"))
    assert lines == ["leg: rpm-amd64-agent", f"{compiler / 'gcc'}: gcc (GCC) 14.3.0", "c++: c++ (GCC) 4.8.5",
                     "cmake: cmake version 3.31.6", *[f"{tool}-1.0" for tool in yum_tools]]
    lines = leg(rpm_bin, CC=str(compiler / "gcc"), ImageOS="macos14", ImageVersion="20251001.1")
    assert lines[:2] == ["leg: rpm-amd64-agent", "runner image: macos14 20251001.1"]
    lines = leg(brew_bin, SYSTEM="macos", ARCHITECTURE_TARGET="arm64")
    assert lines == ["leg: macos-arm64-agent", f"brew list --versions {' '.join(brew_tools)}"]
    assert lines[1].endswith(" bash gnu-tar")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_consolidate_ebpf_toolchain(consolidate_repo, tmp_path):
    repo, refs = consolidate_repo
    leg_tarball(tmp_path / "legs" / "externals-rpm-amd64-agent.tar.gz",
                {f"{refs['zlib']}/sources/zlib.tar.gz": b"z", f"{refs['zlib']}/linux/amd64/zlib.tar.gz": b"zb"})
    for arch in ("amd64", "aarch64"):
        (tmp_path / "ebpf" / arch).mkdir(parents=True)
        tarball(tmp_path / "ebpf" / arch / "libbpf-bootstrap.tar.gz", {"libbpf-bootstrap/x.o": arch.encode()})
    (tmp_path / "ebpf" / "toolchain.txt").write_text("leg: build-ebpf\nzig: 0.14.1\n")
    result = consolidate(repo, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    manifests = sorted((tmp_path / "out" / "pool").rglob("manifest.json"))
    assert sorted(p.parent.relative_to(tmp_path / "out" / "pool").as_posix() for p in manifests) == \
        sorted([refs["libbpf-bootstrap"], refs["zlib"]])
    for path in manifests:
        assert json.loads(path.read_text())["toolchain"]["build-ebpf"] == ["leg: build-ebpf", "zig: 0.14.1"], path
