# Run: python3 -m pytest packages/externals/tests -q

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
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


def doc(*entries):
    return {"schema": 1, "entries": list(entries)}


def minimal():
    return doc(entry("curl"), entry("openssl"), entry("zlib"))


def errors(document, external=None, patches_dir=None, repo_root=None):
    return deps.validate(document, external, patches_dir or HERE, repo_root or deps.REPO)


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_valid_minimal():
    assert errors(minimal()) == []


def test_external_res_match():
    external = {("agent", "linux"): {"curl", "openssl", "zlib"}, ("manager", "linux"): {"curl", "openssl", "zlib"}}
    assert errors(minimal(), external) == []


def test_external_res_extra():
    external = {("agent", "linux"): {"curl", "openssl"}}
    assert errors(minimal(), external) == ["zlib: declared for agent/linux but not in EXTERNAL_RES"]


def test_external_res_missing():
    external = {("manager", "linux"): {"curl", "openssl", "zlib", "sqlite"}}
    assert errors(minimal(), external) == ["sqlite: in EXTERNAL_RES for manager/linux but missing from inventory"]


def test_duplicate_name():
    assert errors(doc(entry("zlib"), entry("zlib"))) == ["zlib: duplicate name"]


def test_unsorted():
    assert errors(doc(entry("zlib"), entry("curl"))) == ["<inventory>: entries must be sorted by `name`"]


def test_upstream_requires_sha():
    item = entry("zlib")
    del item["upstream_sha256"]
    assert errors(doc(item)) == ["zlib: upstream entry needs `upstream_sha256`"]


def test_snapshot_requires_sha():
    item = entry("rpm", source="snapshot")
    del item["upstream_sha256"]
    assert errors(doc(item)) == ["rpm: snapshot entry needs `snapshot_sha256`"]


def test_bad_sha():
    assert errors(doc(entry("zlib", upstream_sha256="a" * 63))) == ["zlib: `upstream_sha256` is not a lowercase sha256"]


def test_patch_missing(tmp_path):
    result = errors(doc(entry("date", patches=["date/0001-fix.patch"])), patches_dir=tmp_path)
    assert result == [f"date: patch 'date/0001-fix.patch' not found under {tmp_path}"]


def test_patch_present(tmp_path):
    (tmp_path / "date").mkdir()
    (tmp_path / "date" / "0001-fix.patch").write_text("")
    assert errors(doc(entry("date", patches=["date/0001-fix.patch"])), patches_dir=tmp_path) == []


def test_scan_false_needs_reason():
    assert errors(doc(entry("jemalloc", cpe=None, scan=False))) == ["jemalloc: `scan: false` requires `reason`"]


def test_null_cpe_needs_scan_false():
    assert errors(doc(entry("jemalloc", cpe=None))) == ["jemalloc: `cpe: null` requires `scan: false`"]


def test_cpe_with_version():
    result = errors(doc(entry("curl", cpe="cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*")))
    assert result == ["curl: CPE 'cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*' carries version '8.12.1'; versions belong in `version`"]


def test_cpe_list_and_malformed():
    good = ["cpe:2.3:a:procps_project:procps:*:*:*:*:*:*:*:*", "cpe:2.3:a:procps-ng_project:procps-ng:*:*:*:*:*:*:*:*"]
    assert errors(doc(entry("procps", cpe=good))) == []
    bad = errors(doc(entry("procps", cpe="cpe:2.3:a:procps_project:procps:*:*:*:*:*:*:*")))
    assert len(bad) == 1 and bad[0].startswith("procps: malformed CPE")


def test_unknown_field_and_types():
    result = errors(doc(entry("zlib", strip="1", colour="blue")))
    assert result == ["zlib: `strip` must be int", "zlib: unknown field `colour`"]


def test_unknown_target_and_platform():
    result = errors(doc(entry("zlib", targets=["server"], platforms=["beos"])))
    assert result == ["zlib: unknown target 'server'", "zlib: unknown platform 'beos'"]


def test_format_and_strip():
    result = errors(doc(entry("zlib", format="rar", strip=-1)))
    assert result == ["zlib: `format` must be one of ['file', 'tar.bz2', 'tar.gz', 'tar.xz', 'zip']",
                      "zlib: `strip` must be >= 0"]


def test_url_rules():
    assert errors(doc(entry("pcre2", url="gh:PCRE2Project/pcre2:pcre2-{version}"))) == [
        "pcre2: `url` must be an http(s) URL, got 'gh:PCRE2Project/pcre2:pcre2-{version}'"]
    assert errors(doc(entry("zlib", url="https://x/{foo}.tar.gz"))) == ["zlib: `url` uses unknown placeholder(s) foo"]
    assert errors(doc(entry("date", url="https://x/{revision}.tar.gz"))) == []


def test_removed_fields():
    assert errors(doc(entry("zlib", links=[], build=1, subpins={}))) == [
        "zlib: unknown field `build`", "zlib: unknown field `links`", "zlib: unknown field `subpins`"]


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


@pytest.mark.skipif(shutil.which("make") is None or not (SRC / "Makefile").is_file(), reason="needs make and src/Makefile")
def test_repo_inventory(tmp_path):
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
    values = bash_lookup(result.stdout, "${EXT_PATCHES[rpm]}", "${EXT_TARGET[nlohmann]}", "${EXT_FORMAT[nlohmann]}",
                         "${EXT_SHA256[zlib]}", "${#EXT_URL[@]}", tmp_path=tmp_path)
    zlib = next(e for e in deps.load(INVENTORY)["entries"] if e["name"] == "zlib")
    assert values == ["rpm/0001-wazuh.patch", "nlohmann", "file", zlib["upstream_sha256"],
                      str(len(deps.load(INVENTORY)["entries"]))]


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


def test_drift_content_fields():
    published = {"entries": copy.deepcopy(minimal()["entries"])}
    published["entries"][2]["version"] = "1.0.1"
    assert deps.drift(minimal(), published) == ["zlib: `version` is '1.0.0' here but '1.0.1' in the set manifest"]
    published = {"entries": copy.deepcopy(minimal()["entries"])}
    published["entries"][2]["license"] = "Zlib"
    assert deps.drift(minimal(), published) == []


def test_drift_names():
    published = {"entries": minimal()["entries"][:2] + [entry("sqlite")]}
    assert deps.drift(minimal(), published) == ["zlib: in the inventory but not in the set manifest",
                                                "sqlite: in the set manifest but not in the inventory"]


def test_drift_missing_manifest(tmp_path):
    inventory = tmp_path / "deps.json"
    inventory.write_text(json.dumps(minimal()))
    result = run("drift", "--inventory", str(inventory), "--manifest", str(tmp_path / "nope.json"))
    assert result.returncode == 1 and "no manifest at" in result.stderr and "nope.json" in result.stderr


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
    published.write_text(json.dumps(deps.manifest(doc(entry("zlib", cpe=None, scan=False, reason="none")), "55")))
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("# comment\nPyYAML==6.0.1\n")
    result = run("sbom", "--manifest", str(published), "--requirements", str(requirements))
    bom = json.loads(result.stdout)
    assert [c["bom-ref"] for c in bom["components"]] == ["pypi:pyyaml", "zlib"]
    assert "cpe" not in bom["components"][1]


def test_manifest_files(tmp_path):
    (tmp_path / "libraries" / "sources").mkdir(parents=True)
    (tmp_path / "libraries" / "sources" / "zlib.tar.gz").write_bytes(b"z")
    (tmp_path / "libraries" / "windows.tar.gz").write_bytes(b"w")
    result = deps.manifest(minimal(), "56", "c" * 40, "123", tmp_path)
    assert result["entries"] == minimal()["entries"] and result["deps_version"] == "56"
    assert list(result["files"]) == ["libraries/sources/zlib.tar.gz", "libraries/windows.tar.gz"]
    assert result["files"]["libraries/windows.tar.gz"] == hashlib.sha256(b"w").hexdigest()
    assert deps.drift(minimal(), result) == []


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


def with_cpython():
    return doc(entry("cpython", version="3.12.14"), entry("openssl"), entry("zlib"))


def python_manifest(**overrides):
    result = deps.manifest(with_cpython(), "5/python/1",
                           python={"built_against": "5/externals/1", "requirements": [("pyyaml", "6.0.1")]})
    result.update(overrides)
    return result


def test_manifest_excludes_cpython():
    assert [e["name"] for e in deps.manifest(with_cpython(), "5/externals/1")["entries"]] == ["openssl", "zlib"]


def test_python_manifest():
    result = python_manifest()
    assert [e["name"] for e in result["entries"]] == ["cpython"]
    assert (result["built_against"], result["requirements"]) == ("5/externals/1", ["pyyaml==6.0.1"])
    assert deps.drift_python(with_cpython(), result, [("pyyaml", "6.0.1")], "5/externals/1") == []
    assert deps.drift(with_cpython(), deps.manifest(with_cpython(), "5/externals/1")) == []


def test_drift_python_built_against():
    assert deps.drift_python(with_cpython(), python_manifest(), [("pyyaml", "6.0.1")], "5/externals/2") == [
        "cpython: the Python set was built against '5/externals/1', but DEPS_VERSION is '5/externals/2'; rebuild it"]


def test_drift_python_requirements():
    result = deps.drift_python(with_cpython(), python_manifest(), [("pyyaml", "6.0.2"), ("idna", "3.7")], "5/externals/1")
    assert result == ["cpython: idna==3.7 is in framework/requirements.txt but not in the Python set",
                      "cpython: pyyaml==6.0.2 is in framework/requirements.txt but not in the Python set",
                      "cpython: pyyaml==6.0.1 is in the Python set but not in framework/requirements.txt"]


def test_drift_python_content():
    newer = doc(entry("cpython", version="3.12.15"), entry("openssl"), entry("zlib"))
    assert deps.drift_python(newer, python_manifest(), [("pyyaml", "6.0.1")], "5/externals/1") == [
        "cpython: `version` is '3.12.15' here but '3.12.14' in the set manifest"]


def test_deps_version_vars(tmp_path):
    (tmp_path / "Makefile").write_text("DEPS_VERSION = 5/externals/1\nPYTHON_DEPS_VERSION = 5/python/1\n")
    assert deps.deps_version(tmp_path) == "5/externals/1"
    assert deps.deps_version(tmp_path, "PYTHON_DEPS_VERSION") == "5/python/1"


def test_manifest_python_needs_built_against(tmp_path):
    inventory = tmp_path / "deps.json"
    inventory.write_text(json.dumps(with_cpython()))
    result = run("manifest", "--inventory", str(inventory), "--deps-version", "5/python/1", "--python")
    assert result.returncode == 1 and "--built-against" in result.stderr


def test_drift_targets_and_platforms():
    published = {"entries": copy.deepcopy(minimal()["entries"]), "patches": {}}
    published["entries"][2]["platforms"] = ["linux", "darwin"]
    assert deps.drift(minimal(), published) == [
        "zlib: `platforms` is ['linux'] here but ['linux', 'darwin'] in the set manifest"]


def test_drift_patch_edited_in_place(tmp_path):
    (tmp_path / "rpm").mkdir()
    patch = tmp_path / "rpm" / "0001-wazuh.patch"
    patch.write_text("old\n")
    inventory = doc(entry("rpm", patches=["rpm/0001-wazuh.patch"]))
    published = deps.manifest(inventory, "5/externals/1", patches_dir=tmp_path)
    assert deps.drift(inventory, published, patches_dir=tmp_path) == []
    patch.write_text("new\n")
    assert deps.drift(inventory, published, patches_dir=tmp_path) == [
        "rpm: patch rpm/0001-wazuh.patch differs from the one the set was built with"]


def test_flatten_checksum_follows_source():
    item = entry("procps", source="snapshot", snapshot_sha256="b" * 64)
    assert "[procps]=" + "b" * 64 in deps.flatten(doc(item))


def test_purl_rules():
    assert errors(doc(entry("llhttp", purl="pkg:github/nodejs/llhttp@release%2Fv9.4.2"))) == []
    assert errors(doc(entry("llhttp", purl="pkg:github/nodejs/llhttp@release/v9.4.2"))) == [
        "llhttp: `purl` 'pkg:github/nodejs/llhttp@release/v9.4.2' is not pkg:<type>/<name>@<version> with an encoded version"]


def test_sbom_extra_cpes():
    item = entry("procps", cpe=["cpe:2.3:a:procps_project:procps:*:*:*:*:*:*:*:*",
                                "cpe:2.3:a:procps-ng_project:procps-ng:*:*:*:*:*:*:*:*"])
    component = deps.sbom([item], [])["components"][0]
    assert component["cpe"].startswith("cpe:2.3:a:procps_project")
    assert {"name": "syft:cpe23", "value": "cpe:2.3:a:procps-ng_project:procps-ng:*:*:*:*:*:*:*:*"} in component["properties"]


def test_linux_combos_force_uname():
    assert all("uname_S=Linux" in args for (target, platform), args in deps.MAKE_COMBOS.items() if platform == "linux")
