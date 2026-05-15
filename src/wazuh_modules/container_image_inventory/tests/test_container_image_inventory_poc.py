"""
Integration tests for container-image-inventory-poc standalone binary.

Fixtures are generated in-memory using only the Python standard library.
No Docker daemon, no committed archives, no network access for local tests.

Run (local tests only):
    pytest -vv src/wazuh_modules/container_image_inventory/tests/

Run (include network smoke tests):
    CII_ENABLE_REMOTE_TESTS=1 pytest -vv src/wazuh_modules/container_image_inventory/tests/

Override the pinned remote image:
    CII_REMOTE_IMAGE_REF=alpine:3.19 CII_ENABLE_REMOTE_TESTS=1 pytest ...
"""

import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Optional

import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODULE_DIR = Path(__file__).parent.parent
BINARY = MODULE_DIR / "build" / "container-image-inventory-poc"

REMOTE_ENABLED = os.environ.get("CII_ENABLE_REMOTE_TESTS", "").strip() in ("1", "true", "yes")

# Alpine 3.19.1 amd64 -- digest-pinned for reproducibility.
# Override with CII_REMOTE_IMAGE_REF if this digest is ever retired.
_DEFAULT_REMOTE_REF = (
    "docker.io/library/alpine@sha256:"
    "c0669ef34cdc14332c0f1ab0c2c01acb91d96014b172f1a76f3a39e63d1f0bda"
)
REMOTE_IMAGE_REF = os.environ.get("CII_REMOTE_IMAGE_REF", "").strip() or _DEFAULT_REMOTE_REF

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _make_layer_tar(files: Dict[str, bytes]) -> bytes:
    """Return raw bytes of a tar archive containing *files* (path -> content)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as t:
        for path, data in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_docker_save(
    layer_files_list: list,
    repo_tag: str = "test-image:latest",
    arch: str = "amd64",
    os_name: str = "linux",
) -> bytes:
    """
    Build a docker-save-style tar from one or more layers.

    layer_files_list: list of dicts mapping relative_path -> bytes, one per layer.
    Returns the raw bytes of the outer docker-save tar.
    """
    layer_entries = []
    diff_ids = []
    for layer_files in layer_files_list:
        raw = _make_layer_tar(layer_files)
        digest = hashlib.sha256(raw).hexdigest()
        diff_ids.append(f"sha256:{digest}")
        layer_entries.append((digest[:12], raw))

    config = json.dumps({
        "architecture": arch,
        "os": os_name,
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }).encode()
    config_digest = hashlib.sha256(config).hexdigest()

    manifest = json.dumps([{
        "Config": f"{config_digest}.json",
        "RepoTags": [repo_tag],
        "Layers": [f"{layer_dir}/layer.tar" for layer_dir, _ in layer_entries],
    }]).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as t:
        for name, data in [("manifest.json", manifest), (f"{config_digest}.json", config)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))

        for layer_dir, layer_bytes in layer_entries:
            d = tarfile.TarInfo(layer_dir)
            d.type = tarfile.DIRTYPE
            t.addfile(d)
            info = tarfile.TarInfo(f"{layer_dir}/layer.tar")
            info.size = len(layer_bytes)
            t.addfile(info, io.BytesIO(layer_bytes))

    return buf.getvalue()


# Canned dpkg/status content with two well-known packages.
_DPKG_STATUS = b"""\
Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.35-0ubuntu3
Installed-Size: 12345
Description: GNU C Library

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.1-6ubuntu1
Installed-Size: 2048
Description: GNU Bourne Again shell

"""

# Canned APK installed db content with two packages.
_APK_INSTALLED = b"""\
C:Q1abcdefabcdef==
P:musl
V:1.2.3-r0
A:x86_64
S:100000
I:512000
T:musl libc
U:https://musl.libc.org/
L:MIT
o:musl
m:maintainer@alpinelinux.org
t:1700000000
c:abc123

C:Q1deadbeefbeef==
P:alpine-baselayout
V:3.4.0-r0
A:x86_64
S:50000
I:204800
T:Alpine base dir structure
U:https://alpinelinux.org/
L:GPL-2.0
o:alpine-baselayout
m:maintainer@alpinelinux.org
t:1700000001
c:def456

"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_poc(archive_path, extra_args=None, expect_success=True):
    """Run the PoC binary, return (returncode, parsed_json_or_None, stderr)."""
    cmd = [str(BINARY), "--archive", str(archive_path)] + (extra_args or [])
    result = subprocess.run(cmd, capture_output=True, text=True)
    if expect_success:
        assert result.returncode == 0, (
            f"PoC exited {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        return json.loads(result.stdout)
    return result


def _find_package(packages, name):
    for pkg in packages:
        if pkg["name"] == name:
            return pkg
    return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def binary_present():
    if not BINARY.exists():
        pytest.skip(
            f"PoC binary not found at {BINARY}. "
            "Build with: cmake -B build && cmake --build build"
        )


@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


# ---------------------------------------------------------------------------
# Local archive tests
# ---------------------------------------------------------------------------

class TestBinaryBaseline:
    def test_help_exits_zero(self):
        result = subprocess.run([str(BINARY), "--help"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "--archive" in result.stdout

    def test_no_args_exits_nonzero(self):
        result = subprocess.run([str(BINARY)], capture_output=True, text=True)
        assert result.returncode != 0

    def test_unknown_flag_exits_nonzero(self):
        result = subprocess.run(
            [str(BINARY), "--unknown-flag"], capture_output=True, text=True
        )
        assert result.returncode != 0

    def test_missing_archive_exits_nonzero(self, tmp_dir):
        result = subprocess.run(
            [str(BINARY), "--archive", str(tmp_dir / "does_not_exist.tar")],
            capture_output=True, text=True,
        )
        assert result.returncode != 0

    def test_corrupt_tar_exits_nonzero(self, tmp_dir):
        bad = tmp_dir / "corrupt.tar"
        bad.write_bytes(b"this is not a valid tar archive at all " * 10)
        result = subprocess.run(
            [str(BINARY), "--archive", str(bad)], capture_output=True, text=True
        )
        assert result.returncode != 0


class TestDpkgArchive:
    @pytest.fixture
    def dpkg_tar(self, tmp_dir):
        data = _make_docker_save(
            [{"var/lib/dpkg/status": _DPKG_STATUS}],
            repo_tag="test-dpkg:1.0",
        )
        path = tmp_dir / "dpkg_image.tar"
        path.write_bytes(data)
        return path

    def test_output_is_valid_json(self, dpkg_tar):
        result = _run_poc(dpkg_tar)
        assert isinstance(result, dict)

    def test_source_fields(self, dpkg_tar):
        result = _run_poc(dpkg_tar)
        src = result["source"]
        assert src["type"] == "archive"
        assert src["configured_ref"] == ""

    def test_image_metadata(self, dpkg_tar):
        result = _run_poc(dpkg_tar)
        img = result["image"]
        assert img["os"] == "linux"
        assert img["architecture"] == "amd64"
        assert img["layer_count"] == 1
        assert "test-dpkg:1.0" in img["repo_tags"]
        assert img["image_id"].startswith("sha256:")
        assert img["config_digest"].startswith("sha256:")

    def test_scan_fields(self, dpkg_tar):
        result = _run_poc(dpkg_tar)
        scan = result["scan"]
        assert scan["package_manager"] == "dpkg"
        assert scan["database_path"] == "var/lib/dpkg/status"
        assert scan["package_count"] == 2
        assert scan["rpm_backend"] is None
        assert scan["elapsed_ms"] >= 0

    def test_packages_count(self, dpkg_tar):
        result = _run_poc(dpkg_tar)
        assert len(result["packages"]) == 2

    def test_package_libc6(self, dpkg_tar):
        result = _run_poc(dpkg_tar)
        pkg = _find_package(result["packages"], "libc6")
        assert pkg is not None
        assert pkg["version_"] == "2.35-0ubuntu3"
        assert pkg["architecture"] == "amd64"
        assert pkg["type"] == "deb"
        assert pkg["size"] == 12345 * 1024
        assert "GNU C Library" in pkg["description"]

    def test_package_bash(self, dpkg_tar):
        result = _run_poc(dpkg_tar)
        pkg = _find_package(result["packages"], "bash")
        assert pkg is not None
        assert pkg["version_"] == "5.1-6ubuntu1"
        assert pkg["type"] == "deb"
        assert pkg["size"] == 2048 * 1024


class TestApkArchive:
    @pytest.fixture
    def apk_tar(self, tmp_dir):
        data = _make_docker_save(
            [{"lib/apk/db/installed": _APK_INSTALLED}],
            repo_tag="test-apk:edge",
            arch="x86_64",
        )
        path = tmp_dir / "apk_image.tar"
        path.write_bytes(data)
        return path

    def test_scan_fields(self, apk_tar):
        result = _run_poc(apk_tar)
        scan = result["scan"]
        assert scan["package_manager"] == "apk"
        assert scan["database_path"] == "lib/apk/db/installed"
        assert scan["package_count"] == 2
        assert scan["rpm_backend"] is None

    def test_package_musl(self, apk_tar):
        result = _run_poc(apk_tar)
        pkg = _find_package(result["packages"], "musl")
        assert pkg is not None
        assert pkg["version_"] == "1.2.3-r0"
        assert pkg["architecture"] == "x86_64"
        assert pkg["type"] == "apk"
        assert pkg["size"] == 512000
        assert "musl libc" in pkg["description"]

    def test_package_alpine_baselayout(self, apk_tar):
        result = _run_poc(apk_tar)
        pkg = _find_package(result["packages"], "alpine-baselayout")
        assert pkg is not None
        assert pkg["version_"] == "3.4.0-r0"
        assert pkg["size"] == 204800

    def test_image_arch_x86_64(self, apk_tar):
        result = _run_poc(apk_tar)
        assert result["image"]["architecture"] == "x86_64"


class TestNoPackageDb:
    """Layer with no recognized package database produces package_manager=none."""

    @pytest.fixture
    def empty_tar(self, tmp_dir):
        data = _make_docker_save(
            [{"etc/some_random_file": b"hello\n"}],
            repo_tag="test-empty:1.0",
        )
        path = tmp_dir / "empty_image.tar"
        path.write_bytes(data)
        return path

    def test_package_manager_is_none(self, empty_tar):
        result = _run_poc(empty_tar)
        assert result["scan"]["package_manager"] == "none"

    def test_package_count_zero(self, empty_tar):
        result = _run_poc(empty_tar)
        assert result["scan"]["package_count"] == 0
        assert result["packages"] == []


class TestMultiLayer:
    """Package db in the second layer is still discovered via overlay resolution."""

    @pytest.fixture
    def multi_layer_tar(self, tmp_dir):
        data = _make_docker_save(
            [
                {"etc/placeholder": b"base\n"},
                {"var/lib/dpkg/status": _DPKG_STATUS},
            ],
            repo_tag="test-multi:latest",
        )
        path = tmp_dir / "multi_layer.tar"
        path.write_bytes(data)
        return path

    def test_packages_found_from_second_layer(self, multi_layer_tar):
        result = _run_poc(multi_layer_tar)
        assert result["scan"]["package_manager"] == "dpkg"
        assert result["scan"]["package_count"] == 2
        assert result["image"]["layer_count"] == 2

    def test_specific_packages_present(self, multi_layer_tar):
        result = _run_poc(multi_layer_tar)
        names = {p["name"] for p in result["packages"]}
        assert {"libc6", "bash"} == names


class TestCliOptions:
    @pytest.fixture
    def dpkg_tar(self, tmp_dir):
        data = _make_docker_save([{"var/lib/dpkg/status": _DPKG_STATUS}])
        path = tmp_dir / "dpkg.tar"
        path.write_bytes(data)
        return path

    def test_ref_flag_sets_configured_ref(self, dpkg_tar):
        result = _run_poc(dpkg_tar, extra_args=["--ref", "myrepo/myimage:v1"])
        assert result["source"]["configured_ref"] == "myrepo/myimage:v1"

    def test_output_json_file(self, dpkg_tar, tmp_dir):
        out = tmp_dir / "result.json"
        cmd = [str(BINARY), "--archive", str(dpkg_tar), "--output-json", str(out)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["scan"]["package_manager"] == "dpkg"

    def test_output_json_and_summary_are_mutually_silent_on_stdout(self, dpkg_tar, tmp_dir):
        out = tmp_dir / "result.json"
        cmd = [str(BINARY), "--archive", str(dpkg_tar), "--output-json", str(out)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        # When --output-json is used without --summary, stdout must be empty.
        assert result.stdout.strip() == ""

    def test_summary_flag_produces_non_json_text(self, dpkg_tar):
        cmd = [str(BINARY), "--archive", str(dpkg_tar), "--summary"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        assert result.stdout.strip() != ""
        # Summary is human-readable, not valid JSON.
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.stdout)

    def test_archive_and_image_mutually_exclusive(self, dpkg_tar):
        cmd = [
            str(BINARY),
            "--archive", str(dpkg_tar),
            "--image", "docker.io/library/alpine:latest",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode != 0


class TestConfigMode:
    """--config mode reads an ossec.conf-style XML and scans listed images."""

    @pytest.fixture
    def dpkg_tar(self, tmp_dir):
        data = _make_docker_save([{"var/lib/dpkg/status": _DPKG_STATUS}])
        path = tmp_dir / "dpkg.tar"
        path.write_bytes(data)
        return path

    def test_config_mode_archive_entry(self, dpkg_tar, tmp_dir):
        conf = tmp_dir / "ossec.conf"
        conf.write_text(f"""\
<ossec_config>
  <wodle name="container-image-inventory">
    <image>
      <type>archive</type>
      <path>{dpkg_tar}</path>
    </image>
  </wodle>
</ossec_config>
""")
        cmd = [str(BINARY), "--config", str(conf)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["scan"]["package_manager"] == "dpkg"

    def test_config_mode_missing_file(self, tmp_dir):
        cmd = [str(BINARY), "--config", str(tmp_dir / "nonexistent.conf")]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# Remote smoke tests (opt-in)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not REMOTE_ENABLED, reason="Set CII_ENABLE_REMOTE_TESTS=1 to run")
class TestRemote:
    """
    Live registry smoke tests.  These tests fetch a real image from Docker Hub.
    They require network access and may be slow (~30 s for first run).

    Default image: Alpine 3.19.1 amd64 (digest-pinned).
    Override:      CII_REMOTE_IMAGE_REF=<ref>
    """

    @pytest.fixture(scope="class")
    def remote_result(self, tmp_path_factory):
        cache = tmp_path_factory.mktemp("remote_cache")
        cmd = [
            str(BINARY),
            "--image", REMOTE_IMAGE_REF,
            "--platform", "linux/amd64",
            "--no-cache",
            "--cache-dir", str(cache),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, (
            f"Remote scan failed (rc={result.returncode})\n"
            f"ref={REMOTE_IMAGE_REF}\n"
            f"stderr={result.stderr}"
        )
        return json.loads(result.stdout)

    def test_source_type_is_remote(self, remote_result):
        assert remote_result["source"]["type"] == "remote"

    def test_has_registry_and_repository(self, remote_result):
        assert remote_result["source"]["registry"] != ""
        assert remote_result["source"]["repository"] != ""

    def test_image_fields_present(self, remote_result):
        img = remote_result["image"]
        assert img["os"] == "linux"
        assert img["architecture"] == "amd64"
        assert img["layer_count"] > 0
        assert img["config_digest"].startswith("sha256:")
        assert img["root_digest"].startswith("sha256:")
        assert img["selected_manifest_digest"].startswith("sha256:")

    def test_packages_found(self, remote_result):
        scan = remote_result["scan"]
        assert scan["package_count"] > 0
        assert len(remote_result["packages"]) == scan["package_count"]

    def test_package_manager_is_apk(self, remote_result):
        # Alpine images always use APK.
        assert remote_result["scan"]["package_manager"] == "apk"

    def test_packages_have_required_fields(self, remote_result):
        for pkg in remote_result["packages"]:
            for field in ("name", "version_", "architecture", "type", "size"):
                assert field in pkg, f"package {pkg.get('name')} missing field {field}"
            assert pkg["name"] != ""
            assert pkg["version_"] != ""
            assert pkg["type"] == "apk"

    def test_cache_second_run_hits(self, tmp_path_factory):
        """Second scan of the same pinned digest should be served from cache."""
        cache = tmp_path_factory.mktemp("remote_cache_hit")
        cmd_base = [
            str(BINARY),
            "--image", REMOTE_IMAGE_REF,
            "--platform", "linux/amd64",
            "--cache-dir", str(cache),
        ]
        r1 = subprocess.run(cmd_base, capture_output=True, text=True, timeout=120)
        assert r1.returncode == 0
        r2 = subprocess.run(cmd_base, capture_output=True, text=True, timeout=30)
        assert r2.returncode == 0
        data2 = json.loads(r2.stdout)
        assert data2["scan"]["cache_hit"] is True
