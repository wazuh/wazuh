#!/usr/bin/env python3
"""Run inside the Linux build container after building the two binaries and driver."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[2]
BIN = SOURCE / "src"
os.environ["LD_LIBRARY_PATH"] = str(BIN)
checks = []

def run(args, ok=True):
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True)
    assert (p.returncode == 0) == ok, (args, p.returncode, p.stdout, p.stderr)
    return p

def setup(root, method):
    (root / "etc").mkdir(parents=True)
    (root / "logs").mkdir()
    shutil.copy(SOURCE / "etc/internal_options.conf", root / "etc/internal_options.conf")
    option = "" if method is None else f"<compression_method>{method}</compression_method>"
    config = root / "etc/ossec.conf"
    config.write_text(f"<ossec_config><global><logall>yes</logall>{option}</global></ossec_config>")
    return config

def check(name):
    checks.append(name)
    print(f"PASS {name}", flush=True)

with tempfile.TemporaryDirectory(prefix="wazuh-compression-") as tmp:
    base = Path(tmp)
    for method in (None, "gzip", "zstd"):
        root = base / str(method)
        config = setup(root, method)
        run([BIN / "wazuh-monitord", "-t", "-u", "root", "-g", "root", "-D", root, "-c", config])
        check(f"daemon configuration {method}")
        expected = {}
        for kind, tag in (("alerts", "alerts"), ("archives", "archive")):
            directory = root / "logs" / kind / "2026/Nov"
            directory.mkdir(parents=True)
            for extension in ("log", "json"):
                for suffix, payload in (("", b""), ("-001", b'{"event":"wazuh test"}\n' * 20000),
                                        ("-002", os.urandom(256000))):
                    path = directory / f"ossec-{tag}-15{suffix}.{extension}"
                    path.write_bytes(payload)
                    expected[path] = payload
        result = run([BIN / "compression-test-driver", root, config])
        assert json.loads(result.stdout)["monitord"]["compression_method"] == (method or "gzip")
        for path, payload in expected.items():
            assert not path.exists(), path
            if method == "zstd":
                compressed = Path(str(path) + ".zst")
                data = subprocess.check_output(["zstd", "-dq", "-c", compressed])
                assert compressed.stat().st_mode & 0o777 == 0o640
            else:
                data = gzip.decompress(Path(str(path) + ".gz").read_bytes())
            assert data == payload, path
        check(f"{method or 'default gzip'}: 12 alert/archive text/JSON round trips, empty and numbered files")
        assert len(list(root.glob("logs/**/*.sum"))) >= 4
        check(f"{method or 'default gzip'}: checksum files retained")
        # The existing internal switch still disables compression.
        (root / "etc/local_internal_options.conf").write_text("monitord.compress=0\n")
        raw = root / "logs/alerts/2026/Nov/ossec-alerts-15.log"
        raw.write_bytes(b"compression disabled\n")
        run([BIN / "compression-test-driver", root, config])
        assert raw.read_bytes() == b"compression disabled\n"
        check(f"{method or 'default gzip'}: monitord.compress=0")

    root = base / "failure"
    config = setup(root, "zstd")
    payload = os.urandom(1024 * 1024)
    (root / "failure.log").write_bytes(payload)
    run([BIN / "compression-test-driver", root, config, "failure"])
    assert (root / "failure.log").read_bytes() == payload
    assert not list(root.glob("failure.log.zst*"))
    check("write failure preserves source and removes temporary output")
    (root / "single.log").write_bytes(payload)
    (root / "single.log.zst").write_bytes(b"existing archive")
    run([BIN / "compression-test-driver", root, config, "single"])
    assert (root / "single.log").read_bytes() == payload
    assert (root / "single.log.zst").read_bytes() == b"existing archive"
    assert not list(root.glob("single.log.zst.*"))
    check("existing destination preserves both source and archive")
    (root / "single.log").unlink()
    run([BIN / "compression-test-driver", root, config, "single"])
    check("missing optional input")

    for method in ("brotli", "ZSTD", "", "zstd "):
        root = base / ("invalid-" + hashlib.sha256(method.encode()).hexdigest()[:8])
        config = setup(root, method)
        run([BIN / "wazuh-monitord", "-t", "-u", "root", "-g", "root", "-D", root, "-c", config], ok=False)
        check(f"invalid configuration {method!r} rejected")

print(f"{len(checks)} checks passed")
