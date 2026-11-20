#!/usr/bin/env python3
"""Drive the real foreground monitord over midnight using libfaketime."""
import gzip
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[2]
BIN = SOURCE / "src"

for method in ("gzip", "zstd"):
    with tempfile.TemporaryDirectory(prefix="wazuh-daemon-") as tmp:
        root = Path(tmp)
        for name in ("etc", "logs", "queue/sockets", "var/run", "queue/alerts"):
            (root / name).mkdir(parents=True)
        shutil.copy(SOURCE / "etc/internal_options.conf", root / "etc/internal_options.conf")
        (root / "etc/local_internal_options.conf").write_text(
            "monitord.rotate_log=0\nmonitord.monitor_agents=0\nmonitord.day_wait=0\n")
        (root / "etc/ossec.conf").write_text(
            f"<ossec_config><global><compression_method>{method}</compression_method></global></ossec_config>")
        clock = root / "clock"
        clock.write_text("@2026-11-15 23:59:00\n")
        payload = b'{"event":"live daemon midnight rotation"}\n' * 10000
        paths = []
        for directory, tag in (("alerts", "alerts"), ("archives", "archive")):
            folder = root / "logs" / directory / "2026/Nov"
            folder.mkdir(parents=True)
            for extension in ("log", "json"):
                for suffix in ("", "-001", "-002"):
                    path = folder / f"ossec-{tag}-15{suffix}.{extension}"
                    path.write_bytes(payload)
                    paths.append(path)
        queue = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        queue.bind(str(root / "queue/sockets/queue"))
        env = dict(os.environ, LD_LIBRARY_PATH=str(BIN),
                   LD_PRELOAD="/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
                   FAKETIME_TIMESTAMP_FILE="clock", FAKETIME_NO_CACHE="1",
                   FAKETIME_DONT_FAKE_MONOTONIC="1")
        with (root / "daemon-output.log").open("w") as output:
            process = subprocess.Popen([str(BIN / "wazuh-monitord"), "-f", "-n", "-u", "root", "-g", "root",
                                        "-D", str(root)], cwd=root, env=env, stdout=output, stderr=output)
            try:
                time.sleep(13)  # Allow startup sleep and time-control initialization.
                assert process.poll() is None, (root / "daemon-output.log").read_text()
                clock.write_text("@2026-11-16 00:00:01\n")
                extension = ".zst" if method == "zstd" else ".gz"
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and any(p.exists() for p in paths):
                    time.sleep(0.2)
                for path in paths:
                    assert not path.exists(), (str(path), (root / "daemon-output.log").read_text())
                    compressed = Path(str(path) + extension)
                    data = (subprocess.check_output(["zstd", "-dq", "-c", compressed]) if method == "zstd"
                            else gzip.decompress(compressed.read_bytes()))
                    assert data == payload
                assert process.poll() is None
                print(f"PASS live {method} daemon: midnight compressed 12 alert/archive files with exact round trips", flush=True)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                queue.close()
