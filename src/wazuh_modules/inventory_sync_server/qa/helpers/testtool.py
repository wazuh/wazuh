"""Boot and stop the real module pair through the testtool's --serve mode.

Shared by the session-wide `server` fixture of conftest.py and by the suites that need a server of their
own (a different runtime option, say): each call is one process in its own working directory, so two of
them never share a socket, a keystore or a log."""

import json
import os
import pathlib
import signal
import subprocess
import time

SOCKET_RELPATH = "queue/sockets/inventory-sync-http.sock"
QA_DIR = pathlib.Path(__file__).resolve().parent.parent
SRC_DIR = QA_DIR.parents[2]  # .../src


def testtool_path():
    """INVSYNC_TESTTOOL, else the harness built in the default tree."""
    return os.environ.get("INVSYNC_TESTTOOL", str(SRC_DIR / "build" / "bin" / "inventory_sync_server_testtool"))


def start_server(testtool, workdir, config):
    """Runs `testtool --serve --no-vd --config <workdir>/config.json` and waits for its socket.

    --no-vd keeps the vulnerability scanner facade down: the server's scanner seam then reports
    feed-ready and answers every scan as a legitimate skip (D22's skip row), so VD-flagged sessions
    still index deterministically.

    `config` is the testtool's config.json as a dict (it may carry `internal_options`, a string of
    `key=value` lines for the indexer client's runtime). Returns (process, socket_path)."""
    workdir = pathlib.Path(workdir)
    config_path = workdir / "config.json"
    config_path.write_text(json.dumps(config))

    # Output goes to a FILE, never a pipe: the server logs every bulk response,
    # and an unread pipe buffer would eventually block a worker mid-flush.
    log_path = workdir / "server.log"
    with open(log_path, "w") as log_file:
        process = subprocess.Popen(
            [testtool, "--serve", "--no-vd", "--config", str(config_path)],
            cwd=workdir,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )

    socket_path = workdir / SOCKET_RELPATH
    if len(str(socket_path)) > 100:  # AF_UNIX sun_path budget
        process.kill()
        raise RuntimeError(f"socket path too long for AF_UNIX: {socket_path}")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"testtool died during startup:\n{log_path.read_text()[-4000:]}")
        if socket_path.exists():
            return process, socket_path
        time.sleep(0.2)
    process.kill()
    raise RuntimeError(f"the server socket never appeared; log tail:\n{log_path.read_text()[-4000:]}")


def stop_server(process):
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
