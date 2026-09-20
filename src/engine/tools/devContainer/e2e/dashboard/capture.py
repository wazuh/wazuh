#!/usr/bin/env python3
"""capture.py — reproducible Wazuh dashboard captures with Playwright.

One line per check in the shared e2e grammar (the one wazuh_verify_manager.sh and
agents/verify_agents.sh print), a PNG plus a JSON sidecar per view, and a captures.md
manifest with the sha256 of every file the run wrote:

    # capture.py — <ISO-8601 UTC> — <dashboard-url>
    PASS  1. indexer cluster health (got: green)
    ...
    # manifest: <out>/captures.md
    # summary: executed=N passed=N failed=N skipped=N

Exit status is 0 iff failed=0. Every check runs inside its own try/except: an unexpected
error becomes 'FAIL n. ... (got: <exception>)' and the run still reaches its summary — and
the manifest is written BEFORE that summary, so a manifest that could not be written is a
counted failure (FAIL 10) and not an exception after a green report.

What it proves: each view is asserted against the data of THIS run — the agents global.db
reports as active, a nonce event injected for this run, ONE concrete package (name and
version) sampled from the indexer for this run's 5.x agent, ONE concrete CVE of that same
agent — and the proof is ONE row of the view's table matched COLUMN BY COLUMN with exact
equality. A dashboard showing stale, empty, foreign or merely similar data cannot produce a
green run. The screenshot is the WHOLE page (V11): the document below the fold or past the
right edge is in the PNG, a container that scrolls on its own is as it was drawn. Where the row
was (inside the viewport, a column cut with '…') is measured and reported as the assertion's `frame_note`, never as a verdict.

Safety: nothing is interpolated into a shell (`--exec-docker` passes argv and feeds the line
through stdin); credentials come from the environment only (a URL carrying them is rejected
by check 0) and every string is redacted before it is printed or serialized.

The decisions (which checks run, where a view had to land, which rows match, what the VD
probe means) live in capture_logic.py and are unit-tested without network, without a browser
and without a manager by test_capture_logic.py.

Prerequisites: run as root (queue/sockets/vd-http.sock is 0660 and queue/db/global.db is not
world readable), the indexer+dashboard stack up, and the venv created once with --setup.
See README.md.
"""

import argparse
import base64
import hashlib
import http.client
import json
import gzip
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from capture_logic import (
    CHECK_NAMES,
    MANIFEST_CHECK,
    SAMPLE_CHECK,
    VIEW_CHECK,
    VIEW_NAMES,
    artifacts_ok,
    blocked_by,
    browsers_dir,
    browsers_env,
    dashboard_row,
    dashboard_version,
    docker_exec_argv,
    expand_row,
    format_line,
    git_status_row,
    grid_rows,
    inventory_candidates,
    landing_ok,
    landing_reason,
    out_dir_exclusive,
    out_dir_refusal,
    parse_hits,
    pick_agent_5x,
    plan_checks,
    png_size,
    probe_blocks,
    probe_source,
    redact,
    redact_obj,
    render_landing,
    render_query,
    resolve_agents,
    row_in_frame,
    rows_matching,
    safe_url,
    secrets_of,
    sources_row,
    summary_line,
    syslog_nonce_line,
    truncated_columns,
    url_credentials_problem,
    validate_container,
    validate_nonce,
    vd_verdict,
    view_block,
    view_verdict,
    vulnerability_sample,
)

DASHBOARD_PACKAGE = "5.0.0-latest"
EVENTS_INDEX = "wazuh-events-v5-*"
WAIT_SELECTOR_TIMEOUT_MS = 25000  # bounded wait for a view's `wait_selector` (data grid rows load after the route settles)
INVENTORY_INDEX = "wazuh-states-inventory-packages*"
VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities*"
AGENT_ID_FIELD = "wazuh.agent.id"
EVENT_FIELD = "user.name"  # event.original is stored with index:false in wazuh-events-v5-*; the system-auth decoder puts the nonce (invalid user) in user.name (keyword) — verified live 2026-09-20
VD_STATUS_PATH = "/vulnerability-detector/status"
VD_SOCKET = "queue/sockets/vd-http.sock"
GLOBAL_DB = "queue/db/global.db"
EVENTS_DEADLINE = 120
INDEXER_DEADLINE = 120
INVENTORY_DEADLINE = 300
# How many package names check 4b may walk looking for one with a single document (multi-arch
# packages have two, and the view asserts exactly one row).
SAMPLE_CANDIDATES = 25
VIEWPORT = {"width": 1280, "height": 800}
# Pinned: "reproducible captures" with whatever playwright/chromium pip resolves that day is a
# promise the tool cannot keep (a browser release moves layout, and this run asserts layout).
# 1.63.0 is the version every live run of this tool used (chromium-1243).
PLAYWRIGHT_PIN = "playwright==1.63.0"
REEXEC_GUARD = "CAPTURE_PY_VENV_REEXEC"
SOURCE_FILES = ("capture.py", "capture_logic.py", "views.json")

VIEW_PROVES = {
    "agents": "the agents active in global.db for this run are listed",
    "discover": "the event carrying this run's nonce is searchable",
    "inventory": "the package sampled from the indexer is shown for this run's 5.x agent",
    "vd": "the CVE sampled from the indexer is shown for this run's 5.x agent",
}


# --------------------------------------------------------------------------- helpers


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compact_iso():
    """ISO-8601 UTC without separators — the run directories sort chronologically."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def canonical(path):
    """The path with every symlink RESOLVED (`os.path.realpath`).

    `--out` and the roots it must stay out of are compared as text, so they have to be the
    same text for the same directory: `/tmp/alias -> <checkout>/out` is inside the checkout
    however innocent its spelling looks, and only the filesystem knows it (v7). realpath does
    not require the path to exist and does not raise.
    """
    return os.path.realpath(str(path or ""))


def entry_kind(path):
    """What an entry of --out IS, for the exclusivity check: file|dir|symlink|other|missing.

    A symlink is answered as a symlink, never as what it points at (`os.path.islink` first):
    a link called `06-agents.png` names an artifact of this tool and points wherever its author
    chose, and `os.remove` on it would be the least of the problems. Nothing here follows it.
    """
    if os.path.islink(path):
        return "symlink"
    if os.path.isdir(path):
        return "dir"
    if os.path.isfile(path):
        return "file"
    return "other" if os.path.exists(path) else "missing"


def clear_dir(path):
    """Empty an explicit --out before writing: its contents go, the directory itself stays
    (the parent is never touched). Returns (removed, problem, ours).

    The directory is emptied ONLY when every entry in it is a REGULAR FILE this tool wrote
    (`out_dir_exclusive` over `(name, kind)`): `--out` runs as root and deleting somebody
    else's directory is not a capture. A directory called `captures.md` and a symlink called
    `06-agents.png` wear an artifact's name and are not artifacts, which is why the kind is
    read from the filesystem and travels into the reason line.

    When it is not exclusive NOTHING is removed, the problem names up to three of the offending
    entries with their kind and `ours` is False — the run must not write into it at all, not
    even the manifest. Removal is `os.remove` on those regular files and nothing else: there is
    no recursive delete anywhere in this file, so no reachable path can walk a tree. A listing
    or a removal that fails is a problem too — never an empty list that silently means 'nothing
    to remove', because a leftover PNG of a previous run must not be mistaken for this run's
    evidence.
    """
    if not os.path.isdir(path):
        return [], "", True
    try:
        names = sorted(os.listdir(path))
    except OSError as exc:
        return [], "out dir not cleared: {0} ({1})".format(path, type(exc).__name__), True
    entries = [(name, entry_kind(os.path.join(path, name))) for name in names]
    exclusive, offenders = out_dir_exclusive(entries)
    if not exclusive:
        return [], "out dir not exclusive: {0}".format(", ".join(offenders)), False
    removed, failed = [], []
    for name, _kind in entries:  # every one of them is a regular file of ours
        try:
            os.remove(os.path.join(path, name))
            removed.append(name)
        except OSError as exc:
            failed.append("{0} ({1})".format(name, type(exc).__name__))
    if failed:
        return removed, "out dir not cleared: {0} ({1})".format(path, "; ".join(failed)), True
    return removed, "", True


def repo_roots():
    """The checkout(s) --out must never be inside: $WAZUH_REPO and the toplevel of the git
    repository this script lives in, CANONICAL. Captures under either would show up in
    `git status` — the very thing the manifest records as provenance."""
    roots = []
    repo = os.environ.get("WAZUH_REPO")
    if repo:
        roots.append(canonical(repo))
    rc, text = git_output(script_dir(), ["rev-parse", "--show-toplevel"])
    if rc == 0 and text.strip():
        roots.append(canonical(text.strip()))
    return roots


def script_dir():
    return Path(__file__).resolve().parent


def workspace_root():
    """$WORKSPACE — the devcontainer workspace, i.e. the parent of the repo checkout."""
    repo = os.environ.get("WAZUH_REPO")
    if repo:
        return str(Path(repo).resolve().parent)
    return str(script_dir().parents[6])


def make_nonce():
    return "e2e-capture-{0}".format(uuid.uuid4().hex[:8])


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def png_dimensions(path):
    """'<width>x<height>' of a capture, read from the file's own IHDR header, or '—'.

    The PNGs are full-page (V11), so their height is the page's, not the viewport's: the
    manifest reports the size it measured here instead of a constant that would no longer
    describe the file. Anything that is not a PNG (a sidecar, a truncated write) is '—'.

    A file that cannot be OPENED is not '—': the OSError propagates (v8), so the manifest counts
    it as `FAIL 10. manifest (got: unreadable: <file> (<type>))` instead of printing a dash under
    a report that said failed=0 — a PNG whose hash was cached at capture time is exactly the
    file nobody else reads again.
    """
    with open(path, "rb") as handle:
        header = handle.read(24)
    size = png_size(header)
    return "{0}x{1}".format(size[0], size[1]) if size else "—"


def git_output(path, argv, timeout=20):
    """(rc, stdout) of one read-only git command in `path`, or (None, "") when git is not
    usable there. Used for provenance only; the capturer never writes to the repo."""
    try:
        out = subprocess.run(
            ["git", "-C", str(path)] + list(argv),
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return None, ""
    return out.returncode, out.stdout


def git_head(path):
    rc, text = git_output(path, ["rev-parse", "--short", "HEAD"])
    if rc != 0:
        return "(unknown)"
    return text.strip() or "(unknown)"


def git_status(path):
    """`git status --porcelain` of the capturer's directory, or '(unknown)'.

    Staged, unstaged AND untracked changes all show up here; the sha256 of each source file
    (see source_digests) is what pins their content, so no diff is hashed.
    """
    rc, text = git_output(path, ["status", "--porcelain", "--", "."])
    if rc is None or rc != 0:
        return "(unknown)"
    return text


def source_digests(args):
    """[(name, sha256)] of the files that produced this run: the capturer, its logic, its
    views — plus --views-file when it is not the one next to the script."""
    entries = []
    here = script_dir()
    for name in SOURCE_FILES:
        try:
            entries.append((name, sha256_of(str(here / name))))
        except OSError as exc:
            entries.append((name, "(unreadable: {0})".format(type(exc).__name__)))
    views_file = os.path.abspath(args.views_file)
    if views_file != str(here / "views.json"):
        try:
            entries.append(("views-file {0}".format(views_file), sha256_of(views_file)))
        except OSError as exc:
            entries.append(("views-file {0}".format(views_file),
                            "(unreadable: {0})".format(type(exc).__name__)))
    return entries


def ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_request(url, auth=None, data=None, method=None, timeout=15):
    """Return (status, body). Raises urllib.error.URLError/socket errors when unreachable."""
    payload = data.encode() if isinstance(data, str) else data
    request = urllib.request.Request(url, data=payload, method=method)
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    if auth:
        token = base64.b64encode("{0}:{1}".format(*auth).encode()).decode()
        request.add_header("Authorization", "Basic {0}".format(token))
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_context()) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:  # an answer is an answer: the server is alive
        return err.code, err.read().decode("utf-8", "replace")


def indexer_json(args, path, body=None):
    url = "{0}/{1}".format(args.indexer_url.rstrip("/"), path.lstrip("/"))
    status, text = http_request(
        url,
        auth=(args.indexer_user, args.indexer_password),
        data=json.dumps(body) if body is not None else None,
        method="POST" if body is not None else "GET",
    )
    try:
        return status, json.loads(text)
    except ValueError:
        return status, {}


def indexer_search(args, index, body):
    status, doc = indexer_json(args, "{0}/_search".format(index), body)
    if status >= 400:
        raise RuntimeError("indexer _search on {0} answered {1}".format(index, status))
    return doc


def indexer_count(args, index, query):
    status, doc = indexer_json(args, "{0}/_count".format(index), {"query": query})
    if status >= 400:
        raise RuntimeError("indexer _count on {0} answered {1}".format(index, status))
    return int(doc.get("count", 0))


def agent_terms_query(agent_ids):
    return {"terms": {AGENT_ID_FIELD: list(agent_ids)}}


def last_scanner_log(args, ids):
    """Last vulnerability-scanner 'scan completed' line of the manager log for these agents (root-only; best effort):
    turns a bare '0 findings' into evidence — did the scanner run, how many packages, how many vulnerable."""
    # The live log first, then the rotated ones (the manager rotates at midnight into
    # logs/wazuh/<YYYY>/<Mon>/wazuh-<DD>.log.gz): a scan that ran yesterday is still evidence today.
    for path in [os.path.join(args.home, "logs", "wazuh-manager.log")] + rotated_manager_logs(args.home):
        for line in reversed(read_log_tail(path)):
            if "vulnerability-scanner" in line and "scan completed" in line and any(
                "agent='{0}'".format(i) in line or "Agent '{0}'".format(i) in line for i in ids
            ):
                return line.split("modulesd:", 1)[-1].strip()[:200]
    return ""


def rotated_manager_logs(home, limit=2):
    """The newest rotated manager logs (wazuh-<DD>.log or .log.gz), newest first, at most `limit`."""
    root = os.path.join(home, "logs", "wazuh")
    found = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            stem = name[:-3] if name.endswith(".gz") else name
            if stem.startswith("wazuh-") and stem.endswith(".log") and stem[6:-4].isdigit():
                full = os.path.join(dirpath, name)
                try:
                    found.append((os.path.getmtime(full), full))
                except OSError:
                    pass
    return [f for _m, f in sorted(found, reverse=True)[:limit]]


def read_log_tail(path, size=2000000):
    """Last `size` bytes of a log as lines; .gz logs are read whole (they are small); errors ⇒ []."""
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as handle:
                data = handle.read()[-size:]
        else:
            with open(path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                handle.seek(max(0, handle.tell() - size))
                data = handle.read()
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over an AF_UNIX socket (the manager modules' UDS HTTP servers)."""

    def __init__(self, path, timeout=10):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


def vd_probe(args):
    """The vulnerability-detector status: --probe-json wins and the socket is then never
    opened; otherwise GET /vulnerability-detector/status over --vd-socket."""
    kind, source = probe_source(args.probe_json, args.vd_socket)
    if kind == "file":
        with open(source) as handle:
            return json.load(handle)
    conn = UnixHTTPConnection(source)
    try:
        conn.request("GET", VD_STATUS_PATH, headers={"Host": "localhost"})
        response = conn.getresponse()
        body = response.read().decode("utf-8", "replace")
        if response.status != 200:
            return {"error": "HTTP {0} on {1}".format(response.status, VD_STATUS_PATH)}
        return json.loads(body)
    except Exception as exc:
        return {"error": "{0}: {1}".format(type(exc).__name__, exc)}
    finally:
        conn.close()


def active_agents(home):
    """[(id3, name, version)] of the agents global.db reports as active.

    Read-only, never writes. The version is what tells the 5.x agent of the run apart, for
    the {{agent_id_5x}} / {{agent_name_5x}} placeholders the inventory and vd views filter by.
    """
    path = os.path.join(home, GLOBAL_DB)
    conn = sqlite3.connect("file:{0}?mode=ro".format(path), uri=True, timeout=10)
    try:
        rows = conn.execute(
            "select id, name, version from agent where connection_status='active' order by id"
        ).fetchall()
    finally:
        conn.close()
    return [("{0:03d}".format(int(i)), n, v or "") for i, n, v in rows]


def placeholder_values(ctx):
    """What views.json placeholders resolve to for this run. Anything still empty makes
    render_query raise, and the view that needed it fails naming the placeholder."""
    package = ctx.get("package_5x") or {}
    names = list(ctx.get("agent_names") or [])
    return {
        "nonce": ctx.get("nonce"),
        "agent_names": names,
        "agent_count": len(names) or None,
        "agent_id_5x": ctx.get("agent_id_5x"),
        "agent_name_5x": ctx.get("agent_name_5x"),
        "package_name": package.get("name"),
        "package_version": package.get("version"),
        "cve_5x": ctx.get("cve_5x"),
    }


# --------------------------------------------------------------------------- reporting


class Reporter:
    """Every line the run prints — and the ONLY place this file may print from.

    Nothing reaches stdout without going through redact(); `test_no_bare_print` asserts
    statically that no `print(` call of capture.py lives outside this class, so a header or a
    progress line cannot quietly become the one place a credential escapes (D-10b).
    """

    def __init__(self, secrets=None):
        self.executed = 0
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.failed_checks = []
        self.secrets = list(secrets or [])

    def clean(self, text):
        return redact(text, self.secrets)

    def note(self, text):
        print("# {0}".format(self.clean(text)), flush=True)

    def record(self, status, n, name, got):
        status = str(status).upper()
        print(format_line(status, n, name, self.clean(got)), flush=True)
        if status == "SKIP":
            self.skipped += 1
        else:
            self.executed += 1
            if status == "PASS":
                self.passed += 1
            else:
                self.failed += 1
                self.failed_checks.append(n)
        return status

    def run(self, n, name, func):
        try:
            status, got = func()
        except Exception as exc:  # a check never aborts the run, and never leaks a credential
            status, got = "FAIL", "{0}: {1}".format(type(exc).__name__, exc)
        return self.record(status, n, name, got)

    def summary(self):
        print(summary_line(self.executed, self.passed, self.failed, self.skipped), flush=True)


def write_text(path, text, secrets):
    """Persist redacted text: a sidecar or a manifest is evidence that gets copied around."""
    with open(path, "w") as handle:
        handle.write(redact(text, secrets))
    return path


def write_json(path, data, secrets):
    """Persist an object as JSON, redacted BEFORE serializing: json.dumps escapes quotes, so
    a password containing one would survive a redaction applied to the dumped text."""
    return write_text(path, json.dumps(redact_obj(data, secrets), indent=2, sort_keys=True) + "\n",
                      secrets)


# --------------------------------------------------------------------------- venv


def venv_python(venv):
    return os.path.join(venv, "bin", "python")


def inside_venv(venv):
    return os.path.realpath(sys.prefix) == os.path.realpath(venv)


def enter_venv(args):
    """Re-exec inside the venv so playwright and its browsers are the ones --setup built.

    Returns "inside", "missing" (no venv: check 0 fails) or "loop" (re-exec went nowhere).
    """
    venv = os.path.abspath(args.venv)
    # One policy for both paths (already the venv's interpreter, or re-exec'd into it):
    # PLAYWRIGHT_BROWSERS_PATH is SET, never defaulted, or an inherited value would send
    # playwright to ~/.cache/ms-playwright while --setup installed under the venv.
    os.environ.update(browsers_env({}, venv, args.browsers_path))
    if inside_venv(venv):
        return "inside"
    if os.environ.get(REEXEC_GUARD):
        return "loop"
    interpreter = venv_python(venv)
    if not os.path.exists(interpreter):
        return "missing"
    os.environ[REEXEC_GUARD] = "1"
    os.execv(interpreter, [interpreter, os.path.abspath(__file__)] + sys.argv[1:])
    return "loop"  # not reached


CHROMIUM_LAUNCH_SNIPPET = (
    "from playwright.sync_api import sync_playwright\n"
    "with sync_playwright() as play:\n"
    "    browser = play.chromium.launch(args=['--no-sandbox'])\n"
    "    page = browser.new_page()\n"
    "    page.goto('about:blank')\n"
    "    browser.close()\n"
)


def launch_chromium_once(venv, env):
    """Prove the browser --setup just installed actually starts (headless, about:blank).

    Returns None when it launched, or the last line of its output: an installed chromium that
    cannot start (a missing system library) must not look like a successful --setup.
    """
    try:
        out = subprocess.run(
            [venv_python(venv), "-c", CHROMIUM_LAUNCH_SNIPPET],
            env=env, capture_output=True, text=True, timeout=300,
        )
    except Exception as exc:
        return "{0}: {1}".format(type(exc).__name__, exc)[:300]
    if out.returncode == 0:
        return None
    lines = (out.stderr or out.stdout or "").strip().splitlines()
    return (lines[-1] if lines else "rc={0}".format(out.returncode))[:300]


def do_setup(args):
    """Create the venv, install playwright and its chromium. Never touches the repo."""
    rep = Reporter(args.secrets)
    venv = os.path.abspath(args.venv)
    browsers = browsers_dir(venv, args.browsers_path)
    rep.note("capture.py --setup — {0} — venv={1}".format(now_iso(), venv))
    if not os.path.exists(venv_python(venv)):
        subprocess.check_call([sys.executable, "-m", "venv", venv])
    subprocess.check_call([venv_python(venv), "-m", "pip", "install", "--upgrade", "pip"])
    # pinned: a capture asserts layout, and layout moves with the browser
    subprocess.check_call([venv_python(venv), "-m", "pip", "install", PLAYWRIGHT_PIN])
    env = browsers_env(os.environ, venv, args.browsers_path)
    install = [venv_python(venv), "-m", "playwright", "install", "chromium"]
    # --with-deps runs apt-get: --setup is the ONE mode of this script that installs system
    # packages, and it says so (README, Prerequisites). A capture run never does.
    rc = subprocess.call(install + ["--with-deps"], env=env)
    if rc != 0:
        rep.note("--with-deps failed (rc={0}); retrying without it".format(rc))
        rc = subprocess.call(install, env=env)
        deps = subprocess.run(
            [venv_python(venv), "-m", "playwright", "install-deps", "--dry-run", "chromium"],
            env=env,
            capture_output=True,
            text=True,
        )
        for line in (deps.stdout or deps.stderr or "").splitlines():
            rep.note("apt: {0}".format(line))
    rep.note("setup rc={0}; browsers under {1}".format(rc, browsers))
    problem = launch_chromium_once(venv, env)
    if problem:
        rep.record("FAIL", 0, CHECK_NAMES[0], "chromium launch failed: {0}".format(problem))
        return 1
    rep.note("chromium launch: ok")
    return rc


# --------------------------------------------------------------------------- checks 0-4b


def check_setup(args):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as play:
        executable = play.chromium.executable_path
    if not executable or not os.path.exists(executable):
        return "FAIL", "chromium missing at {0}; run --setup".format(executable)
    return "PASS", "venv {0}, browsers {1}, chromium {2}".format(
        args.venv, browsers_dir(os.path.abspath(args.venv), args.browsers_path), executable
    )


def check_indexer(args):
    deadline = time.time() + INDEXER_DEADLINE
    last = "no answer"
    while True:
        try:
            status, doc = indexer_json(args, "_cluster/health")
            last = doc.get("status") if status == 200 else "HTTP {0}".format(status)
            if last in ("green", "yellow"):
                return "PASS", last
        except Exception as exc:
            last = "{0}: {1}".format(type(exc).__name__, exc)
        if time.time() >= deadline:
            return "FAIL", "{0} after {1}s".format(last, INDEXER_DEADLINE)
        time.sleep(5)


def dashboard_status_version(args):
    """The version GET /api/status reports, read WITH credentials, or '' when it cannot be.

    Best effort on purpose: the version is provenance, not a check — but it must be measured
    or declared as declared, never printed as a constant that looks measured (D-10b).
    """
    url = "{0}/api/status".format(args.dashboard_url.rstrip("/"))
    try:
        status, body = http_request(url, auth=(args.dashboard_user, args.dashboard_password),
                                    timeout=20)
        if status != 200:
            return ""
        return dashboard_version(json.loads(body))
    except Exception:
        return ""


def check_dashboard(args, ctx=None):
    url = "{0}/api/status".format(args.dashboard_url.rstrip("/"))
    try:
        status, _body = http_request(url, timeout=20)
    except Exception as exc:
        return "FAIL", "{0}: {1}".format(type(exc).__name__, exc)
    # 401 without credentials still proves the server is up and answering.
    if status not in (200, 401):
        return "FAIL", "HTTP {0}".format(status)
    version = dashboard_status_version(args)
    if ctx is not None:
        ctx["dashboard_version"] = version
    return "PASS", "HTTP {0}{1}".format(
        status, ", version {0}".format(version) if version else ", version not readable")


def check_agents(args, ctx):
    """Every id this run will filter by is crossed with global.db: it must be there AND be
    active. --agent-ids never declares an agent active on its own, and the agent the report
    and the views call "the 5.x agent" must be active AND a v5 one (--agent-5x-id 001 for a
    4.14.3 agent is a FAIL, not a relabelling).
    """
    requested = [i.strip() for i in args.agent_ids.split(",") if i.strip()]
    requested = ["{0:03d}".format(int(i)) if i.isdigit() else i for i in requested]
    source = "--agent-ids crossed with {0}/{1}".format(args.home, GLOBAL_DB) if requested \
        else "{0}/{1}".format(args.home, GLOBAL_DB)
    agents = active_agents(args.home)  # an unreadable global.db raises: FAIL 3 with the reason
    ids, names, problem = resolve_agents(requested, agents)
    ctx["agent_ids"], ctx["agent_names"] = ids, names
    if problem:
        return "FAIL", "{0} ({1})".format(problem, source)
    # the 5.x agent is chosen AMONG the ids this run resolved, never outside them
    agent_5x, name_5x, problem_5x = pick_agent_5x(agents, args.agent_5x_id, ids)
    ctx["agent_id_5x"], ctx["agent_name_5x"] = agent_5x, name_5x
    if problem_5x:
        return "FAIL", problem_5x if args.agent_5x_id else "{0} ({1})".format(problem_5x, source)
    return "PASS", "{0} active: {1} ({2}); 5x={3} {4}".format(
        len(ids), ",".join(ids), source, agent_5x, name_5x
    )


def check_events(args, ctx, rep):
    nonce = validate_nonce(ctx["nonce"])  # ValueError => FAIL 4 naming the reason, no execution
    container = validate_container(args.agent_container)
    line = syslog_nonce_line(nonce, container, time.strftime("%b %e %H:%M:%S"))
    argv = docker_exec_argv(container)
    rep.note("nonce carrier for {0}: {1}".format(nonce, line))
    rep.note("nonce command (argv, the line arrives on stdin): {0}".format(argv))
    if args.exec_docker:
        subprocess.run(argv, input=line + "\n", check=True, text=True)
        rep.note("nonce line written by --exec-docker")
    elif not args.nonce_written:
        return "SKIP", "nonce line not written; append it in {0} and re-run with --nonce-written".format(
            container
        )

    query = {"term": {EVENT_FIELD: nonce}}
    deadline = time.time() + EVENTS_DEADLINE
    count = 0
    while True:
        count = indexer_count(args, EVENTS_INDEX, query)
        if count >= 1:
            break
        if time.time() >= deadline:
            return "FAIL", "0 documents in {0} after {1}s".format(EVENTS_INDEX, EVENTS_DEADLINE)
        time.sleep(5)
    doc = indexer_search(args, EVENTS_INDEX, {"query": query, "size": 1})
    hits = (doc.get("hits") or {}).get("hits") or []
    if hits:
        ctx["index"] = hits[0].get("_index")
        source = hits[0].get("_source") or {}
        ctx["category"] = ((source.get("wazuh") or {}).get("integration") or {}).get("category")
    return "PASS", "{0} document(s) in {1}".format(count, ctx.get("index") or EVENTS_INDEX)


def package_count(args, agent_5x, name):
    """How many inventory documents this agent has for that package name."""
    query = {"bool": {"filter": [{"term": {AGENT_ID_FIELD: agent_5x}},
                                 {"term": {"package.name": name}}]}}
    return indexer_count(args, args.inventory_index, query)


def unique_package(args, agent_5x, candidates, rep=None, limit=SAMPLE_CANDIDATES):
    """The first candidate with EXACTLY ONE document for this agent — (name, version) or ("","").

    The inventory view asserts `rows_eq: 1` and `hits_eq: 1` on `package.name:"<sampled>"`, so
    a name the agent has twice (the same package for two architectures) would fail the view on
    a truth about the data instead of on the dashboard. The candidates arrive sorted by name,
    so the choice is deterministic for a given agent.
    """
    for name, version in list(candidates)[:limit]:
        count = package_count(args, agent_5x, name)
        if count == 1:
            return name, version
        if rep is not None:
            rep.note("inventory sample: {0} has {1} documents for agent {2}, next".format(
                name, count, agent_5x))
    return "", ""


def check_inventory_sample(args, ctx, rep):
    """Check 4b — sample ONE inventory document of this run's 5.x agent from the indexer.

    This is what makes the inventory (and, through the same idea, the vd) view assert the
    SAME document the backend has: the browser is then filtered by that package name and the
    row must read that name AND that version, column by column. A total ('there are
    packages') would pass on any agent's data, or on a filter the dashboard silently ignored.

    The sampled package must have exactly one document for the agent, because that is what the
    view is then asked to show (`rows_eq: 1`, `hits_eq: 1`): the first page of names is walked
    until one of them is unique.
    """
    agent_5x = ctx.get("agent_id_5x")
    if not agent_5x:
        return "FAIL", "no 5.x agent resolved (check 3)"
    body = {"query": {"term": {AGENT_ID_FIELD: agent_5x}}, "size": SAMPLE_CANDIDATES,
            "sort": [{"package.name": "asc"}]}
    deadline = time.time() + INVENTORY_DEADLINE
    candidates = []
    while True:
        candidates = inventory_candidates(indexer_search(args, args.inventory_index, body))
        if candidates:
            break
        if time.time() >= deadline:
            return "FAIL", "0 documents in {0} for agent {1} after {2}s".format(
                args.inventory_index, agent_5x, INVENTORY_DEADLINE
            )
        time.sleep(15)
    name, version = unique_package(args, agent_5x, candidates, rep)
    if not name:
        return "FAIL", "no package with exactly one document for agent {0} among the first {1} of {2}".format(
            agent_5x, len(candidates[:SAMPLE_CANDIDATES]), args.inventory_index)
    ctx["package_5x"] = {"name": name, "version": version}
    rep.note("inventory sample for agent {0}: {1} {2}".format(agent_5x, name, version))
    if not version:
        return "FAIL", "package '{0}' of agent {1} has no package.version".format(name, agent_5x)
    return "PASS", "agent {0}: package {1} {2} (1 document) in {3}".format(
        agent_5x, name, version, args.inventory_index
    )


# --------------------------------------------------------------------------- browser


class Session:
    """One browser session: login plus every view, with the plugin API calls counted."""

    def __init__(self, args):
        from playwright.sync_api import sync_playwright

        self._play = sync_playwright().start()
        self.browser = self._play.chromium.launch(args=["--no-sandbox"])
        self.context = self.browser.new_context(viewport=VIEWPORT, ignore_https_errors=True)
        self.page = self.context.new_page()
        self.api_calls = {"total": 0, "status_ge_400": []}
        self.page.on("response", self._track)

    def _track(self, response):
        try:
            if "/api/request" in response.url:
                self.api_calls["total"] += 1
                if response.status >= 400:
                    self.api_calls["status_ge_400"].append([response.status, response.url])
        except Exception:
            pass

    def close(self):
        for closer in (self.context.close, self.browser.close, self._play.stop):
            try:
                closer()
            except Exception:
                pass


LOGIN_LANDING = {"path": "/app/wz-home", "hash_route": None, "hash_params": {}, "state": {}}


def do_login(session, args):
    """Log in without ever quoting Playwright back.

    Playwright's own error text repeats the value it was asked to fill (`fill("<secret>")`),
    so a timeout on the password field would print the password: every step is wrapped and
    only the exception TYPE and the step name are reported. Reporter.redact() is the second
    line of defence, not the first.
    """
    page = session.page
    step = "goto"
    try:
        page.goto(args.dashboard_url.rstrip("/") + "/app/login",
                  wait_until="domcontentloaded", timeout=60000)
        step = "wait user-name"
        page.wait_for_selector('[data-test-subj="user-name"]', timeout=30000)
        step = "fill user"
        page.fill('[data-test-subj="user-name"]', args.dashboard_user)
        step = "fill password"
        page.fill('[data-test-subj="password"]', args.dashboard_password)
        step = "submit"
        submit = page.locator('[data-test-subj="submit"]')
        if submit.count() == 0:
            submit = page.locator("button[type=submit]")
        if submit.count() == 0:
            return "FAIL", "login failed: no submit button at step {0}".format(step)
        submit.first.click(timeout=30000)
    except Exception as exc:
        return "FAIL", "login failed: {0} at {1}".format(type(exc).__name__, step)
    try:
        page.wait_for_url("**/app/wz-home**", timeout=60000)
    except Exception:
        pass
    if landing_ok(page.url, args.dashboard_url, LOGIN_LANDING)[0]:
        return "PASS", page.url
    return "FAIL", "login failed: landed on {0}".format(page.url)


# The visible text of a cell is its innerText MINUS the text of its .euiScreenReaderOnly
# spans: an EuiDataGrid cell reads "Row: 1, Column: 2: wget" to a screen reader and "wget" to
# the eye, and it is the eye's value the screenshot has to prove.
JS_VISIBLE = r"""
    const visible = (el) => {
        if (!el) { return ''; }
        let text = el.innerText || el.textContent || '';
        el.querySelectorAll('.euiScreenReaderOnly').forEach((sr) => {
            const hidden = sr.innerText || sr.textContent || '';
            if (hidden) { text = text.split(hidden).join(' '); }
        });
        return text.replace(/\s+/g, ' ').trim();
    };
    // A cell whose text does not fit is drawn with an ellipsis: innerText still returns the
    // WHOLE value, so an assertion could pass on text the screenshot never showed. EUI puts
    // the clipping on an inner span, hence the walk over the cell and its descendants.
    const truncated = (el) => {
        if (!el) { return false; }
        const nodes = [el].concat(Array.from(el.querySelectorAll('*')));
        return nodes.some((node) => {
            // a .euiScreenReaderOnly span is 1px wide by design: it is always "truncated",
            // and it is not part of what the eye (or the screenshot) reads
            if (node.closest && node.closest('.euiScreenReaderOnly')) { return false; }
            if (!node.getClientRects().length) { return false; }
            // Only an element that CLIPS can hide text: with overflow visible, a scrollWidth a
            // pixel or two above clientWidth is sub-pixel rounding (measured live on the agents
            // table: a euiFlexItem 79/77 and a euiToolTipAnchor 22/20 around the fully visible
            // word "active"), not a cut.
            const style = window.getComputedStyle(node);
            const clips = ['hidden', 'clip', 'auto', 'scroll'].indexOf(style.overflowX) !== -1;
            if (!clips) { return false; }
            if (node.scrollWidth > node.clientWidth + 1) { return true; }
            return style.textOverflow === 'ellipsis' && node.scrollWidth > node.clientWidth;
        });
    };
    const frame = () => ({viewport: window.innerHeight, viewport_width: window.innerWidth});
"""

# The scope must hold EXACTLY ONE table/grid (the scope element itself counts): zero is
# 'table missing' and two is 'ambiguous table', never a silent merge of two grids' rows.
JS_TABLE_OF_SCOPE = r"""
    const scopes = Array.from(document.querySelectorAll(spec.scope));
    if (!scopes.length) { return {error: 'scope missing: ' + spec.scope}; }
    const found = [];
    scopes.forEach((node) => {
        [node].concat(Array.from(node.querySelectorAll(spec.selector))).forEach((el) => {
            if (el.matches(spec.selector) && found.indexOf(el) === -1) { found.push(el); }
        });
    });
    if (!found.length) { return {error: 'table missing: ' + spec.selector}; }
    if (found.length > 1) {
        return {error: 'ambiguous table (' + found.length + ') for ' + spec.selector};
    }
    const table = found[0];
"""

# kind=grid — EuiDataGrid (IT Hygiene, VD). No row element exists: every cell is absolutely
# positioned, so the column is the header cell it shares its `left` with
# ([data-test-subj=dataGridHeaderCell-<field>]) and the row is the exact `top` its cells
# share (grouped by capture_logic.grid_rows, without tolerance).
GRID_ROWS_JS = "(spec) => {" + JS_VISIBLE + JS_TABLE_OF_SCOPE + r"""
    const prefix = 'dataGridHeaderCell-';
    const byLeft = {};
    table.querySelectorAll('[data-test-subj^="' + prefix + '"]').forEach((header) => {
        const field = header.getAttribute('data-test-subj').slice(prefix.length);
        byLeft[Math.round(header.getBoundingClientRect().left)] = field;
    });
    const cells = [];
    table.querySelectorAll('[data-test-subj="dataGridRowCell"]').forEach((cell) => {
        if (!cell.getClientRects().length) { return; }
        const rect = cell.getBoundingClientRect();
        const field = byLeft[Math.round(rect.left)];
        if (field === undefined) { return; }
        cells.push([field, Math.round(rect.top), Math.round(rect.bottom), visible(cell),
                    Math.round(rect.left), Math.round(rect.right), truncated(cell)]);
    });
    return Object.assign({kind: 'grid', cells: cells,
                          columns: Object.keys(byLeft).map((k) => byLeft[k])}, frame());
}"""

# kind=table — EuiBasicTable (the agents list). The column is the header's
# data-test-subj (tableHeaderCell_<field>_<n>) and the cell is the <td> at the header's own
# DOM position among the <th>s: EUI numbers <n> over its data columns only, so a leading
# selection column (a <th> without data-test-subj) shifts every <td> by one — measured live
# on 5.0.0-latest: name_1 is the 3rd <th>/<td>, status_6 the 8th.
TABLE_ROWS_JS = "(spec) => {" + JS_VISIBLE + JS_TABLE_OF_SCOPE + r"""
    const prefix = 'tableHeaderCell_';
    const headers = [];
    Array.from(table.querySelectorAll('thead th')).forEach((th, position) => {
        const subj = th.getAttribute('data-test-subj') || '';
        if (!subj.startsWith(prefix)) { return; }
        const subject = subj.slice(prefix.length);
        const cut = subject.lastIndexOf('_');
        if (cut <= 0) { return; }
        headers.push({field: subject.slice(0, cut), index: position});
    });
    const rows = [];
    table.querySelectorAll('tbody tr').forEach((tr) => {
        if (!tr.getClientRects().length) { return; }
        const tds = Array.from(tr.querySelectorAll('td'));
        if (!tds.length) { return; }
        const columns = {};
        const geometry = {};
        headers.forEach((header) => {
            const td = tds[header.index];
            if (!td) { return; }
            columns[header.field] = visible(td);
            const box = td.getBoundingClientRect();
            geometry[header.field] = {left: Math.round(box.left), right: Math.round(box.right),
                                      truncated: truncated(td)};
        });
        const rect = tr.getBoundingClientRect();
        rows.push({columns: columns, cells: geometry, top: Math.round(rect.top),
                   bottom: Math.round(rect.bottom)});
    });
    return Object.assign({kind: 'table', rows: rows, columns: headers.map((h) => h.field)},
                         frame());
}"""

# kind=doctable — OSD Discover's document table. The columns are fixed by the route
# (columns:!(user.name,wazuh.agent.name,wazuh.protocol.location)): the i-th
# th[docTableHeaderField] names the i-th td[docTableField] of each row.
DOCTABLE_ROWS_JS = "(spec) => {" + JS_VISIBLE + JS_TABLE_OF_SCOPE + r"""
    const headers = [];
    table.querySelectorAll('th[data-test-subj="docTableHeaderField"]').forEach((th) => {
        const tagged = th.querySelector('[data-test-subj^="docTableHeader-"]');
        const field = tagged
            ? tagged.getAttribute('data-test-subj').slice('docTableHeader-'.length)
            : (visible(th).split(' ')[0] || '');
        headers.push(field);
    });
    const rows = [];
    table.querySelectorAll('tbody tr').forEach((tr) => {
        const tds = Array.from(tr.querySelectorAll('td[data-test-subj="docTableField"]'));
        if (!tds.length || !tr.getClientRects().length) { return; }
        const columns = {};
        const geometry = {};
        headers.forEach((field, i) => {
            if (!tds[i]) { return; }
            columns[field] = visible(tds[i]);
            const box = tds[i].getBoundingClientRect();
            geometry[field] = {left: Math.round(box.left), right: Math.round(box.right),
                               truncated: truncated(tds[i])};
        });
        const rect = tr.getBoundingClientRect();
        rows.push({columns: columns, cells: geometry, top: Math.round(rect.top),
                   bottom: Math.round(rect.bottom)});
    });
    return Object.assign({kind: 'doctable', rows: rows, columns: headers}, frame());
}"""

ROWS_JS = {"grid": GRID_ROWS_JS, "table": TABLE_ROWS_JS, "doctable": DOCTABLE_ROWS_JS}


def scope_of(cfg, spec):
    """The scope an assertion is evaluated in: its own "scope" when it declares one, else the
    view's scope_selector."""
    return (spec or {}).get("scope") or cfg.get("scope_selector") or ""


def extract_rows(page, cfg, spec=None):
    """(rows, viewport_height, viewport_width, problem) — the view's table as data.

    rows = [{"columns": {column: visible value}, "cells": {column: {left, right, truncated}},
    "top": px, "bottom": px}], read in the browser by the function of the declared
    `table.kind` and, for a data grid, assembled from its cells by capture_logic.grid_rows
    (same `top` exactly = same row). Both viewport axes come back with them: the frame check
    is horizontal as well as vertical (D-8b). A missing scope, a missing table or two tables
    in the scope are problems, never an empty list that would make a `rows_eq: 0` or a 'no row
    matched' verdict look meaningful.
    """
    table = dict(cfg.get("table") or {})
    scope = scope_of(cfg, spec)
    kind = str(table.get("kind") or "")
    selector = table.get("selector") or ""
    if not scope:
        return [], None, None, "scope missing"
    if kind not in ROWS_JS or not selector:
        return [], None, None, "unknown table {0!r} for scope '{1}'".format(table, scope)
    try:
        data = page.evaluate(ROWS_JS[kind], {"scope": scope, "selector": selector}) or {}
    except Exception as exc:
        return [], None, None, "{0}: {1}".format(type(exc).__name__, exc)
    viewport, viewport_w = data.get("viewport"), data.get("viewport_width")
    if data.get("error"):
        return [], viewport, viewport_w, data["error"]
    if kind == "grid":
        rows = grid_rows(data.get("cells") or [])
    else:
        rows = [
            {"columns": dict(row.get("columns") or {}), "cells": dict(row.get("cells") or {}),
             "top": row.get("top"), "bottom": row.get("bottom")}
            for row in data.get("rows") or []
        ]
    return rows, viewport, viewport_w, None


def count_hits(page, cfg, spec=None):
    """Result count of a view: (hits, problem).

    The counter is resolved INSIDE the assertion's scope (`scope >> count_selector`) and must
    be unique there: a counter that belongs to another panel — or the only counter left on a
    page whose scope does not even exist — must never be reported as this view's (D-8b).
    Its text is parsed by parse_hits (first integer: 'Result (0/10)' is 0).
    """
    selector = cfg.get("count_selector")
    scope = scope_of(cfg, spec)
    if not selector:
        return None, "no count_selector for this view"
    if not scope:
        return None, "scope missing"
    if page.locator(scope).count() == 0:
        return None, "scope missing: {0}".format(scope)
    locator = page.locator(scope).locator(selector)
    found = locator.count()
    if found == 0:
        return None, "counter missing: '{0}' in '{1}'".format(selector, scope)
    if found > 1:
        return None, "ambiguous counter ({0}) for '{1}' in '{2}'".format(found, selector, scope)
    text = (locator.first.inner_text() or "").strip()
    hits = parse_hits(text)
    if hits is None:
        return None, "counter '{0}' shows no number: '{1}'".format(selector, text[:60])
    return hits, None


def eval_assertions(page, cfg, ctx):
    """Evaluate a view's assertions. Kinds (D-8b):

    row:     {"<column>": "<value>"} — EXACTLY ONE row of the table must carry those values,
             column by column and equal (not contained). Where that row was drawn (inside the
             viewport on both axes, any asserted column truncated on screen) is measured and
             reported as `frame_note`, and never decides the verdict (V11: the PNG is the whole
             page). {{agent_names}} expands to one required row per active agent.
    rows_eq: the table must have exactly N data rows ({{agent_count}} allowed).
    hits_eq: the view's counter, read inside the scope, must read exactly N.
    """
    values = placeholder_values(ctx)
    results = []
    cache = {}
    for spec in cfg.get("assertions") or []:
        scope = scope_of(cfg, spec)
        if "row" in spec or "rows_eq" in spec:
            if scope not in cache:
                cache[scope] = extract_rows(page, cfg, spec)
            rows, viewport, viewport_w, problem = cache[scope]
        if "row" in spec:
            expanded = expand_row(spec["row"], values)
            if not expanded:
                results.append({"kind": "row", "value": None, "rows": len(rows), "ok": False,
                                "reason": "0 rows required (no agent names)"})
            for wanted in expanded:
                entry = {"kind": "row", "value": wanted, "rows": len(rows),
                         "scope": scope, "ok": False}
                if problem:
                    entry["reason"] = problem
                    results.append(entry)
                    continue
                matched = rows_matching(rows, wanted)
                entry["matched"] = len(matched)
                columns = list(wanted)
                if len(matched) != 1:
                    entry["reason"] = "{0} rows match {1} in '{2}'".format(
                        len(matched), wanted, scope)
                else:
                    # V11: the capture is full-page, so neither the fold nor a column past the
                    # right edge keeps the row out of the PNG. Both are still MEASURED and
                    # travel to the sidecar and to the report as a note — never as a verdict.
                    entry["frame_note"] = {
                        "in_viewport": bool(row_in_frame(matched[0], viewport, viewport_w,
                                                         columns)),
                        "truncated_columns": truncated_columns(matched[0], columns),
                    }
                    entry["ok"] = True
                results.append(entry)
        elif "rows_eq" in spec:
            entry = {"kind": "rows_eq", "scope": scope, "ok": False}
            try:
                expected = int(render_query(str(spec["rows_eq"]), values))
            except ValueError as exc:
                entry.update(expected=str(spec["rows_eq"]), value=None, reason=str(exc))
                results.append(entry)
                continue
            entry["expected"] = expected
            if problem:
                entry.update(value=None, reason=problem)
            else:
                entry.update(value=len(rows), ok=len(rows) == expected)
                if not entry["ok"]:
                    entry["reason"] = "{0} data row(s) in '{1}', expected exactly {2}".format(
                        len(rows), scope, expected)
            results.append(entry)
        elif "hits_eq" in spec:
            entry = {"kind": "hits_eq", "scope": scope, "ok": False}
            try:
                expected = int(render_query(str(spec["hits_eq"]), values))
            except ValueError as exc:
                entry.update(expected=str(spec["hits_eq"]), value=None, reason=str(exc))
                results.append(entry)
                continue
            found, problem_hits = count_hits(page, cfg, spec)
            entry.update(expected=expected, value=found)
            if problem_hits:
                entry["reason"] = problem_hits
            else:
                entry["ok"] = found == expected
                if not entry["ok"]:
                    entry["reason"] = "{0} hit(s), expected exactly {1}".format(found, expected)
            results.append(entry)
        else:
            results.append({"kind": "unknown", "ok": False,
                            "reason": "unknown assertion {0}".format(spec)})
    return results


def navigate(session, args, cfg, ctx):
    """Try the view's route and then its alternatives. Returns (candidate, tried).

    Routes and landings carry {{...}} placeholders: a view that filters by URL state
    (`_a=(…query:'wazuh.agent.id:%22{{agent_id_5x}}%22 and package.name:%22{{package_name}}%22')`)
    is rendered for THIS run's agent and THIS run's sampled package before the browser goes
    there. An unresolved placeholder raises ValueError, which run_view turns into a FAIL
    naming it.

    A candidate is accepted only when landing_ok says so: same origin as --dashboard-url,
    exact path, exact hash route, every hash parameter equal and every state fragment inside
    the rison value of its own parameter. 'tried' keeps url/url_ok/missing per candidate for
    the sidecar.

    The route is rendered with `encode=True` (the landing is NOT: it is compared against the
    decoded value): a package called `g++` must travel as `g%2B%2B`, or the `+` comes back as
    a space and the view fails on the encoding instead of on the dashboard.
    """
    page = session.page
    candidates = [
        {
            "app": cfg.get("app"),
            "route": cfg.get("route"),
            "ready_selector": cfg.get("ready_selector", ""),
            "landing": cfg.get("landing") or {},
        }
    ] + [dict(alt) for alt in cfg.get("alternatives") or []]
    values = placeholder_values(ctx)
    tried = []
    for candidate in candidates:
        candidate = dict(candidate)
        candidate["route"] = render_query(candidate.get("route"), values, encode=True)
        candidate["landing"] = render_landing(candidate.get("landing") or {}, values)
        page.goto(
            args.dashboard_url.rstrip("/") + candidate["route"],
            wait_until="domcontentloaded",
            timeout=60000,
        )
        ready = candidate.get("ready_selector") or ""
        if ready:
            try:
                page.wait_for_selector(ready, timeout=30000)
            except Exception:
                pass
        for selector in cfg.get("fallback_clicks") or []:
            try:
                target = page.locator(selector)
                if target.count():
                    target.first.click(timeout=10000)
                    page.wait_for_timeout(2000)
            except Exception:
                pass
        url_ok, missing = landing_ok(page.url, args.dashboard_url, candidate["landing"])
        tried.append({
            "app": candidate.get("app"),
            "route": candidate.get("route"),
            "url": page.url,
            "url_ok": url_ok,
            "missing": missing,
        })
        if url_ok:
            return candidate, tried
    return None, tried


def fail_view(session, args, ctx, view, number, cfg, candidate, final_url, tried, reason,
              results=None):
    """A view that failed before its assertions: sidecar + FAIL screenshot, then the reason.

    The session is passed so the sidecar of a FAILURE reports the `/api/request` calls really
    seen — the number a failing view is the most interesting one to read, and it used to be a
    constant `{"total": 0}` that the README described as measured.

    The screenshot of a failure is best effort (there may be no usable page left); the
    screenshot of a PASS is not — see run_view.
    """
    ctx["last_assertions"] = results or []
    write_sidecar(args, ctx, view, number, cfg, candidate, final_url, results or [], tried,
                  api_calls=getattr(session, "api_calls", None))
    try:
        shoot(page_of(ctx), args, view, number, ok=False)
    except Exception:
        pass
    return "FAIL", reason


def page_of(ctx):
    return ctx.get("page")


def run_view(session, args, ctx, view, cfg, number):
    page = session.page
    ctx["page"] = page
    try:
        candidate, tried = navigate(session, args, cfg, ctx)
    except ValueError as exc:  # unresolved placeholder: the view cannot be asserted at all
        return fail_view(session, args, ctx, view, number, cfg, None, page.url, [], str(exc))
    final_url = page.url
    if candidate is None:
        # No candidate landed where it was asked to: report the last one tried, naming the
        # part of the landing (origin, path, #route, #param or state) that did not hold.
        last = tried[-1] if tried else {}
        reason = landing_reason(last.get("url") or final_url, last.get("missing"))
        return fail_view(session, args, ctx, view, number, cfg, None, final_url, tried, reason)

    values = placeholder_values(ctx)
    try:
        query = render_query(cfg.get("query"), values)
    except ValueError as exc:
        return fail_view(session, args, ctx, view, number, cfg, candidate, final_url, tried,
                         str(exc))
    if query and cfg.get("search_selector"):
        box = page.locator(cfg["search_selector"])
        if box.count() == 0:
            return fail_view(session, args, ctx, view, number, cfg, candidate, final_url,
                             tried, "search_selector '{0}' missing".format(
                                 cfg["search_selector"]))
        box.first.click()
        box.first.fill(query)
        box.first.press("Enter")
        page.wait_for_timeout(5000)
        final_url = page.url
    wait_selector = cfg.get("wait_selector")
    if wait_selector:
        # Data grids render their rows after the query/route settles: wait (bounded) for the first data cell.
        # If nothing shows up, press the query bar's Refresh once (the first search may have run against a
        # not-yet-loaded data view) and wait again.
        for attempt in range(2):
            try:
                page.wait_for_selector(wait_selector, timeout=WAIT_SELECTOR_TIMEOUT_MS)
                break
            except Exception:
                if attempt == 0 and page.locator('[data-test-subj="querySubmitButton"]').count():
                    page.locator('[data-test-subj="querySubmitButton"]').first.click()
                    page.wait_for_timeout(3000)

    # The landing is re-checked HERE, after the query and the final wait: a view that
    # accepted the route and then dropped its filter (or navigated itself elsewhere) is not
    # the view that was asked for, however good the screenshot looks.
    final_url = page.url
    landing = landing_ok(final_url, args.dashboard_url, candidate["landing"])
    if not landing[0]:
        return fail_view(session, args, ctx, view, number, cfg, candidate, final_url, tried,
                         landing_reason(final_url, landing[1], " after wait"))

    try:
        results = eval_assertions(page, cfg, ctx)
    except ValueError as exc:  # unresolved placeholder inside an assertion
        return fail_view(session, args, ctx, view, number, cfg, candidate, final_url, tried,
                         str(exc))
    ctx["last_assertions"] = results
    ok, reason = view_verdict(candidate.get("app"), final_url, landing, results)
    sidecar = write_sidecar(args, ctx, view, number, cfg, candidate, final_url, results, tried,
                            api_calls=session.api_calls)
    if not ok:
        try:
            shoot(page, args, view, number, ok=False)
        except Exception:
            pass
        return "FAIL", reason

    # A PASS needs its evidence on disk: the PNG (non-empty), its sidecar and the hash.
    try:
        path = shoot(page, args, view, number, ok=True)
    except Exception as exc:
        return "FAIL", "screenshot failed: {0}".format(type(exc).__name__)
    size = os.path.getsize(path) if path and os.path.exists(path) else None
    good, problem = artifacts_ok(size, bool(sidecar) and os.path.exists(sidecar))
    if not good:
        return "FAIL", "{0} ({1})".format(problem, path)
    try:
        ctx.setdefault("sha256", {})[os.path.basename(path)] = sha256_of(path)
    except Exception as exc:
        return "FAIL", "sha256 of {0} failed: {1}".format(path, type(exc).__name__)
    return "PASS", "{0} ({1})".format(reason, describe(results))


def describe(results):
    """The assertions of a view on one line, plus the frame note the rows measured (V11).

    `row=…; rows_eq=1; hits_eq=1; frame: in_viewport=false, truncated=[package.vendor]` — the
    note is a MEASUREMENT appended to a line that is already a PASS: it says where the proven
    row was drawn and whether the pixels showed less than the text that was compared, so a
    reader of the report (and of the manifest, which prints the same string) knows it without
    opening the sidecar. It is aggregated over every `row` assertion of the view.
    """
    text = "; ".join(
        "{0}={1}".format(r.get("kind"), r.get("value", r.get("expected"))) for r in results
    )
    note = frame_note_line(results)
    if note:
        text = "{0}; {1}".format(text, note) if text else note
    return text or "no assertion"


def frame_note_line(results):
    """'frame: in_viewport=<bool>, truncated=[<columns>]' over every row assertion that
    measured it, or '' when no row was matched (nothing was measured)."""
    notes = [r["frame_note"] for r in results or [] if isinstance(r, dict) and r.get("frame_note")]
    if not notes:
        return ""
    cut = sorted({str(c) for note in notes for c in (note.get("truncated_columns") or ())})
    in_viewport = all(bool(note.get("in_viewport")) for note in notes)
    return "frame: in_viewport={0}, truncated=[{1}]".format(
        "true" if in_viewport else "false", ", ".join(cut))


def shoot(page, args, view, number, ok):
    """Write the PNG: the WHOLE page, 1280 px wide (the viewport is 1280×800; the height is
    whatever the page is) — decision V11.

    `full_page=True` is the point: cropping to the viewport is not a requirement, and a capture
    that stopped at the fold was the only reason a row below it, or a column past the right
    edge, could not be shown. What the row measured about the frame is still reported, as a
    note (see describe/frame_note_line). Exceptions propagate: run_view turns them into the
    view's FAIL.
    """
    suffix = "" if ok else "-FAIL"
    path = os.path.join(args.out, "{0:02d}-{1}{2}.png".format(number, view, suffix))
    page.screenshot(path=path, full_page=True)
    return path


def write_sidecar(args, ctx, view, number, cfg, candidate, final_url, results, tried, api_calls=None):
    data = {
        "run_id": ctx.get("run_id"),
        "view": view,
        "app_used": candidate["app"] if candidate else None,
        "route_requested": cfg.get("route"),
        "landing_requested": (candidate or cfg).get("landing"),
        "routes_tried": tried,
        "final_url": final_url,
        "ready_selector": (candidate or cfg).get("ready_selector"),
        "table": cfg.get("table"),
        "assertions": results,
        "agent_ids": ctx.get("agent_ids"),
        "agent_id_5x": ctx.get("agent_id_5x"),
        "agent_name_5x": ctx.get("agent_name_5x"),
        "package_5x": ctx.get("package_5x"),
        "cve_5x": ctx.get("cve_5x"),
        "counts_by_agent": ctx.get("counts_by_agent", {}).get(view, {}),
        "index": ctx.get("index"),
        "category": ctx.get("category"),
        "nonce": ctx.get("nonce"),
        "api_request_calls": api_calls or {"total": 0, "status_ge_400": []},
    }
    path = os.path.join(args.out, "{0:02d}-{1}.json".format(number, view))
    return write_json(path, data, args.secrets)


# --------------------------------------------------------------------------- manifest


def write_manifest(args, ctx, captured):
    """captures.md — provenance (HEAD, the sha256 of the sources that ran, `git status`) and
    the sha256, the bytes and, for a PNG, the pixel size of every file THIS run wrote in
    --out. The directory is exclusive to the run (fresh, or emptied), so the table is the
    whole of what was produced; a file in --out that is not in the table means the directory
    was not exclusive after all. The size is READ from each PNG's IHDR header (`png_size`):
    the captures are full-page (V11), so their height is the page's and no constant describes
    it.

    Returns (path, problem): a directory that could not be LISTED leaves the 'Every file'
    table with a loud row instead of silently empty, and the problem it returns is check 10
    failing — an evidence index nobody can trust is not an evidence index (D-10b). An artifact
    that could not be read, hashed or measured is the same failure (v7): its row says
    `(unreadable: <type>)` AND the run counts `FAIL 10. manifest (got: unreadable: <file>
    (<type>))`, because a manifest that cannot vouch for a file it lists is not evidence
    either. Every such error is accumulated, so the reason names all of them. The 'Every file'
    table re-reads each file at publication (sha256 and IHDR) instead of trusting the hash
    cached when the view passed (v8): a PNG that cannot be opened any more, or whose bytes are
    no longer the ones hashed then, is the same counted failure.
    """
    lines = ["# Dashboard captures — {0}".format(now_iso()), ""]
    lines.append("| key | value |")
    lines.append("|---|---|")
    lines.append("| run_id | `{0}` |".format(ctx.get("run_id") or "(none)"))
    lines.append("| HEAD | `{0}` |".format(git_head(script_dir())))
    lines.append(sources_row(source_digests(args)))
    lines.append(git_status_row(git_status(script_dir())))
    lines.append(dashboard_row(ctx.get("dashboard_version"), DASHBOARD_PACKAGE))
    lines.append("| dashboard-url | {0} |".format(safe_url(args.dashboard_url)))
    lines.append("| indexer-url | {0} |".format(safe_url(args.indexer_url)))
    lines.append("| nonce | `{0}` |".format(ctx.get("nonce")))
    lines.append("| agents | {0} |".format(",".join(ctx.get("agent_ids") or []) or "(none)"))
    lines.append("| agent 5.x | `{0}` `{1}` |".format(
        ctx.get("agent_id_5x") or "(none)", ctx.get("agent_name_5x") or ""))
    lines.append("| package sampled | `{0}` `{1}` |".format(
        (ctx.get("package_5x") or {}).get("name") or "(none)",
        (ctx.get("package_5x") or {}).get("version") or ""))
    lines.append("| cve sampled | `{0}` |".format(ctx.get("cve_5x") or "(none)"))
    lines.append("| events index | {0} |".format(ctx.get("index") or "(not resolved)"))
    lines.append("")
    lines.append("| vista | fichero | sha256 | qué prueba | assertions |")
    lines.append("|---|---|---|---|---|")
    digests = dict(ctx.get("sha256") or {})
    problems = []
    for view, filename, results in captured:
        full = os.path.join(args.out, filename)
        digest = digests.get(filename)
        if not digest:
            try:
                digest = sha256_of(full) if os.path.exists(full) else "(missing)"
            except OSError as exc:
                digest = "(unreadable: {0})".format(type(exc).__name__)
                problems.append("unreadable: {0} ({1})".format(filename, type(exc).__name__))
        lines.append("| {0} | {1} | `{2}` | {3} | {4} |".format(
            view, filename, digest, VIEW_PROVES.get(view, ""), describe(results)
        ))
    lines.append("")
    lines.append("Every file of this run (`{0}`):".format(args.out))
    lines.append("")
    lines.append("| fichero | sha256 | tamaño | WxH |")
    lines.append("|---|---|---|---|")
    try:
        names = sorted(n for n in os.listdir(args.out) if n != "captures.md")
    except OSError as exc:
        names = []
        problems.append("listing {0} failed: {1}".format(args.out, type(exc).__name__))
        lines.append("| (listing failed: {0}) | — | — | — |".format(type(exc).__name__))
    for name in names:
        full = os.path.join(args.out, name)
        # Every file is READ AGAIN here, at publication — the sha256 and the pixel size — even
        # when run_view cached its hash: a PNG that can no longer be opened is not evidence the
        # manifest may vouch for, and the cached hash would have hidden it (v8).
        try:
            digest = sha256_of(full)
            size = os.path.getsize(full)
            dimensions = png_dimensions(full)
        except OSError as exc:
            lines.append("| {0} | (unreadable: {1}) | — | — |".format(name, type(exc).__name__))
            problems.append("unreadable: {0} ({1})".format(name, type(exc).__name__))
            continue
        cached = digests.get(name)
        if cached and cached != digest:
            problems.append("changed since capture: {0}".format(name))
        lines.append("| {0} | `{1}` | {2} | {3} |".format(name, digest, size, dimensions))
    path = write_text(os.path.join(args.out, "captures.md"), "\n".join(lines) + "\n",
                      args.secrets)
    return path, "; ".join(problems)


def finish(rep, args, ctx, captured, publish=True):
    """Publish the manifest, THEN print the summary, THEN return the exit status (D-10b).

    A manifest that cannot be written — or an --out that never came to exist, or one whose
    listing failed, or an artifact it could not read, hash or measure (v7) — is check 10
    failing: counted, inside the summary and reflected in the
    exit status, never an exception raised after a report that said failed=0 and never a bare
    '#' note. `publish=False` is the one case where there is deliberately nothing to publish:
    a run that refused its --out (or refused its URL before touching anything) must not then
    write a manifest into the very directory it would not touch.
    """
    if publish:
        if not args.out or not os.path.isdir(args.out):
            rep.record("FAIL", MANIFEST_CHECK, CHECK_NAMES[MANIFEST_CHECK],
                       "no out dir: {0}".format(args.out or "(none)"))
        else:
            try:
                path, problem = write_manifest(args, ctx, captured)
            except Exception as exc:
                rep.record("FAIL", MANIFEST_CHECK, CHECK_NAMES[MANIFEST_CHECK],
                           type(exc).__name__)
            else:
                rep.note("manifest: {0}".format(path))
                if problem:
                    rep.record("FAIL", MANIFEST_CHECK, CHECK_NAMES[MANIFEST_CHECK], problem)
    rep.summary()
    return 1 if rep.failed > 0 else 0


# --------------------------------------------------------------------------- vd


def vd_findings(args, ctx):
    """{agent_id: count} on wazuh-states-vulnerabilities*, one query per agent id.

    Only the count of the 5.x agent decides the verdict (vd_verdict), but every active agent
    is counted so the sidecar shows where the findings really are.
    """
    if args.findings_json:
        with open(args.findings_json) as handle:
            return {str(k): int(v) for k, v in json.load(handle).items()}
    counts = {}
    for agent_id in ctx["agent_ids"]:
        counts[agent_id] = indexer_count(args, VULNERABILITIES_INDEX, agent_terms_query([agent_id]))
    return counts


def vd_sample_cve(args, ctx):
    """One vulnerability.id of THIS run's 5.x agent, so the view can be filtered by it."""
    body = {"query": {"term": {AGENT_ID_FIELD: ctx.get("agent_id_5x")}}, "size": 1,
            "sort": [{"vulnerability.id": "asc"}]}
    return vulnerability_sample(indexer_search(args, VULNERABILITIES_INDEX, body))


def vd_poll(args, rep):
    deadline = time.time() + args.vd_deadline
    probe = {}
    while True:
        probe = vd_probe(args)
        rep.note(
            "vd probe: available={0} enabled={1} status={2} offset={3} last_successful_update={4}{5}".format(
                probe.get("available"),
                probe.get("enabled"),
                probe.get("status"),
                probe.get("offset"),
                probe.get("last_successful_update"),
                " error={0}".format(probe["error"]) if probe.get("error") else "",
            )
        )
        if probe.get("error") or probe.get("enabled") is False:
            return probe
        if probe.get("status") in ("ready", "failed"):
            return probe
        if time.time() + args.vd_poll >= deadline:
            return probe
        time.sleep(args.vd_poll)


# --------------------------------------------------------------------------- CLI


def parse_args(argv=None):
    workspace = workspace_root()
    parser = argparse.ArgumentParser(
        prog="capture.py",
        description="Capture the Wazuh dashboard views with Playwright and assert them "
        "against the data of this run (active agents, nonce event, one sampled package, one "
        "sampled CVE), one row matched column by column.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--setup", action="store_true",
                        help="create the venv and install {0} + its chromium (this mode, "
                        "and only this mode, installs system packages with apt), then "
                        "exit".format(PLAYWRIGHT_PIN))
    parser.add_argument("--venv", default=os.environ.get("DASHBOARD_VENV",
                        os.path.join(workspace, "venv-dashboard")),
                        help="virtualenv holding playwright and its browsers")
    parser.add_argument("--browsers-path", default="",
                        help="PLAYWRIGHT_BROWSERS_PATH to use instead of <--venv>/browsers "
                        "(it is always SET, never inherited)")
    parser.add_argument("--out", default="",
                        help="directory for the PNGs, the sidecars and captures.md "
                        "(default: {0}/e2e-dashboard-out/<run_id>, one per run; an explicit "
                        "directory is emptied before the run and a file that cannot be "
                        "removed aborts it)".format(workspace))
    parser.add_argument("--views", default=",".join(VIEW_NAMES),
                        help="comma separated subset of {0}".format(",".join(VIEW_NAMES)))
    parser.add_argument("--dashboard-url", default="https://localhost:443",
                        help="dashboard under test; credentials in the URL are rejected "
                        "(use DASHBOARD_USER/DASHBOARD_PASSWORD)")
    parser.add_argument("--indexer-url", default="https://localhost:9200",
                        help="indexer queried for counts and samples; credentials in the URL "
                        "are rejected (use INDEXER_USER/INDEXER_PASSWORD)")
    parser.add_argument("--home", default="/var/wazuh-manager", help="installed manager")
    parser.add_argument("--agent-container", default="wazuh-agent-5x-ubuntu",
                        help="container the nonce line is appended in (validated, argv only)")
    parser.add_argument("--agent-ids", default="",
                        help="comma separated agent ids; each one must be active in global.db "
                        "(default: every active agent of global.db)")
    parser.add_argument("--agent-5x-id", default="",
                        help="id behind {{agent_id_5x}} in views.json; must be active AND a "
                        "v5 agent (default: the active agent whose version starts with 'v5')")
    parser.add_argument("--inventory-index", default=INVENTORY_INDEX,
                        help="index the package sample of check 4b is taken from")
    parser.add_argument("--events-mode", default="agents", choices=("agents", "benchmark", "none"),
                        help="how the nonce event reaches the pipeline")
    parser.add_argument("--nonce", default="",
                        help="reuse a nonce instead of generating one (must match "
                        "e2e-capture-[A-Za-z0-9._-]{4,32})")
    parser.add_argument("--nonce-written", action="store_true",
                        help="the nonce line was already appended in the container")
    parser.add_argument("--exec-docker", action="store_true",
                        help="append the nonce line with docker exec (argv, line on stdin)")
    parser.add_argument("--vd-deadline", type=int, default=900,
                        help="seconds to wait for the vulnerability-detector feed")
    parser.add_argument("--vd-poll", type=int, default=15, help="seconds between VD probes")
    parser.add_argument("--vd-socket", default="",
                        help="vulnerability-detector UDS socket "
                        "(default: <--home>/{0}); ignored with --probe-json".format(VD_SOCKET))
    parser.add_argument("--views-file", default=str(script_dir() / "views.json"),
                        help="routes, landings, tables and assertions of each view")
    parser.add_argument("--probe-json", default="",
                        help="file used as the VD probe answer (exercises check 9's verdict "
                        "without a manager, and without opening the socket)")
    parser.add_argument("--findings-json", default="",
                        help="file with {agent_id: count} used instead of querying the indexer")
    args = parser.parse_args(argv)
    args.vd_socket = args.vd_socket or os.path.join(args.home, VD_SOCKET)
    args.dashboard_user = os.environ.get("DASHBOARD_USER", "admin")
    args.dashboard_password = os.environ.get("DASHBOARD_PASSWORD", "admin")
    args.indexer_user = os.environ.get("INDEXER_USER", "admin")
    args.indexer_password = os.environ.get("INDEXER_PASSWORD", "admin")
    args.secrets = secrets_of(args.dashboard_user, args.dashboard_password,
                              args.indexer_user, args.indexer_password)
    return args


def events_skip_reason(args, views):
    if "discover" not in views:
        return "not requested"
    if args.events_mode == "none":
        return "events disabled by flag"
    return "benchmark mode not implemented in this stage"


def url_problems(args):
    """The reasons check 0 rejects the run before anything is printed with them in it."""
    return [p for p in (url_credentials_problem(args.dashboard_url, "--dashboard-url"),
                        url_credentials_problem(args.indexer_url, "--indexer-url")) if p]


def run(args, venv_state):
    rep = Reporter(args.secrets)
    # The header goes through the Reporter like every other line, and the URL it prints has
    # had any userinfo REMOVED — the credentials check below then refuses the run outright.
    rep.note("capture.py — {0} — {1}".format(now_iso(), safe_url(args.dashboard_url)))
    nonce = args.nonce or make_nonce()
    nonce_problem = ""
    try:  # the nonce is part of the run directory's name: validate it before building a path
        validate_nonce(nonce)
        run_id = "{0}-{1}".format(compact_iso(), nonce)
    except ValueError as exc:
        nonce_problem = str(exc)
        run_id = "{0}-invalid-nonce".format(compact_iso())
    views = [v.strip() for v in args.views.split(",") if v.strip()]
    for unknown in [v for v in views if v not in VIEW_NAMES]:
        rep.note("unknown view ignored: {0}".format(unknown))
    views = [v for v in views if v in VIEW_NAMES]
    plan = plan_checks(views, args.events_mode)
    requested = {n: req for n, _name, req in plan}
    ctx = {
        "nonce": nonce,
        "run_id": run_id,
        "agent_ids": [],
        "agent_names": [],
        "agent_id_5x": "",
        "agent_name_5x": "",
        "package_5x": {},
        "cve_5x": "",
        "counts_by_agent": {},
        "sha256": {},
        "index": None,
        "category": None,
        "dashboard_version": "",
    }
    captured = []

    problems = url_problems(args)
    if problems:
        # Credentials on the command line are not in `secrets` (those come from the
        # environment), so nothing could redact them: the run refuses them instead.
        rep.record("FAIL", 0, CHECK_NAMES[0], "; ".join(problems))
        for n, name, _req in plan[1:]:
            rep.record("SKIP", n, name, "blocked by 0")
        # nothing was touched and nothing is published: --out was never even resolved
        return finish(rep, args, ctx, captured, publish=False)

    def abort(status, got, publish=True):
        """A check-0 failure that stops the run: the reason, every other check SKIPped, and
        the summary."""
        rep.record(status, 0, CHECK_NAMES[0], got)
        for n, name, _req in plan[1:]:
            rep.record("SKIP", n, name, "blocked by 0")
        return finish(rep, args, ctx, captured, publish=publish)

    if args.out:
        # CANONICAL, not merely absolute: --out is EMPTIED below and the run is root, so the
        # paths a mistake cannot be undone from are refused before looking inside — and a
        # symlink is not a way around that list (v7).
        args.out = canonical(args.out)
        refusal = out_dir_refusal(args.out, canonical(os.path.expanduser("~")), repo_roots())
        if refusal:
            return abort("FAIL", "--out refuses {0}: {1}".format(args.out, refusal),
                         publish=False)
        removed, problem, ours = clear_dir(args.out)
        if removed:
            rep.note("emptied {0} ({1} entries)".format(args.out, len(removed)))
        if problem:
            # Never reuse a directory that still holds another run's PNGs — and never empty
            # (or write into) one that holds anything else.
            return abort("FAIL", problem, publish=ours)
    else:  # one directory per run, so two runs never mix their PNGs
        args.out = os.path.join(workspace_root(), "e2e-dashboard-out", run_id)
    rep.note("run_id: {0}".format(run_id))
    rep.note("out: {0}".format(args.out))
    try:
        os.makedirs(args.out, exist_ok=True)
    except Exception as exc:
        # No --out, no PNG, no sidecar and no manifest: that is check 0 failing (and check 10
        # with it), not a '#' note followed by a report that looks almost green.
        return abort("FAIL", "cannot create {0}: {1}".format(args.out, type(exc).__name__))

    try:
        with open(args.views_file) as handle:
            view_cfgs = json.load(handle)
    except Exception as exc:  # every view then fails naming the file, never a traceback
        rep.note("cannot read {0}: {1}: {2}".format(args.views_file, type(exc).__name__, exc))
        view_cfgs = {}

    if venv_state != "inside":
        reason = ("venv missing; run --setup" if venv_state == "missing"
                  else "re-exec did not land in {0}; run --setup".format(args.venv))
        return abort("FAIL", reason)

    rep.run(0, CHECK_NAMES[0], lambda: check_setup(args))
    rep.run(1, CHECK_NAMES[1], lambda: check_indexer(args))
    rep.run(2, CHECK_NAMES[2], lambda: check_dashboard(args, ctx))
    rep.run(3, CHECK_NAMES[3], lambda: check_agents(args, ctx))

    if not requested[4]:
        rep.record("SKIP", 4, CHECK_NAMES[4], events_skip_reason(args, views))
    elif nonce_problem:
        rep.record("FAIL", 4, CHECK_NAMES[4], nonce_problem)
    else:
        rep.run(4, CHECK_NAMES[4], lambda: check_events(args, ctx, rep))

    sample_name = CHECK_NAMES[SAMPLE_CHECK]
    if not requested[SAMPLE_CHECK]:
        rep.record("SKIP", SAMPLE_CHECK, sample_name, "not requested")
    elif 1 in rep.failed_checks:
        rep.record("SKIP", SAMPLE_CHECK, sample_name, "blocked by 1")
    elif 3 in rep.failed_checks:
        rep.record("FAIL", SAMPLE_CHECK, sample_name, "blocked: check 3 failed")
    else:
        rep.run(SAMPLE_CHECK, sample_name, lambda: check_inventory_sample(args, ctx, rep))

    session = None
    blocker = blocked_by(rep.failed_checks)
    if not requested[5]:
        rep.record("SKIP", 5, CHECK_NAMES[5], "not requested")
    elif blocker is not None:
        rep.record("SKIP", 5, CHECK_NAMES[5], "blocked by {0}".format(blocker))
    else:
        def login():
            nonlocal session
            session = Session(args)
            return do_login(session, args)

        rep.run(5, CHECK_NAMES[5], login)

    try:
        for view in VIEW_NAMES:
            number = VIEW_CHECK[view]
            if not requested[number]:
                rep.record("SKIP", number, view, "not requested")
                continue
            block = view_block(rep.failed_checks, session is not None)
            # Check 9's feed verdict does not need the browser: with --probe-json it is
            # exercised even when the stack (1, 2, 5) or the agents (3) are not there.
            if block and not (view == "vd" and args.probe_json):
                rep.record(block[0], number, view, block[1])
                continue
            cfg = view_cfgs.get(view)
            if cfg is None:
                rep.record("FAIL", number, view, "no '{0}' entry in {1}".format(view, args.views_file))
                continue
            status = rep.run(number, view, lambda v=view, c=cfg, n=number, b=block: view_check(
                session, args, ctx, rep, v, c, n, b))
            png = "{0:02d}-{1}{2}.png".format(number, view, "" if status == "PASS" else "-FAIL")
            if os.path.exists(os.path.join(args.out, png)):
                captured.append((view, png, ctx.get("last_assertions", [])))
    finally:
        if session is not None:
            session.close()

    return finish(rep, args, ctx, captured)


def view_check(session, args, ctx, rep, view, cfg, number, block=None):
    """The per-view preconditions (inventory counts, VD probe and CVE sample) and then the
    view itself. `block` is set only for the vd fixture path, where the feed verdict runs
    without a browser."""
    if view == "inventory":
        per_agent = {
            i: indexer_count(args, args.inventory_index, agent_terms_query([i]))
            for i in ctx["agent_ids"]
        }
        ctx["counts_by_agent"]["inventory"] = per_agent
        rep.note("inventory documents by agent: {0}".format(json.dumps(per_agent)))
        if not (ctx.get("package_5x") or {}).get("name"):
            return "FAIL", "no package sampled for agent {0} (check {1})".format(
                ctx.get("agent_id_5x") or "(none)", SAMPLE_CHECK
            )
    elif view == "vd":
        probe = vd_poll(args, rep)
        blocked = probe_blocks(probe)  # unreachable / disabled / failed: no findings query
        if blocked:
            return blocked
        findings = {}
        try:
            findings = vd_findings(args, ctx)
        except Exception as exc:
            rep.note("vd findings query failed: {0}: {1}".format(type(exc).__name__, exc))
        ctx["counts_by_agent"]["vd"] = findings
        status, reason = vd_verdict(probe, findings, ctx.get("agent_id_5x"))
        if status != "PASS":
            if status == "FAIL" and "0 findings" in reason:
                detail = last_scanner_log(args, ctx["agent_ids"])
                if detail:
                    reason = "{0} — {1}".format(reason, detail)
            return status, reason
        rep.note("vd verdict: {0}".format(reason))
        if block:  # the feed is ready, but this run has no browser to prove the view with
            return block[0], "{0} (feed verdict: {1})".format(block[1], reason)
        try:
            ctx["cve_5x"] = vd_sample_cve(args, ctx)
        except Exception as exc:
            rep.note("vd cve sample failed: {0}: {1}".format(type(exc).__name__, exc))
        rep.note("vd cve sample for agent {0}: {1}".format(
            ctx.get("agent_id_5x"), ctx.get("cve_5x") or "(none)"))

    return run_view(session, args, ctx, view, cfg, number)


def main(argv=None):
    args = parse_args(argv)
    if args.setup:
        return do_setup(args)
    return run(args, enter_venv(args))


if __name__ == "__main__":
    sys.exit(main())
