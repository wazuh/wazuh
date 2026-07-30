#!/usr/bin/env python3
"""
Drives remoted's `POST /download` endpoint the way a real agent does, and checks the
things unit tests cannot reach: the chunked transfer over TLS, and resource resolution
against a real installation.

Signing is identical to /stateless (same AuthMiddleware), so the helpers are imported
from send_stateless.py rather than duplicated.

What it verifies beyond "did it return 200":

  * `Transfer-Encoding: chunked` is present and `Content-Length` is absent -- the
    endpoint must stream, not buffer.
  * The received bytes are IDENTICAL to the file `resource_id` names. The manager serves
    exactly what is requested, so the expectation is derived from the request alone -- this
    tool never reads the manager's database.
  * With --watch-rss, remoted's peak RSS, exact CPU time, fd count and throughput during
    the transfer. RSS answers the issue's "memory usage is constant regardless of file
    size"; CPU is read as a /proc counter delta rather than sampled as a percentage, so
    it cannot miss time between samples; the fd count catches a descriptor leak.

Requires: pip install requests cryptography

Examples:
  python3 send_download.py                            # config download for agent 001's group
  python3 send_download.py --all                      # every success/failure scenario
  python3 send_download.py --resource-type wpk --resource-id pkg.wpk
  python3 send_download.py --simulate 20 --repeat 5   # 20 concurrent simulated agents
  python3 send_download.py --simulate 8 --watch-rss   # + RSS/CPU/fd/throughput report
"""
import argparse
import concurrent.futures
import hashlib
import os
import subprocess
import sys
import threading
import time

import requests
import urllib3

from send_stateless import _auth_header, read_agent_key

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_MANAGER_HOME = "/var/wazuh-manager"
TARGET = "/download"

# Mirrors MAX_RESOURCE_ID_SIZE in downloadEndpoint.cpp.
MAX_RESOURCE_ID_SIZE = 255

# --- Manager-side layout ---------------------------------------------------

class ManagerPaths:
    def __init__(self, home):
        self.home = home.rstrip("/")
        self.client_keys = f"{self.home}/etc/client.keys"
        self.shared_dir = f"{self.home}/etc/shared"
        self.multigroups_dir = f"{self.home}/var/multigroups"
        self.wpk_dir = f"{self.home}/var/upgrade"


def multigroup_dir_name(selector: str) -> str:
    """Same formula wazuh-db uses to NAME the directory: OS_SHA256_String_sized(sel, out, 8).
    Replicated, not queried -- the manager derives it the same way."""
    return hashlib.sha256(selector.encode()).hexdigest()[:8]


def expected_config_path(paths: ManagerPaths, selector: str) -> str:
    """The file the manager should serve for a `config` request naming `selector`.

    resource_id is taken at face value -- no group lookup. One group joins under etc/shared;
    a comma-separated selector is hashed into var/multigroups, exactly as wazuh-db names it.
    """
    selector = selector or "default"
    if "," in selector:
        return f"{paths.multigroups_dir}/{multigroup_dir_name(selector)}/merged.mg"
    return f"{paths.shared_dir}/{selector}/merged.mg"


def sha256_file(path: str):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


# --- The request itself ----------------------------------------------------

def request_body(resource_type: str, resource_id: str) -> bytes:
    # Built by hand rather than with json.dumps so a scenario can send a deliberately
    # malformed body through the same path as a valid one.
    return ('{"resource_type":"%s","resource_id":"%s"}' % (resource_type, resource_id)).encode()


class DownloadResult:
    def __init__(self):
        self.status = None
        self.chunked = False
        self.content_length = None
        self.bytes_received = 0
        self.sha256 = None
        self.error = None
        self.text = ""


def post_download(base_url, agent_id, agent_key, body: bytes, timeout=120) -> DownloadResult:
    """Signs and sends one /download request, consuming the body as a stream so the
    client never holds the whole file either."""
    result = DownloadResult()
    url = base_url.rstrip("/") + TARGET
    headers = _auth_header(agent_id, agent_key, "1", "POST", TARGET, int(time.time()), body)

    try:
        response = requests.post(url, headers=headers, data=body, verify=False, stream=True, timeout=timeout)
    except requests.exceptions.RequestException as error:
        result.error = f"{type(error).__name__}: {error}"
        return result

    result.status = response.status_code
    result.chunked = response.headers.get("Transfer-Encoding", "").lower() == "chunked"
    result.content_length = response.headers.get("Content-Length")

    digest = hashlib.sha256()
    # Keep the first few KiB only when the status says this is an error body: those are the
    # small JSON payloads worth printing, and a 2 GiB WPK must never be buffered. It has to be
    # captured HERE, while streaming -- once iter_content() has drained the response,
    # `response.content` is gone, so reading it afterwards yields nothing.
    error_body = bytearray() if response.status_code != 200 else None

    try:
        for chunk in response.iter_content(64 * 1024):
            if not chunk:
                continue
            digest.update(chunk)
            result.bytes_received += len(chunk)
            if error_body is not None and len(error_body) < 4096:
                error_body.extend(chunk)
    except requests.exceptions.RequestException as error:
        # An interrupted chunked transfer must surface as a failure, never as a short
        # but successful download.
        result.error = f"transfer interrupted: {type(error).__name__}: {error}"
        return result

    result.sha256 = digest.hexdigest()
    if error_body is not None:
        result.text = bytes(error_body).decode(errors="replace")[:200]
    return result


# --- RSS sampling ----------------------------------------------------------

def remoted_pid():
    try:
        out = subprocess.run(["pgrep", "-f", "wazuh-manager-remoted"],
                             capture_output=True, text=True, check=False)
        pids = [line for line in out.stdout.split() if line.isdigit()]
        return int(pids[0]) if pids else None
    except OSError:
        return None


def read_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def read_cpu_seconds(pid):
    """utime+stime from /proc/<pid>/stat, in seconds.

    Read as a counter delta rather than sampled as a percentage: that is exact, and it
    cannot miss CPU spent between two samples the way an instantaneous percentage can.
    """
    try:
        with open(f"/proc/{pid}/stat") as handle:
            # The comm field may contain spaces/parens, so index from the closing paren.
            fields = handle.read().rsplit(") ", 1)[1].split()
        ticks = os.sysconf("SC_CLK_TCK")
        return (int(fields[11]) + int(fields[12])) / ticks   # utime, stime
    except (OSError, IndexError, ValueError):
        return None


def read_fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


class ProcWatcher:
    """Samples remoted's RSS and fd count, and brackets its CPU time.

    RSS and fds are sampled (a peak is what matters); CPU is taken as an exact counter
    delta from /proc/<pid>/stat, so nothing is missed between samples. Together these are
    the three axes the /download work is judged on: memory flat in file size, CPU per
    byte, and no descriptor leak.
    """

    def __init__(self, pid, interval=0.05):
        self.pid = pid
        self.interval = interval
        self.rss = []
        self.fds = []
        self.cpu_start = None
        self.cpu_end = None
        self.wall = 0.0
        self._t0 = None
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if self.pid:
            self.cpu_start = read_cpu_seconds(self.pid)
            self._t0 = time.time()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            r = read_rss_kb(self.pid)
            f = read_fd_count(self.pid)
            if r is not None:
                self.rss.append(r)
            if f is not None:
                self.fds.append(f)
            self._stop.wait(self.interval)

    def __exit__(self, *_):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self.pid:
            self.cpu_end = read_cpu_seconds(self.pid)
            self.wall = time.time() - self._t0
        return False

    def cpu_seconds(self):
        if self.cpu_start is None or self.cpu_end is None:
            return None
        return self.cpu_end - self.cpu_start

    def report(self, bytes_transferred=0):
        if not self.rss:
            return "no samples (is wazuh-manager-remoted running locally?)"
        lo, hi = min(self.rss), max(self.rss)
        parts = [f"remoted RSS {lo / 1024:.1f} -> peak {hi / 1024:.1f} MiB "
                 f"(delta {(hi - lo) / 1024:.1f} MiB, {len(self.rss)} samples)"]
        cpu = self.cpu_seconds()
        if cpu is not None:
            line = f"CPU {cpu:.2f}s"
            if bytes_transferred:
                gib = bytes_transferred / (1024 ** 3)
                if gib > 0:
                    line += f" ({cpu / gib:.2f} CPU-s/GiB)"
            parts.append(line)
        if self.fds:
            parts.append(f"fds {min(self.fds)} -> {max(self.fds)}")
        if bytes_transferred and self.wall > 0:
            parts.append(f"{bytes_transferred / (1024 ** 2) / self.wall:.0f} MiB/s")
        return "\n    ".join(parts)


# --- Scenarios -------------------------------------------------------------
# (name, expected_status, body). A malformed body, an unknown type and a bad id are all
# 400 but with distinct messages; anything that does not resolve to a readable regular
# file is 404.
#
# Note what is deliberately NOT covered: "a group this agent does not belong to". The
# endpoint performs no membership check (protocol decision on #38022), so a request for
# another group that DOES exist is served with 200 by design. The 404 below is about a
# group that does not exist at all -- naming it otherwise would imply an authorization
# property the endpoint does not have, and it would keep passing for the wrong reason.

def build_scenarios(group, unknown_group, wpk_name):
    return [
        ("valid_config", 200, request_body("config", group)),
        ("malformed_not_json", 400, b"not json at all"),
        ("malformed_empty", 400, b""),
        ("malformed_array", 400, b"[]"),
        ("malformed_missing_field", 400, b'{"resource_type":"config"}'),
        ("malformed_extra_field", 400, b'{"resource_type":"config","resource_id":"a","x":1}'),
        ("malformed_wrong_type", 400, b'{"resource_type":"config","resource_id":123}'),
        ("unknown_resource_type", 400, request_body("secrets", "a")),
        ("resource_type_case_sensitive", 400, request_body("CONFIG", group)),
        ("invalid_id_traversal", 400, request_body("config", "../../etc/shadow")),
        ("invalid_id_slash", 400, request_body("config", "a/b")),
        ("invalid_id_dotdot", 400, request_body("config", "..")),
        ("invalid_id_empty", 400, request_body("config", "")),
        ("invalid_id_too_long", 400, request_body("config", "g" * (MAX_RESOURCE_ID_SIZE + 1))),
        ("multigroup_selector_trailing_comma", 400, request_body("config", "web-servers,")),
        ("multigroup_selector_doubled_comma", 400, request_body("config", "web,,servers")),
        ("multigroup_selector_traversal_entry", 400, request_body("config", "web-servers,..")),
        ("wpk_without_extension", 400, request_body("wpk", "package")),
        ("wpk_traversal", 400, request_body("wpk", "../../etc/shadow.wpk")),
        ("unknown_group_is_404", 404, request_body("config", unknown_group)),
        ("missing_wpk_is_404", 404, request_body("wpk", "definitely-not-staged.wpk")),
        ("valid_wpk", 200, request_body("wpk", wpk_name)),
    ]


def run_scenarios(base_url, agent_id, agent_key, scenarios):
    print(f"Running {len(scenarios)} scenarios against {base_url} (agent {agent_id})\n")
    passed = 0
    for name, expected, body in scenarios:
        result = post_download(base_url, agent_id, agent_key, body)
        if result.error:
            print(f"[FAIL] {name}: expected {expected}, request failed: {result.error}")
            continue
        ok = result.status == expected
        passed += ok
        extra = ""
        if result.status == 200:
            extra = f", {result.bytes_received} bytes, chunked={result.chunked}"
            if not result.chunked:
                ok = False
                extra += " <-- NOT CHUNKED"
                passed -= 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: expected {expected}, got {result.status}"
              f"{extra}{(' -- ' + result.text) if result.text else ''}")
    print(f"\n{passed}/{len(scenarios)} scenarios passed.")
    return passed == len(scenarios)


# --- Simulated agents ------------------------------------------------------

def enrolled_agents(paths: ManagerPaths, limit=None):
    """Every usable agent in client.keys, as (id, key) pairs."""
    agents = []
    with open(paths.client_keys) as handle:
        for line in handle:
            if not line or line[0] in ("#", " "):
                continue
            parts = line.split()
            if len(parts) < 4 or parts[1].startswith(("#", "!")):
                continue
            agents.append((parts[0], bytes.fromhex(parts[3])))
            if limit and len(agents) >= limit:
                break
    return agents


def simulate(base_url, agents, repeat, expected):
    """Fires `repeat` config downloads per agent, all concurrently, and checks every one
    byte-for-byte. Concurrency is where a per-connection streaming bug shows up: a shared
    buffer or a mis-scoped descriptor produces interleaved or truncated bodies here and
    nowhere else."""
    jobs = [(agent_id, key, round_index)
            for agent_id, key in agents
            for round_index in range(repeat)]

    print(f"Simulating {len(agents)} agent(s) x {repeat} download(s) = {len(jobs)} concurrent requests")

    def one(job):
        agent_id, key, _ = job
        want = expected.get(agent_id)
        result = post_download(base_url, agent_id, key, request_body("config", want["selector"]))
        return agent_id, result, want

    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(jobs))) as pool:
        results = list(pool.map(one, jobs))
    elapsed = time.time() - started

    failures = []
    total_bytes = 0
    for agent_id, result, want in results:
        total_bytes += result.bytes_received
        if result.error:
            failures.append(f"agent {agent_id}: {result.error}")
        elif result.status != 200:
            failures.append(f"agent {agent_id}: status {result.status} ({result.text})")
        elif not result.chunked:
            failures.append(f"agent {agent_id}: response was not chunked")
        elif want["sha256"] and result.sha256 != want["sha256"]:
            failures.append(f"agent {agent_id}: body mismatch -- got {result.sha256[:16]}, "
                            f"expected {want['sha256'][:16]} ({want['path']})")

    rate = (total_bytes / (1024 * 1024) / elapsed) if elapsed > 0 else 0
    print(f"  {len(results) - len(failures)}/{len(results)} succeeded in {elapsed:.2f}s "
          f"({total_bytes / (1024 * 1024):.1f} MiB, {rate:.1f} MiB/s)")
    for failure in failures[:20]:
        print(f"  [FAIL] {failure}")
    return not failures


# --- main ------------------------------------------------------------------

def resolve_expectations(paths, agents, selectors):
    """Works out which file the manager should serve each simulated agent.

    Selectors are assigned round-robin so concurrent agents pull DIFFERENT files -- that is
    what catches a per-connection streaming bug, since shared or mis-scoped state shows up
    as one agent receiving another's body.

    No database is consulted: `/download` takes `resource_id` at face value, so the
    expectation follows from the request alone. Reading global.db here would only re-create
    the group-aware model the endpoint deliberately does not have.
    """
    expected = {}
    for index, (agent_id, _) in enumerate(agents):
        selector = selectors[index % len(selectors)]
        path = expected_config_path(paths, selector)
        expected[agent_id] = {
            "selector": selector,
            "path": path,
            "sha256": sha256_file(path),
        }
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:9443", help="Base URL of the HTTPS server.")
    parser.add_argument("--agent-id", default="001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--manager-home", default=DEFAULT_MANAGER_HOME,
                        help="Manager installation root (client.keys, global.db, etc/shared, var/upgrade).")
    parser.add_argument("--resource-type", default="config", choices=("config", "wpk"))
    parser.add_argument("--resource-id", default=None,
                        help="Group name or WPK filename. Defaults to the agent's first group.")
    parser.add_argument("--all", action="store_true", help="Run every success/failure scenario.")
    parser.add_argument("--simulate", type=int, metavar="N",
                        help="Simulate N enrolled agents downloading concurrently.")
    parser.add_argument("--repeat", type=int, default=1, help="Downloads per simulated agent.")
    parser.add_argument("--selectors", default="default",
                        help="Semicolon-separated resource_ids to hand the simulated agents, "
                             "round-robin (';' because ',' already separates a multigroup). "
                             "Different selectors make concurrent agents pull different files, "
                             "e.g. 'web-servers;web-servers,databases;default'.")
    parser.add_argument("--watch-rss", action="store_true",
                        help="Sample wazuh-manager-remoted's RSS during the transfers.")
    parser.add_argument("--unknown-group", default="a-group-that-does-not-exist",
                        help="Group used by the 404 scenario; must not exist on the manager.")
    parser.add_argument("--wpk", default=None, help="WPK filename staged under var/upgrade.")
    args = parser.parse_args()

    paths = ManagerPaths(args.manager_home)

    if args.simulate:
        agents = enrolled_agents(paths, limit=args.simulate)
        if not agents:
            raise SystemExit(f"no usable agents in {paths.client_keys}")
        selectors = [s for s in args.selectors.split(";") if s] or ["default"]
        expected = resolve_expectations(paths, agents, selectors)
        for agent_id, want in list(expected.items())[:5]:
            print(f"  agent {agent_id}: requests '{want['selector']}' -> {want['path']} "
                  f"{'(unreadable)' if not want['sha256'] else ''}")
        watcher = ProcWatcher(remoted_pid() if args.watch_rss else None)
        with watcher:
            ok = simulate(args.url, agents, args.repeat, expected)
        if args.watch_rss:
            print(f"  {watcher.report()}")
        return 0 if ok else 1

    agent_key = read_agent_key(args.agent_id, paths.client_keys)
    default_group = args.resource_id or "default"

    if args.all:
        wpk = args.wpk or next((f for f in sorted(os.listdir(paths.wpk_dir))
                                if f.endswith(".wpk")), "none-staged.wpk") \
            if os.path.isdir(paths.wpk_dir) else "none-staged.wpk"
        print(f"agent {args.agent_id}: config selector={default_group}, wpk={wpk}\n")
        return 0 if run_scenarios(args.url, args.agent_id, agent_key,
                                  build_scenarios(default_group, args.unknown_group, wpk)) else 1

    resource_id = args.resource_id or ("default" if args.resource_type == "config" else "")
    if not resource_id:
        raise SystemExit("--resource-id is required for a wpk download")

    body = request_body(args.resource_type, resource_id)
    print(f"--> POST {args.url.rstrip('/')}{TARGET}  {body.decode()}")

    watcher = ProcWatcher(remoted_pid() if args.watch_rss else None)
    with watcher:
        result = post_download(args.url, args.agent_id, agent_key, body)

    if result.error:
        print(f"<-- FAILED: {result.error}")
        return 1

    print(f"<-- {result.status}  chunked={result.chunked}  content-length={result.content_length}")
    print(f"    {result.bytes_received} bytes, sha256={result.sha256}")
    if result.text:
        print(f"    {result.text}")
    if args.watch_rss:
        print(f"    {watcher.report(result.bytes_received)}")

    if result.status == 200 and args.resource_type == "config":
        want_path = expected_config_path(paths, resource_id)
        want_digest = sha256_file(want_path)
        print(f"    expected file: {want_path}")
        if want_digest is None:
            print("    (expected file unreadable from here; skipping byte comparison)")
        elif want_digest == result.sha256:
            print("    [PASS] body matches the file the manager should have served")
        else:
            print(f"    [FAIL] body MISMATCH -- expected sha256={want_digest}")
            return 1
        if not result.chunked:
            print("    [FAIL] response was not chunked")
            return 1

    return 0 if result.status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
