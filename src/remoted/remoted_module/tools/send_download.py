#!/usr/bin/env python3
"""
Drives remoted's `POST /download` endpoint the way a real agent does, and checks the
things unit tests cannot reach: the chunked transfer over TLS, and resource resolution
against a real installation.

Authentication is the same wazuh-agent+jwt bearer as /stateless (see wire_jwt.py, which must sit
next to this script), so the helpers are imported rather than duplicated.

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

Requires: pip install requests

Examples:
  python3 send_download.py                            # config download for agent 001's group
  python3 send_download.py --all                      # every success/failure scenario
  python3 send_download.py --resource-type wpk --resource-id pkg.wpk
  python3 send_download.py --simulate 20 --repeat 5   # 20 concurrent simulated agents
  python3 send_download.py --simulate 8 --watch-rss   # + RSS/CPU/fd/throughput report
  python3 send_download.py --self-test                # codec vectors, no network
  python3 send_download.py --mint --task-id <uuid>    # print a signed WPK id (agent 001)
  python3 send_download.py --mint --task-id <uuid> --subject 7 --ttl 60 --cluster-key-file key.txt
  python3 send_download.py --wpk-id-scenarios --task-id <uuid> --plain-wpk pkg.wpk
"""
import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import struct
import subprocess
import sys
import threading
import time

import requests
import urllib3

from wire_jwt import auth_headers, read_agent_key  # the shared wazuh-agent+jwt signer (same directory)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_MANAGER_HOME = "/var/wazuh-manager"
TARGET = "/download"

# Mirrors MAX_RESOURCE_ID_SIZE in downloadEndpoint.cpp.
MAX_RESOURCE_ID_SIZE = 255

# --- Manager-side layout ---------------------------------------------------

class ManagerPaths:
    def __init__(self, home):
        self.home = home.rstrip("/")
        self.client_keys = "/etc/wazuh-manager/client.keys"
        self.shared_dir = "/etc/wazuh-manager/shared"
        self.multigroups_dir = f"{self.home}/var/multigroups"
        self.wpk_dir = f"{self.home}/var/upgrade"
        self.wpk_tasks_dir = f"{self.home}/var/upgrade/tasks"



# --- Signed WPK download identifier ------------------------------------------------------------
# Same construction as auth/wpkId.cpp:
#   K   = HKDF-SHA256(IKM = cluster.key, salt = 32 x 0x00, info = "WAZUH-WPK-ID-KEY" || 0x01, L = 32)
#   S   = subject (4, big endian) || exp (4, big endian) || task_id (16)
#   tag = HMAC-SHA256(K, "WAZUH-WPK-ID\n1\n" || S)[:16]
#   id  = "wpk1." + base64url_nopad(S || tag) + ".wpk"

WPK_ID_LABEL = b"WAZUH-WPK-ID-KEY"
WPK_ID_VERSION = b"\x01"
WPK_ID_DOMAIN = b"WAZUH-WPK-ID\n1\n"
TASK_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CLUSTER_KEY_RE = re.compile(r"^[A-Za-z0-9]{32}$")

# Not a secret: a well-formed key that differs from the node's, to mint an id the node must reject.
OTHER_CLUSTER_KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

# (name, cluster_key, subject, task_id, now, ttl, expected id)
WPK_ID_VECTORS = [
    ("V1", "0123456789abcdefABCDEFGHIJKLMNOP", 1, "815a10ac-7b2e-a8a8-e137-f3edd8046a38", 1793098550, 600,
     "wpk1.AAAAAWrghY6BWhCsey6oqOE38-3YBGo4YuKOMLVYGj_34xXog1CLbA.wpk"),
    ("V2", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 4294967295, "ffffffff-ffff-ffff-ffff-ffffffffffff", 0, 60,
     "wpk1._____wAAADz_____________________A5mFj1hzUINXzjIh8PmNSQ.wpk"),
    ("V3", "fd3350b86d239654e34866ab3c4988a8", 1234, "2d6a55b2-b99f-d3df-f07e-e64d2f08dc54", 2000000000, 3600,
     "wpk1.AAAE0nc1ohAtalWyuZ_T3_B-5k0vCNxUa38xACSwPHMeWjwiHoBtfQ.wpk"),
]


def derive_wpk_id_key(cluster_key: str) -> bytes:
    if not CLUSTER_KEY_RE.match(cluster_key):
        raise ValueError("cluster key must match ^[A-Za-z0-9]{32}$")
    prk = hmac.new(b"\x00" * 32, cluster_key.encode(), hashlib.sha256).digest()
    return hmac.new(prk, WPK_ID_LABEL + WPK_ID_VERSION + b"\x01", hashlib.sha256).digest()


def parse_task_id(text: str) -> bytes:
    if not TASK_ID_RE.match(text):
        raise ValueError("task id must be 8-4-4-4-12 lowercase hex")
    return bytes.fromhex(text.replace("-", ""))


def mint_wpk_id(cluster_key: str, subject: int, task_id: str, now: int, ttl: int) -> str:
    key = derive_wpk_id_key(cluster_key)
    claims = struct.pack(">II", subject, now + ttl) + parse_task_id(task_id)
    tag = hmac.new(key, WPK_ID_DOMAIN + claims, hashlib.sha256).digest()[:16]
    return "wpk1." + base64.urlsafe_b64encode(claims + tag).rstrip(b"=").decode() + ".wpk"


def self_test() -> int:
    failed = 0
    for name, cluster_key, subject, task_id, now, ttl, expected in WPK_ID_VECTORS:
        got = mint_wpk_id(cluster_key, subject, task_id, now, ttl)
        ok = got == expected
        failed += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {got if ok else f'got {got}, expected {expected}'}")
    offenders = plain_wpk_200_rows()
    failed += bool(offenders)
    print(f"[{'FAIL' if offenders else 'PASS'}] no_200_for_non_identifier_wpk: "
          f"{offenders if offenders else 'every 200 wpk row carries a wpk1 identifier'}")
    return 1 if failed else 0


def plain_wpk_200_rows():
    """Names of scenarios expecting 200 for a `wpk` whose resource_id is not a `wpk1.<...>.wpk` id."""
    key = "0123456789abcdefghijklmnopqrstuv"
    task_id = "00000000-0000-4000-8000-000000000000"
    rows = (build_scenarios("group", "unknown-group", "other-group", "package.wpk")
            + build_wpk_id_scenarios(key, 1, task_id, 600, "/nonexistent", "package.wpk", now=1700000000))
    offenders = []
    for name, expected, body, *_ in rows:
        try:
            request = json.loads(body)
        except ValueError:
            continue
        if (expected == 200 and isinstance(request, dict) and request.get("resource_type") == "wpk"
                and not re.fullmatch(r"wpk1\.[A-Za-z0-9_-]+\.wpk", str(request.get("resource_id")))):
            offenders.append(name)
    return offenders


def tamper_wpk_id(wpk_id: str) -> str:
    """Changes one character in the middle of the base64url body to a different alphabet member."""
    body = wpk_id[len("wpk1."):-len(".wpk")]
    mid = len(body) // 2
    return "wpk1." + body[:mid] + ("A" if body[mid] != "A" else "B") + body[mid + 1:] + ".wpk"


# --- Global endpoint prefix (<remote><https><global_prefix>) ---------------------------------
# Applied to every target when building the URL. Authentication does not cover the target (the
# bearer token binds the agent's identity only), so a mismatch with the manager's configured
# prefix surfaces as 404 (route not found), never as 401.
#
# Resolved like run_benchmark.sh resolves --cluster: the value belongs to the manager under
# test, so when --global-prefix is not given it is read from that manager's own configuration
# instead of making every invocation repeat it -- a default installation needs no flag. An
# explicit value always wins; pass '/' to force the unprefixed paths against a prefixed manager.

DEFAULT_MANAGER_CONF = "/etc/wazuh-manager/wazuh-manager.conf"

GLOBAL_PREFIX = ""


def normalize_global_prefix(raw: str) -> str:
    """'' and '/' mean no prefix; otherwise ensure a leading '/' and strip trailing '/'."""
    stripped = raw.strip("/") if raw else ""
    return "/" + stripped if stripped else ""


def global_prefix_from_conf(conf_path: str = DEFAULT_MANAGER_CONF) -> str:
    """Reads <remote><https><global_prefix> out of the manager's configuration.

    Scoped to the <https> block so a <global_prefix> elsewhere in the file cannot be picked
    up by mistake. Returns "" when the file is missing or unreadable and when the tag is
    absent -- an absent tag is exactly what "no prefix" means to the manager too, so the
    caller needs no separate "not detected" case.
    """
    try:
        with open(conf_path, "r") as handle:
            text = handle.read()
    except OSError:
        return ""
    block = re.search(r"<https>(.*?)</https>", text, re.S)
    if not block:
        return ""
    tag = re.search(r"<global_prefix>(.*?)</global_prefix>", block.group(1), re.S)
    return tag.group(1).strip() if tag else ""


def cluster_key_from_conf(conf_path: str = DEFAULT_MANAGER_CONF) -> str:
    """Reads <cluster><key> out of the manager's configuration.

    XML comments are stripped first and the search is scoped to the <cluster> block, so a
    commented-out block or a <key> elsewhere in the file cannot be picked up. Raises
    ValueError unless the result matches ^[A-Za-z0-9]{32}$; the key is never part of the message.
    """
    try:
        with open(conf_path, "r") as handle:
            text = handle.read()
    except OSError as error:
        raise ValueError(f"cannot read {conf_path}: {error.strerror}")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    block = re.search(r"<cluster>(.*?)</cluster>", text, re.S)
    tag = re.search(r"<key>(.*?)</key>", block.group(1), re.S) if block else None
    key = tag.group(1).strip() if tag else ""
    if not CLUSTER_KEY_RE.match(key):
        raise ValueError(f"no usable <cluster><key> (32 alphanumeric characters) in {conf_path}")
    return key


def read_cluster_key(key_file, conf_path: str = DEFAULT_MANAGER_CONF) -> str:
    """The key from the first line of --cluster-key-file when given, else from the manager's conf."""
    if key_file is None:
        return cluster_key_from_conf(conf_path)
    try:
        with open(key_file, "r") as handle:
            key = handle.readline().strip()
    except OSError as error:
        raise ValueError(f"cannot read {key_file}: {error.strerror}")
    if not CLUSTER_KEY_RE.match(key):
        raise ValueError(f"first line of {key_file} is not a 32 alphanumeric character key")
    return key


def resolve_global_prefix(cli_value, conf_path: str = DEFAULT_MANAGER_CONF) -> str:
    """An explicit --global-prefix wins; None (flag not given) reads the manager's config."""
    if cli_value is not None:
        return normalize_global_prefix(cli_value)
    return normalize_global_prefix(global_prefix_from_conf(conf_path))


def prefixed(path: str) -> str:
    """Serves `path` under the configured global prefix."""
    return GLOBAL_PREFIX + path

def multigroup_dir_name(selector: str) -> str:
    """Same formula wazuh-db uses to NAME the directory: OS_SHA256_String_sized(sel, out, 32).
    Replicated, not queried -- the manager derives it the same way."""
    return hashlib.sha256(selector.encode()).hexdigest()[:32]


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
    """Sends one bearer-authenticated /download request, consuming the body as a stream so the
    client never holds the whole file either."""
    result = DownloadResult()
    url = base_url.rstrip("/") + prefixed(TARGET)
    headers = auth_headers(agent_id, agent_key)

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
# Authorization (#38683): a `config` request is served only when resource_id equals the
# selector /control handed THIS agent as config_token. Anything else is 403, decided before
# the path is resolved -- so a group the agent is not in answers the same whether or not it
# exists on the manager, which is the property the two denial scenarios below pin together.
# 404 therefore now means "your own group's merged.mg is not on disk", not "no such group".
#
# One case this script cannot stage by itself: an agent with no registry entry at all (it
# never sent /control/startup, or its entry was evicted). Reproduce it by restarting remoted
# and running send_download.py BEFORE send_control.py -- the answer must be 403, not 200.
# `wpk` requests are authorized by the identifier itself: a `wpk1.<...>.wpk` id carries the agent,
# the task and an expiry under a MAC (--wpk-id-scenarios, --mint). A flat WPK name is no longer
# served, which is why plain_wpk_rejected below expects 404.

def build_scenarios(group, unknown_group, other_group, wpk_name):
    scenarios = [
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
        ("group_that_does_not_exist_is_denied", 403, request_body("config", unknown_group)),
    ]

    # Only pinned when the group REALLY exists on the manager. Denial is decided before the path is
    # resolved, so a non-existent --other-group answers 403 for the wrong reason and becomes a
    # silent duplicate of the scenario above -- a green sheet that never tested "exists, but not
    # mine", which is the actual defect from #38683. main() passes None (after an explicit WARNING)
    # rather than let that pad the count.
    if other_group:
        scenarios.append(
            ("group_the_agent_is_not_in_is_denied", 403, request_body("config", other_group)))

    scenarios += [
        ("missing_wpk_is_404", 404, request_body("wpk", "definitely-not-staged.wpk")),
        ("plain_wpk_rejected", 404, request_body("wpk", wpk_name)),
    ]
    return scenarios


def build_wpk_id_scenarios(cluster_key, agent_id, task_id, ttl, tasks_dir, plain_wpk, now=None):
    """A valid id is served with the task file's content; every other form is a 404.

    The 404 rows also pass when identifiers are disabled or the task file is missing, so they are
    conclusive only when the valid-id row passes."""
    now = int(time.time()) if now is None else now
    subject = int(agent_id)
    if cluster_key == OTHER_CLUSTER_KEY:
        raise ValueError("the node's cluster key equals the fixed alternative key; M2 would not be a negative")
    task_file = f"{tasks_dir}/{task_id}.wpk"
    want = sha256_file(task_file)
    reason = f"cannot read {task_file}"
    valid = mint_wpk_id(cluster_key, subject, task_id, now, ttl)
    scenarios = [
        ("M1_valid_id", 200, request_body("wpk", valid), (want, reason)),
        ("M2_other_cluster_key", 404,
         request_body("wpk", mint_wpk_id(OTHER_CLUSTER_KEY, subject, task_id, now, ttl))),
        ("M3_expired", 404,
         request_body("wpk", mint_wpk_id(cluster_key, subject, task_id, int(time.time()) - ttl - 1, ttl))),
        ("M4_other_agent", 404,
         request_body("wpk", mint_wpk_id(cluster_key, subject + 1, task_id, now, ttl))),
        ("M5_tampered", 404, request_body("wpk", tamper_wpk_id(valid))),
        ("M6_plain_task_name", 404, request_body("wpk", f"{task_id}.wpk")),
    ]
    if plain_wpk:
        scenarios.append(("M7_plain_wpk_name", 404, request_body("wpk", plain_wpk)))
    else:
        print("WARNING: --plain-wpk not given; M7_plain_wpk_name is SKIPPED.\n")
    return scenarios


def run_scenarios(base_url, agent_id, agent_key, scenarios):
    print(f"Running {len(scenarios)} scenarios against {base_url} (agent {agent_id})\n")
    passed = 0
    for name, expected, body, *rest in scenarios:
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
            if rest and ok:
                # rest[0] = sha256 of the file the body must equal, or a reason it is unavailable
                want, reason = rest[0]
                if want is None:
                    ok = False
                    passed -= 1
                    extra += f" <-- cannot check content: {reason}"
                elif want != result.sha256:
                    ok = False
                    passed -= 1
                    extra += f" <-- sha256 differs from the task file ({want[:16]}...)"
                else:
                    extra += ", sha256 = task file"
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
    global GLOBAL_PREFIX
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:9443", help="Base URL of the HTTPS server.")
    parser.add_argument("--global-prefix", default=None,
                        help="URL path prefix the manager serves every endpoint under "
                             "(<remote><https><global_prefix>). Used only when "
                             "building the URL (authentication does not cover the target). Read from "
                             + DEFAULT_MANAGER_CONF + " when not given; pass '/' to force the "
                             "unprefixed paths.")
    parser.add_argument("--agent-id", default="001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--manager-home", default=DEFAULT_MANAGER_HOME,
                        help="Manager installation root (var/multigroups, var/upgrade). client.keys and "
                             "shared/ are always read from /etc/wazuh-manager.")
    parser.add_argument("--resource-type", default="config", choices=("config", "wpk"))
    parser.add_argument("--resource-id", default=None,
                        help="Group name or WPK filename. Defaults to 'default' for --resource-type config; "
                             "required for wpk.")
    parser.add_argument("--all", action="store_true", help="Run every success/failure scenario.")
    parser.add_argument("--simulate", type=int, metavar="N",
                        help="Simulate N enrolled agents downloading concurrently.")
    parser.add_argument("--repeat", type=int, default=1,
                        help="Downloads per simulated agent, all in flight at once. Above the manager's "
                             "remoted.max_requests_per_agent (6 by default) the excess is answered 503 by design.")
    parser.add_argument("--selectors", default="default",
                        help="Semicolon-separated resource_ids to hand the simulated agents, "
                             "round-robin (';' because ',' already separates a multigroup). "
                             "Different selectors make concurrent agents pull different files, "
                             "e.g. 'web-servers;web-servers,databases;default'.")
    parser.add_argument("--watch-rss", action="store_true",
                        help="Sample wazuh-manager-remoted's RSS during the transfers.")
    parser.add_argument("--unknown-group", default="a-group-that-does-not-exist",
                        help="Group that must NOT exist on the manager; the denial scenario proves "
                             "it answers 403, not 404.")
    parser.add_argument("--other-group", default="databases",
                        help="Group that DOES exist but this agent is not in; must answer 403 "
                             "identically to --unknown-group (no enumeration oracle). The default "
                             "is absent from a stock install, in which case that scenario is "
                             "skipped with a warning rather than passing for the wrong reason.")
    parser.add_argument("--wpk", default=None, help="WPK filename staged under var/upgrade.")
    parser.add_argument("--self-test", action="store_true",
                        help="Check the signed-id codec against fixed vectors; needs no network.")
    parser.add_argument("--mint", action="store_true",
                        help="Print a signed WPK id for --task-id and exit.")
    parser.add_argument("--wpk-id-scenarios", action="store_true",
                        help="Run the signed-id matrix (valid, other key, expired, other agent, tampered, "
                             "flat task name, flat WPK name) for --task-id.")
    parser.add_argument("--task-id", default=None, help="Task id, 8-4-4-4-12 lowercase hex.")
    parser.add_argument("--ttl", type=int, default=600, help="Identifier lifetime in seconds.")
    parser.add_argument("--now", type=int, default=None, help="Issue time (UNIX seconds) for --mint; default: now.")
    parser.add_argument("--subject", type=int, default=None, help="Agent id numeric value for --mint; default: --agent-id.")
    parser.add_argument("--cluster-key-file", default=None,
                        help="File whose first line is the cluster key, instead of <cluster><key> in "
                             + DEFAULT_MANAGER_CONF + ". The key is never printed.")
    parser.add_argument("--plain-wpk", default=None,
                        help="Flat WPK name under var/upgrade; no longer served, so it only feeds the 404 row.")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if args.mint or args.wpk_id_scenarios:
        if not args.task_id:
            raise SystemExit("--task-id is required")
        try:
            cluster_key = read_cluster_key(args.cluster_key_file)
            parse_task_id(args.task_id)
            if args.mint:
                subject = args.subject if args.subject is not None else int(args.agent_id)
                now = args.now if args.now is not None else int(time.time())
                print(mint_wpk_id(cluster_key, subject, args.task_id, now, args.ttl))
                return 0
            paths = ManagerPaths(args.manager_home)
            scenarios = build_wpk_id_scenarios(cluster_key, args.agent_id, args.task_id, args.ttl,
                                               paths.wpk_tasks_dir, args.plain_wpk)
        except ValueError as error:
            raise SystemExit(f"error: {error}")
        GLOBAL_PREFIX = resolve_global_prefix(args.global_prefix)
        agent_key = read_agent_key(args.agent_id, paths.client_keys)
        print("The 404 rows are conclusive only if M1_valid_id passes.\n")
        return 0 if run_scenarios(args.url, args.agent_id, agent_key, scenarios) else 1

    GLOBAL_PREFIX = resolve_global_prefix(args.global_prefix)
    if args.global_prefix is None and GLOBAL_PREFIX:
        print(f"Global prefix not given; using '{GLOBAL_PREFIX}' from {DEFAULT_MANAGER_CONF}")

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
        # --other-group must name a group that EXISTS but is not this agent's. Its default does not
        # exist on a stock install, and a missing one still answers 403 (denial precedes
        # resolution), so the scenario would pass without proving anything. Say so loudly and drop
        # it instead of reporting a green sheet for a case that was never exercised.
        other_group = args.other_group
        other_group_path = expected_config_path(paths, other_group)
        if not os.path.isfile(other_group_path):
            print(f"WARNING: --other-group '{other_group}' has no {other_group_path}.")
            print("         'group_the_agent_is_not_in_is_denied' cannot prove \"exists, but not "
                  "mine\" and is SKIPPED.")
            print("         Create that group on the manager (and let its merged.mg build), or "
                  "pass --other-group <an existing group>.\n")
            other_group = None

        print(f"agent {args.agent_id}: config selector={default_group}, wpk={wpk}\n")
        return 0 if run_scenarios(args.url, args.agent_id, agent_key,
                                  build_scenarios(default_group, args.unknown_group,
                                                  other_group, wpk)) else 1

    resource_id = args.resource_id or ("default" if args.resource_type == "config" else "")
    if not resource_id:
        raise SystemExit("--resource-id is required for a wpk download")

    body = request_body(args.resource_type, resource_id)
    print(f"--> POST {args.url.rstrip('/')}{prefixed(TARGET)}  {body.decode()}")

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
