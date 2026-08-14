#!/usr/bin/env python3
"""
Process resource monitor for Wazuh Manager benchmarks.

Monitors all Wazuh manager processes by default and writes periodic resource
samples to per-process CSV files inside an output directory.  Disk usage is
tracked independently in a separate ``disk_usage.csv``.

Usage:
    # Monitor all default Wazuh processes with default disk paths
    python3 monitor.py

    # Monitor specific processes by executable path
    python3 monitor.py --exe /var/wazuh-manager/bin/wazuh-manager-analysisd \
                       --exe /var/wazuh-manager/bin/wazuh-manager-remoted

    # Legacy: monitor single process by name
    python3 monitor.py -n wazuh-modulesd -o monitor.csv -s 1

    # Stop a running monitor
    kill $(cat monitor.pid)
"""
from __future__ import annotations

import argparse
import atexit
import csv
import http.client
import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import psutil

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_EXECUTABLES = [
    "/var/wazuh-manager/bin/wazuh-manager-analysisd",
    "/var/wazuh-manager/bin/wazuh-manager-monitord",
    "/var/wazuh-manager/api/scripts/wazuh_manager_apid.py",
    "/var/wazuh-manager/framework/scripts/wazuh_manager_clusterd.py",
    "/var/wazuh-manager/bin/wazuh-manager-db",
    "/var/wazuh-manager/bin/wazuh-manager-modulesd",
    "/var/wazuh-manager/bin/wazuh-manager-remoted",
]

# wazuh-indexer is co-located only in all-in-one deployments. The monitor
# probes for its executable at startup and silently skips it if absent.
INDEXER_EXECUTABLE = "/usr/share/wazuh-indexer/jdk/bin/java"
INDEXER_ENGINE_EXECUTABLE = "/usr/share/wazuh-indexer/engine/bin/wazuh-engine"
DASHBOARD_EXECUTABLE = "/usr/share/wazuh-dashboard/bin/opensearch-dashboards"
DASHBOARD_NODE_EXECUTABLE = "/usr/share/wazuh-dashboard/node/bin/node"

# queue/inventory_sync is deliberately absent: it belonged to the retired
# inventory_sync module. inventory_sync_server keeps no local store at all (it
# streams straight to the indexer), so whatever is left at that path is frozen
# residue and would only plot a flat line. queue/vd stays — the vulnerability
# scanner's RocksDB is live and does grow.
DEFAULT_DISK_PATHS = [
    "/var/wazuh-manager/queue/vd",
    "/var/wazuh-manager/",
]

DEFAULT_REMOTED_SOCKET = "/var/wazuh-manager/queue/sockets/remote"
REMOTED_STATS_CSV = "stats-api-remoted.csv"
REMOTED_QUERY = {"command": "getstats"}
REMOTED_MAX_RESPONSE_SIZE = 4 * 1024 * 1024

DEFAULT_INVSYNC_SOCKET = "/var/wazuh-manager/queue/sockets/inventory-sync.sock"
INVSYNC_STATS_CSV = "stats-api-inventory-sync.csv"
INVSYNC_MAX_RESPONSE_SIZE = 4 * 1024 * 1024

DEFAULT_ANALYSISD_SOCKET = "/var/wazuh-manager/queue/sockets/analysis"
ANALYSISD_STATS_CSV = "stats-api-analysisd.csv"
ANALYSISD_MAX_RESPONSE_SIZE = 4 * 1024 * 1024
ANALYSISD_HEADER = [
    "timestamp",
    "elapsed_s",
    "query_ok",
    "query_error",
    "server_events_received",
    "router_queue_size",
    "router_queue_usage_percent",
    "router_queue_bytes_used",
    "router_queue_bytes_usage_percent",
    "router_events_processed",
    "router_events_dropped",
    "indexer_queue_size",
    "indexer_queue_usage_percent",
    "indexer_events_dropped",
    "router_eps_1m",
    "agent_cache_entries",
    "agent_cache_hits",
    "agent_cache_insertions",
    "agent_cache_updates",
    "agent_cache_evictions",
    "spaces_standard_events_unclassified",
    "raw_response_json",
]

# inventory_sync_server exposes GET /metrics on its own UDS socket. The route is
# budget-exempt on purpose, so it keeps answering while the module sheds real
# traffic -- which is exactly when these numbers matter.
#
# The per-shard gauges (sync.shard.<i>.{depth,bytes}) are aggregated rather than
# given a column each: the shard count follows the configured worker count, so a
# per-shard header would differ between machines and make two runs
# incomparable. depth_max against depth_sum still shows imbalance, and the full
# per-shard detail survives verbatim in raw_response_json.
_INVSYNC_HISTOGRAMS: tuple[tuple[str, str], ...] = (
    ("sync.session.duration.bulk", "session_duration_bulk"),
    ("sync.session.duration.immediate", "session_duration_immediate"),
    ("vd.lane.time", "vd_lane_time"),
    ("vd.scan.duration", "vd_scan_duration"),
)
# Histogram values are microseconds (see the module's metricNames.hpp).
_INVSYNC_HIST_FIELDS: tuple[str, ...] = ("count", "p50", "p90", "p99", "max")

# metric name in the dump -> CSV column
_INVSYNC_SCALARS: tuple[tuple[str, str], ...] = (
    ("sync.requests.total.200", "requests_200"),
    ("sync.requests.total.400", "requests_400"),
    ("sync.requests.total.403", "requests_403"),
    ("sync.requests.total.409", "requests_409"),
    ("sync.requests.total.500", "requests_500"),
    ("sync.requests.total.503", "requests_503"),
    ("sync.requests.total.other", "requests_other"),
    ("sync.docs.indexed", "docs_indexed"),
    ("sync.docs.skipped", "docs_skipped"),
    ("sync.bytes.ingested", "bytes_ingested"),
    ("sync.pipeline.shed.total", "pipeline_shed_total"),
    ("sync.bulk.flushes", "bulk_flushes"),
    ("sync.bulk.sessions.total", "bulk_sessions_total"),
    ("sync.bulk.bytes.total", "bulk_bytes_total"),
    ("vd.lane.depth", "vd_lane_depth"),
    ("vd.scans.ok", "vd_scans_ok"),
    ("vd.scans.failed", "vd_scans_failed"),
    ("vd.scans.skipped", "vd_scans_skipped"),
    ("vd.capacity.503.total", "vd_capacity_503_total"),
    ("vd.retry_after.total", "vd_retry_after_total"),
)

INVSYNC_HEADER = (
    ["timestamp", "elapsed_s", "query_ok", "query_error"]
    + [col for _, col in _INVSYNC_SCALARS]
    + ["shard_count", "shard_depth_max", "shard_depth_sum",
       "shard_bytes_max", "shard_bytes_sum"]
    + [f"{prefix}_{field}"
       for _, prefix in _INVSYNC_HISTOGRAMS
       for field in _INVSYNC_HIST_FIELDS]
    + ["raw_response_json"]
)

REMOTED_HEADER = [
    "timestamp",
    "elapsed_s",
    "query_ok",
    "query_error",
    "error",
    "message",
    "data_name",
    "data_timestamp",
    "data_uptime",
    "metrics_bytes_received",
    "metrics_bytes_sent",
    "metrics_keys_reload_count",
    "messages_received_breakdown_control",
    "messages_received_breakdown_dequeued_after",
    "messages_received_breakdown_discarded",
    "messages_received_breakdown_events",
    "messages_received_breakdown_events_failed",
    "messages_received_breakdown_ping",
    "messages_received_breakdown_states",
    "messages_received_breakdown_unknown",
    "messages_received_breakdown_control_breakdown_keepalive",
    "messages_received_breakdown_control_breakdown_request",
    "messages_received_breakdown_control_breakdown_shutdown",
    "messages_received_breakdown_control_breakdown_startup",
    "messages_sent_breakdown_ack",
    "messages_sent_breakdown_ar",
    "messages_sent_breakdown_discarded",
    "messages_sent_breakdown_request",
    "messages_sent_breakdown_shared",
    "queues_received_size",
    "queues_received_usage",
    "tcp_sessions",
    "control_messages_queue_usage",
    "control_messages_queue_breakdown_inserted",
    "control_messages_queue_breakdown_replaced",
    "control_messages_queue_breakdown_processed",
    "raw_response_json",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("monitor")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_running = True


# ---------------------------------------------------------------------------
# Signal handling & PID file
# ---------------------------------------------------------------------------
def _signal_handler(_signum, _frame):
    global _running
    _running = False
    logger.info("Stop signal received — finishing current sample and exiting.")


def write_pid_file(path: str) -> None:
    with open(path, "w") as f:
        f.write(str(os.getpid()))
    logger.info("PID file written: %s (pid=%d)", path, os.getpid())
    atexit.register(_remove_pid_file, path)


def _remove_pid_file(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Process discovery
# ---------------------------------------------------------------------------
def find_process(pid: int | None, name: str | None) -> psutil.Process:
    if pid is not None:
        try:
            proc = psutil.Process(pid)
            logger.info("Attached to PID %d (%s)", proc.pid, proc.name())
            return proc
        except psutil.NoSuchProcess:
            logger.critical("PID %d does not exist.", pid)
            sys.exit(1)

    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info["name"] == name:
            logger.info("Found process '%s' with PID %d", name, proc.pid)
            return proc

    logger.critical("No running process named '%s' found.", name)
    sys.exit(1)


@dataclass(frozen=True)
class ProcessTarget:
    key: str
    exe_paths: tuple[str, ...]
    cmdline_markers: tuple[str, ...] = ()
    require_cmdline_marker: bool = False
    csv_name: str | None = None
    display_name: str | None = None

    @property
    def name(self) -> str:
        return self.display_name or self.csv_name or os.path.basename(self.key)


def process_target_from_exe(
    exe_path: str,
    *,
    csv_name: str | None = None,
    display_name: str | None = None,
    cmdline_markers: tuple[str, ...] | None = None,
    extra_exe_paths: tuple[str, ...] = (),
    require_cmdline_marker: bool = False,
) -> ProcessTarget:
    markers = (exe_path,) if cmdline_markers is None else cmdline_markers
    return ProcessTarget(
        key=exe_path,
        exe_paths=(exe_path,) + extra_exe_paths,
        cmdline_markers=markers,
        require_cmdline_marker=require_cmdline_marker,
        csv_name=csv_name,
        display_name=display_name,
    )


def _cmdline_has_marker(cmdline: list[str], markers: tuple[str, ...]) -> bool:
    if not markers:
        return False
    return any(marker in arg for marker in markers for arg in cmdline)


def find_process_by_target(target: ProcessTarget) -> psutil.Process | None:
    """Find a process matching *target*.

    Matches native binaries via ``exe`` and interpreted commands via stable
    command-line markers. Dashboard monitoring uses an additional cmdline
    marker requirement so a generic Node.js process is not mistaken for
    wazuh-dashboard.

    Selection when multiple processes match:
      - Native binaries match via `exe`. Only fall back to `cmdline` when no
        exe matches. This prevents transient helpers (bash subshells, pgrep,
        ps) that happen to have the binary path in their cmdline from
        outvoting the real binary process.
      - Most recently started first. This handles the zombie-after-restart
        case: stale orphans from a previous service restart keep their old
        create_time(), while the active master spawned by the new restart
        has a fresh create_time().
      - Lowest PID within the same generation (parent over its workers).
    """
    exe_matches: list[psutil.Process] = []
    cmdline_matches: list[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "exe", "cmdline"]):
        try:
            exe = proc.info.get("exe") or ""
            cmdline = proc.info.get("cmdline") or []
            exe_match = exe in target.exe_paths
            cmdline_match = _cmdline_has_marker(cmdline, target.cmdline_markers)

            if target.require_cmdline_marker:
                if exe_match and cmdline_match:
                    exe_matches.append(proc)
                continue

            if exe_match:
                exe_matches.append(proc)
                continue
            if cmdline_match:
                cmdline_matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    candidates = exe_matches if exe_matches else cmdline_matches
    if not candidates:
        return None

    candidates.sort(key=lambda p: (-p.create_time(), p.pid))
    chosen = candidates[0]

    # Warn loudly if there are leftover processes from a previous generation -
    # they typically hold file locks on shared queues (e.g. RocksDB) and
    # silently break the active master.
    stale = [p for p in candidates[1:]
             if (chosen.create_time() - p.create_time()) > 60]
    if stale:
        others = ", ".join(f"PID {p.pid} (started {time.ctime(p.create_time())})"
                           for p in stale)
        logger.warning(
            "Multiple %s instances detected. Attaching to PID %d (newest, "
            "started %s). Stale instances: %s. Consider "
            "'pkill -9 -f %s && service wazuh-manager restart' before re-running.",
            target.name, chosen.pid,
            time.ctime(chosen.create_time()), others,
            target.name,
        )

    return chosen


def find_process_by_exe(exe_path: str) -> psutil.Process | None:
    return find_process_by_target(process_target_from_exe(exe_path))


def wait_for_processes(
    targets: list[ProcessTarget] | list[str],
    timeout: float = 30.0,
) -> dict[ProcessTarget, psutil.Process]:
    """Wait until every target in *targets* is running.

    Returns a dict mapping ProcessTarget -> psutil.Process.
    Raises SystemExit if timeout expires before all processes appear.
    """
    target_list = [
        process_target_from_exe(t) if isinstance(t, str) else t
        for t in targets
    ]
    remaining = set(target_list)
    found: dict[ProcessTarget, psutil.Process] = {}
    deadline = time.monotonic() + timeout

    logger.info("Waiting for %d processes (timeout=%ds)...", len(remaining), int(timeout))
    while remaining and time.monotonic() < deadline and _running:
        for target in list(remaining):
            proc = find_process_by_target(target)
            if proc is not None:
                logger.info("  Found %s -> PID %d", target.name, proc.pid)
                found[target] = proc
                remaining.discard(target)
        if remaining:
            time.sleep(1)

    if remaining:
        missing = ", ".join(t.name for t in sorted(remaining, key=lambda t: t.name))
        logger.critical(
            "Timeout: the following processes were NOT found after %ds: %s",
            int(timeout), missing,
        )
        sys.exit(1)

    logger.info("All %d processes found.", len(found))
    return found


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------
BASE_CSV_HEADER = [
    "timestamp",
    "elapsed_s",
    "pid",
    "uptime_sec",
    "cpu_pct",
    "mem_pct",
    "rss_mb",
    "vms_mb",
    "fds",
    "threads",
    "read_bytes",
    "write_bytes",
]


def disk_col_name(path: str) -> str:
    """Stable CSV column name derived from a directory path.

    Example: /var/wazuh-manager/queue/vd/  ->  dir_vd_mb
    """
    basename = os.path.basename(os.path.normpath(path)) or "root"
    safe = re.sub(r"[^A-Za-z0-9_]", "_", basename)
    return f"dir_{safe}_mb"


def dir_size_mb(path: str) -> float:
    """Recursive directory size in MB. Returns 0 if path doesn't exist or
    can't be read. Implemented with os.scandir for low overhead, no subprocess.
    """
    total = 0
    try:
        stack = [path]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_file(follow_symlinks=False):
                                total += entry.stat(follow_symlinks=False).st_size
                            elif entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                        except (FileNotFoundError, PermissionError):
                            continue
            except (FileNotFoundError, PermissionError, NotADirectoryError):
                continue
    except Exception:
        return 0.0
    return round(total / (1024 * 1024), 2)


def sample(proc: psutil.Process, interval: float, start_time: float) -> dict | None:
    try:
        cpu = proc.cpu_percent(interval=interval)
        mem = proc.memory_info()
        rss_mb = round(mem.rss / (1024 * 1024), 2)
        vms_mb = round(mem.vms / (1024 * 1024), 2)

        try:
            mem_pct = round(proc.memory_percent(), 2)
        except (psutil.AccessDenied, AttributeError):
            mem_pct = 0.0

        try:
            uptime_sec = int(time.time() - proc.create_time())
        except (psutil.AccessDenied, AttributeError):
            uptime_sec = 0

        try:
            fds = proc.num_fds()
        except AttributeError:
            fds = getattr(proc, "num_handles", lambda: 0)()

        try:
            threads = proc.num_threads()
        except (psutil.AccessDenied, AttributeError):
            threads = 0

        try:
            io = proc.io_counters()
            read_bytes = io.read_bytes
            write_bytes = io.write_bytes
        except (psutil.AccessDenied, AttributeError):
            read_bytes = write_bytes = 0

        return {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "elapsed_s": round(time.monotonic() - start_time, 1),
            "pid": proc.pid,
            "uptime_sec": uptime_sec,
            "cpu_pct": round(cpu, 2),
            "mem_pct": mem_pct,
            "rss_mb": rss_mb,
            "vms_mb": vms_mb,
            "fds": fds,
            "threads": threads,
            "read_bytes": read_bytes,
            "write_bytes": write_bytes,
        }

    except psutil.NoSuchProcess:
        logger.warning("Process %d no longer exists.", proc.pid)
        return None
    except psutil.AccessDenied as e:
        logger.warning("Access denied reading process %d: %s", proc.pid, e)
        return None


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------
def monitor_loop(proc: psutil.Process, csv_path: str, interval: float) -> None:
    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=BASE_CSV_HEADER)
        if write_header:
            writer.writeheader()
            fh.flush()

        try:
            proc_label = proc.name()
        except psutil.NoSuchProcess:
            logger.warning("Process PID %d vanished before monitoring started.", proc.pid)
            return
        logger.info(
            "Monitoring PID %d (%s) every %.1fs -> %s",
            proc.pid, proc_label, interval, csv_path,
        )

        while _running:
            row = sample(proc, interval, start_time)
            if row is None:
                logger.info("Target process %s (PID %d) exited. Stopping its monitor.",
                            proc_label, proc.pid)
                break
            writer.writerow(row)
            fh.flush()

            logger.info(
                "[%s] cpu=%.1f%%  mem=%.1f%%  rss=%.1fMB  vms=%.1fMB  fds=%d  "
                "threads=%d  up=%ds  r_bytes=%d  w_bytes=%d",
                proc_label,
                row["cpu_pct"], row["mem_pct"], row["rss_mb"], row["vms_mb"],
                row["fds"], row["threads"], row["uptime_sec"],
                row["read_bytes"], row["write_bytes"],
            )

    logger.info("Monitor finished for %s. CSV written to %s", proc_label, csv_path)


def disk_monitor_loop(csv_path: str, interval: float,
                      disk_paths: list[str],
                      stop_event: threading.Event | None = None) -> None:
    """Periodically measure directory sizes and write to a dedicated CSV."""
    header = ["timestamp", "elapsed_s"] + [disk_col_name(p) for p in disk_paths]

    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info("Disk monitor every %.1fs -> %s", interval, csv_path)
        logger.info("Disk paths: %s", ", ".join(disk_paths))

        while _running and not (stop_event and stop_event.is_set()):
            row = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "elapsed_s": round(time.monotonic() - start_time, 1),
            }
            for p in disk_paths:
                row[disk_col_name(p)] = dir_size_mb(p)
            writer.writerow(row)
            fh.flush()

            logger.info(
                "[disk] %s",
                "  ".join(f"{disk_col_name(p)}={row[disk_col_name(p)]:.1f}MB"
                          for p in disk_paths),
            )
            # Sleep in small steps so we react quickly to stop_event.
            deadline = time.monotonic() + interval
            while time.monotonic() < deadline and _running and not (stop_event and stop_event.is_set()):
                time.sleep(min(0.5, deadline - time.monotonic()))

    logger.info("Disk monitor finished. CSV written to %s", csv_path)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly *size* bytes or raise if stream closes early."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(f"Socket closed while reading {size} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _query_remoted_stats(socket_path: str, timeout: float = 2.0) -> dict[str, object]:
    payload = json.dumps(REMOTED_QUERY, separators=(",", ":")).encode("utf-8")
    header = struct.pack("<I", len(payload))

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(socket_path)
        conn.sendall(header + payload)

        resp_size_raw = _recv_exact(conn, 4)
        resp_size = struct.unpack("<I", resp_size_raw)[0]
        if resp_size <= 0 or resp_size > REMOTED_MAX_RESPONSE_SIZE:
            raise ValueError(f"Invalid response size: {resp_size}")

        response = _recv_exact(conn, resp_size)

    data = json.loads(response.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Remoted response is not a JSON object")
    return data


def _empty_remoted_row(timestamp: str, elapsed_s: float) -> dict[str, object]:
    row: dict[str, object] = {k: "" for k in REMOTED_HEADER}
    row["timestamp"] = timestamp
    row["elapsed_s"] = elapsed_s
    return row


def _flatten_remoted_stats(raw: dict[str, object], timestamp: str, elapsed_s: float) -> dict[str, object]:
    row = _empty_remoted_row(timestamp, elapsed_s)
    row["query_ok"] = 1
    row["query_error"] = ""
    row["error"] = _as_int(raw.get("error"))
    row["message"] = str(raw.get("message", ""))

    data = raw.get("data")
    if not isinstance(data, dict):
        return row

    row["data_name"] = str(data.get("name", ""))
    row["data_timestamp"] = _as_int(data.get("timestamp"))
    row["data_uptime"] = _as_int(data.get("uptime"))

    metrics = data.get("metrics")
    if not isinstance(metrics, dict):
        return row

    bytes_data = metrics.get("bytes")
    if isinstance(bytes_data, dict):
        row["metrics_bytes_received"] = _as_int(bytes_data.get("received"))
        row["metrics_bytes_sent"] = _as_int(bytes_data.get("sent"))

    row["metrics_keys_reload_count"] = _as_int(metrics.get("keys_reload_count"))
    row["tcp_sessions"] = _as_int(metrics.get("tcp_sessions"))
    row["control_messages_queue_usage"] = _as_int(metrics.get("control_messages_queue_usage"))

    messages = metrics.get("messages")
    if isinstance(messages, dict):
        recv_breakdown = messages.get("received_breakdown")
        if isinstance(recv_breakdown, dict):
            row["messages_received_breakdown_control"] = _as_int(recv_breakdown.get("control"))
            row["messages_received_breakdown_dequeued_after"] = _as_int(recv_breakdown.get("dequeued_after"))
            row["messages_received_breakdown_discarded"] = _as_int(recv_breakdown.get("discarded"))
            row["messages_received_breakdown_events"] = _as_int(recv_breakdown.get("events"))
            row["messages_received_breakdown_events_failed"] = _as_int(recv_breakdown.get("events_failed"))
            row["messages_received_breakdown_ping"] = _as_int(recv_breakdown.get("ping"))
            row["messages_received_breakdown_states"] = _as_int(recv_breakdown.get("states"))
            row["messages_received_breakdown_unknown"] = _as_int(recv_breakdown.get("unknown"))

            ctrl_breakdown = recv_breakdown.get("control_breakdown")
            if isinstance(ctrl_breakdown, dict):
                row["messages_received_breakdown_control_breakdown_keepalive"] = _as_int(ctrl_breakdown.get("keepalive"))
                row["messages_received_breakdown_control_breakdown_request"] = _as_int(ctrl_breakdown.get("request"))
                row["messages_received_breakdown_control_breakdown_shutdown"] = _as_int(ctrl_breakdown.get("shutdown"))
                row["messages_received_breakdown_control_breakdown_startup"] = _as_int(ctrl_breakdown.get("startup"))

        sent_breakdown = messages.get("sent_breakdown")
        if isinstance(sent_breakdown, dict):
            row["messages_sent_breakdown_ack"] = _as_int(sent_breakdown.get("ack"))
            row["messages_sent_breakdown_ar"] = _as_int(sent_breakdown.get("ar"))
            row["messages_sent_breakdown_discarded"] = _as_int(sent_breakdown.get("discarded"))
            row["messages_sent_breakdown_request"] = _as_int(sent_breakdown.get("request"))
            row["messages_sent_breakdown_shared"] = _as_int(sent_breakdown.get("shared"))

    queues = metrics.get("queues")
    if isinstance(queues, dict):
        received = queues.get("received")
        if isinstance(received, dict):
            row["queues_received_size"] = _as_int(received.get("size"))
            row["queues_received_usage"] = _as_float(received.get("usage"))

    ctrl_queue_breakdown = metrics.get("control_messages_queue_breakdown")
    if isinstance(ctrl_queue_breakdown, dict):
        row["control_messages_queue_breakdown_inserted"] = _as_int(ctrl_queue_breakdown.get("inserted"))
        row["control_messages_queue_breakdown_replaced"] = _as_int(ctrl_queue_breakdown.get("replaced"))
        row["control_messages_queue_breakdown_processed"] = _as_int(ctrl_queue_breakdown.get("processed"))

    row["raw_response_json"] = json.dumps(raw, separators=(",", ":"), ensure_ascii=True)
    return row


def remoted_api_monitor_loop(csv_path: str, interval: float, socket_path: str,
                             stop_event: threading.Event | None = None) -> None:
    """Poll remoted getstats over framed unix socket and write per-second CSV."""
    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=REMOTED_HEADER)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info("Remoted API monitor every %.1fs -> %s", interval, csv_path)
        logger.info("Remoted API socket: %s", socket_path)

        while _running and not (stop_event and stop_event.is_set()):
            ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            elapsed_s = round(time.monotonic() - start_time, 1)

            try:
                raw = _query_remoted_stats(socket_path)
                row = _flatten_remoted_stats(raw, ts_now, elapsed_s)
                logger.info(
                    "[remoted-api] usage=%.3f recv_discarded=%d recv_events=%d recv_states=%d sent_discarded=%d tcp_sessions=%d",
                    _as_float(row.get("queues_received_usage")),
                    _as_int(row.get("messages_received_breakdown_discarded")),
                    _as_int(row.get("messages_received_breakdown_events")),
                    _as_int(row.get("messages_received_breakdown_states")),
                    _as_int(row.get("messages_sent_breakdown_discarded")),
                    _as_int(row.get("tcp_sessions")),
                )
            except Exception as exc:
                row = _empty_remoted_row(ts_now, elapsed_s)
                row["query_ok"] = 0
                row["query_error"] = str(exc)
                logger.warning("Remoted API poll failed: %s", exc)

            writer.writerow(row)
            fh.flush()

            deadline = time.monotonic() + interval
            while time.monotonic() < deadline and _running and not (stop_event and stop_event.is_set()):
                time.sleep(min(0.5, deadline - time.monotonic()))

    logger.info("Remoted API monitor finished. CSV written to %s", csv_path)


# ---------------------------------------------------------------------------
# Analysisd HTTP API monitor
# ---------------------------------------------------------------------------
class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that routes traffic through a Unix domain socket."""

    def __init__(self, socket_path: str, timeout: float = 5.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def _query_analysisd_stats(socket_path: str, timeout: float = 5.0) -> dict[str, object]:
    """POST /metrics/dump over the analysisd HTTP Unix socket."""
    conn = _UnixSocketHTTPConnection(socket_path, timeout=timeout)
    try:
        body = b"{}"
        conn.request(
            "POST", "/metrics/dump",
            body=body,
            headers={"Content-Type": "text/plain", "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        raw_bytes = resp.read(ANALYSISD_MAX_RESPONSE_SIZE)
    finally:
        conn.close()

    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Analysisd response is not a JSON object")
    return data


def _empty_analysisd_row(timestamp: str, elapsed_s: float) -> dict[str, object]:
    row: dict[str, object] = {k: "" for k in ANALYSISD_HEADER}
    row["timestamp"] = timestamp
    row["elapsed_s"] = elapsed_s
    return row


def _flatten_analysisd_stats(raw: dict[str, object], timestamp: str, elapsed_s: float) -> dict[str, object]:
    row = _empty_analysisd_row(timestamp, elapsed_s)
    row["query_ok"] = 1
    row["query_error"] = ""

    # Index global metrics by name for O(1) access.
    global_metrics: dict[str, object] = {}
    for item in raw.get("global") or []:
        if isinstance(item, dict) and "name" in item:
            global_metrics[item["name"]] = item.get("value")

    row["server_events_received"]     = _as_int(global_metrics.get("server.events.received"))
    row["router_queue_size"]          = _as_int(global_metrics.get("router.queue.size"))
    row["router_queue_usage_percent"] = _as_float(global_metrics.get("router.queue.usage.percent"))
    row["router_queue_bytes_used"]           = _as_int(global_metrics.get("router.queue.bytes.used"))
    row["router_queue_bytes_usage_percent"]  = _as_float(global_metrics.get("router.queue.bytes.usage.percent"))
    row["router_events_processed"]    = _as_int(global_metrics.get("router.events.processed"))
    row["router_events_dropped"]      = _as_int(global_metrics.get("router.events.dropped"))
    row["indexer_queue_size"]         = _as_int(global_metrics.get("indexer.queue.size"))
    row["indexer_queue_usage_percent"] = _as_float(global_metrics.get("indexer.queue.usage.percent"))
    row["indexer_events_dropped"]     = _as_int(global_metrics.get("indexer.events.dropped"))
    row["router_eps_1m"]              = _as_float(global_metrics.get("router.eps.1m"))

    # Agent metadata cache (entries is an instantaneous gauge; the rest are cumulative counters).
    row["agent_cache_entries"]        = _as_int(global_metrics.get("agent.cache.entries"))
    row["agent_cache_hits"]           = _as_int(global_metrics.get("agent.cache.hits"))
    row["agent_cache_insertions"]     = _as_int(global_metrics.get("agent.cache.insertions"))
    row["agent_cache_updates"]        = _as_int(global_metrics.get("agent.cache.updates"))
    row["agent_cache_evictions"]      = _as_int(global_metrics.get("agent.cache.evictions"))

    # Walk spaces to find the "standard" space and extract events.unclassified.
    for space in raw.get("spaces") or []:
        if not isinstance(space, dict) or space.get("name") != "standard":
            continue
        for metric in space.get("metrics") or []:
            if isinstance(metric, dict) and metric.get("name") == "events.unclassified":
                row["spaces_standard_events_unclassified"] = _as_int(metric.get("value"))
                break

    row["raw_response_json"] = json.dumps(raw, separators=(",", ":"), ensure_ascii=True)
    return row


def analysisd_api_monitor_loop(csv_path: str, interval: float, socket_path: str,
                               stop_event: threading.Event | None = None) -> None:
    """Poll analysisd /metrics/dump over HTTP Unix socket and write per-second CSV."""
    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=ANALYSISD_HEADER)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info("Analysisd API monitor every %.1fs -> %s", interval, csv_path)
        logger.info("Analysisd API socket: %s", socket_path)

        while _running and not (stop_event and stop_event.is_set()):
            ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            elapsed_s = round(time.monotonic() - start_time, 1)

            try:
                raw = _query_analysisd_stats(socket_path)
                row = _flatten_analysisd_stats(raw, ts_now, elapsed_s)
                logger.info(
                    "[analysisd-api] events_received=%d router_q=%d router_q_pct=%.1f "
                    "indexer_q=%d indexer_q_pct=%.1f indexer_dropped=%d unclassified=%d "
                    "cache_entries=%d cache_hits=%d cache_ins=%d cache_upd=%d cache_evict=%d",
                    _as_int(row.get("server_events_received")),
                    _as_int(row.get("router_queue_size")),
                    _as_float(row.get("router_queue_usage_percent")),
                    _as_int(row.get("indexer_queue_size")),
                    _as_float(row.get("indexer_queue_usage_percent")),
                    _as_int(row.get("indexer_events_dropped")),
                    _as_int(row.get("spaces_standard_events_unclassified")),
                    _as_int(row.get("agent_cache_entries")),
                    _as_int(row.get("agent_cache_hits")),
                    _as_int(row.get("agent_cache_insertions")),
                    _as_int(row.get("agent_cache_updates")),
                    _as_int(row.get("agent_cache_evictions")),
                )
            except Exception as exc:
                row = _empty_analysisd_row(ts_now, elapsed_s)
                row["query_ok"] = 0
                row["query_error"] = str(exc)
                logger.warning("Analysisd API poll failed: %s", exc)

            writer.writerow(row)
            fh.flush()

            deadline = time.monotonic() + interval
            while time.monotonic() < deadline and _running and not (stop_event and stop_event.is_set()):
                time.sleep(min(0.5, deadline - time.monotonic()))

    logger.info("Analysisd API monitor finished. CSV written to %s", csv_path)


# ---------------------------------------------------------------------------
# inventory_sync_server metrics monitor
# ---------------------------------------------------------------------------
def _query_invsync_stats(socket_path: str, timeout: float = 5.0) -> dict[str, object]:
    """GET /metrics over the module's HTTP-over-UDS socket."""
    conn = _UnixSocketHTTPConnection(socket_path, timeout=timeout)
    try:
        conn.request("GET", "/metrics", headers={"Host": "localhost"})
        resp = conn.getresponse()
        raw_bytes = resp.read(INVSYNC_MAX_RESPONSE_SIZE)
        if resp.status != 200:
            raise ValueError(f"/metrics answered {resp.status}: {raw_bytes[:200]!r}")
    finally:
        conn.close()

    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("inventory_sync_server response is not a JSON object")
    return data


def _empty_invsync_row(timestamp: str, elapsed_s: float) -> dict[str, object]:
    row: dict[str, object] = {k: "" for k in INVSYNC_HEADER}
    row["timestamp"] = timestamp
    row["elapsed_s"] = elapsed_s
    return row


def _flatten_invsync_stats(raw: dict[str, object], timestamp: str,
                           elapsed_s: float) -> dict[str, object]:
    """Map the metrics dump onto the flat CSV row.

    The dump is a list of {name, type, value, summary?} objects; a histogram
    carries its distribution in "summary" and only its observation count in
    "value" (see wazuh::metrics::dumpJson).
    """
    row = _empty_invsync_row(timestamp, elapsed_s)
    row["query_ok"] = 1
    row["query_error"] = ""

    by_name: dict[str, dict] = {}
    for item in raw.get("metrics") or []:
        if isinstance(item, dict) and "name" in item:
            by_name[item["name"]] = item

    for metric_name, column in _INVSYNC_SCALARS:
        item = by_name.get(metric_name)
        row[column] = _as_int(item.get("value")) if item else 0

    # Per-shard gauges: aggregate, since how many there are follows the
    # configured worker count and must not leak into the header.
    depths: list[int] = []
    sizes: list[int] = []
    for name, item in by_name.items():
        if not name.startswith("sync.shard."):
            continue
        if name.endswith(".depth"):
            depths.append(_as_int(item.get("value")))
        elif name.endswith(".bytes"):
            sizes.append(_as_int(item.get("value")))
    row["shard_count"] = len(depths)
    row["shard_depth_max"] = max(depths) if depths else 0
    row["shard_depth_sum"] = sum(depths)
    row["shard_bytes_max"] = max(sizes) if sizes else 0
    row["shard_bytes_sum"] = sum(sizes)

    for metric_name, prefix in _INVSYNC_HISTOGRAMS:
        summary = (by_name.get(metric_name) or {}).get("summary")
        for field in _INVSYNC_HIST_FIELDS:
            value = summary.get(field) if isinstance(summary, dict) else None
            row[f"{prefix}_{field}"] = _as_int(value)

    row["raw_response_json"] = json.dumps(raw, separators=(",", ":"), ensure_ascii=True)
    return row


def invsync_api_monitor_loop(csv_path: str, interval: float, socket_path: str,
                             stop_event: threading.Event | None = None) -> None:
    """Poll inventory_sync_server's GET /metrics and write per-second CSV."""
    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=INVSYNC_HEADER)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info("Inventory sync API monitor every %.1fs -> %s", interval, csv_path)
        logger.info("Inventory sync API socket: %s", socket_path)

        while _running and not (stop_event and stop_event.is_set()):
            ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            elapsed_s = round(time.monotonic() - start_time, 1)

            try:
                raw = _query_invsync_stats(socket_path)
                row = _flatten_invsync_stats(raw, ts_now, elapsed_s)
                logger.info(
                    "[invsync-api] 200=%d 503=%d 500=%d docs=%d shed=%d "
                    "shard_depth(max/sum)=%d/%d vd_lane=%d vd_503=%d "
                    "session_p99=%dus vd_lane_p99=%dus",
                    _as_int(row.get("requests_200")),
                    _as_int(row.get("requests_503")),
                    _as_int(row.get("requests_500")),
                    _as_int(row.get("docs_indexed")),
                    _as_int(row.get("pipeline_shed_total")),
                    _as_int(row.get("shard_depth_max")),
                    _as_int(row.get("shard_depth_sum")),
                    _as_int(row.get("vd_lane_depth")),
                    _as_int(row.get("vd_capacity_503_total")),
                    _as_int(row.get("session_duration_bulk_p99")),
                    _as_int(row.get("vd_lane_time_p99")),
                )
            except Exception as exc:
                row = _empty_invsync_row(ts_now, elapsed_s)
                row["query_ok"] = 0
                row["query_error"] = str(exc)
                logger.warning("Inventory sync API poll failed: %s", exc)

            writer.writerow(row)
            fh.flush()

            deadline = time.monotonic() + interval
            while time.monotonic() < deadline and _running and not (stop_event and stop_event.is_set()):
                time.sleep(min(0.5, deadline - time.monotonic()))

    logger.info("Inventory sync API monitor finished. CSV written to %s", csv_path)

# Friendly CSV filename overrides for processes whose basename is generic.
# e.g. wazuh-indexer runs as "java" - we want wazuh-indexer.csv instead.
_EXE_CSV_ALIAS: dict[str, str] = {
    INDEXER_EXECUTABLE: "wazuh-indexer",
    INDEXER_ENGINE_EXECUTABLE: "wazuh-indexer-engine",
    DASHBOARD_EXECUTABLE: "wazuh-dashboard",
    DASHBOARD_NODE_EXECUTABLE: "wazuh-dashboard",
}

OPTIONAL_PROCESS_TARGETS = [
    process_target_from_exe(
        INDEXER_EXECUTABLE,
        csv_name="wazuh-indexer",
        display_name="wazuh-indexer",
    ),
    process_target_from_exe(
        INDEXER_ENGINE_EXECUTABLE,
        csv_name="wazuh-indexer-engine",
        display_name="wazuh-indexer-engine",
    ),
    ProcessTarget(
        key=DASHBOARD_EXECUTABLE,
        exe_paths=(DASHBOARD_EXECUTABLE, DASHBOARD_NODE_EXECUTABLE),
        cmdline_markers=(
            DASHBOARD_EXECUTABLE,
            "/usr/share/wazuh-dashboard/src/cli",
            "/usr/share/wazuh-dashboard",
        ),
        require_cmdline_marker=True,
        csv_name="wazuh-dashboard",
        display_name="wazuh-dashboard",
    ),
]


def monitor_multi(processes: dict[ProcessTarget, psutil.Process], output_dir: str,
                  interval: float, disk_paths: list[str]) -> None:
    """Spawn the process, disk and per-daemon API monitoring threads."""
    os.makedirs(output_dir, exist_ok=True)
    logger.info("Output directory: %s", output_dir)

    proc_threads: list[threading.Thread] = []
    disk_stop = threading.Event()
    remoted_stop = threading.Event()
    analysisd_stop = threading.Event()
    invsync_stop = threading.Event()

    # Per-process resource threads
    for target, proc in processes.items():
        basename = (
            target.csv_name
            or _EXE_CSV_ALIAS.get(target.key, os.path.basename(target.key))
        )
        csv_path = os.path.join(output_dir, f"{basename}.csv")
        t = threading.Thread(
            target=monitor_loop,
            args=(proc, csv_path, interval),
            name=f"mon-{basename}",
            daemon=True,
        )
        proc_threads.append(t)

    # Disk-usage thread (single, independent of processes)
    disk_thread: threading.Thread | None = None
    if disk_paths:
        disk_csv = os.path.join(output_dir, "disk_usage.csv")
        disk_thread = threading.Thread(
            target=disk_monitor_loop,
            args=(disk_csv, interval, disk_paths, disk_stop),
            name="mon-disk",
            daemon=True,
        )

    remoted_csv = os.path.join(output_dir, REMOTED_STATS_CSV)
    remoted_thread = threading.Thread(
        target=remoted_api_monitor_loop,
        args=(remoted_csv, interval, DEFAULT_REMOTED_SOCKET, remoted_stop),
        name="mon-remoted-api",
        daemon=True,
    )

    analysisd_csv = os.path.join(output_dir, ANALYSISD_STATS_CSV)
    analysisd_thread = threading.Thread(
        target=analysisd_api_monitor_loop,
        args=(analysisd_csv, interval, DEFAULT_ANALYSISD_SOCKET, analysisd_stop),
        name="mon-analysisd-api",
        daemon=True,
    )

    invsync_csv = os.path.join(output_dir, INVSYNC_STATS_CSV)
    invsync_thread = threading.Thread(
        target=invsync_api_monitor_loop,
        args=(invsync_csv, interval, DEFAULT_INVSYNC_SOCKET, invsync_stop),
        name="mon-invsync-api",
        daemon=True,
    )

    for t in proc_threads:
        t.start()
    if disk_thread:
        disk_thread.start()
    remoted_thread.start()
    analysisd_thread.start()
    invsync_thread.start()

    # Wait for all process threads to finish.
    while _running and any(t.is_alive() for t in proc_threads):
        for t in proc_threads:
            t.join(timeout=1.0)

    # All process monitors done — stop independent monitors.
    disk_stop.set()
    remoted_stop.set()
    analysisd_stop.set()
    invsync_stop.set()
    if disk_thread and disk_thread.is_alive():
        disk_thread.join(timeout=5.0)
    if remoted_thread.is_alive():
        remoted_thread.join(timeout=5.0)
    if analysisd_thread.is_alive():
        analysisd_thread.join(timeout=5.0)
    if invsync_thread.is_alive():
        invsync_thread.join(timeout=5.0)

    logger.info("All monitoring threads finished. Results in %s", output_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor Wazuh manager process resource usage during benchmarks.",
    )
    # --- multi-process mode (default) ---
    p.add_argument(
        "--exe",
        action="append",
        default=None,
        metavar="PATH",
        help="Executable path to monitor. Repeat for multiple. "
             "If omitted, monitors all default Wazuh manager processes.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for all target processes to appear (default: 30)",
    )

    # --- legacy single-process mode ---
    legacy = p.add_argument_group("legacy single-process mode")
    legacy.add_argument("-p", "--pid", type=int, help="PID of a single process to monitor")
    legacy.add_argument("-n", "--name", type=str, help="Process name to monitor (single)")
    legacy.add_argument("-o", "--output", type=str, default=None,
                        help="Output CSV path (only for legacy single-process mode)")

    # --- common ---
    p.add_argument("-s", "--interval", type=float, default=1.0, help="Sample interval (s)")
    p.add_argument("--pidfile", type=str, default="monitor.pid", help="PID file path")
    p.add_argument(
        "--disk-path",
        action="append",
        default=None,
        metavar="PATH",
        help="Recursive directory size to track. Repeat to track multiple. "
             "Each path adds a 'dir_<basename>_mb' column to the CSV. "
             "If omitted, uses default Wazuh paths.",
    )
    p.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for multi-process mode. "
             "Defaults to ./result_<timestamp>.",
    )
    p.add_argument(
        "--log-path",
        type=str,
        default=WAZUH_LOG_PATH,
        help="Manager log path used for the final log-event extraction "
             f"(default: {WAZUH_LOG_PATH})",
    )
    p.add_argument("-d", "--debug", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    write_pid_file(args.pidfile)

    disk_paths = args.disk_path if args.disk_path is not None else DEFAULT_DISK_PATHS

    # Legacy single-process mode
    if args.pid is not None or args.name is not None:
        if args.output is None:
            logger.critical("Legacy mode requires -o/--output.")
            sys.exit(1)
        proc = find_process(args.pid, args.name)
        monitor_loop(proc, args.output, args.interval)
        return

    # Multi-process mode (default)
    exe_list = args.exe if args.exe is not None else DEFAULT_EXECUTABLES
    targets = [process_target_from_exe(exe) for exe in exe_list]

    # Probe for all-in-one companion processes. Add them only when they are
    # actually running so the monitor works unchanged on manager-only hosts.
    if args.exe is None:
        for optional_target in OPTIONAL_PROCESS_TARGETS:
            optional_proc = find_process_by_target(optional_target)
            if optional_proc is not None:
                logger.info("%s detected (PID %d) - adding to monitored set",
                            optional_target.name, optional_proc.pid)
                targets.append(optional_target)
            else:
                logger.info("%s not found - skipping", optional_target.name)

    processes = wait_for_processes(targets, timeout=args.timeout)

    output_dir = args.output_dir
    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(".", f"result_{ts}")

    monitor_start_time = datetime.now()
    monitor_multi(processes, output_dir, args.interval, disk_paths)

    # Post-processing: count the manager-log events that have no metric.
    extract_manager_log_events(output_dir, log_path=args.log_path, start_time=monitor_start_time)


# ---------------------------------------------------------------------------
# Manager log event counting
# ---------------------------------------------------------------------------
# Everything the retired inventory_sync module used to log ("InventorySync queue
# stats:", session stats, the RocksDB gauges) is gone: that module is no longer
# built or registered, so those lines can never appear again. What remains here
# counts what the CURRENT modules actually emit, and exists mainly for one gap:
# the UDS transport's accept/parse/timeout failures have no metric counterpart,
# so a log line is the only way to see them. Everything else below has a metric
# in GET /metrics too, and is counted here only because a spike is easier to
# spot against the same timeline as the rest of logs.csv.
WAZUH_LOG_PATH = "/var/wazuh-manager/logs/wazuh-manager.log"

# Rejections are logged THROTTLED, carrying their own count for the window:
#   "Rejected 1234 request(s) with 503 in the last 90 s: ..."
# Counting occurrences would undercount by orders of magnitude, so these
# patterns capture the number and the counter sums it instead.
_THROTTLED_EVENTS: dict[str, re.Pattern] = {
    "session_rejected_403": re.compile(
        r"Rejected (\d+) request\(s\) with 403 .*identity does not match"),
    "vd_lane_full_503": re.compile(
        r"Rejected (\d+) .*with 503 .*scan lane queue is full"),
    "indexer_unhealthy_503": re.compile(
        r"Rejected (\d+) session\(s\) with 503 .*no configured indexer host is currently healthy"),
    "pipeline_full_503": re.compile(
        r"Rejected (\d+) session\(s\) with 503 .*sync pipeline queue is full"),
}

# One line, one occurrence.
_EVENT_PATTERNS: dict[str, re.Pattern] = {
    "bulk_flush_failed":   re.compile(r"A bulk flush of \d+ session\(s\) failed"),
    "scan_failed":         re.compile(r"The vulnerability scan for agent .* failed"),
    "indexer_unreachable": re.compile(r"No configured indexer host is currently reachable"),
    # The observability gap: transport errors have no metric, only this.
    "transport_error":     re.compile(
        r"inventory-sync-server:server.*(ERROR|WARNING)", re.IGNORECASE),
}

_COUNTER_NAMES: tuple[str, ...] = tuple(_THROTTLED_EVENTS) + tuple(_EVENT_PATTERNS)
_LOGS_CSV_HEADER = ["timestamp", "elapsed_s"] + list(_COUNTER_NAMES)

_RE_LOG_TIMESTAMP = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
_LOG_TS_FMT = "%Y/%m/%d %H:%M:%S"


def extract_manager_log_events(output_dir: str,
                               log_path: str = WAZUH_LOG_PATH,
                               start_time: datetime | None = None) -> None:
    """Parse wazuh-manager.log into ``logs.csv``: per-second event counters.

    Only lines at or after *start_time* are counted, so a previous run's noise
    is not mixed in. Throttled rejection lines contribute the count they carry
    rather than 1, which is the difference between reading "4 rejections" and
    the 40 000 they actually represent.
    """
    if not os.path.isfile(log_path):
        logger.info("Log file %s not found — skipping log extraction.", log_path)
        return

    # elapsed second -> {counter: total}
    buckets: dict[int, dict[str, int]] = {}

    def bump(second: int, name: str, amount: int) -> None:
        bucket = buckets.setdefault(second, {k: 0 for k in _COUNTER_NAMES})
        bucket[name] += amount

    logger.info("Extracting manager log events from %s (since %s) ...",
                log_path,
                start_time.strftime(_LOG_TS_FMT) if start_time else "beginning")

    with open(log_path, "r", errors="replace") as fh:
        for line in fh:
            ts_match = _RE_LOG_TIMESTAMP.match(line)
            if not ts_match:
                continue
            try:
                line_dt = datetime.strptime(ts_match.group(1), _LOG_TS_FMT)
            except ValueError:
                continue
            if start_time and line_dt < start_time:
                continue

            elapsed_s = int((line_dt - start_time).total_seconds()) if start_time else 0

            for name, regex in _THROTTLED_EVENTS.items():
                m = regex.search(line)
                if m:
                    bump(elapsed_s, name, _as_int(m.group(1), 1))

            for name, regex in _EVENT_PATTERNS.items():
                if regex.search(line):
                    bump(elapsed_s, name, 1)

    if not buckets:
        logger.info("No matching log events found — logs.csv not written.")
        return

    max_sec = max(buckets)
    rows: list[dict[str, object]] = []
    for sec in range(0, max_sec + 1):
        counters = buckets.get(sec, {})
        row: dict[str, object] = {
            "timestamp": (start_time + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
            if start_time else "",
            "elapsed_s": sec,
        }
        for name in _COUNTER_NAMES:
            row[name] = counters.get(name, 0)
        rows.append(row)

    logs_path = os.path.join(output_dir, "logs.csv")
    with open(logs_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_LOGS_CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Wrote %d rows -> %s", len(rows), logs_path)


if __name__ == "__main__":
    main()
