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

DEFAULT_DISK_PATHS = [
    "/var/wazuh-manager/queue/inventory_sync",
    "/var/wazuh-manager/queue/engine-output",
    "/var/wazuh-manager/queue/vd",
    "/var/wazuh-manager/",
]

DEFAULT_REMOTED_SOCKET = "/var/wazuh-manager/queue/sockets/remote"
REMOTED_STATS_CSV = "stats-api-remoted.csv"
REMOTED_QUERY = {"command": "getstats"}
REMOTED_MAX_RESPONSE_SIZE = 4 * 1024 * 1024

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
    "router_events_processed",
    "router_events_dropped",
    "indexer_queue_usage_percent",
    "indexer_queue_size",
    "indexer_events_dropped",
    "router_eps_1m",
    "spaces_standard_events_unclassified",
    "raw_response_json",
]

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


def find_process_by_exe(exe_path: str) -> psutil.Process | None:
    """Find a process whose executable or any cmdline argument matches *exe_path*.

    Matches both native binaries (exe == path) and Python scripts where the
    script path appears as cmdline[1] (e.g. python3 /path/to/script.py).

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
            if proc.info["exe"] == exe_path:
                exe_matches.append(proc)
                continue
            cmdline = proc.info.get("cmdline") or []
            if exe_path in cmdline:
                cmdline_matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    candidates = exe_matches if exe_matches else cmdline_matches
    if not candidates:
        return None

    candidates.sort(key=lambda p: (-p.create_time(), p.pid))
    chosen = candidates[0]

    # Warn loudly if there are leftover processes from a previous generation —
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
            os.path.basename(exe_path), chosen.pid,
            time.ctime(chosen.create_time()), others,
            os.path.basename(exe_path),
        )

    return chosen


def wait_for_processes(exe_paths: list[str], timeout: float = 30.0) -> dict[str, psutil.Process]:
    """Wait until every executable in *exe_paths* is running.

    Returns a dict mapping exe_path -> psutil.Process.
    Raises SystemExit if timeout expires before all processes appear.
    """
    remaining = set(exe_paths)
    found: dict[str, psutil.Process] = {}
    deadline = time.monotonic() + timeout

    logger.info("Waiting for %d processes (timeout=%ds)...", len(remaining), int(timeout))
    while remaining and time.monotonic() < deadline and _running:
        for exe in list(remaining):
            proc = find_process_by_exe(exe)
            if proc is not None:
                logger.info("  Found %s -> PID %d", os.path.basename(exe), proc.pid)
                found[exe] = proc
                remaining.discard(exe)
        if remaining:
            time.sleep(1)

    if remaining:
        logger.critical(
            "Timeout: the following processes were NOT found after %ds: %s",
            int(timeout), ", ".join(os.path.basename(e) for e in sorted(remaining)),
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

    Example: /var/wazuh-manager/queue/inventory_sync/  ->  dir_inventory_sync_mb
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
    row["router_events_processed"]    = _as_int(global_metrics.get("router.events.processed"))
    row["router_events_dropped"]      = _as_int(global_metrics.get("router.events.dropped"))
    row["indexer_queue_usage_percent"] = _as_float(global_metrics.get("indexer.queue.usage.percent"))
    row["indexer_queue_size"]         = _as_int(global_metrics.get("indexer.queue.size"))
    row["indexer_events_dropped"]     = _as_int(global_metrics.get("indexer.events.dropped"))
    row["router_eps_1m"]              = _as_float(global_metrics.get("router.eps.1m"))

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
                    "indexer_q=%d indexer_q_pct=%.1f indexer_dropped=%d unclassified=%d",
                    _as_int(row.get("server_events_received")),
                    _as_int(row.get("router_queue_size")),
                    _as_float(row.get("router_queue_usage_percent")),
                    _as_int(row.get("indexer_queue_size")),
                    _as_float(row.get("indexer_queue_usage_percent")),
                    _as_int(row.get("indexer_events_dropped")),
                    _as_int(row.get("spaces_standard_events_unclassified")),
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


# Friendly CSV filename overrides for processes whose basename is generic.
# e.g. wazuh-indexer runs as "java" — we want wazuh-indexer.csv instead.
_EXE_CSV_ALIAS: dict[str, str] = {
    INDEXER_EXECUTABLE: "wazuh-indexer",
}


def monitor_multi(processes: dict[str, psutil.Process], output_dir: str,
                  interval: float, disk_paths: list[str]) -> None:
    """Spawn process, disk and remoted API monitoring threads."""
    os.makedirs(output_dir, exist_ok=True)
    logger.info("Output directory: %s", output_dir)

    proc_threads: list[threading.Thread] = []
    disk_stop = threading.Event()
    remoted_stop = threading.Event()
    analysisd_stop = threading.Event()

    # Per-process resource threads
    for exe_path, proc in processes.items():
        basename = _EXE_CSV_ALIAS.get(exe_path, os.path.basename(exe_path))
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

    for t in proc_threads:
        t.start()
    if disk_thread:
        disk_thread.start()
    remoted_thread.start()
    analysisd_thread.start()

    # Wait for all process threads to finish.
    while _running and any(t.is_alive() for t in proc_threads):
        for t in proc_threads:
            t.join(timeout=1.0)

    # All process monitors done — stop independent monitors.
    disk_stop.set()
    remoted_stop.set()
    analysisd_stop.set()
    if disk_thread and disk_thread.is_alive():
        disk_thread.join(timeout=5.0)
    if remoted_thread.is_alive():
        remoted_thread.join(timeout=5.0)
    if analysisd_thread.is_alive():
        analysisd_thread.join(timeout=5.0)

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
        help="Manager log path used for final InventorySync log extraction "
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

    # Probe for wazuh-indexer (all-in-one only) — add it only when it is
    # actually running so the monitor works unchanged on manager-only hosts.
    if args.exe is None:
        indexer_proc = find_process_by_exe(INDEXER_EXECUTABLE)
        if indexer_proc is not None:
            logger.info("wazuh-indexer detected (PID %d) — adding to monitored set",
                        indexer_proc.pid)
            exe_list = list(exe_list) + [INDEXER_EXECUTABLE]
        else:
            logger.info("wazuh-indexer not found — skipping (manager-only host)")

    processes = wait_for_processes(exe_list, timeout=args.timeout)

    output_dir = args.output_dir
    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(".", f"result_{ts}")

    monitor_start_time = datetime.now()
    monitor_multi(processes, output_dir, args.interval, disk_paths)

    # Post-processing: extract InventorySync stats from wazuh-manager.log
    extract_invsync_logs(output_dir, log_path=args.log_path, start_time=monitor_start_time)


# ---------------------------------------------------------------------------
# InventorySync log extraction & event counting
# ---------------------------------------------------------------------------
WAZUH_LOG_PATH = "/var/wazuh-manager/logs/wazuh-manager.log"

_RE_QUEUE_STATS = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) .+InventorySync queue stats: (.+)$"
)
_RE_SESSION_STATS = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) .+InventorySync session stats: (.+)$"
)

# Event counter patterns — matches error/warning events in the manager log.
# Each match increments a per-second counter in logs.csv.
_EVENT_PATTERNS: dict[str, re.Pattern] = {
    "session_limit_reached":        re.compile(r"Session limit reached \(\d+/\d+ active sessions\)"),
    "data_value_quota_exhausted":   re.compile(r"DataValue quota exhausted"),
    "zombie_cleaned":               re.compile(r"Cleaning up zombie session \d+ for agent"),
    "session_timeout":              re.compile(r"Session \d+ has timed out"),
    "vdsync_timeout":               re.compile(r"Feed update scan timeout waiting for VDSync"),
    "parse_error":                  re.compile(r"Failed to parse JSON message"),
    "module_check_failed":          re.compile(r"ModuleCheck failed"),
    "inventory_sync_error":         re.compile(r"InventorySyncFacade::start: (?!(Session not found|DataValue quota exhausted))"),
    "indexer_error":                re.compile(r"(indexer.*error|Indexer.*error|indexer.*offline|indexer.*not available)",
                                        re.IGNORECASE),
}

# Gauge metrics captured from "InventorySync queue stats:" lines.
_GAUGE_PATTERN = re.compile(
    r"InventorySync queue stats:\s+"
    r"workers_q=(?P<workers_q>\d+)\s+"
    r"indexer_q=(?P<indexer_q>\d+)\s+"
    r"sessions=(?P<sessions>\d+)\s+"
    r"blocked_agents=(?P<blocked_agents>\d+)\s+"
    r"active_vdfirst=(?P<active_vdfirst>\d+)\s+"
    r"indexer_bulk_bytes=(?P<indexer_bulk_bytes>\d+|\?)\s+"
    r"indexer_notify=(?P<indexer_notify>\d+|\?)\s+"
    r"indexer_delbyq=(?P<indexer_delbyq>\d+|\?)\s+"
    r"rocksdb_dir_bytes=(?P<rocksdb_dir_bytes>\d+)"
    r"(?:\s+workers_q_limit=(?P<workers_q_limit>\d+)"
    r"\s+workers_q_used_pct=(?P<workers_q_used_pct>\d+(?:\.\d+)?)"
    r"\s+session_limit=(?P<session_limit>\d+)"
    r"\s+session_used_pct=(?P<session_used_pct>\d+(?:\.\d+)?)"
    r"\s+data_value_quota_total=(?P<data_value_quota_total>\d+)"
    r"\s+data_value_quota_remaining=(?P<data_value_quota_remaining>\d+)"
    r"\s+data_value_quota_reserved=(?P<data_value_quota_reserved>\d+)"
    r"\s+data_value_quota_used_pct=(?P<data_value_quota_used_pct>\d+(?:\.\d+)?)"
    r"\s+data_value_quota_rejections=(?P<data_value_quota_rejections>\d+))?"
)

_GAUGE_NAMES: tuple[str, ...] = (
    "workers_q", "indexer_q", "sessions", "blocked_agents", "active_vdfirst",
    "indexer_bulk_bytes", "indexer_notify", "indexer_delbyq", "rocksdb_dir_bytes",
    "workers_q_limit", "workers_q_used_pct", "session_limit", "session_used_pct",
    "data_value_quota_total", "data_value_quota_remaining", "data_value_quota_reserved",
    "data_value_quota_used_pct", "data_value_quota_rejections",
)

_LOGS_CSV_HEADER = (
    ["timestamp", "elapsed_s"]
    + list(_EVENT_PATTERNS.keys())
    + list(_GAUGE_NAMES)
)

_RE_LOG_TIMESTAMP = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
_LOG_TS_FMT = "%Y/%m/%d %H:%M:%S"


def _parse_gauge_number(value: str | None) -> int | float | None:
    if value in (None, "", "?"):
        return None
    return float(value) if "." in value else int(value)


def _parse_flat_kv(text: str) -> dict[str, str]:
    """Parse 'key=value key2=value2 key3={a=1 b=2}' into a flat dict.

    Nested braces like  raw_bytes={total=587568 avg=693 max=744 min_nonzero=672}
    are flattened as   raw_bytes_total=587568  raw_bytes_avg=693  ...
    """
    result: dict[str, str] = {}
    i = 0
    while i < len(text):
        # skip whitespace
        while i < len(text) and text[i] == " ":
            i += 1
        if i >= len(text):
            break
        # read key
        eq = text.index("=", i)
        key = text[i:eq]
        i = eq + 1
        if i < len(text) and text[i] == "{":
            # nested block
            close = text.index("}", i)
            inner = text[i + 1:close]
            for sub_kv in inner.split():
                sk, sv = sub_kv.split("=", 1)
                result[f"{key}_{sk}"] = sv
            i = close + 1
        else:
            # simple value — runs until next space or end
            end = text.find(" ", i)
            if end == -1:
                end = len(text)
            result[key] = text[i:end]
            i = end
    return result


def extract_invsync_logs(output_dir: str,
                         log_path: str = WAZUH_LOG_PATH,
                         start_time: datetime | None = None) -> None:
    """Parse wazuh-manager.log and produce three CSV outputs:

    1. ``logs.csv`` — per-second event counters + gauge values (replaces
       the former standalone log_parser.py).
    2. ``invsync_queue_stats.csv`` — one row per raw queue-stats log line.
    3. ``invsync_session_stats.csv`` — one row per session-stats log line.

    Only log lines with a timestamp >= *start_time* are included so that
    data from previous runs is not mixed in.
    """
    if not os.path.isfile(log_path):
        logger.info("Log file %s not found — skipping log extraction.", log_path)
        return

    queue_rows: list[dict[str, str]] = []
    session_rows: list[dict[str, str]] = []

    # For logs.csv: bucket events and gauges into 1-second intervals.
    # Key = integer elapsed second, value = {counter_name: count, ...}
    buckets: dict[int, dict[str, int]] = {}
    # Gauge values carry forward — last seen value persists until updated.
    gauges: dict[str, int | float] = {}
    # Track per-bucket gauge snapshots separately so carry-forward works.
    bucket_gauges: dict[int, dict[str, int | float]] = {}

    logger.info("Extracting InventorySync logs from %s (since %s) ...",
                log_path,
                start_time.strftime(_LOG_TS_FMT) if start_time else "beginning")

    with open(log_path, "r", errors="replace") as fh:
        for line in fh:
            # Extract timestamp from log line
            ts_match = _RE_LOG_TIMESTAMP.match(line)
            if not ts_match:
                continue
            ts_str = ts_match.group(1)
            try:
                line_dt = datetime.strptime(ts_str, _LOG_TS_FMT)
            except ValueError:
                continue
            if start_time and line_dt < start_time:
                continue

            # Compute elapsed second for this line
            elapsed_s = int((line_dt - start_time).total_seconds()) if start_time else 0

            # --- Queue stats (raw CSV + gauge extraction) ---
            m = _RE_QUEUE_STATS.match(line)
            if m:
                row = {"timestamp": ts_str}
                row.update(_parse_flat_kv(m.group(2)))
                queue_rows.append(row)
                # Update gauges from this line
                gauge_match = _GAUGE_PATTERN.search(line)
                if gauge_match:
                    for name in _GAUGE_NAMES:
                        parsed = _parse_gauge_number(gauge_match.group(name))
                        if parsed is not None:
                            gauges[name] = parsed
                    bucket_gauges[elapsed_s] = dict(gauges)
                continue

            # --- Session stats (raw CSV) ---
            m = _RE_SESSION_STATS.match(line)
            if m:
                row = {"timestamp": ts_str}
                row.update(_parse_flat_kv(m.group(2)))
                session_rows.append(row)
                continue

            # --- Event patterns (counters for logs.csv) ---
            for key, regex in _EVENT_PATTERNS.items():
                if regex.search(line):
                    if elapsed_s not in buckets:
                        buckets[elapsed_s] = {k: 0 for k in _EVENT_PATTERNS}
                    buckets[elapsed_s][key] += 1

            # Also check for gauge in non-queue-stats lines (shouldn't happen
            # but be safe)
            gauge_match = _GAUGE_PATTERN.search(line)
            if gauge_match:
                for name in _GAUGE_NAMES:
                    gauges[name] = int(gauge_match.group(name))
                bucket_gauges[elapsed_s] = dict(gauges)

    # --- Write logs.csv (per-second counters + carry-forward gauges) ---
    if buckets or bucket_gauges:
        max_sec = max(
            max(buckets.keys()) if buckets else 0,
            max(bucket_gauges.keys()) if bucket_gauges else 0,
        )
        logs_rows: list[dict] = []
        # Initialise all gauge metrics to 0 so that every second from the
        # monitor start has a real value: before the first queue-stats log
        # line the benchmark hasn't started yet and all session/queue counts
        # are 0.  This makes the chart show a clean rise from 0 rather than
        # the sessions line appearing blank (NaN) for the pre-benchmark window.
        carried_gauges: dict[str, int | float] = {name: 0 for name in _GAUGE_NAMES}
        for sec in range(0, max_sec + 1):
            # Update carried gauges if this second has a snapshot
            if sec in bucket_gauges:
                carried_gauges.update(bucket_gauges[sec])
            counters = buckets.get(sec, {k: 0 for k in _EVENT_PATTERNS})
            row: dict[str, object] = {
                "timestamp": (start_time + timedelta(seconds=sec)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ") if start_time else "",
                "elapsed_s": sec,
            }
            for k in _EVENT_PATTERNS:
                row[k] = counters.get(k, 0)
            for name in _GAUGE_NAMES:
                row[name] = carried_gauges.get(name, "")
            logs_rows.append(row)

        logs_path = os.path.join(output_dir, "logs.csv")
        with open(logs_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=_LOGS_CSV_HEADER)
            writer.writeheader()
            writer.writerows(logs_rows)
        logger.info("Wrote %d rows -> %s", len(logs_rows), logs_path)
    else:
        logger.info("No event/gauge data found — logs.csv not written.")

    # --- Write invsync_queue_stats.csv ---
    if queue_rows:
        path = os.path.join(output_dir, "invsync_queue_stats.csv")
        _write_csv(path, queue_rows)
        logger.info("Wrote %d queue-stats rows -> %s", len(queue_rows), path)
    else:
        logger.info("No InventorySync queue stats found in log.")

    # --- Write invsync_session_stats.csv ---
    if session_rows:
        path = os.path.join(output_dir, "invsync_session_stats.csv")
        _write_csv(path, session_rows)
        logger.info("Wrote %d session-stats rows -> %s", len(session_rows), path)
    else:
        logger.info("No InventorySync session stats found in log.")


def _write_csv(path: str, rows: list[dict[str, str]]) -> None:
    """Write a list of dicts to CSV, deriving the header from all keys."""
    all_keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for k in row:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=all_keys)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
