#!/usr/bin/env python3
"""
log_parser.py — Tail the manager log and count Inventory Sync related events.

Designed to run alongside monitor.py / benchmark_sender.py.  Reads the
manager log (default /var/wazuh-manager/logs/wazuh-manager.log) starting from
EOF (or from a configurable byte offset) and emits per-second counters to a
CSV file.

The patterns parsed here correspond to log lines that ALREADY exist in the
inventory_sync module (no production instrumentation is added by this tool).
Each pattern maps to one CSV column.

Patterns (regex precompiled, anchored loosely):

  session_limit_reached    -- "Session limit reached \\(\\d+/\\d+ active sessions\\)"
                              (inventorySyncFacade.hpp line ~314)
  zombie_cleaned           -- "Cleaning up zombie session \\d+ for agent"
                              (inventorySyncFacade.hpp line ~1651)
  session_timeout          -- "Session \\d+ has timed out"
                              (inventorySyncFacade.hpp line ~1313)
  vdsync_timeout           -- "Feed update scan timeout waiting for VDSync"
                              (inventorySyncFacade.hpp line ~1583)
  parse_error              -- "Failed to parse JSON message"
                              (inventorySyncFacade.hpp line ~119)
  module_check_failed      -- "ModuleCheck failed"
                              (inventorySyncFacade.hpp line ~952)
  inventory_sync_error     -- "InventorySyncFacade::start: " + non-debug
  indexer_error            -- "indexer" + "error" / "not available" / "offline"
                              (heuristic across logs from indexer_connector)

These cover the manager-side signals that the benchmark can correlate with
sender-side drops, ReqRet bursts and RSS growth.  Any "queue full" or
"messages dropped" warning would require a separate production change and is
NOT present today — those columns stay at 0.

Usage:

    python3 log_parser.py \
        --log /var/wazuh-manager/logs/wazuh-manager.log \
        --output logs.csv \
        --interval 1.0 \
        --pidfile log_parser.pid

    # Stop:
    kill $(cat log_parser.pid)
"""
from __future__ import annotations

import argparse
import atexit
import csv
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("log_parser")

_running = True


def _signal_handler(_signum, _frame):
    global _running
    _running = False
    logger.info("Stop signal received — flushing and exiting.")


def _write_pid_file(path: str) -> None:
    with open(path, "w") as f:
        f.write(str(os.getpid()))
    atexit.register(lambda: _safe_remove(path))


def _safe_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
PATTERNS: dict[str, re.Pattern] = {
    "session_limit_reached": re.compile(r"Session limit reached \(\d+/\d+ active sessions\)"),
    "zombie_cleaned":        re.compile(r"Cleaning up zombie session \d+ for agent"),
    "session_timeout":       re.compile(r"Session \d+ has timed out"),
    "vdsync_timeout":        re.compile(r"Feed update scan timeout waiting for VDSync"),
    "parse_error":           re.compile(r"Failed to parse JSON message"),
    "module_check_failed":   re.compile(r"ModuleCheck failed"),
    "inventory_sync_error":  re.compile(r"InventorySyncFacade::start: (?!Session not found)"),
    "indexer_error":         re.compile(r"(indexer.*error|Indexer.*error|indexer.*offline|indexer.*not available)",
                                        re.IGNORECASE),
}

# Gauge metrics emitted by the manager as instantaneous values, not events.
# Source: "logger-helper: INFO: InventorySync queue stats: ..." lines
# (added in the dbsync-stats commit). We capture the latest value seen in
# each flush window and carry it forward when no new sample arrives, so the
# time series has no spurious zeros where the manager just didn't emit.
GAUGE_PATTERN = re.compile(
    r"InventorySync queue stats:\s+"
    r"workers_q=(?P<workers_q>\d+)\s+"
    r"indexer_q=(?P<indexer_q>\d+)\s+"
    r"sessions=(?P<sessions>\d+)\s+"
    r"blocked_agents=(?P<blocked_agents>\d+)\s+"
    r"active_vdfirst=(?P<active_vdfirst>\d+)\s+"
    r"indexer_bulk_bytes=(?P<indexer_bulk_bytes>\d+)\s+"
    r"indexer_notify=(?P<indexer_notify>\d+)\s+"
    r"indexer_delbyq=(?P<indexer_delbyq>\d+)\s+"
    r"rocksdb_dir_bytes=(?P<rocksdb_dir_bytes>\d+)"
)

GAUGE_NAMES: tuple[str, ...] = (
    "workers_q", "indexer_q", "sessions", "blocked_agents", "active_vdfirst",
    "indexer_bulk_bytes", "indexer_notify", "indexer_delbyq", "rocksdb_dir_bytes",
)

CSV_HEADER = ["timestamp", "elapsed_s"] + list(PATTERNS.keys()) + list(GAUGE_NAMES)


# ---------------------------------------------------------------------------
# Tail loop
# ---------------------------------------------------------------------------
def follow(path: str, from_start: bool):
    """Generator that yields complete lines from `path` as they are appended.

    Starts at EOF unless `from_start=True`. Handles log rotation by reopening
    when inode changes.
    """
    f = None
    inode = None
    while _running:
        try:
            new_stat = os.stat(path)
        except FileNotFoundError:
            time.sleep(0.5)
            continue

        if f is None or new_stat.st_ino != inode:
            if f is not None:
                f.close()
            f = open(path, "r", errors="replace")
            inode = new_stat.st_ino
            if not from_start:
                f.seek(0, os.SEEK_END)
            from_start = False  # only honor on first open

        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def parse_loop(log_path: str, csv_path: str, interval: float, from_start: bool) -> None:
    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()
    bucket = {k: 0 for k in PATTERNS}
    cumulative = {k: 0 for k in PATTERNS}
    # Gauges carry the last seen value across flushes. Initialized empty so
    # that early rows (before any stats line is emitted) write empty cells
    # rather than misleading zeros — downstream charts will skip those.
    gauges: dict[str, int] = {}

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADER)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info("Tailing %s -> %s (interval %.1fs)", log_path, csv_path, interval)
        last_flush = time.monotonic()

        for line in follow(log_path, from_start):
            if not _running:
                break

            for key, regex in PATTERNS.items():
                if regex.search(line):
                    bucket[key] += 1

            gauge_match = GAUGE_PATTERN.search(line)
            if gauge_match:
                for name in GAUGE_NAMES:
                    gauges[name] = int(gauge_match.group(name))

            now = time.monotonic()
            if now - last_flush >= interval:
                row = {
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "elapsed_s": round(now - start_time, 1),
                    **bucket,
                    **{name: gauges.get(name, "") for name in GAUGE_NAMES},
                }
                writer.writerow(row)
                fh.flush()
                for k, v in bucket.items():
                    cumulative[k] += v
                    bucket[k] = 0
                last_flush = now
                if any(row[k] for k in PATTERNS) or gauges:
                    log_extra = {k: row[k] for k in PATTERNS if row[k]}
                    if gauges:
                        log_extra.update({n: gauges[n] for n in
                                          ("workers_q", "indexer_q", "sessions")
                                          if n in gauges})
                    logger.info("counters/gauges: %s", log_extra)

    # Final flush of the open bucket (counters + last-seen gauges)
    if any(bucket.values()) or gauges:
        row = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "elapsed_s": round(time.monotonic() - start_time, 1),
            **bucket,
            **{name: gauges.get(name, "") for name in GAUGE_NAMES},
        }
        with open(csv_path, "a", newline="") as fh:
            csv.DictWriter(fh, fieldnames=CSV_HEADER).writerow(row)
        for k, v in bucket.items():
            cumulative[k] += v

    logger.info("Done. Cumulative counters: %s. Last gauges: %s",
                cumulative, gauges)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Tail the manager log and count Inventory Sync events.",
    )
    p.add_argument("--log",      type=str,
                   default="/var/wazuh-manager/logs/wazuh-manager.log",
                   help="Path to the manager log (default: %(default)s)")
    p.add_argument("-o", "--output",   type=str, default="logs.csv",
                   help="Output CSV path (default: %(default)s)")
    p.add_argument("-s", "--interval", type=float, default=1.0,
                   help="Aggregation interval in seconds (default: 1.0)")
    p.add_argument("--from-start", action="store_true",
                   help="Read log from the beginning instead of EOF "
                        "(useful when post-processing an existing file).")
    p.add_argument("--pidfile",  type=str, default="log_parser.pid",
                   help="PID file path (default: %(default)s)")
    p.add_argument("--debug",    action="store_true", help="Verbose logging")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    _write_pid_file(args.pidfile)
    parse_loop(args.log, args.output, args.interval, args.from_start)


if __name__ == "__main__":
    main()
