#!/usr/bin/env python3
"""
bench_collect.py — poll the manager daemons' statistics endpoints into a samples file.

This is THE collector. `monitor.py` runs it alongside its process sampling, and
`scrape_metrics.sh` runs it alone when psutil is missing; neither has its own copy of the
loop, because the second one used to and the two drifted. The shell fallback reimplemented
the collection in a `curl` pipeline and inline Python, and so it:

  - recorded an HTTP 503 as a SUCCESSFUL scrape with no metrics, which reads downstream as
    every counter resetting to nothing and then coming back;
  - wrote nothing at all when the socket was missing, where a failed scrape is precisely
    the evidence that the plane was unobservable during the run;
  - folded the error body into the sample's `d` block as if it were the daemon's own
    document scalars;
  - never emitted the descriptor manifest, and dropped types.

It shared the NDJSON syntax and none of the contract. Splitting the loop out here is what
makes "the same lines" true rather than aspirational: there is one implementation, and
running it without psutil costs only the process samples.

Layering: bench_samples.py owns the FORMAT (what a line means, how to read it back, how
to project it), this module owns the COLLECTION (how to talk to each daemon, what to do
when it does not answer), monitor.py owns the process/disk sampling and the orchestration.

The collector writes ONE artifact: the samples file. It used to also derive a wide CSV per
daemon on every scrape; `python3 bench_samples.py <results_dir>` produces that on demand
instead, and with every column rather than the aliased subset.
"""
from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_samples  # noqa: E402  (sibling module, needs the path above)

logger = logging.getLogger("bench_collect")

DEFAULT_REMOTED_SOCKET = "/var/wazuh-manager/queue/sockets/remote.sock"
REMOTED_QUERY = {"command": "getstats"}
REMOTED_MAX_RESPONSE_SIZE = 4 * 1024 * 1024

DEFAULT_INVSYNC_SOCKET = "/var/wazuh-manager/queue/sockets/inventory-sync-http.sock"
INVSYNC_MAX_RESPONSE_SIZE = 4 * 1024 * 1024

DEFAULT_REMOTED_MODULE_SOCKET = "/var/wazuh-manager/queue/sockets/remote-admin-http.sock"
REMOTED_MODULE_MAX_RESPONSE_SIZE = 4 * 1024 * 1024

DEFAULT_ANALYSISD_SOCKET = "/var/wazuh-manager/queue/sockets/engine-api-http.sock"
ANALYSISD_MAX_RESPONSE_SIZE = 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# Query adapters — one per wire protocol, not one per daemon
# ---------------------------------------------------------------------------
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
        status = resp.status
    finally:
        conn.close()

    # An error body is not a dump, however well-formed it is. Without this check a shedding
    # daemon answers 503 with a JSON object, the extractor finds no metrics in it, and the
    # scrape is recorded as a success in which every counter vanished.
    if status != 200:
        raise ValueError(f"/metrics/dump answered {status}: {raw_bytes[:200]!r}")

    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Analysisd response is not a JSON object")
    return data


def _query_uds_metrics(socket_path: str, max_size: int, timeout: float = 5.0) -> dict[str, object]:
    """GET /metrics over a module's HTTP-over-UDS socket."""
    conn = _UnixSocketHTTPConnection(socket_path, timeout=timeout)
    try:
        conn.request("GET", "/metrics", headers={"Host": "localhost"})
        resp = conn.getresponse()
        raw_bytes = resp.read(max_size)
        if resp.status != 200:
            raise ValueError(f"/metrics answered {resp.status}: {raw_bytes[:200]!r}")
    finally:
        conn.close()

    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{socket_path} /metrics response is not a JSON object")
    return data


# ---------------------------------------------------------------------------
# The API monitor loop
#
# One loop serves every daemon. It used to be four near-identical copies, one per
# daemon, each with its own empty-row builder, its own flattener and its own header
# constant; what actually differs between them is the socket, the wire protocol and
# which numbers are worth putting in the log, so those are the only parameters.
#
# Each scrape is written TWICE, on purpose and to different files:
#   - one line in samples/metrics.ndjson, lossless, every metric the dump carried;
#   - one row in the daemon's CSV, the short-named projection of that same line.
# The CSV is derived, not collected: it is bench_samples.wide_row() of the line just
# written, so the two can never disagree, and it is kept only while consumers migrate
# off it. Deleting the CSV writer here does not lose a number.
# ---------------------------------------------------------------------------
def _v(sample: dict, name: str) -> int:
    """One metric of a sample as an int, 0 when it is not there.

    The progress lines read the module's OWN names now. They used to read the derived CSV
    row by alias, which is the only reason that row had to exist at this point in the loop.
    """
    return _as_int((sample.get("m") or {}).get(name))


def _h(sample: dict, name: str, field: str = "p99") -> int:
    return _as_int(((sample.get("h") or {}).get(name) or {}).get(field))


def _log_invsync(s: dict) -> str:
    return (
        "[invsync-api] 200=%d 503=%d 500=%d docs=%d shed=%d shard_depth(max/sum)=%d/%d "
        "vd_lane=%d vd_503=%d session_p99=%dus vd_lane_p99=%dus" % (
            _v(s, "sync.requests.total.200"), _v(s, "sync.requests.total.503"),
            _v(s, "sync.requests.total.500"), _v(s, "sync.docs.indexed"),
            _v(s, "sync.pipeline.shed.total"),
            max([_v(s, n) for n in (s.get("m") or {}) if n.startswith("sync.shard.")
                 and n.endswith(".depth")] or [0]),
            sum(_v(s, n) for n in (s.get("m") or {}) if n.startswith("sync.shard.")
                and n.endswith(".depth")),
            _v(s, "vd.lane.depth"), _v(s, "vd.capacity.503.total"),
            _h(s, "sync.session.duration.bulk"), _h(s, "vd.lane.time"),
        )
    )


def _log_remoted_module(s: dict) -> str:
    # The admission split, in the order a saturation run is read: what arrived, what VD
    # queued (and will run), and what was shed -- by capacity or otherwise -- plus the
    # data-plane hot path (stateless) and the two shed totals that name the bottleneck
    # (byte budget vs deferred-work slots).
    return (
        "[remoted-module] scanvd req=%d accepted=%d queue_full=%d idx_unavail=%d vd_err=%d "
        "mismatch=%d | control notify=%d wdb_err=%d | stateless 2xx=%d 503=%d p99=%dus | "
        "shed budget=%d deferred=%d | admin sessions=%d" % (
            _v(s, "remoted.scanvd.requests.total"), _v(s, "remoted.scanvd.accepted"),
            _v(s, "remoted.scanvd.queue_full"), _v(s, "remoted.scanvd.indexer_unavailable"),
            _v(s, "remoted.scanvd.vd_error"), _v(s, "remoted.scanvd.version_mismatch"),
            _v(s, "remoted.control.notify"), _v(s, "remoted.control.wdb_error"),
            _v(s, "remoted.http.stateless.responses.2xx"),
            _v(s, "remoted.http.stateless.responses.503"),
            _h(s, "remoted.http.stateless.latency"),
            _v(s, "remoted.server.budget.rejected.total"),
            _v(s, "remoted.forwarder.deferred.rejected.total"),
            _v(s, "remoted.admin.server.sessions.live"),
        )
    )


def _log_analysisd(s: dict) -> str:
    m = s.get("m") or {}
    return (
        "[analysisd-api] events_received=%d router_q=%d router_q_pct=%.1f indexer_q=%d "
        "indexer_q_pct=%.1f indexer_dropped=%d unclassified=%d cache_entries=%d cache_hits=%d "
        "cache_ins=%d cache_upd=%d cache_evict=%d" % (
            _v(s, "server.events.received"), _v(s, "router.queue.size"),
            _as_float(m.get("router.queue.usage.percent")), _v(s, "indexer.queue.size"),
            _as_float(m.get("indexer.queue.usage.percent")),
            _v(s, "indexer.events.dropped"),
            _v(s, "spaces.standard.events.unclassified"),
            _v(s, "agent.cache.entries"), _v(s, "agent.cache.hits"),
            _v(s, "agent.cache.insertions"), _v(s, "agent.cache.updates"),
            _v(s, "agent.cache.evictions"),
        )
    )


def _log_remoted(s: dict) -> str:
    m = s.get("m") or {}
    return (
        "[remoted-api] usage=%.3f recv_discarded=%d recv_events=%d sent_discarded=%d "
        "tcp_sessions=%d" % (
            _as_float(m.get("data.metrics.queues.received.usage")),
            _v(s, "data.metrics.messages.received_breakdown.discarded"),
            _v(s, "data.metrics.messages.received_breakdown.events"),
            _v(s, "data.metrics.messages.sent_breakdown.discarded"),
            _v(s, "data.metrics.tcp_sessions"),
        )
    )


# src -> (socket path, query callable, log-line builder). The socket is what decides the
# scrape's scope; the query callable is what decides how to talk to it.
API_MONITORS: dict[str, tuple[str, object, object]] = {
    "inventory-sync": (
        DEFAULT_INVSYNC_SOCKET,
        lambda sock: _query_uds_metrics(sock, INVSYNC_MAX_RESPONSE_SIZE),
        _log_invsync,
    ),
    "remoted-module": (
        DEFAULT_REMOTED_MODULE_SOCKET,
        lambda sock: _query_uds_metrics(sock, REMOTED_MODULE_MAX_RESPONSE_SIZE),
        _log_remoted_module,
    ),
    "analysisd": (DEFAULT_ANALYSISD_SOCKET, _query_analysisd_stats, _log_analysisd),
    "remoted": (DEFAULT_REMOTED_SOCKET, _query_remoted_stats, _log_remoted),
}


def api_monitor_loop(src: str, interval: float, socket_path: str,
                     query, log_line, ndjson: bench_samples.NdjsonWriter,
                     stop_event: threading.Event | None = None) -> None:
    """Poll one daemon's statistics endpoint into the run's samples file.

    A socket that is not there is not fatal: remoted only warns if its admin server cannot
    bind, so an absent socket must degrade to failed-scrape lines rather than take the
    collector down. Those lines are themselves the evidence that the plane was unobservable
    during the run -- which is why they carry no metrics at all instead of zeros.

    One artifact, not two. This used to also write a wide CSV per daemon, derived from the
    very line it had just written; nothing read it, and it held strictly less than the
    samples file because a fixed header can only carry what somebody aliased. Ask for one
    when you want it: `python3 bench_samples.py <results_dir>`.
    """
    stop_event = stop_event or threading.Event()
    source = bench_samples.SOURCES[src]
    start_time = time.monotonic()
    last_descriptors: dict | None = None

    logger.info("%s API monitor every %.1fs -> %s", src, interval, ndjson.path)
    logger.info("%s API socket: %s", src, socket_path)

    while not stop_event.is_set():
        ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        elapsed_s = round(time.monotonic() - start_time, 1)

        try:
            raw = query(socket_path)
            extraction = source.extract(raw)
            # The registration-time descriptors (type, unit, description) go out once, on
            # the first scrape that answered -- a reader learns them without asking a
            # second source of truth, and without paying for them on every scrape.
            # Re-emitted if they ever change, so nothing here assumes a module cannot
            # register a metric mid-run.
            if extraction.types and extraction.descriptors != last_descriptors:
                ndjson.write(bench_samples.meta_line_from(src, socket_path, extraction))
                last_descriptors = extraction.descriptors
            sample = bench_samples.sample_line_from(src, ts_now, elapsed_s, extraction)
        except Exception as exc:
            sample = bench_samples.error_line(src, ts_now, elapsed_s, str(exc))
            logger.warning("%s API poll failed: %s", src, exc)

        ndjson.write(sample)
        if sample.get("ok"):
            logger.info("%s", log_line(sample))

        deadline = time.monotonic() + interval
        while time.monotonic() < deadline and not stop_event.is_set():
            time.sleep(min(0.5, deadline - time.monotonic()))

    logger.info("%s API monitor finished.", src)




# ---------------------------------------------------------------------------
# Standalone entry point
#
# What scrape_metrics.sh runs. Same loop, same validation, same lines as the collector
# threads monitor.py starts -- the point of the module being importable is that the
# psutil-less path is not a second implementation.
# ---------------------------------------------------------------------------
def collect_once_standalone(src: str, socket_path: str, ndjson_path: str,
                            interval: float, run_label: str | None = None,
                            duration: float | None = None) -> int:
    """Poll one source until interrupted (or `duration` elapses)."""
    stop = threading.Event()

    def _stop(_signum, _frame):
        stop.set()

    import signal as _signal
    for sig in (_signal.SIGTERM, _signal.SIGINT):
        _signal.signal(sig, _stop)

    default_socket, query, log_line = API_MONITORS[src]
    ndjson = bench_samples.NdjsonWriter(ndjson_path, label=run_label or f"{src} standalone")
    logger.info("Samples: %s (run %s)", ndjson_path, ndjson.run_id)

    worker = threading.Thread(
        target=api_monitor_loop,
        args=(src, interval, socket_path or default_socket, query, log_line, ndjson, stop),
        daemon=True,
    )
    worker.start()
    if duration:
        stop.wait(duration)
        stop.set()
    worker.join()
    ndjson.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Poll a manager daemon's statistics endpoint into a samples file.")
    parser.add_argument("--src", default="inventory-sync", choices=sorted(API_MONITORS),
                        help="Which daemon's endpoint to poll (default: inventory-sync)")
    parser.add_argument("--socket", default=None, help="Override the source's default socket")
    parser.add_argument("--ndjson", required=True, help="Samples file to append to")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between scrapes")
    parser.add_argument("--run-label", default=None, help="Label recorded in the run marker")
    parser.add_argument("--duration", type=float, default=None,
                        help="Stop after this many seconds (default: until SIGTERM/SIGINT)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)
    return collect_once_standalone(args.src, args.socket, args.ndjson,
                                   args.interval, args.run_label, args.duration)


if __name__ == "__main__":
    sys.exit(main())
