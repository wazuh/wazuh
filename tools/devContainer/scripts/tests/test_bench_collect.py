# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_bench_collect.py -v

"""Tests for the collector: the loop that turns statistics endpoints into a samples file.

Drives bench_collect.api_monitor_loop against a real Unix socket serving a real response,
because the parts worth testing here are the ones a unit test on the format cannot reach:
that scrapes reach the samples file and can be projected, that an endpoint answering an
ERROR is recorded as a failed scrape rather than an empty successful one, and
that an endpoint which is not there degrades into failed-scrape lines instead of taking the
collector down mid-run.

There is one collector, shared by monitor.py and scrape_metrics.sh, so these cover both.
"""
import csv
import http.server
import json
import os
import socket
import socketserver
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import bench_collect
import bench_samples as bs

DUMP = {
    "name": "inventory-sync",
    "metrics": [
        {"name": "sync.requests.total.200", "type": "counter", "value": 7},
        {"name": "sync.docs.indexed", "type": "counter", "enabled": True, "value": 42,
         "description": "Documents indexed", "unit": "documents"},
        {"name": "sync.shard.0.depth", "type": "pull", "value": 3.0},
        {"name": "vd.lane.time", "type": "histogram", "value": 2,
         "summary": {"count": 2, "sum": 10, "min": 1, "max": 9, "p50": 5, "p90": 9, "p99": 9}},
    ],
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(DUMP).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _UnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", 0


@pytest.fixture
def metrics_socket(tmp_path):
    """A module's GET /metrics endpoint, on a real UDS the collector connects to."""
    path = str(tmp_path / "metrics.sock")
    server = _UnixHTTPServer(path, _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield path
    server.shutdown()
    server.server_close()


def _run_loop(src, socket_path, ndjson, scrapes=2):
    """Run the collector for a few scrapes, then stop it the way the orchestrator does."""
    stop = threading.Event()
    _socket, query, log_line = bench_collect.API_MONITORS[src]
    thread = threading.Thread(
        target=bench_collect.api_monitor_loop,
        args=(src, 0.05, socket_path, query, log_line, ndjson, stop),
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if ndjson is not None and os.path.isfile(ndjson.path):
            if sum(1 for _ in bs.read_samples(ndjson.path, src=src)) >= scrapes:
                break
        time.sleep(0.02)
    stop.set()
    thread.join(timeout=5)
    assert not thread.is_alive(), "the collector did not stop when asked"


def test_loop_writes_the_samples_file(tmp_path, metrics_socket):
    """One artifact. The loop used to also derive a wide CSV from the line it had just
    written; that CSV is produced on demand now, by bench_samples.export_csv()."""
    ndjson = bs.NdjsonWriter(str(tmp_path / "samples" / "metrics.ndjson"))
    _run_loop("inventory-sync", metrics_socket, ndjson)
    ndjson.close()

    samples = list(bs.read_samples(ndjson.path, src="inventory-sync"))
    assert samples, "no samples were written"
    assert samples[0]["ok"] is True
    assert samples[0]["m"]["sync.docs.indexed"] == 42
    # Lossless: the per-shard gauge has no alias and never had a column, and is here anyway.
    assert samples[0]["m"]["sync.shard.0.depth"] == 3.0
    assert samples[0]["h"]["vd.lane.time"]["p99"] == 9

    assert not list(tmp_path.glob("*.csv")), "the collector writes no CSV"


def test_the_projection_of_what_was_collected_has_the_aliased_columns(tmp_path, metrics_socket):
    """What the charts read. The aliased names still exist -- they moved from a written
    header to a computed one."""
    pytest.importorskip("pandas")
    ndjson = bs.NdjsonWriter(str(tmp_path / "samples" / "metrics.ndjson"))
    _run_loop("inventory-sync", metrics_socket, ndjson)
    ndjson.close()

    df = bs.project(ndjson.path, "inventory-sync")
    assert df["requests_200"].iloc[0] == 7
    assert df["docs_indexed"].iloc[0] == 42
    assert df["vd_lane_time_p99"].iloc[0] == 9
    assert df["shard_depth_max"].iloc[0] == 3
    assert df["sync_shard_0_depth"].iloc[0] == 3.0, "and the columns no CSV could hold"


def test_meta_line_is_written_once(tmp_path, metrics_socket):
    """One meta line per source: a reader needs the types, not a copy of them per scrape."""
    ndjson = bs.NdjsonWriter(str(tmp_path / "samples" / "metrics.ndjson"))
    _run_loop("inventory-sync", metrics_socket, ndjson, scrapes=3)
    ndjson.close()

    metas = [o for o in bs.read_samples(ndjson.path, include_meta=True)
             if o.get("kind") == "meta"]
    assert len(metas) == 1
    assert metas[0]["types"]["sync.docs.indexed"] == "counter"
    assert bs.read_types(ndjson.path, "inventory-sync")["vd.lane.time"] == "histogram"


def test_absent_socket_degrades_to_failed_scrapes(tmp_path):
    """remoted only warns if its admin server cannot bind, so an absent socket has to
    produce evidence that the plane was unobservable -- not kill the run's monitoring."""
    ndjson = bs.NdjsonWriter(str(tmp_path / "samples" / "metrics.ndjson"))
    _run_loop("inventory-sync", str(tmp_path / "does-not-exist.sock"), ndjson)
    ndjson.close()

    samples = list(bs.read_samples(ndjson.path, src="inventory-sync"))
    assert samples, "a missing socket must still produce lines"
    assert all(s["ok"] is False for s in samples)
    assert all("m" not in s for s in samples), "a failed scrape must carry no metrics"
    assert all(s["err"] for s in samples)


def test_concurrent_sources_do_not_interleave_lines(tmp_path, metrics_socket):
    """Four collectors share one file; a half-written line would corrupt the run."""
    ndjson = bs.NdjsonWriter(str(tmp_path / "samples" / "metrics.ndjson"))
    threads = []
    for src in ("inventory-sync", "remoted-module"):
        t = threading.Thread(
            target=_run_loop,
            args=(src, metrics_socket, ndjson, 5),
            daemon=True,
        )
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=20)
    ndjson.close()

    with open(ndjson.path) as fh:
        lines = [ln for ln in fh.read().splitlines() if ln]
    objects = [json.loads(ln) for ln in lines]  # raises if two writers interleaved a line
    assert {o["src"] for o in objects if "src" in o} == {"inventory-sync", "remoted-module"}
    # One sink, one run: both collectors stamp the run the writer opened.
    assert {o["r"] for o in objects} == {ndjson.run_id}


# ---------------------------------------------------------------------------
# An endpoint that answers, but not with a dump
# ---------------------------------------------------------------------------
class _StatusHandler(http.server.BaseHTTPRequestHandler):
    """Answers whatever `status`/`body` the server was configured with."""

    def do_GET(self):
        body = self.server.body
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *args):
        pass


@pytest.fixture
def bad_endpoint(tmp_path):
    """A socket that answers, with something that is not a metrics dump."""
    servers = []

    def make(status, body):
        path = str(tmp_path / f"bad-{status}-{len(servers)}.sock")
        server = _UnixHTTPServer(path, _StatusHandler)
        server.status, server.body = status, body
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return path

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("status,body,why", [
    (503, b'{"error":"shedding"}', "a shedding daemon"),
    (500, b'{"error":"boom"}', "an internal error"),
    (404, b'{"error":"no such route"}', "a renamed route"),
])
def test_http_error_is_a_failed_scrape(tmp_path, bad_endpoint, status, body, why):
    """An error response is not a dump, however well-formed its JSON is.

    Recording it as a success with no metrics is the worst of both worlds: every counter
    reads as having reset to nothing, and the run looks observed when it was not. This is
    what the shell fallback did before it was reduced to a wrapper around this loop.
    """
    ndjson = bs.NdjsonWriter(str(tmp_path / f"s{status}" / "metrics.ndjson"))
    _run_loop("inventory-sync", bad_endpoint(status, body), ndjson)
    ndjson.close()

    samples = list(bs.read_samples(ndjson.path, src="inventory-sync"))
    assert samples, f"{why} must still produce lines"
    assert all(s["ok"] is False for s in samples), f"{why} must not read as a success"
    assert all(str(status) in s["err"] for s in samples), "the status belongs in the error"
    assert all("m" not in s and "d" not in s for s in samples), \
        "an error body is not a reading, and not the daemon's document scalars either"


def test_a_body_that_is_not_a_json_object_is_a_failed_scrape(tmp_path, bad_endpoint):
    """200 is not enough: the body still has to be a dump."""
    for body in (b"not json at all", b"[1, 2, 3]"):
        ndjson = bs.NdjsonWriter(str(tmp_path / f"n{len(body)}" / "metrics.ndjson"))
        _run_loop("inventory-sync", bad_endpoint(200, body), ndjson)
        ndjson.close()
        samples = list(bs.read_samples(ndjson.path, src="inventory-sync"))
        assert samples and all(s["ok"] is False for s in samples), body


def test_failed_scrapes_never_write_a_meta_line(tmp_path, bad_endpoint):
    """Descriptors come from a dump; there is none, so there is nothing to declare."""
    ndjson = bs.NdjsonWriter(str(tmp_path / "meta" / "metrics.ndjson"))
    _run_loop("inventory-sync", bad_endpoint(503, b'{"error":"shedding"}'), ndjson)
    ndjson.close()
    assert bs.read_descriptors(ndjson.path, "inventory-sync") == {}


# ---------------------------------------------------------------------------
# The standalone entry point — what scrape_metrics.sh runs
# ---------------------------------------------------------------------------
def test_standalone_entry_point_honours_the_same_contract(tmp_path, metrics_socket):
    """scrape_metrics.sh is a wrapper around this, so it inherits the contract instead of
    reimplementing it -- which is how the two came to disagree in the first place."""
    ndjson_path = str(tmp_path / "samples" / "metrics.ndjson")
    bench_collect.collect_once_standalone(
        "inventory-sync", metrics_socket, ndjson_path,
        interval=0.05, run_label="standalone-test", duration=0.4)

    samples = list(bs.read_samples(ndjson_path, src="inventory-sync"))
    assert samples and all(s["ok"] for s in samples)
    assert samples[0]["m"]["sync.docs.indexed"] == 42
    # The manifest, which the old shell path never produced.
    assert bs.read_descriptors(ndjson_path, "inventory-sync")["sync.docs.indexed"]["type"] == "counter"
    markers = [o for o in bs._iter_lines(ndjson_path) if o.get("kind") == "run"]
    assert markers[0]["label"] == "standalone-test"


def test_standalone_entry_point_records_an_unreachable_endpoint(tmp_path):
    """Silence is not an acceptable answer: the failed scrapes ARE the evidence."""
    ndjson_path = str(tmp_path / "samples" / "metrics.ndjson")
    bench_collect.collect_once_standalone(
        "inventory-sync", str(tmp_path / "nope.sock"), ndjson_path,
        interval=0.05, duration=0.3)
    samples = list(bs.read_samples(ndjson_path, src="inventory-sync"))
    assert samples, "an unreachable endpoint must still be recorded"
    assert all(s["ok"] is False for s in samples)


# ---------------------------------------------------------------------------
# The writer's half of the same contract
# ---------------------------------------------------------------------------
class _GrowingHandler(http.server.BaseHTTPRequestHandler):
    """A module that registers a second metric lazily, once the run is under way."""

    def do_GET(self):
        self.server.scrapes += 1
        dump = {"name": "inventory_sync_server", "timestamp": "T", "metrics": [
            {"name": "sync.docs.indexed", "type": "counter", "enabled": True, "value": 1,
             "description": "Documents indexed", "unit": "documents"}]}
        if self.server.scrapes > 1:
            dump["metrics"].append(
                {"name": "vd.lane.depth", "type": "gauge_int", "enabled": True, "value": 7,
                 "description": "Lane depth", "unit": "items"})
        body = json.dumps(dump).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_a_metric_registered_mid_run_gets_a_manifest(tmp_path):
    """Lazily registered metrics are normal -- the transport diagnostics only exist once
    the server has started -- so the manifest has to be re-emitted, not written once."""
    sock = str(tmp_path / "growing.sock")
    server = _UnixHTTPServer(sock, _GrowingHandler)
    server.scrapes = 0
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ndjson = bs.NdjsonWriter(str(tmp_path / "samples" / "metrics.ndjson"))
        _run_loop("inventory-sync", sock, ndjson, scrapes=3)
        ndjson.close()
    finally:
        server.shutdown()
        server.server_close()

    manifests = [o for o in bs._iter_lines(ndjson.path) if o.get("kind") == "meta"]
    assert len(manifests) == 2, "the manifest must be revised when the descriptors change"
    assert "vd.lane.depth" not in manifests[0]["types"]
    assert manifests[1]["types"]["vd.lane.depth"] == "gauge_int"
    assert bs.read_types(ndjson.path, "inventory-sync")["vd.lane.depth"] == "gauge_int"


def test_an_unchanged_manifest_is_not_rewritten(tmp_path, metrics_socket):
    """Revision, not repetition: 400 identical manifests would cost more than the readings."""
    ndjson = bs.NdjsonWriter(str(tmp_path / "samples" / "metrics.ndjson"))
    _run_loop("inventory-sync", metrics_socket, ndjson, scrapes=4)
    ndjson.close()
    manifests = [o for o in bs._iter_lines(ndjson.path) if o.get("kind") == "meta"]
    assert len(manifests) == 1
