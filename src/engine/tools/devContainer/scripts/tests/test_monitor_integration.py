# Copyright (C) 2015, Wazuh Inc.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Regressions at the monitor/collector and monitor/chart boundaries."""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import bench_samples as bs


@pytest.mark.parametrize("fail_query", [False, True])
def test_monitor_finishes_inflight_scrape_before_closing(tmp_path, monkeypatch, fail_query):
    pytest.importorskip("psutil")
    import monitor

    entered = threading.Event()
    release = threading.Event()
    errors = []
    workers = []
    real_thread = threading.Thread

    class SlowCollectorThread(real_thread):
        def join(self, timeout=None):
            if self.name.startswith("mon-inventory-sync-api"):
                if timeout is not None:
                    # Model a query still in flight when a timed join expires.
                    return
                release.set()
            super().join(timeout=2)
            assert not self.is_alive()

    def query(_socket):
        entered.set()
        assert release.wait(3), "test did not release the in-flight query"
        if fail_query:
            raise TimeoutError("late timeout")
        return {"metrics": [{"name": "sync.docs.indexed", "type": "counter", "value": 42}]}

    def process_loop(*_args):
        assert entered.wait(2), "collector did not start its query"

    def make_thread(*args, **kwargs):
        thread = SlowCollectorThread(*args, **kwargs)
        workers.append(thread)
        return thread

    monkeypatch.setattr(monitor.threading, "Thread", make_thread)
    monkeypatch.setattr(threading, "excepthook", errors.append)
    monkeypatch.setattr(monitor, "monitor_loop", process_loop)
    monkeypatch.setattr(monitor, "_running", True)
    monkeypatch.setattr(monitor, "_API_STOP_EVENTS", [])
    monkeypatch.setattr(monitor.bench_collect, "API_MONITORS", {
        "inventory-sync": ("/unused", query, lambda sample: "scraped"),
    })
    target = monitor.process_target_from_exe("/fake-process")
    try:
        monitor.monitor_multi({target: object()}, str(tmp_path), 0.01, [])
    finally:
        release.set()
        for thread in workers:
            real_thread.join(thread, timeout=3)
            assert not thread.is_alive()

    assert not errors, [str(error.exc_value) for error in errors]
    samples = list(bs.read_samples(bs.samples_path(str(tmp_path))))
    assert len(samples) == 1
    assert samples[0]["ok"] is not fail_query
    if fail_query:
        assert samples[0]["err"] == "late timeout"
    else:
        assert samples[0]["m"]["sync.docs.indexed"] == 42


@pytest.fixture
def charts(tmp_path, monkeypatch):
    monkeypatch.setenv("MPLCONFIGDIR", str(tmp_path / "mpl"))
    monkeypatch.setenv("MPLBACKEND", "Agg")
    pytest.importorskip("pandas")
    pytest.importorskip("matplotlib")
    import monitor_graphics_generator
    return monitor_graphics_generator


def write_samples(directory, value):
    writer = bs.NdjsonWriter(bs.samples_path(str(directory)))
    writer.write(bs.sample_line("inventory-sync", "T", 0, {"sync.docs.indexed": value}))
    writer.close()


@pytest.mark.parametrize("subdir", ["", "monitor"])
def test_charts_load_both_monitor_layouts(tmp_path, charts, subdir):
    write_samples(tmp_path / subdir, 42)
    df = charts.load_stats(str(tmp_path), "inventory-sync")
    assert df is not None
    assert df["docs_indexed"].tolist() == [42]


def test_charts_prefer_orchestrated_samples(tmp_path, charts):
    write_samples(tmp_path, 42)
    write_samples(tmp_path / "monitor", 99)
    assert charts.load_stats(str(tmp_path), "inventory-sync")["docs_indexed"].tolist() == [42]


def test_charts_with_no_samples(tmp_path, charts):
    assert charts.load_stats(str(tmp_path), "inventory-sync") is None
