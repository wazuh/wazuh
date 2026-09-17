# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_result_summary.py -v

"""Tests for the benchmark run collator.

Covers what summary.json is now responsible for: aggregating every source rather than one
hand-picked file, refusing to subtract two percentiles, ignoring failed scrapes instead of
reading them as counter resets, and naming its inputs instead of copying them.
"""
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
# result_summary imports bench_samples, which lives with the monitor that writes the file.
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'src', 'engine', 'tools',
                                'devContainer', 'scripts'))
import bench_samples as bs
import result_summary as rs


@pytest.fixture
def samples_file(tmp_path):
    """A run where inventory sync was scraped three times and failed once.

    Counters advance, a gauge moves down as well as up, and the histogram's p99 changes
    between scrapes -- the three shapes the aggregation has to treat differently.
    """
    path = str(tmp_path / "samples" / "metrics.ndjson")
    writer = bs.NdjsonWriter(path)
    writer.write(bs.meta_line("inventory-sync", "/sock", {"sync.docs.indexed": "counter"}))
    writer.write(bs.sample_line("inventory-sync", "T1", 1.0,
                                {"sync.docs.indexed": 100, "server.sessions.live": 5},
                                {"vd.lane.time": {"count": 2, "p99": 30}}))
    writer.write(bs.error_line("inventory-sync", "T2", 2.0, "connection refused"))
    writer.write(bs.sample_line("inventory-sync", "T3", 3.0,
                                {"sync.docs.indexed": 180, "server.sessions.live": 2},
                                {"vd.lane.time": {"count": 9, "p99": 45}}))
    writer.write(bs.sample_line("remoted", "T1", 1.0, {"data.metrics.tcp_sessions": 3}))
    writer.close()
    return path


def test_delta_attributes_work_to_this_run(samples_file):
    """The server's counters are cumulative for the module's lifetime, so only the delta
    belongs to the run being measured."""
    agg = rs.aggregate_samples(samples_file)
    assert agg["inventory-sync"]["delta"]["sync.docs.indexed"] == 80
    assert agg["inventory-sync"]["final"]["sync.docs.indexed"] == 180


def test_peak_is_kept_for_gauges_that_come_back_down(samples_file):
    inv = rs.aggregate_samples(samples_file)["inventory-sync"]
    assert inv["peak"]["server.sessions.live"] == 5
    assert inv["final"]["server.sessions.live"] == 2


def test_histograms_get_no_delta(samples_file):
    """Subtracting two p99 snapshots is meaningless. The samples file makes this
    structural -- histograms live in their own object -- where the legacy CSV reader had
    to recognise a distribution by the shape of its column name."""
    inv = rs.aggregate_samples(samples_file)["inventory-sync"]
    assert inv["histograms"]["vd.lane.time"]["p99"] == 45
    assert not any("vd.lane.time" in key for key in inv["delta"])


def test_failed_scrape_is_counted_but_not_aggregated(samples_file):
    """A failed scrape must not read as a drop to zero and then a recovery, which would
    make the delta negative and invent traffic that never happened."""
    inv = rs.aggregate_samples(samples_file)["inventory-sync"]
    assert inv["samples"] == 2
    assert inv["failed_scrapes"] == 1
    assert inv["delta"]["sync.docs.indexed"] == 80


def test_every_source_in_the_file_is_aggregated(samples_file):
    """summary.json used to carry inventory sync alone, so the other three daemons were
    scraped for the whole run and then dropped before anything could read them."""
    agg = rs.aggregate_samples(samples_file)
    assert set(agg) == {"inventory-sync", "remoted"}
    assert agg["remoted"]["final"]["data.metrics.tcp_sessions"] == 3


def test_missing_samples_file_is_not_an_error(tmp_path):
    assert rs.aggregate_samples(str(tmp_path / "nope.ndjson")) == {}
    assert rs.aggregate_samples(None) == {}


# ---------------------------------------------------------------------------
# Process aggregation
# ---------------------------------------------------------------------------
def _write_process_csv(path, rows):
    with open(path, "w") as fh:
        fh.write("timestamp,elapsed_s,pid,uptime_sec,cpu_pct,mem_pct,rss_mb,vms_mb,fds,threads,read_bytes,write_bytes\n")
        for i, (cpu, rss) in enumerate(rows):
            fh.write(f"T{i},{i},1,1,{cpu},1.0,{rss},1,10,4,0,0\n")


def test_all_process_csvs_are_aggregated(tmp_path):
    """Every process the monitor sampled, not just modulesd."""
    monitor = tmp_path / "monitor"
    monitor.mkdir()
    _write_process_csv(monitor / "wazuh-manager-modulesd.csv", [(1.0, 100.0), (2.0, 150.0)])
    _write_process_csv(monitor / "wazuh-manager-remoted.csv", [(3.0, 200.0), (4.0, 210.0)])
    # Not processes: these must not be mistaken for one.
    (monitor / "disk_usage.csv").write_text("timestamp,elapsed_s,dir_vd_mb\nT0,0,1.0\n")
    (monitor / bs.SOURCES["inventory-sync"].csv_name).write_text("timestamp,elapsed_s\nT0,0\n")

    agg = rs.aggregate_all_processes(str(monitor))
    assert set(agg) == {"wazuh-manager-modulesd", "wazuh-manager-remoted"}
    assert agg["wazuh-manager-modulesd"]["rss_mb_max"] == 150.0
    assert agg["wazuh-manager-remoted"]["cpu_pct_max"] == 4.0


def test_missing_monitor_dir_is_not_an_error(tmp_path):
    assert rs.aggregate_all_processes(str(tmp_path / "nope")) == {}
    assert rs.aggregate_all_processes(None) == {}


# ---------------------------------------------------------------------------
# The verdict, and not copying the inputs
# ---------------------------------------------------------------------------
def test_verdict_is_condensed_not_copied():
    sender = {"expected": {"passed": False, "checked": 5,
                           "failures": ["a: expected eq 1, got 2", "b: expected eq 0, got 3"]}}
    v = rs.verdict(sender)
    assert v == {"passed": False, "checked": 5, "failed": 2,
                 "first_failure": "a: expected eq 1, got 2"}
    assert v != sender["expected"], "the summary must not carry a verbatim copy"


def test_scenario_without_assertions_did_not_pass_by_default():
    """No expected block means nothing was asserted, which is not the same as passing."""
    assert rs.verdict({})["passed"] is None
    assert rs.verdict({"expected": {}})["checked"] == 0


def test_inputs_are_named_relative_to_the_run_directory(tmp_path):
    """summary.json names its siblings so the results directory survives being moved."""
    args = rs.argparse.Namespace(
        out=str(tmp_path / "summary.json"),
        params=str(tmp_path / "params.json"),
        sender_json=str(tmp_path / "sender_summary.json"),
        bench=str(tmp_path / "bench.csv"),
        samples=str(tmp_path / "samples" / "metrics.ndjson"),
        monitor_dir=str(tmp_path / "monitor"),
    )
    assert rs.relative_inputs(args) == {
        "params": "params.json",
        "sender_summary": "sender_summary.json",
        "bench": "bench.csv",
        "samples": "samples/metrics.ndjson",
        "monitor_dir": "monitor",
    }


def test_inputs_skip_what_the_run_does_not_have(tmp_path):
    args = rs.argparse.Namespace(out=str(tmp_path / "summary.json"), params=None,
                                 sender_json=None, bench=str(tmp_path / "bench.csv"),
                                 samples=None, monitor_dir=None)
    assert rs.relative_inputs(args) == {"bench": "bench.csv"}


# ---------------------------------------------------------------------------
# Run boundaries — the summary and the charts must read the same run
# ---------------------------------------------------------------------------
@pytest.fixture
def two_runs_file(tmp_path):
    """One file, two runs of the same label: 100 -> 150, then 200 -> 220."""
    path = str(tmp_path / "samples" / "metrics.ndjson")
    first = bs.NdjsonWriter(path, label="reused")
    first.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    first.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": 100}))
    first.write(bs.sample_line("inventory-sync", "T2", 2.0, {"sync.docs.indexed": 150}))
    first.close()
    second = bs.NdjsonWriter(path, label="reused")
    second.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    second.write(bs.sample_line("inventory-sync", "T3", 1.0, {"sync.docs.indexed": 200}))
    second.write(bs.sample_line("inventory-sync", "T4", 2.0, {"sync.docs.indexed": 220}))
    second.close()
    return path, second.run_id


def test_reused_label_reports_the_last_run_not_the_sum(two_runs_file):
    """The regression: reading the file whole gave 220-100=120 for a run that moved 20.

    run_benchmark.sh reuses `results_<label>/` and the collectors append, so the summary
    was reporting a delta across both runs while the charts, which trimmed to the last,
    showed the second alone -- two different numbers from one file.
    """
    path, second_id = two_runs_file
    inv = rs.aggregate_samples(path)["inventory-sync"]
    assert inv["delta"]["sync.docs.indexed"] == 20
    assert inv["samples"] == 2
    assert inv["run"] == second_id


def test_summary_and_charts_agree_on_the_same_file(two_runs_file):
    """The two consumers must not disagree; this is the invariant, not the number 20."""
    pytest.importorskip("pandas")
    path, _ = two_runs_file
    charted = bs.project(path, "inventory-sync")["sync_docs_indexed"]
    aggregated = rs.aggregate_samples(path)["inventory-sync"]
    assert aggregated["delta"]["sync.docs.indexed"] == charted.iloc[-1] - charted.iloc[0]
    assert aggregated["final"]["sync.docs.indexed"] == charted.iloc[-1]


def test_summary_names_the_run_it_aggregated(two_runs_file):
    """A reader has to be able to tell which run the numbers came from."""
    path, second_id = two_runs_file
    for block in rs.aggregate_samples(path).values():
        assert block["run"] == second_id


# ---------------------------------------------------------------------------
# Metric kinds — what may legitimately be computed from a series
# ---------------------------------------------------------------------------
@pytest.fixture
def typed_file(tmp_path):
    """A run carrying one of each kind, with the declared types the module publishes."""
    path = str(tmp_path / "samples" / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="kinds")
    w.write(bs.meta_line("inventory-sync", "/s", {
        "sync.docs.indexed": "counter",
        "server.sessions.live": "pull",
        "vd.lane.depth": "gauge_int",
    }))
    w.write(bs.sample_line("inventory-sync", "T1", 1.0,
                           {"sync.docs.indexed": 100, "server.sessions.live": 5,
                            "vd.lane.depth": 3}))
    w.write(bs.sample_line("inventory-sync", "T2", 2.0,
                           {"sync.docs.indexed": 150, "server.sessions.live": 2,
                            "vd.lane.depth": 9}))
    w.close()
    return path


def test_a_level_gets_no_delta(typed_file):
    """5 live sessions then 2 is not "-3 sessions". It is a level that moved.

    The aggregation used to publish that subtraction as a delta for every gauge and pull in
    the dump, because it never looked at the type the file had been carrying all along.
    """
    inv = rs.aggregate_samples(typed_file)["inventory-sync"]
    assert "server.sessions.live" not in inv["delta"]
    assert "vd.lane.depth" not in inv["delta"]
    assert inv["levels"]["server.sessions.live"] == {"first": 5, "last": 2, "min": 2, "max": 5}
    assert inv["levels"]["vd.lane.depth"] == {"first": 3, "last": 9, "min": 3, "max": 9}


def test_a_counter_gets_its_delta(typed_file):
    inv = rs.aggregate_samples(typed_file)["inventory-sync"]
    assert inv["counters"]["sync.docs.indexed"]["delta"] == 50
    assert inv["delta"]["sync.docs.indexed"] == 50
    assert inv["counters"]["sync.docs.indexed"]["resets"] == 0


def test_text_keeps_its_value(tmp_path):
    """A name is not a measurement, and coercing it produced 0.0 for BOTH delta and final --
    the reading was destroyed, not just mis-summarised."""
    path = str(tmp_path / "samples" / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="text")
    for value in (10, 20):
        e = bs.extract_remoted({"message": "ok", "data": {"name": "wazuh-manager-remoted",
                                                          "metrics": {"bytes": {"received": value}}}})
        w.write(bs.meta_line_from("remoted", "/s", e))
        w.write(bs.sample_line_from("remoted", "T", 1.0, e))
    w.close()

    rem = rs.aggregate_samples(path)["remoted"]
    assert rem["text"]["data.name"] == "wazuh-manager-remoted"
    assert rem["text"]["message"] == "ok"
    for flat in ("delta", "final", "peak"):
        assert "data.name" not in rem[flat], f"a string must not appear in {flat}"
    assert rem["delta"]["data.metrics.bytes.received"] == 10


def test_large_counters_stay_exact(tmp_path):
    """2**53 is where a float stops being able to tell consecutive integers apart.

    The aggregation ran every reading through float() on the way in, so a counter stepping
    by one across that boundary reported a delta of zero.
    """
    path = str(tmp_path / "samples" / "metrics.ndjson")
    big = 2 ** 53
    w = bs.NdjsonWriter(path, label="big")
    w.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    w.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": big}))
    w.write(bs.sample_line("inventory-sync", "T2", 2.0, {"sync.docs.indexed": big + 1}))
    w.close()

    inv = rs.aggregate_samples(path)["inventory-sync"]
    assert inv["delta"]["sync.docs.indexed"] == 1
    assert isinstance(inv["delta"]["sync.docs.indexed"], int), "an int must not become a float"
    assert inv["final"]["sync.docs.indexed"] == big + 1


def test_a_counter_reset_is_counted_not_negated(tmp_path):
    """A counter only falls by restarting. The work after the restart still happened."""
    path = str(tmp_path / "samples" / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="reset")
    w.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    for value in (100, 150, 10, 30):      # daemon restarts between 150 and 10
        w.write(bs.sample_line("inventory-sync", "T", 1.0, {"sync.docs.indexed": value}))
    w.close()

    counter = rs.aggregate_samples(path)["inventory-sync"]["counters"]["sync.docs.indexed"]
    assert counter["delta"] == 80, "50 before the restart, 30 after it"
    assert counter["resets"] == 1, "and the restart is reported, not hidden"
    assert counter["last"] == 30


def test_an_undeclared_series_is_a_level_however_it_moves(tmp_path):
    """Classification must not depend on the load.

    An undeclared numeric series used to be called a counter when it happened never to go
    down, so `tcp_sessions` was a counter under steady traffic and a level under traffic
    that closed connections -- the same metric in a different category between two runs of
    the same scenario, and two summaries that cannot be compared.
    """
    for values in ([3, 4, 5], [3, 2, 5]):
        path = str(tmp_path / f"u{values[1]}.ndjson")
        w = bs.NdjsonWriter(path)
        for v in values:
            w.write(bs.sample_line("remoted", "T", 1.0, {"some.undeclared.series": v}))
        w.close()
        rem = rs.aggregate_samples(path)["remoted"]
        assert "some.undeclared.series" in rem["levels"], values
        assert "some.undeclared.series" not in rem["delta"], values


def test_remoted_metrics_are_classified_from_the_declared_table(tmp_path):
    """remoted publishes a document with no types, so REMOTED_TYPES supplies them: its
    counters keep their delta and its gauges never get one, whatever the readings did."""
    path = str(tmp_path / "remoted.ndjson")
    w = bs.NdjsonWriter(path)
    for i, sessions in enumerate((3, 4, 5)):          # only ever rises
        e = bs.extract_remoted({"data": {"metrics": {
            "tcp_sessions": sessions,
            "bytes": {"received": 100 + i * 10},
            "queues": {"received": {"size": 67108864, "usage": 0.5}},
        }}})
        w.write(bs.meta_line_from("remoted", "/s", e))
        w.write(bs.sample_line_from("remoted", f"T{i}", float(i), e))
    w.close()

    rem = rs.aggregate_samples(path)["remoted"]
    assert rem["delta"]["data.metrics.bytes.received"] == 20, "a counter keeps its delta"
    assert "data.metrics.tcp_sessions" in rem["levels"], "live connections are a level"
    assert "data.metrics.tcp_sessions" not in rem["delta"]
    assert "data.metrics.queues.received.size" in rem["levels"], "queue capacity is a level"
    assert "data.metrics.queues.received.usage" in rem["levels"], "and so is its occupancy"


def test_declared_type_beats_what_the_readings_happen_to_do(typed_file):
    """A gauge that only rose during the run is still a gauge."""
    inv = rs.aggregate_samples(typed_file)["inventory-sync"]
    assert "vd.lane.depth" in inv["levels"], "3 -> 9 never dipped, but gauge_int says level"
    assert "vd.lane.depth" not in inv["counters"]


def test_a_metric_registered_mid_run_is_classified_by_its_type(tmp_path):
    """The end of the chain: a late metric must be classified, not treated as undeclared.

    An undeclared numeric series that only rises is inferred to be a counter, so a gauge
    that appeared late and happened not to dip would have been handed a delta.
    """
    path = str(tmp_path / "samples" / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="late")
    w.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    w.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": 10}))
    w.write(bs.meta_line("inventory-sync", "/s",
                         {"sync.docs.indexed": "counter", "vd.lane.depth": "gauge_int"}))
    # Registered late and only ever rises: inference alone would call it a counter.
    w.write(bs.sample_line("inventory-sync", "T2", 2.0,
                           {"sync.docs.indexed": 20, "vd.lane.depth": 3}))
    w.write(bs.sample_line("inventory-sync", "T3", 3.0,
                           {"sync.docs.indexed": 30, "vd.lane.depth": 9}))
    w.close()

    inv = rs.aggregate_samples(path)["inventory-sync"]
    assert "vd.lane.depth" in inv["levels"], "its declared type arrived in the second manifest"
    assert "vd.lane.depth" not in inv["delta"]
    assert inv["descriptors"]["vd.lane.depth"]["type"] == "gauge_int"
    assert inv["delta"]["sync.docs.indexed"] == 20


def test_a_disabled_histogram_is_left_out_of_the_summary(tmp_path):
    """The summary read `h` directly, so a disabled histogram's distribution was published
    under `histograms` as if the run had measured it."""
    path = str(tmp_path / "samples" / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="off-hist")
    w.write(bs.sample_line(
        "inventory-sync", "T1", 1.0,
        {"sync.docs.indexed": 5, "vd.lane.time": 3, "vd.scan.duration": 2},
        hists={"vd.lane.time": {"count": 3, "p99": 40},
               "vd.scan.duration": {"count": 2, "p99": 15}},
        disabled=["vd.lane.time"]))
    w.close()

    inv = rs.aggregate_samples(path)["inventory-sync"]
    assert "vd.lane.time" not in inv["histograms"], "a disabled histogram is not a measurement"
    assert inv["histograms"]["vd.scan.duration"]["p99"] == 15
    assert "vd.lane.time" not in inv["delta"], "nor is its observation count a counter"
    assert inv["disabled"] == ["vd.lane.time"], "but the fact that it was off is reported"


def test_remoted_classifies_from_the_table_even_without_a_manifest(tmp_path):
    """The types of a source that declares none on the wire are knowledge about the daemon,
    not about the file, so they apply when reading a run recorded before the table existed."""
    path = str(tmp_path / "samples" / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="no-manifest")
    for i, sessions in enumerate((3, 4, 5)):
        w.write(bs.sample_line("remoted", f"T{i}", float(i), {
            "data.metrics.tcp_sessions": sessions,
            "data.metrics.bytes.received": 100 + i * 10}))
    w.close()

    rem = rs.aggregate_samples(path)["remoted"]
    assert rem["descriptors"] == {}, "the file declares nothing"
    assert rem["delta"]["data.metrics.bytes.received"] == 20, "the table still supplies the type"
    assert "data.metrics.tcp_sessions" in rem["levels"]


def test_the_file_wins_over_the_static_table(tmp_path):
    """A module that starts declaring a type must be believed over anything hardcoded."""
    path = str(tmp_path / "samples" / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="declared")
    w.write(bs.meta_line("remoted", "/s", {"data.metrics.tcp_sessions": "counter"}))
    for v in (3, 4, 5):
        w.write(bs.sample_line("remoted", "T", 1.0, {"data.metrics.tcp_sessions": v}))
    w.close()

    rem = rs.aggregate_samples(path)["remoted"]
    assert rem["delta"]["data.metrics.tcp_sessions"] == 2, "the file said counter"


def test_the_projection_and_the_summary_agree_across_a_gap(tmp_path):
    """Two readers of one file cannot report different movement.

    A missing sample used to turn an integer column into float64 in the projection, so a
    counter crossing 2**53 across a failed scrape showed no movement there while the
    summary, which never leaves Python ints, showed one.
    """
    pytest.importorskip("pandas")
    big = 2 ** 53
    path = str(tmp_path / "gap.ndjson")
    w = bs.NdjsonWriter(path)
    w.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    w.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": big}))
    w.write(bs.error_line("inventory-sync", "T2", 2.0, "boom"))
    w.write(bs.sample_line("inventory-sync", "T3", 3.0, {"sync.docs.indexed": big + 1}))
    w.close()

    column = bs.project(path, "inventory-sync")["docs_indexed"]
    delta = rs.aggregate_samples(path)["inventory-sync"]["delta"]["sync.docs.indexed"]
    assert column.iloc[-1] - column.iloc[0] == delta == 1
