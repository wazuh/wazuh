# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_bench_samples.py -v

"""Tests for the manager_benchmark sample format.

The properties under test are the ones the format exists to guarantee: a metric absent
from a dump stays absent instead of becoming a zero, a failed scrape records no metrics
at all, nothing the module published is dropped for want of an alias, and the derived
CSV still reproduces the wide rows the collectors used to write.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import bench_samples as bs


# ---------------------------------------------------------------------------
# Fixtures — dumps in each module's real response shape
# ---------------------------------------------------------------------------
@pytest.fixture
def invsync_dump():
    """inventory_sync_server GET /metrics: a wazuh_metrics registry dump.

    Deliberately partial: it carries two shards and a histogram, and it OMITS most of the
    aliased catalog, which is what a build that has not registered those metrics looks
    like on the wire.
    """
    return {
        "name": "inventory_sync_server",
        "timestamp": "2026-08-25T13:40:49Z",
        "metrics": [
            {"name": "sync.requests.total.200", "type": "counter", "enabled": True, "value": 476,
             "description": "Sessions answered 200", "unit": "requests"},
            {"name": "sync.docs.indexed", "type": "counter", "enabled": True, "value": 1200,
             "description": "Documents indexed", "unit": "documents"},
            {"name": "sync.shard.0.depth", "type": "pull", "enabled": True, "value": 3.0},
            {"name": "sync.shard.1.depth", "type": "pull", "enabled": True, "value": 7.0},
            {"name": "sync.shard.0.bytes", "type": "pull", "enabled": True, "value": 1024.0},
            {"name": "sync.shard.1.bytes", "type": "pull", "enabled": True, "value": 2048.0},
            {"name": "sync.brand.new.metric", "type": "counter", "enabled": True, "value": 9},
            {"name": "vd.lane.time", "type": "histogram", "enabled": True, "value": 9,
             "summary": {"count": 9, "sum": 81, "min": 1, "max": 40,
                         "p50": 10, "p90": 30, "p99": 35}},
        ],
    }


@pytest.fixture
def analysisd_dump():
    return {
        "status": "OK",
        "global": [
            {"name": "server.events.received", "type": "counter", "enabled": True, "value": 238},
            {"name": "router.queue.usage.percent", "type": "pull", "enabled": True, "value": 12.5},
        ],
        "spaces": [
            {"name": "standard", "metrics": [
                {"name": "events.unclassified", "type": "counter", "enabled": True, "value": 4},
            ]},
        ],
    }


@pytest.fixture
def remoted_dump():
    return {
        "error": 0,
        "message": "ok",
        "data": {
            "name": "wazuh-manager-remoted", "uptime": 100, "timestamp": 200,
            "metrics": {
                "bytes": {"received": 44328, "sent": 4450},
                "tcp_sessions": 3,
                "queues": {"received": {"size": 67108864, "usage": 0.25}},
            },
        },
    }


def _one_row(src, dump, tmp_path, name="one.ndjson"):
    """Project a single dump through the file, and return its one row as a dict.

    wide_row() used to give this directly; it existed to build the derived CSV, which the
    collectors no longer write. Going through the file keeps the tests on the path the
    charts and the export actually take.
    """
    pytest.importorskip("pandas")
    path = str(tmp_path / name)
    writer = bs.NdjsonWriter(path)
    writer.write(bs.sample_line_from(src, "T", 1.0, bs.SOURCES[src].extract(dump)))
    writer.close()
    df = bs.project(path, src)
    return {c: df[c].iloc[0] for c in df.columns}


# ---------------------------------------------------------------------------
# Extraction — nothing the module published may be dropped
# ---------------------------------------------------------------------------
def test_metrics_array_extraction_keeps_unaliased_metrics(invsync_dump):
    """A metric nobody has aliased still reaches the samples file.

    This is the regression the format change is for: the wide CSV could only carry what
    its table named, so a newly instrumented counter was silently discarded until someone
    edited monitor.py.
    """
    e = bs.extract_metrics_array(invsync_dump)
    metrics, hists, types = e.metrics, e.histograms, e.types

    assert "sync.brand.new.metric" in metrics
    assert metrics["sync.brand.new.metric"] == 9
    assert types["sync.brand.new.metric"] == "counter"
    aliased = {name for name, _ in bs.INVSYNC_SCALARS}
    assert "sync.brand.new.metric" not in aliased, "fixture must use a name with no alias"


def test_metrics_array_extraction_keeps_per_shard_detail(invsync_dump):
    """Per-shard gauges have no alias on purpose, and must survive anyway."""
    metrics = bs.extract_metrics_array(invsync_dump).metrics
    assert metrics["sync.shard.0.depth"] == 3.0
    assert metrics["sync.shard.1.bytes"] == 2048.0


def test_histogram_goes_to_its_own_object(invsync_dump):
    """A histogram's distribution belongs in `h`, not among the scalars.

    Keeping them apart is what lets a consumer refuse to compute a delta on a percentile
    without having to guess from the metric's name.
    """
    e = bs.extract_metrics_array(invsync_dump)
    metrics, hists = e.metrics, e.histograms
    assert hists["vd.lane.time"]["p99"] == 35
    assert metrics["vd.lane.time"] == 9, "the scalar value is the observation count"


def test_analysisd_extraction_flattens_spaces(analysisd_dump):
    e = bs.extract_analysisd(analysisd_dump)
    metrics, types = e.metrics, e.types
    assert metrics["server.events.received"] == 238
    assert metrics["spaces.standard.events.unclassified"] == 4
    assert types["router.queue.usage.percent"] == "pull"


def test_remoted_extraction_flattens_nested_document(remoted_dump):
    metrics = bs.extract_remoted(remoted_dump).metrics
    assert metrics["data.metrics.bytes.received"] == 44328
    assert metrics["data.metrics.queues.received.usage"] == 0.25
    assert metrics["message"] == "ok"


# ---------------------------------------------------------------------------
# The absent-is-not-zero contract
# ---------------------------------------------------------------------------
def test_a_metric_never_observed_has_no_column(invsync_dump, tmp_path):
    """The defect this format replaces: an unregistered metric read as a hard zero.

    `sync.docs.skipped` is in the alias table but not in the dump. It gets no column at
    all, rather than a column of zeros -- indistinguishable-from-zero was how a metric that
    did not exist in the build under test got charted as a flat line along the x axis.
    """
    row = _one_row("inventory-sync", invsync_dump, tmp_path)
    assert row["docs_indexed"] == 1200, "a metric that IS present keeps its value"
    assert "docs_skipped" not in row, "a metric no scrape carried is not a column of zeros"
    assert "requests_503" not in row


def test_a_metric_missing_from_only_some_scrapes_is_nan_there(tmp_path):
    """Observed once, then gone: the column exists and the gap is NaN, not 0."""
    pd = pytest.importorskip("pandas")
    path = str(tmp_path / "metrics.ndjson")
    w = bs.NdjsonWriter(path)
    w.write(bs.sample_line("inventory-sync", "T1", 1.0,
                           {"sync.docs.indexed": 5, "sync.docs.skipped": 2}))
    w.write(bs.sample_line("inventory-sync", "T2", 2.0, {"sync.docs.indexed": 9}))
    w.close()

    df = bs.project(path, "inventory-sync")
    assert df["docs_skipped"].tolist()[0] == 2
    assert pd.isna(df["docs_skipped"].iloc[1]), "the scrape that lacked it must not read 0"


def test_failed_scrape_records_no_metrics():
    """A failed scrape observed nothing, so it must contribute nothing.

    Writing zeros here would look like a counter reset to every consumer computing a
    delta, and turn an unreachable socket into a fake drop to zero on every chart.
    """
    line = bs.error_line("inventory-sync", "T", 5.0, "connection refused")
    assert line["ok"] is False
    assert "m" not in line and "h" not in line
    assert line["err"] == "connection refused"




def test_sample_line_omits_empty_histograms():
    line = bs.sample_line("analysisd", "T", 1.0, {"a.b": 1}, {})
    assert "h" not in line
    assert bs.sample_line("analysisd", "T", 1.0, {"a.b": 1}, {"x": {"p99": 1}})["h"]


# ---------------------------------------------------------------------------
# Derived columns
# ---------------------------------------------------------------------------
def test_shard_aggregates_are_machine_independent(invsync_dump, tmp_path):
    """Aggregates, not a column per shard: the shard count follows the worker count, so
    per-shard columns would make two machines' runs different widths."""
    row = _one_row("inventory-sync", invsync_dump, tmp_path)
    assert row["shard_count"] == 2
    assert row["shard_depth_max"] == 7
    assert row["shard_depth_sum"] == 10
    assert row["shard_bytes_max"] == 2048
    assert row["shard_bytes_sum"] == 3072
    assert all(f"sync_shard_{i}_depth" in row for i in (0, 1)), \
        "and the per-shard detail is reachable, which no fixed header allowed"


def test_histogram_fields_expand_to_columns(invsync_dump, tmp_path):
    pd = pytest.importorskip("pandas")
    row = _one_row("inventory-sync", invsync_dump, tmp_path)
    assert row["vd_lane_time_p99"] == 35
    assert row["vd_lane_time_count"] == 9
    assert "vd_scan_duration_p99" not in row, "a histogram absent from the dump has no column"


def test_numbers_and_text_keep_their_type(analysisd_dump, remoted_dump, tmp_path):
    """No hand-listed text columns: a column whose values will not parse as numbers is
    left alone, which is how remoted's daemon name and status survive projection."""
    row = _one_row("analysisd", analysisd_dump, tmp_path, "a.ndjson")
    assert row["router_queue_usage_percent"] == 12.5, "a percentage must not be truncated"

    row = _one_row("remoted", remoted_dump, tmp_path, "r.ndjson")
    assert row["message"] == "ok"
    assert row["data_name"] == "wazuh-manager-remoted"
    assert row["queues_received_usage"] == 0.25


# ---------------------------------------------------------------------------
# Round trip through the file
# ---------------------------------------------------------------------------
def test_read_samples_filters_by_source(tmp_path):
    """Four collectors append to one file, so a reader must be able to pick one out."""
    path = str(tmp_path / "metrics.ndjson")
    writer = bs.NdjsonWriter(path)
    writer.write(bs.meta_line("analysisd", "/sock", {"a.b": "counter"}))
    writer.write(bs.sample_line("analysisd", "T1", 1.0, {"a.b": 1}))
    writer.write(bs.sample_line("remoted", "T1", 1.0, {"error": 0}))
    writer.write(bs.sample_line("analysisd", "T2", 2.0, {"a.b": 2}))
    writer.close()

    ana = list(bs.read_samples(path, src="analysisd"))
    assert [s["m"]["a.b"] for s in ana] == [1, 2]
    assert len(list(bs.read_samples(path))) == 3, "meta lines are not samples"
    assert bs.read_types(path, "analysisd") == {"a.b": "counter"}


def test_truncated_last_line_is_skipped(tmp_path):
    """A run killed mid-write leaves one partial line; the rest is still good data."""
    path = str(tmp_path / "metrics.ndjson")
    with open(path, "w") as fh:
        fh.write(json.dumps(bs.sample_line("analysisd", "T1", 1.0, {"a.b": 1})) + "\n")
        fh.write('{"ts":"T2","t":2.0,"src":"analysi')
    samples = list(bs.read_samples(path, src="analysisd"))
    assert len(samples) == 1
    assert samples[0]["m"]["a.b"] == 1


def test_read_samples_on_missing_file_is_empty(tmp_path):
    assert list(bs.read_samples(str(tmp_path / "nope.ndjson"))) == []


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------
def test_projection_is_a_superset_of_the_aliased_columns(tmp_path, invsync_dump):
    """The projection must offer the aliased names AND the raw ones.

    The aliases are what the existing charts are keyed on; the raw names are what the
    wide CSV could never carry.
    """
    pytest.importorskip("pandas")
    path = str(tmp_path / "metrics.ndjson")
    source = bs.SOURCES["inventory-sync"]
    writer = bs.NdjsonWriter(path)
    writer.write(bs.sample_line_from("inventory-sync", "T1", 1.0, source.extract(invsync_dump)))
    writer.close()

    invsync_dump_names = {m["name"] for m in invsync_dump["metrics"]}
    df = bs.project(path, "inventory-sync")
    assert df["requests_200"].iloc[0] == 476, "aliased column"
    assert df["sync_shard_1_depth"].iloc[0] == 7.0, "raw per-shard column, no alias exists"
    assert df["sync_brand_new_metric"].iloc[0] == 9, "raw column for an unaliased metric"
    assert df["vd_lane_time_sum"].iloc[0] == 81, "histogram field with no aliased column"
    present = {m for m, _ in source.scalars if m in invsync_dump_names}
    for metric, column in source.scalars:
        if metric in present:
            assert column in df.columns, f"projection dropped the aliased column {column}"


def test_a_failed_scrape_projects_as_nan(tmp_path, invsync_dump):
    """A scrape that observed nothing must not pull every series down to zero."""
    pd = pytest.importorskip("pandas")
    path = str(tmp_path / "metrics.ndjson")
    source = bs.SOURCES["inventory-sync"]
    writer = bs.NdjsonWriter(path)
    writer.write(bs.sample_line_from("inventory-sync", "T1", 1.0, source.extract(invsync_dump)))
    writer.write(bs.error_line("inventory-sync", "T2", 2.0, "boom"))
    writer.close()

    df = bs.project(path, "inventory-sync")
    assert df["docs_indexed"].iloc[0] == 1200
    assert pd.isna(df["docs_indexed"].iloc[1]), "failed scrape must not project as 0"
    assert df["query_ok"].tolist() == [1, 0]
    assert df["query_error"].iloc[1] == "boom"


def test_project_rejects_an_unknown_source(tmp_path):
    pytest.importorskip("pandas")
    with pytest.raises(KeyError):
        bs.project(str(tmp_path / "metrics.ndjson"), "not-a-daemon")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def test_every_source_has_a_unique_export_name():
    """csv_name is now only the export's default filename, not a written artifact."""
    names = [s.csv_name for s in bs.SOURCES.values()]
    assert len(names) == len(set(names))


def test_alias_tables_have_no_duplicate_targets():
    """Two metrics aliased to one column would make the second silently overwrite the
    first, and the CSV would show one of them under the other's name."""
    for name, source in bs.SOURCES.items():
        columns = [col for _, col in source.scalars]
        assert len(columns) == len(set(columns)), f"{name} aliases two metrics to one column"
        metrics = [metric for metric, _ in source.scalars]
        assert len(metrics) == len(set(metrics)), f"{name} aliases one metric twice"



# ---------------------------------------------------------------------------
# Run boundaries
# ---------------------------------------------------------------------------
def _two_runs(path):
    """A file holding two runs of one source, as a reused benchmark label produces.

    Counters are cumulative for the module's lifetime, so the second run starts above
    where the first ended: 100 -> 150, then 200 -> 220.
    """
    first = bs.NdjsonWriter(path, label="reused-label")
    first.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": 100}))
    first.write(bs.sample_line("inventory-sync", "T2", 2.0, {"sync.docs.indexed": 150}))
    first.close()
    second = bs.NdjsonWriter(path, label="reused-label")
    second.write(bs.sample_line("inventory-sync", "T3", 1.0, {"sync.docs.indexed": 200}))
    second.write(bs.sample_line("inventory-sync", "T4", 2.0, {"sync.docs.indexed": 220}))
    second.close()
    return first.run_id, second.run_id


def test_reusing_a_label_does_not_merge_runs(tmp_path):
    """The file accumulates, so a reader must take one run or it reports both as one."""
    path = str(tmp_path / "metrics.ndjson")
    first_id, second_id = _two_runs(path)
    assert first_id != second_id

    values = [s["m"]["sync.docs.indexed"] for s in bs.read_samples(path, src="inventory-sync")]
    assert values == [200, 220], "the default read must be the last run only"
    assert bs.last_run_id(path) == second_id


def test_earlier_runs_are_still_reachable(tmp_path):
    """Appending keeps the history; the default just does not silently span it."""
    path = str(tmp_path / "metrics.ndjson")
    first_id, _ = _two_runs(path)

    all_values = [s["m"]["sync.docs.indexed"]
                  for s in bs.read_samples(path, src="inventory-sync", run="all")]
    assert all_values == [100, 150, 200, 220]
    first_values = [s["m"]["sync.docs.indexed"]
                    for s in bs.read_samples(path, src="inventory-sync", run=first_id)]
    assert first_values == [100, 150]


def test_projection_is_scoped_to_one_run(tmp_path):
    """The charts read through project(), so it must not span runs either."""
    pytest.importorskip("pandas")
    path = str(tmp_path / "metrics.ndjson")
    _two_runs(path)
    df = bs.project(path, "inventory-sync")
    assert df["sync_docs_indexed"].tolist() == [200.0, 220.0]
    assert len(bs.project(path, "inventory-sync", run="all")) == 4


def test_run_marker_is_not_a_sample(tmp_path):
    path = str(tmp_path / "metrics.ndjson")
    writer = bs.NdjsonWriter(path, label="x")
    writer.write(bs.sample_line("analysisd", "T1", 1.0, {"a.b": 1}))
    writer.close()

    assert len(list(bs.read_samples(path))) == 1, "the run marker must not read as a sample"
    markers = [o for o in bs._iter_lines(path) if o.get("kind") == "run"]
    assert markers[0]["label"] == "x"
    assert markers[0]["r"] == writer.run_id
    assert markers[0]["started"]


def test_every_written_line_carries_its_run(tmp_path):
    """Callers do not pass the id around, so the writer has to attach it to everything."""
    path = str(tmp_path / "metrics.ndjson")
    writer = bs.NdjsonWriter(path)
    writer.write(bs.meta_line("analysisd", "/sock", {"a.b": "counter"}))
    writer.write(bs.sample_line("analysisd", "T1", 1.0, {"a.b": 1}))
    writer.write(bs.error_line("analysisd", "T2", 2.0, "boom"))
    writer.close()
    assert all(o.get("r") == writer.run_id for o in bs._iter_lines(path))


def test_file_without_run_ids_is_read_whole(tmp_path):
    """A samples file written before run ids existed is one run's worth, not zero."""
    path = str(tmp_path / "metrics.ndjson")
    with open(path, "w") as fh:
        for value in (100, 150):
            line = bs.sample_line("inventory-sync", "T", 1.0, {"sync.docs.indexed": value})
            fh.write(json.dumps(line) + "\n")
    assert bs.last_run_id(path) is None
    assert len(list(bs.read_samples(path, src="inventory-sync"))) == 2


def test_run_ids_sort_in_start_order(tmp_path):
    """"The last run" must be the same answer by file order and by id order."""
    ids = [bs.new_run_id() for _ in range(3)]
    assert len(set(ids)) == 3, "two runs in the same second must still differ"
    assert [i[:8] for i in ids] == sorted(i[:8] for i in ids)


# ---------------------------------------------------------------------------
# Payload fidelity — what the dump said must be recoverable from the file
# ---------------------------------------------------------------------------
def test_descriptors_are_preserved(invsync_dump):
    """unit and description are part of the payload, not decoration.

    They used to survive only because the whole response was pasted into every CSV row;
    dropping that column without capturing them would have made the new format lossier
    than the one it replaced, whatever the column-by-column comparison said.
    """
    e = bs.extract_metrics_array(invsync_dump)
    assert e.units["sync.docs.indexed"] == "documents"
    assert e.descriptions["sync.docs.indexed"] == "Documents indexed"
    assert e.types["sync.docs.indexed"] == "counter"


def test_server_document_scalars_are_preserved(invsync_dump, analysisd_dump):
    """The dump's own fields: which daemon answered, and its clock -- not the collector's."""
    inv = bs.extract_metrics_array(invsync_dump)
    assert inv.doc["name"] == "inventory_sync_server"
    assert inv.doc["timestamp"] == "2026-08-25T13:40:49Z"
    assert "metrics" not in inv.doc, "the metric array is not a document scalar"

    ana = bs.extract_analysisd(analysisd_dump)
    assert ana.doc["status"] == "OK"
    assert "global" not in ana.doc and "spaces" not in ana.doc


def test_descriptors_round_trip_through_the_file(tmp_path, invsync_dump):
    path = str(tmp_path / "metrics.ndjson")
    writer = bs.NdjsonWriter(path)
    e = bs.SOURCES["inventory-sync"].extract(invsync_dump)
    writer.write(bs.meta_line_from("inventory-sync", "/sock", e))
    writer.write(bs.sample_line_from("inventory-sync", "T1", 1.0, e))
    writer.close()

    got = bs.read_descriptors(path, "inventory-sync")
    assert got["sync.docs.indexed"] == {"type": "counter", "unit": "documents",
                                        "description": "Documents indexed"}
    sample = next(bs.read_samples(path, src="inventory-sync"))
    assert sample["d"]["timestamp"] == "2026-08-25T13:40:49Z"


def test_a_changed_descriptor_wins_over_the_earlier_one(tmp_path):
    """Descriptors are written once, but "once" must not become an assumption."""
    path = str(tmp_path / "metrics.ndjson")
    writer = bs.NdjsonWriter(path)
    writer.write(bs.meta_line("analysisd", "/s", {"a.b": "counter"}, {"a.b": "bytes"}))
    writer.write(bs.meta_line("analysisd", "/s", {"a.b": "counter"}, {"a.b": "kibibytes"}))
    writer.close()
    assert bs.read_descriptors(path, "analysisd")["a.b"]["unit"] == "kibibytes"


def test_nothing_the_dump_carried_is_unrecoverable(invsync_dump, analysisd_dump):
    """The guarantee, stated as a test: every key of every dump entry is captured.

    Fails the moment the wire format grows a field the extractor does not know about,
    which is the failure mode that made `raw_response_json` feel necessary.
    """
    captured_per_metric = {"name", "type", "enabled", "value", "summary", "unit", "description"}
    for dump, extract in ((invsync_dump, bs.extract_metrics_array),
                          (analysisd_dump, bs.extract_analysisd)):
        items = list(dump.get("metrics") or []) + list(dump.get("global") or [])
        for space in dump.get("spaces") or []:
            items += space.get("metrics") or []
        for item in items:
            unknown = set(item) - captured_per_metric
            assert not unknown, f"dump entry carries uncaptured fields: {unknown}"

        e = extract(dump)
        # And every doc-level scalar reached `doc`.
        for key, value in dump.items():
            if not isinstance(value, (dict, list)):
                assert e.doc[key] == value


# ---------------------------------------------------------------------------
# Disabled metrics
# ---------------------------------------------------------------------------
def test_a_disabled_metric_is_recorded_as_off():
    """jsonDump writes a value for a disabled metric too, so the flag has to travel."""
    dump = {"name": "m", "metrics": [
        {"name": "a.live", "type": "counter", "enabled": True, "value": 5},
        {"name": "a.stopped", "type": "counter", "enabled": False, "value": 99},
    ]}
    e = bs.extract_metrics_array(dump)
    assert e.disabled == ["a.stopped"]
    assert e.metrics["a.stopped"] == 99, "the raw reading is still captured verbatim"

    line = bs.sample_line_from("inventory-sync", "T", 1.0, e)
    assert line["off"] == ["a.stopped"]
    assert bs.observed(line)[0] == {"a.live": 5}, "a stopped metric is not an observation"


def test_disabled_metric_does_not_reach_a_column(tmp_path):
    """Its last value must not chart as a live reading -- a gap is the honest answer."""
    pd = pytest.importorskip("pandas")
    dump = {"name": "m", "metrics": [
        {"name": "sync.docs.indexed", "type": "counter", "enabled": True, "value": 5},
        {"name": "sync.docs.skipped", "type": "counter", "enabled": False, "value": 99},
    ]}
    path = str(tmp_path / "metrics.ndjson")
    writer = bs.NdjsonWriter(path)
    writer.write(bs.sample_line_from("inventory-sync", "T", 1.0,
                                     bs.SOURCES["inventory-sync"].extract(dump)))
    writer.close()

    df = bs.project(path, "inventory-sync")
    assert df["docs_indexed"].iloc[0] == 5
    assert "docs_skipped" not in df.columns or pd.isna(df["docs_skipped"].iloc[0]), \
        "a disabled metric must read as a gap, not 99"


def test_sample_line_omits_off_and_d_when_empty():
    """The uncommon case must not tax the common one."""
    line = bs.sample_line("analysisd", "T", 1.0, {"a.b": 1})
    assert "off" not in line and "d" not in line


def test_a_dump_can_be_rebuilt_from_the_file(tmp_path, invsync_dump):
    """The guarantee end to end: samples file in, the module's own response back out.

    This is what "lossless" has to mean. Comparing derived CSV columns proves the
    projection works, not that the payload survived -- the columns are a subset of the
    dump by construction, so they cannot notice a field nobody aliased going missing.
    """
    path = str(tmp_path / "metrics.ndjson")
    source = bs.SOURCES["inventory-sync"]
    extraction = source.extract(invsync_dump)
    writer = bs.NdjsonWriter(path)
    writer.write(bs.meta_line_from("inventory-sync", "/sock", extraction))
    writer.write(bs.sample_line_from("inventory-sync", "T1", 1.0, extraction))
    writer.close()

    descriptors = bs.read_descriptors(path, "inventory-sync")
    sample = next(bs.read_samples(path, src="inventory-sync"))

    rebuilt = dict(sample["d"])
    off = set(sample.get("off") or ())
    items = []
    for name, value in sample["m"].items():
        d = descriptors.get(name, {})
        item = {"name": name, "type": d.get("type"), "enabled": name not in off, "value": value}
        if d.get("description"):
            item["description"] = d["description"]
        if d.get("unit"):
            item["unit"] = d["unit"]
        if name in (sample.get("h") or {}):
            item["summary"] = sample["h"][name]
        items.append(item)
    rebuilt["metrics"] = items

    def norm(doc):
        doc = json.loads(json.dumps(doc))
        doc["metrics"] = sorted(doc["metrics"], key=lambda i: i["name"])
        return doc

    assert norm(rebuilt) == norm(invsync_dump)


# ---------------------------------------------------------------------------
# Manifest revisions — a module may register a metric after the run started
# ---------------------------------------------------------------------------
def _file_with_a_revised_manifest(path):
    """A run whose second manifest adds a metric the first did not describe."""
    w = bs.NdjsonWriter(path, label="late")
    w.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"},
                         {"sync.docs.indexed": "documents"},
                         {"sync.docs.indexed": "Documents indexed"}))
    w.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": 1}))
    w.write(bs.meta_line("inventory-sync", "/s",
                         {"sync.docs.indexed": "counter", "vd.lane.depth": "gauge_int"},
                         {"sync.docs.indexed": "documents", "vd.lane.depth": "items"},
                         {"sync.docs.indexed": "Documents indexed", "vd.lane.depth": "Lane depth"}))
    w.write(bs.sample_line("inventory-sync", "T2", 2.0,
                           {"sync.docs.indexed": 2, "vd.lane.depth": 7}))
    w.close()


def test_read_types_sees_a_later_manifest(tmp_path):
    """A manifest is a revision, not a one-shot header.

    read_types() used to walk the file itself and return the FIRST one, which undid the
    point of re-emitting: a metric registered after the first scrape kept its readings and
    lost its type, so a consumer classifying by type saw it as undeclared.
    """
    path = str(tmp_path / "metrics.ndjson")
    _file_with_a_revised_manifest(path)
    assert bs.read_types(path, "inventory-sync") == {
        "sync.docs.indexed": "counter", "vd.lane.depth": "gauge_int"}


def test_read_types_and_read_descriptors_cannot_disagree(tmp_path):
    """One traversal, so the two readers cannot drift the way they had."""
    path = str(tmp_path / "metrics.ndjson")
    _file_with_a_revised_manifest(path)
    assert bs.read_types(path, "inventory-sync") == {
        m: d["type"] for m, d in bs.read_descriptors(path, "inventory-sync").items()}


def test_a_late_metric_keeps_unit_and_description_too(tmp_path):
    path = str(tmp_path / "metrics.ndjson")
    _file_with_a_revised_manifest(path)
    assert bs.read_descriptors(path, "inventory-sync")["vd.lane.depth"] == {
        "type": "gauge_int", "unit": "items", "description": "Lane depth"}


def test_a_revised_descriptor_takes_the_latest_value(tmp_path):
    path = str(tmp_path / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="revised")
    w.write(bs.meta_line("analysisd", "/s", {"a.b": "counter"}, {"a.b": "bytes"}))
    w.write(bs.meta_line("analysisd", "/s", {"a.b": "gauge_int"}, {"a.b": "kibibytes"}))
    w.close()
    assert bs.read_types(path, "analysisd")["a.b"] == "gauge_int"
    assert bs.read_descriptors(path, "analysisd")["a.b"]["unit"] == "kibibytes"


def test_an_unregistered_metric_keeps_the_type_it_declared(tmp_path):
    """Its readings are still in the run, and they still need classifying."""
    path = str(tmp_path / "metrics.ndjson")
    w = bs.NdjsonWriter(path, label="gone")
    w.write(bs.meta_line("analysisd", "/s", {"a.b": "counter", "a.gone": "gauge_int"}))
    w.write(bs.sample_line("analysisd", "T1", 1.0, {"a.b": 1, "a.gone": 5}))
    w.write(bs.meta_line("analysisd", "/s", {"a.b": "counter"}))
    w.write(bs.sample_line("analysisd", "T2", 2.0, {"a.b": 2}))
    w.close()
    assert bs.read_types(path, "analysisd")["a.gone"] == "gauge_int"


def test_a_disabled_histogram_is_not_a_measurement():
    """`off` has to reach `h` as well, not just `m`.

    wazuh_metrics emits a summary for a disabled histogram exactly as it emits a value for a
    disabled counter, so a p99 left unfiltered is a stale distribution reported as if it had
    been measured during the run. observed() returns both objects for this reason: filtering
    one and leaving the caller to fetch the other is how the histograms were missed.
    """
    dump = {"name": "inv", "metrics": [
        {"name": "vd.lane.time", "type": "histogram", "enabled": False, "value": 3,
         "summary": {"count": 3, "p50": 30, "p90": 40, "p99": 40, "max": 40}},
        {"name": "vd.scan.duration", "type": "histogram", "enabled": True, "value": 2,
         "summary": {"count": 2, "p50": 10, "p90": 15, "p99": 15, "max": 15}},
    ]}
    line = bs.sample_line_from("inventory-sync", "T", 1.0,
                               bs.SOURCES["inventory-sync"].extract(dump))
    metrics, hists = bs.observed(line)
    assert "vd.lane.time" not in hists, "a disabled histogram is not an observation"
    assert "vd.lane.time" not in metrics, "nor is its observation count"
    assert hists["vd.scan.duration"]["p99"] == 15, "an enabled one is untouched"
    # The raw reading is still captured verbatim; it is the READING that is filtered.
    assert line["h"]["vd.lane.time"]["p99"] == 40


def test_a_disabled_histogram_does_not_reach_the_projection(tmp_path):
    pytest.importorskip("pandas")
    dump = {"name": "inv", "metrics": [
        {"name": "vd.lane.time", "type": "histogram", "enabled": False, "value": 3,
         "summary": {"count": 3, "p50": 30, "p90": 40, "p99": 40, "max": 40}},
        {"name": "sync.docs.indexed", "type": "counter", "enabled": True, "value": 5},
    ]}
    path = str(tmp_path / "metrics.ndjson")
    w = bs.NdjsonWriter(path)
    w.write(bs.sample_line_from("inventory-sync", "T", 1.0,
                                bs.SOURCES["inventory-sync"].extract(dump)))
    w.close()

    df = bs.project(path, "inventory-sync")
    assert df["docs_indexed"].iloc[0] == 5
    assert "vd_lane_time_p99" not in df.columns, "the aliased histogram column must not appear"
    assert "vd_lane_time_p50" not in df.columns, "nor the raw one"


def test_shard_aggregates_are_absent_when_no_shard_was_observed(tmp_path):
    """A derived column can invent a measurement exactly like a raw one.

    A scrape that carried no shard gauges used to produce `shard_depth_sum=0`, which plots
    as a measured zero for a scrape that observed nothing -- the behaviour the format exists
    to remove, reintroduced by the aggregation on top of it.
    """
    pytest.importorskip("pandas")
    path = str(tmp_path / "metrics.ndjson")
    w = bs.NdjsonWriter(path)
    w.write(bs.sample_line("inventory-sync", "T", 1.0, {"sync.docs.indexed": 5}))
    w.close()

    assert bs._invsync_shard_aggregates({"sync.docs.indexed": 5}) == {}
    df = bs.project(path, "inventory-sync")
    assert df["docs_indexed"].iloc[0] == 5
    for column in ("shard_count", "shard_depth_max", "shard_depth_sum",
                   "shard_bytes_max", "shard_bytes_sum"):
        assert column not in df.columns, f"{column} was never measured"


def test_each_shard_family_aggregates_on_its_own():
    """Observing depths says nothing about bytes, so one family must not fill in the other."""
    only_depths = bs._invsync_shard_aggregates(
        {"sync.shard.0.depth": 3, "sync.shard.1.depth": 7})
    assert only_depths == {"shard_count": 2, "shard_depth_max": 7, "shard_depth_sum": 10}
    assert "shard_bytes_sum" not in only_depths


def test_shard_count_covers_every_shard_seen():
    """It used to be len(depths), so a build publishing only bytes reported zero shards."""
    assert bs._invsync_shard_aggregates(
        {"sync.shard.0.bytes": 10, "sync.shard.1.bytes": 20})["shard_count"] == 2
    assert bs._invsync_shard_aggregates(
        {"sync.shard.0.depth": 3, "sync.shard.1.bytes": 20})["shard_count"] == 2


def test_shard_aggregates_still_describe_imbalance(tmp_path):
    """The reason they exist: max against sum, without a column per shard."""
    pytest.importorskip("pandas")
    path = str(tmp_path / "metrics.ndjson")
    w = bs.NdjsonWriter(path)
    w.write(bs.sample_line("inventory-sync", "T", 1.0,
                           {"sync.shard.0.depth": 1, "sync.shard.1.depth": 9,
                            "sync.shard.0.bytes": 100, "sync.shard.1.bytes": 900}))
    w.close()

    df = bs.project(path, "inventory-sync")
    assert df["shard_count"].iloc[0] == 2
    assert df["shard_depth_max"].iloc[0] == 9
    assert df["shard_depth_sum"].iloc[0] == 10
    assert df["shard_bytes_sum"].iloc[0] == 1000
    # And the per-shard detail is reachable, which no fixed header allowed.
    assert df["sync_shard_1_depth"].iloc[0] == 9


# ---------------------------------------------------------------------------
# Integer exactness in the projection
# ---------------------------------------------------------------------------
def _gap_run(tmp_path, first, last, name="metrics.ndjson"):
    """Two readings of a counter with a failed scrape between them."""
    path = str(tmp_path / name)
    w = bs.NdjsonWriter(path)
    w.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    w.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": first}))
    w.write(bs.error_line("inventory-sync", "T2", 2.0, "boom"))
    w.write(bs.sample_line("inventory-sync", "T3", 3.0, {"sync.docs.indexed": last}))
    w.close()
    return path


def test_a_gap_does_not_cost_the_column_its_precision(tmp_path):
    """A missing sample used to turn an integer column into float64.

    2**53 is where float64 stops telling consecutive integers apart, so a counter that
    crossed it across a failed scrape came out with both ends equal: the projection saw no
    movement where the summary, which never leaves Python ints, saw one.
    """
    pytest.importorskip("pandas")
    big = 2 ** 53
    column = bs.project(_gap_run(tmp_path, big, big + 1), "inventory-sync")["docs_indexed"]
    assert str(column.dtype) == "Int64", "an integral column with a gap must stay integral"
    assert column.iloc[0] == big
    assert column.iloc[-1] == big + 1
    assert column.iloc[-1] - column.iloc[0] == 1


def test_a_column_with_no_gap_keeps_the_plain_dtype(tmp_path):
    """Nullable Int64 only where a gap forces it; the common case is unchanged."""
    pytest.importorskip("pandas")
    path = str(tmp_path / "nogap.ndjson")
    w = bs.NdjsonWriter(path)
    for value in (1, 2):
        w.write(bs.sample_line("inventory-sync", "T", 1.0, {"sync.docs.indexed": value}))
    w.close()
    assert str(bs.project(path, "inventory-sync")["docs_indexed"].dtype) == "int64"


def test_a_float_metric_stays_a_float(tmp_path):
    """Pull metrics arrive as JSON doubles and must not be coerced into integers."""
    pytest.importorskip("pandas")
    path = str(tmp_path / "floats.ndjson")
    w = bs.NdjsonWriter(path)
    w.write(bs.sample_line("inventory-sync", "T1", 1.0, {"server.sessions.live": 1.5}))
    w.write(bs.error_line("inventory-sync", "T2", 2.0, "boom"))
    w.close()
    column = bs.project(path, "inventory-sync")["server_sessions_live"]
    assert str(column.dtype) == "float64"
    assert column.iloc[0] == 1.5


def test_the_exported_csv_keeps_the_increment(tmp_path):
    """The export goes through the same projection, so it inherits the exactness."""
    pytest.importorskip("pandas")
    import csv as _csv
    big = 2 ** 53
    run_dir = tmp_path / "results_x"
    (run_dir / "samples").mkdir(parents=True)
    w = bs.NdjsonWriter(str(run_dir / "samples" / "metrics.ndjson"))
    w.write(bs.sample_line("inventory-sync", "T1", 1.0, {"sync.docs.indexed": big}))
    w.write(bs.error_line("inventory-sync", "T2", 2.0, "boom"))
    w.write(bs.sample_line("inventory-sync", "T3", 3.0, {"sync.docs.indexed": big + 1}))
    w.close()

    rows = list(_csv.DictReader(open(bs.export_csv(str(run_dir), "inventory-sync"))))
    assert rows[0]["docs_indexed"] == str(big)
    assert rows[2]["docs_indexed"] == str(big + 1)
    assert rows[1]["docs_indexed"] == "", "the failed scrape stays a gap, not a 0"


def _run_with(tmp_path, values, metric="sync.docs.indexed", name="w.ndjson"):
    """A run of `values`, where None means a failed scrape."""
    path = str(tmp_path / name)
    w = bs.NdjsonWriter(path)
    for i, v in enumerate(values):
        if v is None:
            w.write(bs.error_line("inventory-sync", f"T{i}", float(i), "boom"))
        else:
            w.write(bs.sample_line("inventory-sync", f"T{i}", float(i), {metric: v}))
    w.close()
    return path


def test_a_counter_past_int64_does_not_kill_the_projection(tmp_path):
    """wazuh_metrics writes counters with writer.Uint64(), so INT64_MAX is not the ceiling.

    Forcing int64 raised OverflowError out of project(), which is not a rounding error but
    a dead source: no charts for that daemon and no export at all.
    """
    pytest.importorskip("pandas")
    big = 2 ** 63
    column = bs.project(_run_with(tmp_path, [big, big + 1]), "inventory-sync")["docs_indexed"]
    assert str(column.dtype) == "uint64"
    assert column.iloc[-1] - column.iloc[0] == 1


def test_a_counter_past_int64_survives_a_gap_too(tmp_path):
    pytest.importorskip("pandas")
    big = 2 ** 63
    column = bs.project(_run_with(tmp_path, [big, None, big + 1], name="g.ndjson"),
                        "inventory-sync")["docs_indexed"]
    assert str(column.dtype) == "UInt64", "unsigned and nullable at once"
    assert column.iloc[-1] - column.iloc[0] == 1


def test_a_signed_gauge_stays_signed(tmp_path):
    """The catalog has signed values -- cert_expiry_days goes negative once expired -- so
    the unsigned choice must depend on the data, not on the metric being a counter."""
    pytest.importorskip("pandas")
    column = bs.project(_run_with(tmp_path, [-5, 3], metric="vd.lane.depth", name="s.ndjson"),
                        "inventory-sync")["vd_lane_depth"]
    assert str(column.dtype) == "int64"
    assert column.iloc[0] == -5


def test_ordinary_counters_keep_the_plain_dtype(tmp_path):
    """The width is chosen per column, so the common case must not change type."""
    pytest.importorskip("pandas")
    assert str(bs.project(_run_with(tmp_path, [7, 9], name="o.ndjson"),
                          "inventory-sync")["docs_indexed"].dtype) == "int64"


def test_a_value_wider_than_uint64_degrades_instead_of_failing(tmp_path):
    """Nothing we publish reaches here, but a projection must not die on a number."""
    pytest.importorskip("pandas")
    column = bs.project(_run_with(tmp_path, [2 ** 64 + 1, 2 ** 64 + 2], name="h.ndjson"),
                        "inventory-sync")["docs_indexed"]
    assert str(column.dtype) == "float64", "lossy, but the source still charts"


@pytest.mark.parametrize("values", [[-1, 2 ** 63], [-1, None, 2 ** 63]])
def test_mixed_sign_wide_integers_do_not_kill_projection(tmp_path, values):
    pd = pytest.importorskip("pandas")
    column = bs.project(_run_with(tmp_path, values), "inventory-sync")["docs_indexed"]
    assert str(column.dtype) == "float64"
    assert column.iloc[0] == -1
    assert column.iloc[-1] == float(2 ** 63)
    if None in values:
        assert pd.isna(column.iloc[1])


# ---------------------------------------------------------------------------
# Finding the last run without reading the file
#
# The file is append-only and a reused label reuses its results directory, so it holds
# every run ever recorded under that label while every consumer reads only the last. The
# reader therefore seeks to that run instead of filtering the whole file down to it: on a
# file of twenty seven-minute runs, walking forwards cost 7.6s to describe the 420 scrapes
# it wanted, and the figure grew with each re-run. What these tests pin is that seeking
# returns the SAME lines the walk did -- a wrong offset would silently drop samples, since
# a half-line is skipped like any other malformed one.
# ---------------------------------------------------------------------------
def _marker_offsets(path):
    """The byte offset of every `run` marker, by walking the file the slow way."""
    offsets, pos = [], 0
    with open(path, "rb") as fh:
        for raw in fh:
            try:
                is_marker = json.loads(raw).get("kind") == "run"
            except ValueError:
                is_marker = False  # a blank line, or the half-line a kill leaves behind
            if is_marker:
                offsets.append(pos)
            pos += len(raw)
    return offsets


def _runs_file(tmp_path, runs=3, per_run=40, name="runs.ndjson"):
    """`runs` runs appended to one file, as a reused label produces."""
    path = str(tmp_path / name)
    for r in range(runs):
        w = bs.NdjsonWriter(path, label=f"run{r}")
        w.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
        for t in range(per_run):
            w.write(bs.sample_line("inventory-sync", f"T{t}", float(t),
                                   {"sync.docs.indexed": r * 1000 + t}))
        w.close()
    return path


def test_the_last_run_is_found_at_its_marker(tmp_path):
    path = _runs_file(tmp_path)
    run_id, offset = bs._last_run_start(path)

    assert offset == _marker_offsets(path)[-1], "must be the LAST marker, not the first"
    with open(path, "rb") as fh:
        fh.seek(offset)
        first = json.loads(fh.readline())
    assert first == {"kind": "run", "r": run_id, "started": first["started"],
                     "label": "run2"}, "the offset must land on a line boundary"


def test_history_does_not_change_what_the_last_run_reads(tmp_path):
    """The whole point: the same final run reads the same whether 1 run precedes it or 9."""
    short = list(bs.read_samples(_runs_file(tmp_path, runs=1, name="a.ndjson")))
    long = list(bs.read_samples(_runs_file(tmp_path, runs=10, name="b.ndjson")))

    assert len(short) == len(long) == 40, "the run's samples, whatever precedes them"
    # _runs_file numbers run r from r*1000, so the values say which run was read: the
    # long file must yield its tenth run and none of the 360 samples before it.
    assert [s["m"]["sync.docs.indexed"] for s in short] == list(range(0, 40))
    assert [s["m"]["sync.docs.indexed"] for s in long] == list(range(9000, 9040))


def test_seeking_does_not_lose_the_run_it_lands_in(tmp_path):
    """Every line of a run is written after its marker, so none can be before the offset."""
    path = _runs_file(tmp_path, runs=4, per_run=25)
    run_id, _ = bs._last_run_start(path)

    seen = list(bs.read_samples(path, src="inventory-sync"))
    assert len([s for s in seen if s.get("ok")]) == 25
    assert {s["r"] for s in seen} == {run_id}, "nothing from an earlier run leaked in"


@pytest.mark.parametrize("corrupt,why", [
    (lambda t: t + '{"ts":"T","src":"remo', "a run killed mid-write leaves half a line"),
    (lambda t: t.rstrip("\n"), "a file that does not end in a newline"),
    (lambda t: t.replace("\n", "\n\n"), "blank lines between records"),
])
def test_the_backwards_scan_survives_a_malformed_tail(tmp_path, corrupt, why):
    path = _runs_file(tmp_path, runs=2, per_run=10)
    with open(path) as fh:
        text = fh.read()
    with open(path, "w") as fh:
        fh.write(corrupt(text))

    run_id, offset = bs._last_run_start(path)
    assert run_id, why
    assert offset == _marker_offsets(path)[-1], why
    assert len([s for s in bs.read_samples(path) if s.get("ok")]) == 10, why


def test_a_run_longer_than_one_scan_block_is_still_found(tmp_path):
    """The scan reads fixed blocks backwards; a run bigger than one must still resolve."""
    path = str(tmp_path / "big.ndjson")
    w = bs.NdjsonWriter(path, label="first")
    w.write(bs.sample_line("inventory-sync", "T", 0.0, {"sync.docs.indexed": 0}))
    w.close()
    w = bs.NdjsonWriter(path, label="second")
    for t in range(400):  # ~500 B each, well past the 64 KiB block
        w.write(bs.sample_line("inventory-sync", f"T{t}", float(t),
                               {"sync.docs.indexed": t, "pad": "x" * 500}))
    w.close()

    assert bs._last_run_start(path)[1] == _marker_offsets(path)[-1]
    assert len(list(bs.read_samples(path))) == 400


def test_a_file_with_no_marker_is_read_whole(tmp_path):
    """The pre-marker fallback: nothing to scope by, so everything is in scope."""
    path = str(tmp_path / "markerless.ndjson")
    with open(path, "w") as fh:
        for t in range(3):
            fh.write(json.dumps(
                bs.sample_line("inventory-sync", f"T{t}", float(t),
                               {"sync.docs.indexed": t})) + "\n")

    assert bs._last_run_start(path) == (None, 0)
    assert len(list(bs.read_samples(path))) == 3


def test_an_explicit_run_id_still_reaches_earlier_runs(tmp_path):
    """Seeking is only for "last": naming a run must still find one further back."""
    path = _runs_file(tmp_path, runs=3, per_run=5)
    first_run = json.loads(open(path).readline())["r"]

    samples = [s for s in bs.read_samples(path, run=first_run) if s.get("ok")]
    assert len(samples) == 5
    assert {s["m"]["sync.docs.indexed"] for s in samples} == {0, 1, 2, 3, 4}


def _interrupted_then_reopened(tmp_path, earlier_samples, name="swallowed.ndjson"):
    """A run whose last write was cut mid-line, followed by the next run appending.

    The cut leaves a line with no newline on it, so the marker the NEXT run writes lands
    on the end of that line and the two together parse as nothing. The second run's own
    samples are perfectly good; only its marker is gone.
    """
    path = str(tmp_path / name)
    writer = bs.NdjsonWriter(path, label="A")
    for t in range(earlier_samples):
        writer.write(bs.sample_line("inventory-sync", f"A{t}", float(t),
                                    {"sync.docs.indexed": t}))
    writer.close()
    with open(path, "a") as fh:
        fh.write('{"ts":"T","src":"inventory-sync","ok":true,"m":{"sync.doc')  # killed here

    writer = bs.NdjsonWriter(path, label="B")
    for t in range(3):
        writer.write(bs.sample_line("inventory-sync", f"B{t}", float(t),
                                    {"sync.docs.indexed": 100 + t}))
    writer.close()
    return path, writer.run_id


def test_a_swallowed_marker_does_not_select_the_previous_run(tmp_path):
    """The run being read is the one the TAIL names, never an older marker.

    With its own marker swallowed, the only marker left in the file belongs to the run
    before it. Seeking there would scope the read to a run that has no readings left --
    answering with zero samples while three sit at the end of the file, which is the one
    failure mode a silent seek can produce.
    """
    path, run_b = _interrupted_then_reopened(tmp_path, earlier_samples=0)

    run_id, offset = bs._last_run_start(path)
    assert run_id == run_b, "the tail says which run this is"
    assert offset == 0, "no marker for it survived, so the file has to be read whole"

    samples = [s for s in bs.read_samples(path, src="inventory-sync") if s.get("ok")]
    assert [s["m"]["sync.docs.indexed"] for s in samples] == [100, 101, 102]


def test_a_swallowed_marker_falls_back_even_with_samples_before_it(tmp_path):
    """Still the whole file: the earlier run's lines are not a boundary either.

    An earlier `r` looks like the edge of the run only while one writer owns the file.
    Nothing enforces that, so the id change cannot be trusted to bound the scan -- see
    test_interleaved_writers_do_not_truncate_the_run_being_read.
    """
    path, run_b = _interrupted_then_reopened(tmp_path, earlier_samples=5, name="s2.ndjson")

    run_id, offset = bs._last_run_start(path)
    assert run_id == run_b
    assert offset == 0, "without its own marker there is no offset that is safe"

    samples = [s for s in bs.read_samples(path, src="inventory-sync") if s.get("ok")]
    assert [s["m"]["sync.docs.indexed"] for s in samples] == [100, 101, 102]


# ---------------------------------------------------------------------------
# Two writers on one file
#
# run_benchmark.sh chooses between the monitor and the fallback scraper within a single
# invocation, but nothing stops two invocations sharing a --label, or a hand-run
# `monitor.py --ndjson` aimed at a live run's file. Runs then interleave, and the seek has
# to stay correct without assuming they do not.
# ---------------------------------------------------------------------------
def _interleaved(tmp_path, samples=6, name="interleaved.ndjson"):
    """Two collectors appending to one file, each with its own run id."""
    path = str(tmp_path / name)
    first = bs.NdjsonWriter(path, label="first")
    first.write(bs.meta_line("inventory-sync", "/s", {"sync.docs.indexed": "counter"}))
    second = bs.NdjsonWriter(path, label="second")
    for v in range(samples):
        first.write(bs.sample_line("inventory-sync", f"T{v}", float(v),
                                   {"sync.docs.indexed": 100 + v * 10}))
        second.write(bs.sample_line("remoted", f"T{v}", float(v),
                                    {"data.metrics.tcp_sessions": v}))
    first.close()
    second.close()
    return path, first.run_id, second.run_id


def test_interleaved_writers_do_not_truncate_the_run_being_read(tmp_path):
    """Every line of the run must be read, however many other runs sit between them.

    Cutting the scan at the first line carrying a different `r` left exactly one sample of
    six: its counter then had nothing to move against, so the run lost its delta, and the
    meta line ahead of the cut took its descriptors with it. Silent, and wrong in the
    direction that looks like a quiet benchmark rather than a broken read.
    """
    path, _, second = _interleaved(tmp_path)

    run_id, offset = bs._last_run_start(path)
    assert run_id == second, "the tail names the run"
    assert offset > 0, "its own marker is intact, so the seek is still the cheap path"

    samples = [s for s in bs.read_samples(path, src="remoted") if s.get("ok")]
    assert [s["m"]["data.metrics.tcp_sessions"] for s in samples] == [0, 1, 2, 3, 4, 5]


def test_an_interleaved_run_keeps_its_descriptors_and_its_delta(tmp_path):
    """What the truncation actually cost, asserted on the run whose marker comes first."""
    path, first, _ = _interleaved(tmp_path)

    samples = [s for s in bs.read_samples(path, src="inventory-sync", run=first)
               if s.get("ok")]
    assert [s["m"]["sync.docs.indexed"] for s in samples] == [100, 110, 120, 130, 140, 150]
    descriptors = bs.read_descriptors(path, "inventory-sync", run=first)
    assert descriptors["sync.docs.indexed"]["type"] == "counter", "the meta line survives"
