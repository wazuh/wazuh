# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_ab_report.py -v

"""Tests for the indexer A/B: the verdict rule (I204), the drain maths, collect, and the dry runs.

The verdict tests build sides at 0.90, 0.97 and 1.02 of each other: the three places around the
0.95 / 1.00 thresholds that CA-E11c-2 names. The dry-run tests run the real scripts with
--dry-run: no manager, container or indexer exists in the test, so anything they touched would
fail loudly.
"""
import json
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.realpath(__file__))
BENCH = os.path.join(HERE, '..')
sys.path.insert(0, BENCH)
import ab_report as ab

SCRIPTS = ("ab_indexer.sh", "ab_report.py", "indexer_ingest_probe.sh", "indexer_credentials.sh")


def idx_env(tmp_path, **extra):
    """The indexer credentials and CA a real (non dry) run needs: there is no default (P-9)."""
    ca = tmp_path / "indexer-ca.pem"
    ca.write_text("not a real CA: the stubs never verify it\n")
    return dict({"INDEXER_USER": "bench", "INDEXER_PASSWORD": "pw", "INDEXER_CACERT": str(ca)}, **extra)


def clean_env(**extra):
    """os.environ without any indexer credential or CA the developer's shell may carry."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("INDEXER_USER", "INDEXER_PASSWORD", "INDEXER_PASS", "INDEXER_CACERT",
                        "INDEXER_INSECURE", "INDEXER_CREDENTIALS_FILE", "INDEXER_URL")}
    env.update(extra)
    return env


def run(side, scenario, metrics, kind="drain", verdict=("docs_per_s_drain",), warmup=False, index="1",
        dropped=0, fraction=0.5):
    """One collected run. A drain run is comparable by default: it records indexer.events.dropped = 0
    and indexes `fraction` of the events remoted accepted (I226)."""
    doc = {"side": side, "scenario": scenario, "index": index, "kind": kind, "warmup": warmup,
           "verdict_metrics": list(verdict), "metrics": dict(metrics)}
    if kind == "drain":
        doc["engine_events_dropped"] = dropped
        if fraction is not None:
            doc["metrics"].setdefault("indexed_fraction", fraction)
    return doc


def sides(ratio, base=1000.0, n=4):
    """n runs per side where v2's docs/s is `ratio` times v1's."""
    return ([run("v1", "drain-engine", {"docs_per_s_drain": base, "docs_drained": 300000}) for _ in range(n)]
            + [run("v2", "drain-engine", {"docs_per_s_drain": base * ratio, "docs_drained": 300000})
               for _ in range(n)])


# ---------------------------------------------------------------------------
# The verdict rule (CA-E11c-2)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ratio, expected, code", [
    (0.90, "FAIL", 1),
    (0.97, "PASS_WITHIN_NOISE", 0),
    (1.02, "PASS", 0),
])
def test_verdict_around_the_thresholds(ratio, expected, code, tmp_path):
    result = ab.compare(sides(ratio))
    entry = result["scenarios"]["drain-engine"]
    assert entry["verdict"] == expected
    assert entry["metrics"]["docs_per_s_drain"]["ratio"] == pytest.approx(ratio, abs=1e-3)
    assert result["overall"] == ("FAIL" if expected == "FAIL" else "PASS")

    # the same through the CLI: the exit status is the verdict
    for i, r in enumerate(sides(ratio)):
        d = tmp_path / f"results_ab-{r['side']}-drain-engine-{i}"
        d.mkdir()
        (d / "ab_metrics.json").write_text(json.dumps(r))
    assert ab.main(["report", "--root", str(tmp_path)]) == code


@pytest.mark.parametrize("ratio, expected", [(0.9499, "FAIL"), (0.95, "PASS_WITHIN_NOISE"),
                                              (0.9999, "PASS_WITHIN_NOISE"), (1.0, "PASS")])
def test_boundaries(ratio, expected):
    assert ab.classify(ratio) == expected


def test_a_time_is_inverted():
    # v2 drains in 111 s where v1 takes 100 s: v2 is SLOWER, ratio 100/111 = 0.90
    runs = ([run("v1", "s", {"drain_seconds": 100.0, "docs_drained": 5000}, verdict=("drain_seconds",))
             for _ in range(2)]
            + [run("v2", "s", {"drain_seconds": 111.0, "docs_drained": 5000}, verdict=("drain_seconds",))
               for _ in range(2)])
    cell = ab.compare(runs)["scenarios"]["s"]["metrics"]["drain_seconds"]
    assert cell["ratio"] == pytest.approx(0.9009, abs=1e-3)
    assert cell["verdict"] == "FAIL"
    assert cell["raw_ratio_v2_over_v1"] == pytest.approx(1.11)


def test_median_not_mean():
    # one wild v2 repetition must not move the verdict
    runs = sides(1.02)
    runs[-1]["metrics"]["docs_per_s_drain"] = 1.0
    entry = ab.compare(runs)["scenarios"]["drain-engine"]
    assert entry["verdict"] == "PASS"
    assert any("spread" in n for n in entry["notes"])


def test_warmup_runs_are_dropped():
    runs = sides(1.02) + [run("v2", "drain-engine", {"docs_per_s_drain": 1.0}, warmup=True, index="w")]
    entry = ab.compare(runs)["scenarios"]["drain-engine"]
    assert entry["n_v2"] == 4 and entry["verdict"] == "PASS"


def test_fixed_rate_scenarios_get_ratios_but_no_verdict():
    runs = ([run("v1", "fixed-fim", {"latency_p99_ms": 100.0}, kind="fixed", verdict=()) for _ in range(2)]
            + [run("v2", "fixed-fim", {"latency_p99_ms": 300.0}, kind="fixed", verdict=()) for _ in range(2)])
    result = ab.compare(runs)
    entry = result["scenarios"]["fixed-fim"]
    assert entry["verdict"] == "NO_VERDICT"
    assert entry["metrics"]["latency_p99_ms"]["ratio"] == pytest.approx(0.3333, abs=1e-3)
    assert "verdict" not in entry["metrics"]["latency_p99_ms"]
    assert result["overall"] == "INCOMPLETE"      # nothing was judged


def test_a_missing_side_is_incomplete_not_a_pass():
    runs = [r for r in sides(1.02) if r["side"] == "v2"]
    result = ab.compare(runs)
    assert result["scenarios"]["drain-engine"]["verdict"] == "INCOMPLETE"
    assert result["overall"] == "INCOMPLETE"
    assert ab.compare([])["overall"] == "INCOMPLETE"


def test_one_failing_scenario_fails_the_whole():
    runs = sides(1.02) + [dict(r, scenario="drain-syscollector", verdict_metrics=["docs_per_s_drain"])
                          for r in sides(0.90)]
    result = ab.compare(runs)
    assert result["scenarios"]["drain-engine"]["verdict"] == "PASS"
    assert result["scenarios"]["drain-syscollector"]["verdict"] == "FAIL"
    assert result["overall"] == "FAIL"


def drained(v1_docs, v2_docs, ratio=1.20, n=2, v1_accepted=None, v2_accepted=None, v1_dropped=0, v2_dropped=0,
            **extra):
    """Drain runs where v2 is `ratio` times faster; each side drained its own documents out of the events
    remoted accepted from it (default: twice the documents, the half-classified syslog sample)."""
    def side(name, docs, accepted, dropped, rate, secs):
        accepted = accepted if accepted is not None else 2 * docs
        return [dict(run(name, "drain-engine", {"docs_per_s_drain": rate, "drain_seconds": secs,
                                                "docs_drained": docs, "events_accepted": accepted},
                         verdict=("docs_per_s_drain", "drain_seconds"), dropped=dropped,
                         fraction=round(docs / accepted, 6)), **extra) for _ in range(n)]
    return (side("v1", v1_docs, v1_accepted, v1_dropped, 1000.0, 100.0)
            + side("v2", v2_docs, v2_accepted, v2_dropped, 1000.0 * ratio, 100.0 / ratio))


def test_a_side_that_indexed_a_smaller_fraction_is_incomparable_not_a_win():
    # both accepted 100,000 events; v2 "drains 20 % faster" only because it lost 40 % of the documents
    result = ab.compare(drained(50000, 30000, v1_accepted=100000, v2_accepted=100000))
    entry = result["scenarios"]["drain-engine"]
    assert entry["verdict"] == "INCOMPARABLE" and result["overall"] == "INCOMPARABLE"
    for m in ("docs_per_s_drain", "drain_seconds"):
        assert entry["metrics"][m]["verdict"] == "INCOMPARABLE"
    assert entry["comparability"]["fraction_gap"] == pytest.approx(0.4)
    assert any("0.5000" in n and "0.3000" in n and "40.00%" in n for n in entry["notes"])


def test_the_smoke_case_fewer_documents_but_the_same_fraction_is_judged():
    """I226, the E12 smoke: v2 got more 503s from remoted (98,000 events accepted against 100,000), so it
    drained 1.4 % fewer documents, but both sides indexed exactly half of what reached the engine."""
    entry = ab.compare(drained(50000, 49000, v1_accepted=100000, v2_accepted=98000))["scenarios"]["drain-engine"]
    assert entry["verdict"] == "PASS"
    assert entry["comparability"]["fraction_gap"] == 0
    assert any("documents drained differ by 2.0%" in n and "drain_seconds favours" in n for n in entry["notes"])


def test_the_fraction_tolerance_is_one_percent_relative():
    within = drained(49600, 50000, v1_accepted=100000, v2_accepted=100000)    # 0.496 vs 0.5: 0.8 %
    assert ab.compare(within)["scenarios"]["drain-engine"]["verdict"] == "PASS"
    beyond = drained(49400, 50000, v1_accepted=100000, v2_accepted=100000)    # 0.494 vs 0.5: 1.2 %
    assert ab.compare(beyond)["scenarios"]["drain-engine"]["verdict"] == "INCOMPARABLE"
    edge = drained(49500, 50000, v1_accepted=100000, v2_accepted=100000)      # exactly 1 %: comparable
    assert ab.compare(edge)["scenarios"]["drain-engine"]["verdict"] == "PASS"


def test_missing_indexed_fraction_is_incomparable():
    runs = drained(50000, 50000)
    runs[0]["metrics"].pop("indexed_fraction")          # one run without accepted events
    entry = ab.compare(runs)["scenarios"]["drain-engine"]
    assert entry["verdict"] == "INCOMPARABLE"
    assert any("indexed_fraction" in n and "missing" in n for n in entry["notes"])


@pytest.mark.parametrize("v1_dropped, v2_dropped, side", [(0, 7, "v2"), (3, 0, "v1")])
def test_a_side_whose_engine_dropped_events_is_incomparable(v1_dropped, v2_dropped, side):
    entry = ab.compare(drained(50000, 50000, v1_dropped=v1_dropped, v2_dropped=v2_dropped))["scenarios"]["drain-engine"]
    assert entry["verdict"] == "INCOMPARABLE"
    assert any(f"side {side} dropped events" in n and "indexer.events.dropped" in n for n in entry["notes"])


def test_an_unknown_engine_drop_count_is_incomparable_and_so_is_one_dropping_run():
    runs = drained(50000, 50000)
    runs[1]["engine_events_dropped"] = None               # the engine API did not answer
    entry = ab.compare(runs)["scenarios"]["drain-engine"]
    assert entry["verdict"] == "INCOMPARABLE" and any("no indexer.events.dropped" in n for n in entry["notes"])
    runs = drained(50000, 50000)
    runs[-1]["engine_events_dropped"] = 1                 # a single run of a single side is enough
    assert ab.compare(runs)["scenarios"]["drain-engine"]["verdict"] == "INCOMPARABLE"


def test_the_drop_guard_covers_a_drain_whose_verdict_is_not_a_document_drain():
    """drain-syscollector (verdict sessions/s) has no fraction guard but still needs dropped == 0."""
    runs = ([run("v1", "drain-syscollector", {"sessions_per_s": 10.0, "docs_drained": 36000},
                 verdict=("sessions_per_s",), fraction=None) for _ in range(2)]
            + [run("v2", "drain-syscollector", {"sessions_per_s": 11.0, "docs_drained": 36000},
                   verdict=("sessions_per_s",), fraction=None) for _ in range(2)])
    assert ab.compare(runs)["scenarios"]["drain-syscollector"]["verdict"] == "PASS"
    runs[-1]["engine_events_dropped"] = 5
    assert ab.compare(runs)["scenarios"]["drain-syscollector"]["verdict"] == "INCOMPARABLE"


def test_incomparable_exits_with_2(tmp_path):
    for i, r in enumerate(drained(50000, 30000, v1_accepted=100000, v2_accepted=100000)):
        d = tmp_path / f"results_ab-{r['side']}-drain-engine-{i}"
        d.mkdir()
        (d / "ab_metrics.json").write_text(json.dumps(r))
    assert ab.main(["report", "--root", str(tmp_path)]) == 2


def test_a_fail_beats_incomparable_in_the_overall():
    runs = drained(50000, 30000, v1_accepted=100000, v2_accepted=100000) + [
        dict(r, scenario="drain-syscollector") for r in drained(50000, 50000, ratio=0.5)]
    assert ab.compare(runs)["overall"] == "FAIL"


def test_a_side_that_mixes_binary_sets_is_incomplete():
    runs = sides(1.02)
    for i, r in enumerate(runs):
        r["provenance_sha256"] = "aa" if r["side"] == "v1" else ("bb" if i % 2 else "cc")
    result = ab.compare(runs)
    entry = result["scenarios"]["drain-engine"]
    assert entry["verdict"] == "INCOMPLETE" and result["overall"] == "INCOMPLETE"
    assert any("side v2 mixes 2 sets" in n for n in entry["notes"]) and not any("side v1" in n for n in entry["notes"])


def test_one_set_per_side_is_fine_even_when_the_sides_differ():
    runs = sides(1.02)
    for r in runs:
        r["provenance_sha256"] = "aa" if r["side"] == "v1" else "bb"
    assert ab.compare(runs)["scenarios"]["drain-engine"]["verdict"] == "PASS"


def test_provenance_hash_ignores_date_and_side_but_not_binaries(tmp_path):
    h = "0123456789abcdef" * 4
    g = "fedcba9876543210" * 4

    def write(name, side, date, sha):
        (tmp_path / name).write_text(f"side: {side}\ndate: {date}\n{sha}  /home/bin/a\n{h}  /home/lib/x.so\n"
                                     "conf validate: ok\n")
        return ab.provenance_hash(str(tmp_path / name))
    assert write("p1", "v1", "t1", g) == write("p2", "v1", "t2", g)
    assert write("p3", "v2", "t3", g) == write("p4", "v1", "t4", g)     # the label is not part of it
    assert write("p5", "v1", "t1", h) != write("p6", "v1", "t1", g)
    assert ab.provenance_hash(str(tmp_path / "nowhere")) is None


def test_collect_keeps_docs_drained_the_fraction_the_drop_count_and_the_provenance_hash(tmp_path):
    (tmp_path / "provenance.txt").write_text("side: v1\n" + "ab" * 32 + "  /x/bin/a\n")
    write_probe(tmp_path / "probe.csv", [0, 0, 0, 100, 200, 200, 200])
    (tmp_path / "drain.json").write_text(json.dumps({
        "t_pause": 999.0, "t_resume": 1002.0, "drain_end": "quiet", "docs_final": 200,
        "events_sent": 500, "events_accepted": 400, "events_rejected_503": 100, "engine_events_dropped": 0}))
    doc = ab.collect(str(tmp_path), "v1", "drain-engine", "1", "drain", False, ["docs_per_s_drain"])
    m = doc["metrics"]
    assert m["docs_drained"] == 200 and m["events_accepted"] == 400 and m["indexed_fraction"] == 0.5
    assert m["events_sent"] == 500 and m["events_rejected_503"] == 100
    assert doc["provenance_sha256"] == ab.provenance_hash(str(tmp_path / "provenance.txt"))
    assert doc["drain_end"] == "quiet" and doc["engine_events_dropped"] == 0
    assert "expected_docs" not in doc


def test_collect_without_accepted_events_has_no_fraction(tmp_path):
    write_probe(tmp_path / "probe.csv", [0, 0, 100, 100])
    (tmp_path / "drain.json").write_text(json.dumps({"t_pause": 999.0, "t_resume": 1001.0, "drain_end": "quiet",
                                                     "docs_final": 100, "engine_events_dropped": None}))
    doc = ab.collect(str(tmp_path), "v2", "drain-engine", "1", "drain", False, ["docs_per_s_drain"])
    assert "indexed_fraction" not in doc["metrics"] and doc["engine_events_dropped"] is None


def smoke_summary(path, events_sent=100000, batches=1000, s202=986, s503=14):
    path.write_text(json.dumps({"totals": {
        "stateless": {"events_sent": events_sent, "sent": batches, "s202": s202, "s503": s503,
                      "s400": 0, "s413": 0, "other": 0},
        "sessions": {"documents_sent": 64000}}}))


def test_accepted_events_subtract_the_batches_remoted_did_not_take(tmp_path):
    """The smoke's v2-1 run: 1,000 batches of 100, 14 answered 503 -> 98,600 events reached the engine."""
    smoke_summary(tmp_path / "sender_summary.json")
    assert ab.accepted_counts(str(tmp_path), "agent") == {
        "events_sent": 100000, "events_accepted": 98600, "events_rejected_503": 1400, "events_rejected": 1400}
    assert ab.accepted_events(str(tmp_path), "agent") == 98600
    assert ab.accepted_events(str(tmp_path), "uds") == 64000
    assert ab.accepted_events(str(tmp_path / "nowhere"), "agent") == 0
    smoke_summary(tmp_path / "sender_summary.json", s202=1000, s503=0)
    assert ab.accepted_events(str(tmp_path), "agent") == 100000
    smoke_summary(tmp_path / "sender_summary.json", s202=990, s503=4)       # 6 batches were 400/413/other
    c = ab.accepted_counts(str(tmp_path), "agent")
    assert c["events_accepted"] == 99000 and c["events_rejected_503"] == 400 and c["events_rejected"] == 1000
    smoke_summary(tmp_path / "sender_summary.json", events_sent=0, batches=0, s202=0, s503=0)
    assert ab.accepted_counts(str(tmp_path), "agent") is None


def test_accepted_cli_prints_the_count_and_the_json(tmp_path, capsys):
    smoke_summary(tmp_path / "sender_summary.json")
    assert ab.main(["accepted", str(tmp_path), "--mode", "agent"]) == 0
    assert capsys.readouterr().out.strip() == "98600"
    assert ab.main(["accepted", str(tmp_path), "--mode", "agent", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["events_rejected_503"] == 1400
    assert ab.main(["accepted", str(tmp_path / "nowhere"), "--mode", "agent", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_engine_metric_reads_the_global_counter(monkeypatch, capsys):
    import io
    dump = {"global": [{"name": "router.events.dropped", "value": 9},
                       {"name": "indexer.events.dropped", "value": 3.0}], "spaces": {}}
    assert ab.engine_metric(dump, "indexer.events.dropped") == 3
    assert ab.engine_metric(dump, "nope") is None
    assert ab.engine_metric([], "indexer.events.dropped") is None
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(dump)))
    assert ab.main(["engine-metric", "indexer.events.dropped"]) == 0 and capsys.readouterr().out.strip() == "3"
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
    assert ab.main(["engine-metric", "indexer.events.dropped"]) == 1 and capsys.readouterr().out == ""


def test_markdown_names_the_rule_and_the_verdict():
    text = ab.render_markdown(ab.compare(sides(0.97)))
    assert "0.95" in text and "PASS_WITHIN_NOISE" in text and "docs_per_s_drain" in text


# ---------------------------------------------------------------------------
# The drain maths and collect
# ---------------------------------------------------------------------------
def rows(counts, t0=1000.0):
    return [{"epoch": t0 + i, "count": c, "index_total": c} for i, c in enumerate(counts)]


def test_drain_metrics():
    # paused (flat at 0) for 3 s, resumed at t0+3, grows 500 a second for 4 s, then flat
    series = rows([0, 0, 0, 0, 500, 1000, 1500, 2000, 2000, 2000, 2000])
    m = ab.drain_metrics(series, t_resume=1003.0)
    assert m["docs_drained"] == 2000
    assert m["drain_seconds"] == 4.0
    assert m["docs_per_s_drain"] == 500.0


def test_drain_metrics_without_growth_is_zero_not_an_error():
    m = ab.drain_metrics(rows([7, 7, 7]), t_resume=1001.0)
    assert m == {"docs_drained": 0, "drain_seconds": 0.0, "docs_per_s_drain": 0.0}
    assert ab.drain_metrics([], 0)["docs_per_s_drain"] == 0.0


def write_probe(path, counts, t0=1000.0, patterns=("wazuh-events*",), holes=()):
    lines = ["epoch,pattern,count,index_total"]
    for i, c in enumerate(counts):
        for p in patterns:
            blank = i in holes
            lines.append(f"{t0 + i},{p},{'' if blank else c},{'' if blank else c * 2}")
    path.write_text("\n".join(lines) + "\n")


def test_a_probe_hole_is_dropped_not_read_as_zero(tmp_path):
    write_probe(tmp_path / "probe.csv", [0, 10, 20, 30], holes=(2,))
    got = ab.read_probe(str(tmp_path / "probe.csv"))
    assert [r["count"] for r in got] == [0, 10, 30]


def test_probe_patterns_are_summed_per_second(tmp_path):
    write_probe(tmp_path / "probe.csv", [5, 6], patterns=("wazuh-events*", "wazuh-states-*"))
    assert [r["count"] for r in ab.read_probe(str(tmp_path / "probe.csv"))] == [10, 12]


def test_collect_reads_what_a_run_leaves(tmp_path):
    (tmp_path / "sender_summary.json").write_text(json.dumps({
        "throughput": {"sessions_per_second": 12.5, "events_per_second": 0},
        "latency_ms": {"session": {"p50": 40.0, "p99": 900.0}}}))
    (tmp_path / "summary.json").write_text(json.dumps({"processes": {
        "wazuh-manager-modulesd": {"cpu_pct_avg": 10, "rss_mb_max": 200},
        "wazuh-manager-analysisd": {"cpu_pct_avg": 5, "rss_mb_max": 300}}}))
    write_probe(tmp_path / "probe.csv", [0, 0, 0, 100, 200, 200, 200])
    (tmp_path / "drain.json").write_text(json.dumps({"t_pause": 999.0, "t_resume": 1002.0}))
    doc = ab.collect(str(tmp_path), "v2", "drain-engine", "1", "drain", False,
                     ["docs_per_s_drain", "drain_seconds"])
    m = doc["metrics"]
    assert m["sessions_per_s"] == 12.5 and m["latency_p99_ms"] == 900.0
    assert m["cpu_pct_avg"] == 15 and m["rss_mb_max"] == 500
    assert m["docs_indexed"] == 200 and m["index_total_delta"] == 400
    assert m["drain_seconds"] == 2.0 and m["docs_per_s_drain"] == 100.0
    assert json.load(open(tmp_path / "ab_metrics.json"))["verdict_metrics"] == ["docs_per_s_drain", "drain_seconds"]


# ---------------------------------------------------------------------------
# The dry runs (CA-E11c-1 and CA-E11c-3)
# ---------------------------------------------------------------------------
def dry(script, *args, env=None):
    full_env = dict(os.environ, **(env or {}))
    return subprocess.run(["bash", os.path.join(BENCH, script), "--dry-run", *args],
                          capture_output=True, text=True, env=full_env, timeout=60)


def test_ab_indexer_dry_run_lists_abba_runs_with_warmup(tmp_path):
    lock = tmp_path / "measure.lock"
    out = dry("ab_indexer.sh", "--scenario", "drain-engine", "--snapshots", str(tmp_path / "snaps"),
              env={"AB_MEASURE_LOCK": str(lock)})
    assert out.returncode == 0, out.stderr
    labels = [line.split()[1] for line in out.stdout.splitlines() if re.match(r"^  \[\d+/\d+\] ", line)]
    assert labels == [
        "ab-v2-drain-engine-w", "ab-v1-drain-engine-w",
        "ab-v1-drain-engine-1", "ab-v2-drain-engine-1", "ab-v2-drain-engine-2", "ab-v1-drain-engine-2",
        "ab-v2-drain-engine-3", "ab-v1-drain-engine-3", "ab-v1-drain-engine-4", "ab-v2-drain-engine-4"]
    assert out.stdout.count("restore side") == 10                 # every run restores its side
    assert "docker pause wazuh-indexer" in out.stdout
    assert "never .wazuh-threatintel-" in out.stdout
    assert not lock.exists(), "a dry run must not take or create the lock"


def test_ab_indexer_dry_run_covers_every_scenario_and_no_verdict_on_fixed():
    out = dry("ab_indexer.sh", "--n", "2", "--no-warmup")
    assert out.returncode == 0, out.stderr
    for name in ("drain-engine", "drain-syscollector", "fixed-engine", "fixed-syscollector",
                 "fixed-fim", "fixed-vd"):
        assert f"== {name}" in out.stdout
    collects = [l for l in out.stdout.splitlines() if "ab_report.py collect" in l and "fixed" in l]
    assert collects and all("verdict:" not in l for l in collects)


def test_ab_indexer_refuses_an_odd_n():
    out = dry("ab_indexer.sh", "--n", "3")
    assert out.returncode != 0 and "even" in out.stderr


def test_the_lock_reexec_replays_every_argument(tmp_path):
    """P1: the parse loop shifts the arguments away; the re-exec under the lock must replay them."""
    lock = tmp_path / "measure.lock"
    out = subprocess.run(
        ["bash", os.path.join(BENCH, "ab_indexer.sh"), "--scenario", "drain-engine", "--n", "2",
         "--snapshots", str(tmp_path / "snaps"), "--no-warmup"],
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, AB_MEASURE_LOCK=str(lock), AB_REEXEC_PRINT="1", **idx_env(tmp_path)))
    assert out.returncode == 0, out.stderr
    line = [l for l in out.stdout.splitlines() if l.startswith("REEXEC")][0]
    assert line.endswith("[--scenario] [drain-engine] [--n] [2] [--snapshots] [%s] [--no-warmup] [--locked]"
                         % (tmp_path / "snaps"))
    assert f"flock -o {lock} bash " in line


def test_the_lock_is_really_taken_and_the_child_gets_its_arguments(tmp_path):
    """The same branch without the hook, end to end: flock is real, the child is the script itself.
    A copy of the scripts whose prepare_manager.sh is a stub records what it is asked to restore;
    it fails on purpose so that nothing after the first restore runs."""
    work = tmp_path / "bench"
    work.mkdir()
    for name in SCRIPTS:
        (work / name).write_text(open(os.path.join(BENCH, name)).read())
    stub = work / "prepare_manager.sh"
    stub.write_text('#!/usr/bin/env bash\necho "STUB $*" > "$AB_STUB_OUT"\nexit 1\n')
    stub.chmod(0o755)
    rec = tmp_path / "stub.out"
    out = subprocess.run(
        ["bash", str(work / "ab_indexer.sh"), "--scenario", "drain-engine", "--n", "2", "--no-warmup",
         "--snapshots", str(tmp_path / "snaps")],
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, AB_MEASURE_LOCK=str(tmp_path / "measure.lock"), AB_STUB_OUT=str(rec),
                 AB_RAW_PATTERN="", PYTHON=sys.executable, **idx_env(tmp_path)))
    assert (tmp_path / "measure.lock").exists()
    assert "1 scenario(s), N=2 per side" in out.stdout, out.stdout + out.stderr    # not the default matrix
    assert "STUB --side v1 --side-only --snapshots %s" % (tmp_path / "snaps") in rec.read_text()


def test_the_quiet_window_has_a_60s_floor(tmp_path):
    out = dry("ab_indexer.sh", "--scenario", "drain-engine", "--quiet-seconds", "10",
              "--snapshots", str(tmp_path))
    assert out.returncode == 0
    assert "raised to the 60s floor" in out.stderr and "quiet 60s" in out.stdout
    out = dry("ab_indexer.sh", "--scenario", "drain-engine", "--quiet-seconds", "90",
              "--snapshots", str(tmp_path))
    assert "quiet 90s" in out.stdout and "floor" not in out.stderr


def fake_manager(tmp_path, v2_extra=()):
    """A scratch home + conf dir with stub control/conf binaries and two real snapshots."""
    home, conf = tmp_path / "home", tmp_path / "etc"
    (home / "bin").mkdir(parents=True)
    (home / "lib").mkdir()
    conf.mkdir()
    log = tmp_path / "calls.log"
    for name in ("wazuh-manager-control", "wazuh-manager-conf"):
        f = home / "bin" / name
        f.write_text(f'#!/usr/bin/env bash\necho "{name} $*" >> "{log}"\n')
        f.chmod(0o755)
    (conf / "wazuh-manager.conf").write_text("<x/>\n")
    (conf / "wazuh-manager-internal-options.conf").write_text("wazuh_modules.x=1\n")
    snaps = tmp_path / "snaps"
    for side, extra in (("v1", ["lib/libold.so"]), ("v2", list(v2_extra))):
        d = snaps / side
        d.mkdir(parents=True)
        src = tmp_path / f"src-{side}"
        (src / "bin").mkdir(parents=True)
        (src / "lib").mkdir()
        (src / "bin" / "marker").write_text(side)
        for e in extra:
            (src / e).write_text(side)
        members = ["bin/marker"] + extra
        subprocess.run(["tar", "-cpf", str(d / "snapshot.tar"), "-C", str(src), *members], check=True)
        (d / "manifest.txt").write_text("\n".join(members) + "\n")
        (d / "internal-options.conf").write_text(f"wazuh_modules.x=1\n# saved from {side}\n")
    env = dict(os.environ, WAZUH_MANAGER_HOME=str(home), AB_CONF_DIR=str(conf), PYTHON=sys.executable)
    return home, conf, snaps, log, env


def prepare(env, *args):
    return subprocess.run(["bash", os.path.join(BENCH, "prepare_manager.sh"), *args],
                          capture_output=True, text=True, env=env, timeout=60)


def test_restore_side_when_the_other_side_adds_nothing_is_not_aborted_by_set_e(tmp_path):
    """P2-1: v1's manifest is a subset of v2's, so restoring v2 subtracts nothing (grep . = rc 1)."""
    home, conf, snaps, log, env = fake_manager(tmp_path)
    out = prepare(env, "--side", "v1", "--side-only", "--snapshots", str(snaps))   # v2 manifest has no extras
    assert out.returncode == 0, out.stdout + out.stderr
    assert (home / "bin" / "marker").read_text() == "v1"                          # the tar was unpacked
    calls = log.read_text()
    assert "wazuh-manager-control stop" in calls and "wazuh-manager-control restart" in calls
    assert "validate" in calls


def test_restore_side_still_deletes_what_the_other_side_added(tmp_path):
    home, conf, snaps, log, env = fake_manager(tmp_path)
    (home / "lib" / "libold.so").write_text("x")
    out = prepare(env, "--side", "v2", "--side-only", "--snapshots", str(snaps))
    assert out.returncode == 0, out.stdout + out.stderr
    assert not (home / "lib" / "libold.so").exists()
    assert (home / "bin" / "marker").read_text() == "v2"


def test_restore_original_puts_the_internal_options_back(tmp_path):
    """P3-10: the first --side keeps the original once; --restore-original brings it back."""
    home, conf, snaps, log, env = fake_manager(tmp_path)
    opts = conf / "wazuh-manager-internal-options.conf"
    original = opts.read_text()
    assert prepare(env, "--side", "v1", "--side-only", "--snapshots", str(snaps)).returncode == 0
    assert prepare(env, "--side", "v2", "--side-only", "--snapshots", str(snaps)).returncode == 0
    assert opts.read_text() != original and "analysisd.indexer_queue_max_bytes" in opts.read_text()
    assert (conf / (opts.name + ".ab-orig")).read_text() == original          # kept once, not overwritten
    out = prepare(env, "--restore-original")
    assert out.returncode == 0, out.stdout + out.stderr
    assert opts.read_text() == original
    assert not (conf / (opts.name + ".ab-orig")).exists()
    assert "bin/ and lib/ stay" in out.stdout
    again = prepare(env, "--restore-original")                                # nothing left to restore
    assert again.returncode != 0 and ".ab-orig not found" in again.stderr


def test_restore_original_dry_run_touches_nothing(tmp_path):
    home, conf, snaps, log, env = fake_manager(tmp_path)
    opts = conf / "wazuh-manager-internal-options.conf"
    (conf / (opts.name + ".ab-orig")).write_text("orig\n")
    before = opts.read_text()
    out = prepare(env, "--restore-original", "--dry-run")
    assert out.returncode == 0 and "[dry-run] cp -p" in out.stdout
    assert opts.read_text() == before and (conf / (opts.name + ".ab-orig")).exists()
    assert not log.exists()


def test_restore_original_refuses_a_side(tmp_path):
    out = prepare(dict(os.environ), "--restore-original", "--side", "v1", "--dry-run")
    assert out.returncode != 0 and "stands alone" in out.stderr


def curl_stub(tmp_path):
    """A curl that records its argv and its stdin, and answers like the indexer."""
    bindir = tmp_path / "stubbin"
    bindir.mkdir(exist_ok=True)
    f = bindir / "curl"
    f.write_text('#!/usr/bin/env bash\necho "ARGV $*" >> "$CURL_LOG"\ncat >> "$CURL_LOG"\n'
                 'case "$*" in *_stats*) echo \'{"_all":{"total":{"indexing":{"index_total":7}}}}\';;'
                 ' *) echo \'{"count":3}\';; esac\n')
    f.chmod(0o755)
    return bindir


def test_indexer_credentials_go_on_stdin_not_in_argv(tmp_path):
    """P3-9: the probe and the cleaner give curl the user through `-K -`."""
    log = tmp_path / "curl.log"
    env = dict(os.environ, PATH=f"{curl_stub(tmp_path)}:{os.environ['PATH']}", CURL_LOG=str(log),
               PYTHON=sys.executable, **idx_env(tmp_path, INDEXER_USER="admin", INDEXER_PASSWORD='s3cr"et\\pw'))
    out = subprocess.run(["bash", os.path.join(BENCH, "indexer_ingest_probe.sh"), "--once",
                          "--patterns", "wazuh-events*"], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0 and out.stdout.strip() == "3", out.stderr
    text = log.read_text()
    assert "s3cr" not in "".join(l for l in text.splitlines() if l.startswith("ARGV"))
    assert " -u " not in text and "-K -" in text
    assert 'user = "admin:s3cr\\"et\\\\pw"' in text                          # escaped for curl's config syntax


def make_snapshots(root):
    for side, files in (("v1", ["bin/wazuh-manager-analysisd", "lib/libindexer_connector.so", "lib/libcommon.so"]),
                        ("v2", ["bin/wazuh-manager-analysisd", "lib/libcommon.so", "lib/libindexer_client.so"])):
        d = root / side
        d.mkdir(parents=True)
        (d / "snapshot.tar").write_bytes(b"")
        (d / "internal-options.conf").write_text("wazuh_modules.x=1\n")
        (d / "manifest.txt").write_text("\n".join(files) + "\n")


def test_prepare_manager_side_dry_run_lists_the_whole_restore(tmp_path):
    make_snapshots(tmp_path)
    out = dry("prepare_manager.sh", "--side", "v1", "--snapshots", str(tmp_path),
              env={"WAZUH_MANAGER_HOME": str(tmp_path / "home")})
    assert out.returncode == 0, out.stderr
    text = out.stdout
    assert "stop the manager" in text
    assert "rm lib/libindexer_client.so" in text                  # what v2 added and v1 lacks
    assert "libindexer_connector.so" not in text.split("3. unpack")[0].split("2. delete")[1]
    assert "tar -xpf" in text and str(tmp_path / "v1" / "snapshot.tar") in text
    assert "ab_options/v1.conf" in text and "analysisd.indexer_queue_max_bytes=1073741824" in text
    assert "wazuh-manager-conf -f /etc/wazuh-manager/wazuh-manager.conf" in text and "validate" in text
    assert not (tmp_path / "home").exists()


def test_prepare_manager_side_dry_run_says_what_is_missing(tmp_path):
    out = dry("prepare_manager.sh", "--side", "v2", "--snapshots", str(tmp_path))
    assert out.returncode == 0
    assert "missing" in out.stdout


# ---------------------------------------------------------------------------
# Round 2 of the G-diff: campaigns, wait_quiet, docker pause, missing results dir, sizing, patterns
# ---------------------------------------------------------------------------
def write_stub(path, body):
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


def bench_copy(tmp_path):
    """A copy of the scripts under test in its own directory: SCRIPT_DIR is where results_* land."""
    work = tmp_path / "bench"
    work.mkdir()
    for name in SCRIPTS:
        (work / name).write_text(open(os.path.join(BENCH, name)).read())
        (work / name).chmod(0o755)
    # the agent cleaner talks to the API: a stub that succeeds unless AB_CLEANUP_FAIL is set
    write_stub(work / "cleanup_agents.sh",
               'echo "cleanup $*" >> "${AB_CLEANUP_LOG:-/dev/null}"\n'
               '[[ -n "${AB_CLEANUP_FAIL:-}" ]] && { echo "cleanup_agents: ERROR: 3 agent(s) still registered" >&2; exit 1; }\n'
               'exit 0\n')
    return work


def stale_runs(work, campaign, ratio=1.02, n=4, scenario="drain-engine"):
    """Leave n measured runs per side in results_ab-*/ab_metrics.json, stamped with `campaign`."""
    for r in sides(ratio, n=n):
        r = dict(r, campaign=campaign, index=str(len(list(work.glob("results_ab-*"))) + 1),
                 verdict_metrics=["docs_per_s_drain"])
        d = work / f"results_ab-{r['side']}-{scenario}-{r['index']}"
        d.mkdir()
        (d / "ab_metrics.json").write_text(json.dumps(r))


def run_campaign(work, tmp_path, extra_env=None, args=("--scenario", "drain-engine", "--n", "2", "--no-warmup")):
    env = dict(os.environ, AB_MEASURE_LOCK=str(tmp_path / "measure.lock"), PYTHON=sys.executable,
               AB_RAW_PATTERN="", AB_STUB_OUT=str(tmp_path / "stub.out"), AB_TEST_SKIP_READY="1",
               AB_TEST_CLEANUP_SLEEP_S="0", **idx_env(tmp_path))
    env.update(extra_env or {})
    return subprocess.run(["bash", str(work / "ab_indexer.sh"), *args, "--snapshots", str(tmp_path / "snaps")],
                          capture_output=True, text=True, env=env, timeout=120)


def test_stale_results_of_another_campaign_do_not_pass_an_aborted_run(tmp_path):
    """P2: stale ab_metrics.json of an older campaign (a clear PASS) + a run that aborts: not a PASS, rc != 0."""
    work = bench_copy(tmp_path)
    stale_runs(work, campaign="20200101T000000Z-1")
    write_stub(work / "prepare_manager.sh", 'echo "STUB $*" > "$AB_STUB_OUT"\nexit 1\n')
    out = run_campaign(work, tmp_path)
    assert "Overall: PASS" not in out.stdout, out.stdout
    assert "Overall: INCOMPLETE" in out.stdout and out.returncode == 2, out.stdout + out.stderr
    assert "1 scenario(s) aborted" in out.stdout


def test_an_aborted_scenario_never_exits_zero_even_if_the_report_passes(tmp_path):
    """P2: the report alone says PASS (the runs carry this campaign's id), but a scenario aborted: rc 2."""
    work = bench_copy(tmp_path)
    stale_runs(work, campaign="fixed-campaign")
    write_stub(work / "prepare_manager.sh", 'exit 1\n')
    out = run_campaign(work, tmp_path, {"AB_TEST_CAMPAIGN_ID": "fixed-campaign"})
    assert "Overall: PASS" in out.stdout, out.stdout            # the filter let them in: the guard is the rc
    assert out.returncode == 2 and "campaign is incomplete" in out.stderr


def test_report_reads_only_the_runs_of_the_current_campaign(tmp_path):
    """P2: --n 2 after --n 4: the 4 leftover runs of the old campaign stay out of the medians."""
    work = tmp_path
    stale_runs(work, campaign="old", ratio=0.5, n=4)             # would FAIL if it leaked in
    stale_runs(work, campaign="new", ratio=1.02, n=2)
    assert len(ab.load_runs(str(work))) == 12
    assert len(ab.load_runs(str(work), "new")) == 4
    assert ab.load_runs(str(work), "nope") == []
    assert ab.main(["report", "--root", str(work), "--campaign", "new"]) == 0
    result = ab.compare(ab.load_runs(str(work), "new"))
    entry = result["scenarios"]["drain-engine"]
    assert (entry["n_v1"], entry["n_v2"]) == (2, 2) and entry["verdict"] == "PASS"
    assert ab.main(["report", "--root", str(work)]) == 1         # without a campaign the old runs mix in


def test_collect_stamps_the_campaign(tmp_path):
    assert ab.collect(str(tmp_path), "v1", "s", "1", "fixed", False, [], "c-1")["campaign"] == "c-1"
    assert json.loads((tmp_path / "ab_metrics.json").read_text())["campaign"] == "c-1"


def probe_harness(tmp_path, sequence, quiet=2, timeout=30, floor=1):
    """Source ab_indexer.sh (hook) with a probe that answers `sequence` (the last value repeats; `grow`
    = the call number; `fail` = exit 1) and run wait_quiet. Returns (stdout line fields, calls)."""
    work = bench_copy(tmp_path)
    seq, state = tmp_path / "seq", tmp_path / "state"
    seq.write_text("\n".join(str(v) for v in sequence) + "\n")
    write_stub(work / "indexer_ingest_probe.sh",
               'n=$(cat "$AB_STATE" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$AB_STATE"\n'
               'mapfile -t seq < "$AB_SEQ"\n'
               'if [[ ${#seq[@]} -ge $n ]]; then v="${seq[n-1]}"; else v="${seq[-1]}"; fi\n'
               '[[ "$v" == grow ]] && v=$n\n[[ "$v" == fail ]] && exit 1\necho "$v"\n')
    script = (f'AB_SOURCE_ONLY=1 source "{work}/ab_indexer.sh" --scenario drain-engine '
              f'--quiet-seconds {quiet} --drain-timeout {timeout}\n'
              f'wait_quiet "p*"; echo "rc=$? end=$DRAIN_END final=$DRAIN_FINAL"\n')
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120,
                         env=dict(os.environ, AB_SEQ=str(seq), AB_STATE=str(state), AB_TEST_QUIET_FLOOR_S=str(floor)))
    line = [l for l in out.stdout.splitlines() if l.startswith("rc=")]
    assert line, out.stdout + out.stderr
    fields = dict(kv.split("=") for kv in line[0].split())
    return fields, int(state.read_text())


def test_wait_quiet_has_no_expected_end_only_quiet(tmp_path):
    """I226: no total is known ahead, so even a count equal to everything the sender sent waits for the quiet."""
    fields, calls = probe_harness(tmp_path, [1, 2, 3, 3, 3, 3], quiet=3)
    assert fields == {"rc": "0", "end": "quiet", "final": "3"} and calls == 6
    src = open(os.path.join(BENCH, "ab_indexer.sh")).read()
    assert "DRAIN_END=expected" not in src and "expected_docs" not in src


def test_wait_quiet_a_failed_probe_keeps_waiting(tmp_path):
    fields, _ = probe_harness(tmp_path, ["fail"], timeout=3)
    assert fields["end"] == "timeout"


def test_wait_quiet_ends_on_quiet_after_the_count_stops_growing(tmp_path):
    fields, calls = probe_harness(tmp_path, [5, 5, 6, 7, 7, 7], quiet=2)
    assert fields == {"rc": "0", "end": "quiet", "final": "7"}
    assert calls == 6            # the window restarts at every change: 7, 7, 7 -> two stable samples


def test_wait_quiet_a_failing_probe_is_not_quiet(tmp_path):
    fields, _ = probe_harness(tmp_path, [4, "fail"], quiet=2, timeout=4)
    assert fields["end"] == "timeout" and fields["rc"] == "1"


def test_wait_quiet_times_out_while_the_count_keeps_growing(tmp_path):
    fields, _ = probe_harness(tmp_path, ["grow"], quiet=2, timeout=3)
    assert fields["rc"] == "1" and fields["end"] == "timeout" and int(fields["final"]) >= 2


def test_a_failed_docker_pause_aborts_the_drain_run(tmp_path):
    """P3: a drain run whose `docker pause` fails measures nothing: abort, no sender, no drain.json."""
    work = bench_copy(tmp_path)
    write_stub(work / "prepare_manager.sh", 'exit 0\n')
    write_stub(work / "run_benchmark.sh", 'touch "$AB_BENCH_MARK"\n')
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    write_stub(bindir / "docker", 'echo "docker $*" >> "$AB_DOCKER_LOG"\n[[ "$1" == pause ]] && exit 1\nexit 0\n')
    write_stub(bindir / "curl", 'cat >/dev/null\ncase "$*" in *_stats*) echo \'{"_all":{"total":{"indexing":'
                                '{"index_total":0}}}}\';; *) echo \'{"count":0}\';; esac\n')
    (tmp_path / "home").mkdir()
    out = run_campaign(work, tmp_path, {
        "PATH": f"{bindir}:{os.environ['PATH']}", "AB_DOCKER_LOG": str(tmp_path / "docker.log"),
        "AB_BENCH_MARK": str(tmp_path / "bench.ran"), "WAZUH_MANAGER_HOME": str(tmp_path / "home")})
    assert out.returncode != 0
    assert "docker pause wazuh-indexer failed" in out.stderr and "NOT a valid measurement" in out.stderr
    assert not (tmp_path / "bench.ran").exists(), "the sender must not run without the pause"
    assert not list(work.glob("results_*/drain.json"))
    assert "1 scenario(s) aborted" in out.stdout


def test_report_with_a_missing_results_dir_is_incomplete_not_a_traceback(tmp_path, capsys):
    gone = tmp_path / "nowhere"
    assert ab.main(["report", "--root", str(gone)]) == 2
    assert "does not exist" in capsys.readouterr().err
    out = subprocess.run([sys.executable, os.path.join(BENCH, "ab_report.py"), "report", "--root", str(gone)],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 2 and "Traceback" not in out.stderr and "INCOMPLETE" in out.stderr


def test_report_creates_the_output_directory(tmp_path):
    stale_runs(tmp_path, campaign="c")
    target = tmp_path / "results_ab" / "deep"
    assert ab.main(["report", "--root", str(tmp_path), "--json", str(target / "r.json"),
                    "--markdown", str(target / "r.md")]) == 0
    assert (target / "r.json").exists() and (target / "r.md").exists()


def test_the_drain_backlog_fits_both_queues():
    """P3: 100,000 events x (payload + 2,048) must stay within the 1 GiB quota with margin at a 3 KiB payload,
    the options give both sides the same quota, and v2's global quota holds the engine's two buckets."""
    sc = json.load(open(os.path.join(BENCH, "scenarios", "ab_drain_engine.json")))
    lines = sum(1 for _ in open(os.path.join(BENCH, "sample_payloads", "engine", "syslog.log")))
    lane = sc["lanes"]["engine"][0]
    events = sum(f["agents"] for f in sc["fleets"]) * lines * lane["repeat_count"]
    quota = 1073741824
    for conf in ("v1.conf", "v2.conf"):
        text = open(os.path.join(BENCH, "ab_options", conf)).read()
        assert f"analysisd.indexer_queue_max_bytes={quota}" in text
    v2 = open(os.path.join(BENCH, "ab_options", "v2.conf")).read()
    assert "analysisd.indexer_client_global_quota_bytes=2147483648" in v2
    assert "wazuh_modules.indexer_client_global_quota_bytes" not in v2   # modulesd's key does not reach the engine (I227)
    assert events == 100000
    assert events * (3072 + 2048) <= quota // 2          # v2, 3 KiB payload: under half the quota
    assert events * 3072 <= quota // 2                   # v1 charges the payload only
    assert "RESULT_RESERVE" in sc["description"] and "100,000" in sc["description"]


def test_drain_syscollector_waits_on_the_inventory_indices_only(tmp_path):
    """P3: the expected-total wait must not count VD's wazuh-states-vulnerabilities-* documents."""
    import fnmatch
    out = dry("ab_indexer.sh", "--scenario", "drain-syscollector", "--no-warmup", "--n", "2",
              "--snapshots", str(tmp_path))
    pats = {m.group(1) for m in re.finditer(r"indexer_ingest_probe\.sh --patterns (\S+)", out.stdout)}
    assert pats == {"wazuh-states-inventory-*"}, out.stdout
    pattern = pats.pop()
    assert fnmatch.fnmatch("wazuh-states-inventory-packages", pattern)
    assert not fnmatch.fnmatch("wazuh-states-vulnerabilities-000001", pattern)
    # and the probe really sums per pattern: the VD index is invisible to the count that ends the wait
    bindir = tmp_path / "bin"
    bindir.mkdir()
    write_stub(bindir / "curl",
               'cat >/dev/null\ncase "$*" in *wazuh-states-inventory-\\**_count*) echo \'{"count":100}\';;'
               ' *wazuh-states-\\**_count*) echo \'{"count":150}\';; *) echo \'{"count":0}\';; esac\n')
    res = subprocess.run(["bash", os.path.join(BENCH, "indexer_ingest_probe.sh"), "--once", "--patterns", pattern],
                         capture_output=True, text=True, timeout=60,
                         env=dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", PYTHON=sys.executable,
                                  **idx_env(tmp_path)))
    assert res.stdout.strip() == "100", res.stderr


# ---------------------------------------------------------------------------
# E12 (I226): the lock the daemons inherited, the probe's address, the cleaner's password, the drain record
# ---------------------------------------------------------------------------
def test_the_daemons_a_run_starts_do_not_inherit_the_measure_lock(tmp_path):
    """A1 of the E12 smoke: `flock LOCK bash ...` without -o left the lock's descriptor open in the manager
    daemons that prepare_manager.sh --side restarts, so the lock stayed taken after the campaign. Here the
    restore stub leaves a detached daemon behind; once the campaign is over the lock must be free."""
    work = bench_copy(tmp_path)
    pidfile = tmp_path / "daemon.pid"
    write_stub(work / "prepare_manager.sh",
               f'sleep 30 </dev/null >/dev/null 2>&1 &\necho $! > "{pidfile}"\nexit 1\n')
    lock = tmp_path / "measure.lock"
    try:
        out = run_campaign(work, tmp_path)
        assert "1 scenario(s) aborted" in out.stdout, out.stdout + out.stderr
        pid = int(pidfile.read_text())
        os.kill(pid, 0)                                            # the daemon outlives the campaign
        free = subprocess.run(["flock", "-n", str(lock), "true"], timeout=10)
        assert free.returncode == 0, "the measure lock is still held by a daemon the run started"
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), 9)
            except ProcessLookupError:
                pass


def print_url(env_extra):
    env = dict(os.environ, PYTHON=sys.executable, **env_extra)
    env.pop("INDEXER_URL", None) if "INDEXER_URL" not in env_extra else None
    return subprocess.run(["bash", os.path.join(BENCH, "indexer_ingest_probe.sh"), "--print-url"],
                          capture_output=True, text=True, env=env, timeout=30).stdout.strip()


def test_the_probe_address_comes_from_the_manager_config_else_127_0_0_1(tmp_path):
    """A2 of the E12 smoke: `localhost` is not in the e2e node's certificate (IP:127.0.0.1, DNS:wazuh-indexer)."""
    conf = tmp_path / "wazuh-manager.conf"
    conf.write_text("<wazuh_config><indexer><hosts><host>https://10.1.2.3:9200</host>"
                    "<host>https://10.9.9.9:9200</host></hosts></indexer></wazuh_config>\n")
    assert print_url({"WAZUH_MANAGER_CONF": str(conf)}) == "https://10.1.2.3:9200"
    conf.write_text("<wazuh_config><indexer><hosts><host>wazuh-indexer:9200</host></hosts></indexer></wazuh_config>")
    assert print_url({"WAZUH_MANAGER_CONF": str(conf)}) == "https://wazuh-indexer:9200"
    assert print_url({"WAZUH_MANAGER_CONF": str(tmp_path / "none.conf")}) == "https://127.0.0.1:9200"
    conf.write_text("<not xml")
    assert print_url({"WAZUH_MANAGER_CONF": str(conf)}) == "https://127.0.0.1:9200"
    assert print_url({"WAZUH_MANAGER_CONF": str(conf), "INDEXER_URL": "https://idx:9201/"}) == "https://idx:9201"
    for script in ("indexer_ingest_probe.sh", "ab_indexer.sh"):
        assert "https://localhost:9200" not in open(os.path.join(BENCH, script)).read()


def test_ab_indexer_uses_the_derived_address(tmp_path):
    conf = tmp_path / "wazuh-manager.conf"
    conf.write_text("<wazuh_config><indexer><hosts><host>https://10.1.2.3:9200</host></hosts></indexer></wazuh_config>")
    env = dict(os.environ, PYTHON=sys.executable, WAZUH_MANAGER_CONF=str(conf))
    env.pop("INDEXER_URL", None)
    out = subprocess.run(["bash", "-c", f'AB_SOURCE_ONLY=1 source "{BENCH}/ab_indexer.sh" --scenario drain-engine; '
                          'echo "URL=$INDEXER_URL"'], capture_output=True, text=True, env=env, timeout=30)
    assert "URL=https://10.1.2.3:9200" in out.stdout, out.stderr
    env["WAZUH_MANAGER_CONF"] = str(tmp_path / "none")
    out = subprocess.run(["bash", "-c", f'AB_SOURCE_ONLY=1 source "{BENCH}/ab_indexer.sh" --scenario drain-engine; '
                          'echo "URL=$INDEXER_URL"'], capture_output=True, text=True, env=env, timeout=30)
    assert "URL=https://127.0.0.1:9200" in out.stdout


def api_stub(tmp_path, left_after_delete=False, failed_items=0):
    """A curl that plays the Server API: login (body to -o, status on stdout, as cleanup_agents.sh asks), GET
    /agents (two bench agents until the DELETE, then none unless `left_after_delete`), DELETE. It logs its argv
    and stdin (the -K config) to $CURL_LOG. The password sources are test_scripts.py's."""
    bindir = tmp_path / "apibin"
    bindir.mkdir()
    state = tmp_path / "deleted"
    write_stub(bindir / "curl",
               'echo "ARGV $*" >> "$CURL_LOG"\ncat >> "$CURL_LOG"\n'
               'case "$*" in\n'
               '  *authenticate*) out=""; prev=""; for a in "$@"; do [[ "$prev" == -o ]] && out="$a"; prev="$a"; done\n'
               '     if [[ -n "$out" ]]; then echo \'{"data":{"token":"tok-123"}}\' > "$out"; echo -n 200;\n'
               '     else echo \'{"data":{"token":"tok-123"}}\'; fi ;;\n'
               f'  *"-X DELETE"*) touch "{state}"; echo \'{{"data":{{"total_affected_items":2,"total_failed_items":{failed_items}}}}}\' ;;\n'
               f'  *) if [[ -e "{state}" && -z "{"1" if left_after_delete else ""}" ]]; then echo \'{{"data":{{"affected_items":[]}}}}\';\n'
               '     else echo \'{"data":{"affected_items":[{"id":"001","name":"bench-a"},{"id":"002","name":"bench-b"}]}}\'; fi ;;\n'
               'esac\n')
    return bindir


def cleanup(tmp_path, env_extra, **stub):
    log = tmp_path / "curl.log"
    env = {k: v for k, v in os.environ.items() if k not in ("WAZUH_API_PASS", "WAZUH_MANAGER_API_PASSWORD")}
    env.update({"PATH": f"{api_stub(tmp_path, **stub)}:{os.environ['PATH']}", "CURL_LOG": str(log),
                "PYTHON": sys.executable})
    env.update(env_extra)
    out = subprocess.run(["bash", os.path.join(BENCH, "cleanup_agents.sh")], capture_output=True, text=True,
                         env=env, timeout=60)
    return out, (log.read_text() if log.exists() else "")





def test_cleanup_agents_fails_loudly_when_agents_survive_the_delete(tmp_path):
    out, _ = cleanup(tmp_path, {"WAZUH_API_PASS": "pw"}, left_after_delete=True)
    assert out.returncode == 1 and "still registered after the DELETE" in out.stderr and "001,002" in out.stderr


def test_cleanup_agents_fails_loudly_on_failed_items(tmp_path):
    out, _ = cleanup(tmp_path, {"WAZUH_API_PASS": "pw"}, failed_items=1)
    assert out.returncode == 1 and "failed items: 1" in out.stderr


def test_cleanup_agents_fails_when_the_login_is_refused(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    write_stub(bindir / "curl", 'cat >/dev/null\necho \'{"title":"Unauthorized"}\'\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", WAZUH_API_PASS="bad", PYTHON=sys.executable)
    out = subprocess.run(["bash", os.path.join(BENCH, "cleanup_agents.sh")], capture_output=True, text=True,
                         env=env, timeout=60)
    assert out.returncode == 1 and "could not authenticate" in out.stderr


def drain_stubs(tmp_path, work, dropped="0"):
    """Stubs for one whole drain run: restore OK, a sender that writes the smoke's sender_summary.json, docker,
    and a curl that answers the indexer (0 documents until the sender ran, then 49,300) and the engine API."""
    write_stub(work / "prepare_manager.sh", 'exit 0\n')
    write_stub(work / "run_benchmark.sh",
               'while [[ $# -gt 0 ]]; do [[ "$1" == --label ]] && label="$2"; shift; done\n'
               'd="$(dirname "$0")/results_$label"; mkdir -p "$d"\n'
               'echo \'{"totals":{"stateless":{"events_sent":100000,"sent":1000,"s202":986,"s503":14}}}\''
               ' > "$d/sender_summary.json"\n'
               'touch "$AB_SENT_MARK"\n')
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    write_stub(bindir / "docker", 'exit 0\n')
    write_stub(bindir / "curl",
               'cat >/dev/null\n'
               'case "$*" in\n'
               '  *--unix-socket*) [[ "$AB_DROPPED" == none ]] && exit 7;'
               ' echo "{\\"global\\":[{\\"name\\":\\"indexer.events.dropped\\",\\"value\\":$AB_DROPPED}]}" ;;\n'
               '  *_delete_by_query*) rm -f "$AB_SENT_MARK"; echo \'{}\' ;;\n'
               '  *_stats*) echo \'{"_all":{"total":{"indexing":{"index_total":1}}}}\' ;;\n'
               '  *) if [[ -e "$AB_SENT_MARK" ]]; then echo \'{"count":49300}\'; else echo \'{"count":0}\'; fi ;;\n'
               'esac\n')
    (tmp_path / "home").mkdir()
    return {"PATH": f"{bindir}:{os.environ['PATH']}", "AB_SENT_MARK": str(tmp_path / "sent.mark"),
            "AB_DROPPED": dropped, "WAZUH_MANAGER_HOME": str(tmp_path / "home"), "AB_TEST_QUIET_FLOOR_S": "1",
            "AB_CLEANUP_LOG": str(tmp_path / "cleanup.log")}


def test_a_drain_run_records_the_accepted_events_and_the_engine_drop_count(tmp_path):
    work = bench_copy(tmp_path)
    env = drain_stubs(tmp_path, work, dropped="0")
    out = run_campaign(work, tmp_path, env, args=("--scenario", "drain-engine", "--n", "2", "--no-warmup",
                                                   "--quiet-seconds", "1"))
    assert "0 scenario(s) aborted" in out.stdout, out.stdout + out.stderr
    drain = json.loads((work / "results_ab-v1-drain-engine-1" / "drain.json").read_text())
    assert drain["drain_end"] == "quiet" and drain["docs_final"] == 49300
    assert drain["events_sent"] == 100000 and drain["events_accepted"] == 98600
    assert drain["events_rejected_503"] == 1400 and drain["engine_events_dropped"] == 0
    assert "expected_docs" not in drain
    m = json.loads((work / "results_ab-v1-drain-engine-1" / "ab_metrics.json").read_text())
    assert m["engine_events_dropped"] == 0 and m["metrics"]["events_accepted"] == 98600
    assert (tmp_path / "cleanup.log").read_text().count("cleanup") == 4      # every agent-mode run cleans


@pytest.mark.parametrize("dropped, reason", [("12", "dropped events"), ("none", "no indexer.events.dropped")])
def test_a_drain_campaign_whose_engine_dropped_or_did_not_answer_is_incomparable(tmp_path, dropped, reason):
    work = bench_copy(tmp_path)
    env = drain_stubs(tmp_path, work, dropped=dropped)
    out = run_campaign(work, tmp_path, env, args=("--scenario", "drain-engine", "--n", "2", "--no-warmup",
                                                   "--quiet-seconds", "1"))
    drain = json.loads((work / "results_ab-v2-drain-engine-1" / "drain.json").read_text())
    assert drain["engine_events_dropped"] == (None if dropped == "none" else 12)
    assert "Overall: INCOMPARABLE" in out.stdout and reason in out.stdout and out.returncode == 2, out.stdout


def test_a_failed_agent_cleanup_aborts_the_run(tmp_path):
    """D111: a cleanup that leaves bench-* agents makes the next enrollment answer 409: the run is not measured."""
    work = bench_copy(tmp_path)
    env = drain_stubs(tmp_path, work)
    env["AB_CLEANUP_FAIL"] = "1"
    out = run_campaign(work, tmp_path, env)
    assert "cleanup_agents.sh failed" in out.stderr and "still registered" in out.stderr
    assert not (tmp_path / "sent.mark").exists(), "the sender must not run after a failed cleanup"
    assert "1 scenario(s) aborted" in out.stdout and out.returncode != 0


def sessions_drain(v1_docs, v2_docs, v1_abandoned=32, v2_abandoned=32):
    return ([run("v1", "drain-syscollector", {"sessions_per_s": 15.7, "docs_drained": d, "sessions_abandoned": v1_abandoned},
                 verdict=("sessions_per_s",), fraction=None) for d in v1_docs]
            + [run("v2", "drain-syscollector", {"sessions_per_s": 18.8, "docs_drained": d, "sessions_abandoned": v2_abandoned},
                   verdict=("sessions_per_s",), fraction=None) for d in v2_docs])


def test_a_sessions_drain_that_retained_fewer_documents_is_incomparable_not_a_win():
    """The E12 campaign: v2's inventory sync answered 503 while the indexer was paused, the sender gave up
    after its retry budget, and v2 indexed 10,000-22,000 documents against v1's 36,000: its higher
    sessions/s measured how fast it rejected. That must not read as a PASS."""
    entry = ab.compare(sessions_drain([36000] * 4, [22000, 18000, 22000, 10000], 32, 54))["scenarios"]["drain-syscollector"]
    assert entry["verdict"] == "INCOMPARABLE"
    assert entry["metrics"]["sessions_per_s"]["verdict"] == "INCOMPARABLE"
    assert any("v1 drained 36000 documents, v2 20000" in n and "abandoned" in n for n in entry["notes"])
    assert entry["comparability"]["docs_gap"] == pytest.approx(0.4444, abs=1e-4)


def test_a_sessions_drain_with_the_same_documents_is_judged():
    entry = ab.compare(sessions_drain([36000] * 2, [36000, 35800]))["scenarios"]["drain-syscollector"]
    assert entry["verdict"] == "PASS"
    entry = ab.compare(sessions_drain([36000] * 2, [35640] * 2))["scenarios"]["drain-syscollector"]   # exactly 1 %
    assert entry["verdict"] == "PASS"
    entry = ab.compare(sessions_drain([36000] * 2, [35600] * 2))["scenarios"]["drain-syscollector"]   # 1.1 %
    assert entry["verdict"] == "INCOMPARABLE"
    runs = sessions_drain([36000] * 2, [36000] * 2)
    runs[0]["metrics"].pop("docs_drained")
    assert ab.compare(runs)["scenarios"]["drain-syscollector"]["verdict"] == "INCOMPARABLE"


def test_collect_counts_the_abandoned_sessions(tmp_path):
    (tmp_path / "sender_summary.json").write_text(json.dumps({"totals": {"sessions": {
        "sent": 636, "ok": 42, "retries_exhausted": 54, "abandoned_on_drain": 2, "documents_sent": 550000}}}))
    doc = ab.collect(str(tmp_path), "v2", "drain-syscollector", "1", "drain", False, ["sessions_per_s"])
    assert doc["metrics"]["sessions_abandoned"] == 56
    (tmp_path / "sender_summary.json").write_text(json.dumps({"totals": {"sessions": {"sent": 0}}}))
    assert "sessions_abandoned" not in ab.collect(str(tmp_path), "v2", "s", "1", "drain", False, [])["metrics"]


def test_syscollector_drain_scenario_never_abandons_a_session():
    """I227: the syscollector A/B drain must not abandon sessions shed with 503 during the pause (the 2026-10-27
    campaign was INCOMPARABLE because the sender gave up after ~5 s of 503s): retries are unbounded, cut by drain."""
    scenario = json.load(open(os.path.join(BENCH, "scenarios", "ab_drain_syscollector_debian.json")))
    retry = scenario["defaults"]["retry"]
    assert retry["enabled"] is True and retry["max_attempts"] == 0
    assert scenario["pacing"]["drain_timeout"] not in ("", "0", "0s")


# ---------------------------------------------------------------------------
# E12 retomada: P-9 (no default indexer credential, no silent -k), A2 (readiness), A6 (index_total)
# ---------------------------------------------------------------------------
def run_probe(tmp_path, env_extra, args=("--once", "--patterns", "wazuh-events*")):
    log = tmp_path / "curl.log"
    env = clean_env(PATH=f"{curl_stub(tmp_path)}:{os.environ['PATH']}", CURL_LOG=str(log), PYTHON=sys.executable,
                    WAZUH_MANAGER_CONF=str(tmp_path / "no-manager.conf"),
                    INDEXER_CREDENTIALS_FILE=str(tmp_path / "no-credentials.env"))
    env.update(env_extra)
    out = subprocess.run(["bash", os.path.join(BENCH, "indexer_ingest_probe.sh"), *args],
                         capture_output=True, text=True, env=env, timeout=60)
    return out, (log.read_text() if log.exists() else "")


def argv_lines(log):
    return [l for l in log.splitlines() if l.startswith("ARGV")]


@pytest.mark.parametrize("partial", [{}, {"INDEXER_USER": "admin"}, {"INDEXER_PASSWORD": "pw"}])
def test_the_probe_without_credentials_fails_and_never_tries_admin_admin(tmp_path, partial):
    """P-9: no INDEXER_USER/INDEXER_PASSWORD pair and no credentials file -> a clear error, exit 1, no request."""
    out, log = run_probe(tmp_path, dict(partial, INDEXER_CACERT=str(idx_env(tmp_path)["INDEXER_CACERT"])))
    assert out.returncode == 1, out.stdout + out.stderr
    assert ("no indexer credentials" in out.stderr) if not partial else ("set both INDEXER_USER" in out.stderr)
    assert log == "", "the probe must not send a request without credentials"
    for script in ("indexer_ingest_probe.sh", "ab_indexer.sh", "indexer_control.sh"):
        src = open(os.path.join(BENCH, script)).read()
        assert ":-admin}" not in src and "admin:admin" not in src and "curl -sk" not in src, script


def test_the_credentials_file_is_parsed_never_sourced(tmp_path):
    marker = tmp_path / "PWNED"
    creds = tmp_path / "credentials.env"
    creds.write_text(f"WAZUH_INDEXER_KIBANASERVER_PASSWORD=other\nWAZUH_INDEXER_ADMIN_PASSWORD=a=b$(touch {marker})\n")
    out, log = run_probe(tmp_path, {"INDEXER_CREDENTIALS_FILE": str(creds),
                                    "INDEXER_CACERT": idx_env(tmp_path)["INDEXER_CACERT"]})
    assert out.returncode == 0 and out.stdout.strip() == "3", out.stderr
    assert f'user = "admin:a=b$(touch {marker})"' in log                # the value, split at the first '='
    assert not marker.exists(), "the credentials file was executed"
    assert "a=b" not in "".join(argv_lines(log)) and "a=b" not in out.stdout + out.stderr


def test_the_default_ca_is_the_managers_indexer_ca_and_k_needs_insecure(tmp_path):
    creds = {"INDEXER_USER": "admin", "INDEXER_PASSWORD": "pw"}
    default_ca = "/etc/wazuh-manager/certs/indexer-ca.pem"
    out, log = run_probe(tmp_path, creds)
    if os.access(default_ca, os.R_OK):                                    # a host with an installed manager
        assert out.returncode == 0, out.stderr
        assert all(f"--cacert {default_ca}" in l and " -k" not in l for l in argv_lines(log)), log
    else:                                                                  # elsewhere: refused, naming it
        assert out.returncode == 1 and default_ca in out.stderr and log == ""
    # the CA the manager's config names wins over the default
    ca = tmp_path / "configured-ca.pem"
    ca.write_text("ca\n")
    conf = tmp_path / "wazuh-manager.conf"
    conf.write_text("<wazuh_config><indexer><hosts><host>https://10.1.2.3:9200</host></hosts><ssl>"
                    f"<certificate_authorities><ca>{ca}</ca></certificate_authorities></ssl></indexer></wazuh_config>")
    (tmp_path / "curl.log").unlink(missing_ok=True)
    out, log = run_probe(tmp_path, dict(creds, WAZUH_MANAGER_CONF=str(conf)))
    assert out.returncode == 0 and all(f"--cacert {ca}" in l for l in argv_lines(log)), out.stderr + log
    assert all("https://10.1.2.3:9200/" in l for l in argv_lines(log))
    # INDEXER_CACERT wins over both; an unreadable one is an error, not a fallback to -k
    (tmp_path / "curl.log").unlink(missing_ok=True)
    out, log = run_probe(tmp_path, dict(creds, WAZUH_MANAGER_CONF=str(conf), INDEXER_CACERT=str(tmp_path / "gone.pem")))
    assert out.returncode == 1 and "gone.pem is not readable" in out.stderr and log == ""
    # -k only when asked for, and said aloud
    out, log = run_probe(tmp_path, dict(creds, INDEXER_INSECURE="1"))
    assert out.returncode == 0 and all(" -k" in l and "--cacert" not in l for l in argv_lines(log))
    assert "NOT verified" in out.stderr


def test_ab_indexer_without_credentials_stops_before_the_lock_and_the_manager(tmp_path):
    work = bench_copy(tmp_path)
    write_stub(work / "prepare_manager.sh", 'touch "$AB_STUB_OUT"\nexit 0\n')
    env = clean_env(AB_MEASURE_LOCK=str(tmp_path / "locks" / "measure.lock"), PYTHON=sys.executable,
                    AB_STUB_OUT=str(tmp_path / "restored"), WAZUH_MANAGER_CONF=str(tmp_path / "none.conf"),
                    INDEXER_CREDENTIALS_FILE=str(tmp_path / "none.env"))
    out = subprocess.run(["bash", str(work / "ab_indexer.sh"), "--scenario", "drain-engine", "--n", "2",
                          "--snapshots", str(tmp_path / "snaps")], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 1 and "no indexer credentials" in out.stderr, out.stdout + out.stderr
    assert not (tmp_path / "locks").exists() and not (tmp_path / "restored").exists()
    # a dry run needs none: it touches nothing
    assert dry("ab_indexer.sh", "--scenario", "drain-engine", "--snapshots", str(tmp_path),
               env={"INDEXER_CREDENTIALS_FILE": str(tmp_path / "none.env")}).returncode == 0


def bind_socket(path):
    import socket
    path.parent.mkdir(parents=True, exist_ok=True)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    s.close()                                  # the socket file stays: [[ -S ]] is what the script checks


def ready_harness(tmp_path, before="", after="", sockets=("inventory-sync-http.sock", "engine-api-http.sock")):
    """Source ab_indexer.sh (hook), take the log mark, append `after` to the log, run wait_manager_ready."""
    home = tmp_path / "home"
    (home / "logs").mkdir(parents=True)
    log = home / "logs" / "wazuh-manager.log"
    log.write_text(before)
    for name in sockets:
        bind_socket(home / "queue" / "sockets" / name)
    script = (f'AB_SOURCE_ONLY=1 source "{BENCH}/ab_indexer.sh" --scenario drain-engine\n'
              'mark="$(manager_log_mark)"\n'
              f'printf "%s" "$AFTER" >> "{log}"\n'
              'wait_manager_ready "$mark"; echo "rc=$?"\n')
    env = dict(os.environ, WAZUH_MANAGER_HOME=str(home), AFTER=after, AB_TEST_READY_TIMEOUT_S="2",
               AB_TEST_READY_SETTLE_S="0")
    env.pop("AB_ENGINE_API_SOCKET", None)
    env.pop("AB_TEST_SKIP_READY", None)
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)


READY = "2026/11/06 18:00:00 wazuh-manager-modulesd: inventory-sync-server: INFO: The indexer is reachable; inventory documents can be delivered.\n"


def test_wait_manager_ready_needs_the_reachable_line_after_the_restart_and_both_sockets(tmp_path):
    """A2: the line must be logged AFTER the mark (a line of the previous start does not count)."""
    out = ready_harness(tmp_path / "a", after="noise\n" + READY)
    assert "rc=0" in out.stdout and "ready: inventory_sync reachable" in out.stdout, out.stdout + out.stderr
    out = ready_harness(tmp_path / "b", before=READY, after="noise\n")
    assert "rc=1" in out.stdout and "ready: timeout" in out.stderr
    out = ready_harness(tmp_path / "c", after=READY, sockets=("inventory-sync-http.sock",))
    assert "rc=1" in out.stdout and "ready: timeout" in out.stderr


def test_a_manager_that_never_gets_ready_aborts_the_run(tmp_path):
    work = bench_copy(tmp_path)
    env = drain_stubs(tmp_path, work)
    env.update({"AB_TEST_READY_TIMEOUT_S": "1", "AB_TEST_SKIP_READY": ""})
    out = run_campaign(work, tmp_path, env)
    assert "manager not ready" in out.stderr and "1 scenario(s) aborted" in out.stdout, out.stdout + out.stderr
    assert not (tmp_path / "sent.mark").exists(), "the sender must not run before the manager is ready"
    assert dry("ab_indexer.sh", "--scenario", "drain-engine", "--snapshots", str(tmp_path)).stdout.count(
        "The indexer is reachable") >= 1


def test_a_deferred_agent_deletion_is_retried_not_fatal(tmp_path):
    """A2(b): authd applies the DELETE later; the first cleanups still list bench-* agents."""
    work = bench_copy(tmp_path)
    env = drain_stubs(tmp_path, work)
    count = tmp_path / "cleanup.count"
    write_stub(work / "cleanup_agents.sh",
               f'n=$(cat "{count}" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "{count}"\n'
               '(( n % 3 == 0 )) && exit 0\necho "cleanup_agents: ERROR: 25 agent(s) still registered" >&2; exit 1\n')
    out = run_campaign(work, tmp_path, env, args=("--scenario", "drain-engine", "--n", "2", "--no-warmup",
                                                   "--quiet-seconds", "1"))
    assert "0 scenario(s) aborted" in out.stdout, out.stdout + out.stderr
    assert "cleanup_agents.sh attempt 1/6 failed" in out.stderr and int(count.read_text()) == 12   # 4 runs x 3 tries
    env["AB_TEST_CLEANUP_TRIES"] = "2"
    count.unlink()
    out = run_campaign(work, tmp_path, env)
    assert "cleanup_agents.sh failed" in out.stderr and int(count.read_text()) == 2


def test_index_total_delta_needs_the_pre_pause_baseline(tmp_path):
    """A6: the E12 v2 drain-engine run: the first sample's _stats did not answer (the pause raced it), the
    whole drain fitted between two samples, so every complete row read 506301 and the delta came out 0."""
    probe = tmp_path / "probe.csv"
    probe.write_text("epoch,pattern,count,index_total\n"
                     "1000,wazuh-events*,0,\n1001,wazuh-events*,,\n1035,wazuh-events*,0,506301\n"
                     "1037,wazuh-events*,49050,506301\n1040,wazuh-events*,49050,506301\n")
    (tmp_path / "drain.json").write_text(json.dumps({"t_pause": 1000.1, "t_resume": 1034.8}))
    m = ab.collect(str(tmp_path), "v2", "drain-engine", "1", "drain", False, [])["metrics"]
    assert "index_total_delta" not in m                    # unknown, not 0
    assert m["docs_indexed"] == 49050 and m["docs_drained"] == 49050   # the count series keeps the baseline row
    probe.write_text("epoch,pattern,count,index_total\n"
                     "999,wazuh-events*,0,457251\n1001,wazuh-events*,,\n"
                     "1037,wazuh-events*,49050,506301\n1040,wazuh-events*,49050,506301\n")
    m = ab.collect(str(tmp_path), "v2", "drain-engine", "1", "drain", False, [])["metrics"]
    assert m["index_total_delta"] == 49050


def test_a_drain_run_takes_the_probe_baseline_before_the_pause(tmp_path):
    """A6: a probe whose _stats never answers gets no baseline: the run aborts before `docker pause`."""
    work = bench_copy(tmp_path)
    env = drain_stubs(tmp_path, work)
    write_stub(tmp_path / "fakebin" / "curl", 'cat >/dev/null\ncase "$*" in *_stats*) exit 7;; esac\necho \'{"count":0}\'\n')
    write_stub(tmp_path / "fakebin" / "docker", 'echo "docker $*" >> "$AB_DOCKER_LOG"\n')
    env.update({"AB_TEST_BASELINE_TIMEOUT_S": "1", "AB_DOCKER_LOG": str(tmp_path / "docker.log")})
    out = run_campaign(work, tmp_path, env)
    assert "no complete baseline sample" in out.stderr and "1 scenario(s) aborted" in out.stdout, out.stderr
    assert not (tmp_path / "docker.log").exists() and not (tmp_path / "sent.mark").exists()
    # with the stubs that answer both, the first row of every probe.csv is a complete baseline
    (tmp_path / "ok").mkdir()
    work2 = bench_copy(tmp_path / "ok")
    env2 = drain_stubs(tmp_path / "ok", work2)
    out = run_campaign(work2, tmp_path / "ok", env2, args=("--scenario", "drain-engine", "--n", "2", "--no-warmup",
                                                            "--quiet-seconds", "1"))
    assert "0 scenario(s) aborted" in out.stdout, out.stdout + out.stderr
    first = (work2 / "results_ab-v1-drain-engine-1" / "probe.csv").read_text().splitlines()[1].split(",")
    assert first[2] != "" and first[3] != ""
