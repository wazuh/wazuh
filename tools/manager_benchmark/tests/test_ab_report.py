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


def run(side, scenario, metrics, kind="drain", verdict=("docs_per_s_drain",), warmup=False, index="1"):
    return {"side": side, "scenario": scenario, "index": index, "kind": kind, "warmup": warmup,
            "verdict_metrics": list(verdict), "metrics": metrics}


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


def drained(v1_docs, v2_docs, ratio=1.20, n=2, **extra):
    """Drain runs where v2 is `ratio` times faster, each side having drained its own documents."""
    return ([dict(run("v1", "drain-engine", {"docs_per_s_drain": 1000.0, "drain_seconds": 100.0,
                                             "docs_drained": v1_docs},
                      verdict=("docs_per_s_drain", "drain_seconds")), **extra) for _ in range(n)]
            + [dict(run("v2", "drain-engine", {"docs_per_s_drain": 1000.0 * ratio,
                                               "drain_seconds": 100.0 / ratio, "docs_drained": v2_docs},
                        verdict=("docs_per_s_drain", "drain_seconds")), **extra) for _ in range(n)])


def test_a_side_that_drained_fewer_documents_is_incomparable_not_a_win():
    # v2 "drains 20 % faster" only because it dropped 40 % of the documents
    result = ab.compare(drained(300000, 180000))
    entry = result["scenarios"]["drain-engine"]
    assert entry["verdict"] == "INCOMPARABLE" and result["overall"] == "INCOMPARABLE"
    for m in ("docs_per_s_drain", "drain_seconds"):
        assert entry["metrics"][m]["verdict"] == "INCOMPARABLE"
        assert entry["metrics"][m]["docs_gap"] == pytest.approx(0.4)
    assert any("300000" in n and "180000" in n and "40.0%" in n for n in entry["notes"])


def test_the_same_documents_within_tolerance_are_judged():
    entry = ab.compare(drained(300000, 298000))["scenarios"]["drain-engine"]   # 0.67 % apart
    assert entry["verdict"] == "PASS"
    entry = ab.compare(drained(300000, 296000))["scenarios"]["drain-engine"]   # 1.33 % apart
    assert entry["verdict"] == "INCOMPARABLE"


def test_missing_docs_drained_is_incomparable():
    runs = drained(300000, 300000)
    for r in runs:
        r["metrics"].pop("docs_drained")
    assert ab.compare(runs)["scenarios"]["drain-engine"]["verdict"] == "INCOMPARABLE"


def test_incomparable_exits_with_2(tmp_path):
    for i, r in enumerate(drained(300000, 180000)):
        d = tmp_path / f"results_ab-{r['side']}-drain-engine-{i}"
        d.mkdir()
        (d / "ab_metrics.json").write_text(json.dumps(r))
    assert ab.main(["report", "--root", str(tmp_path)]) == 2


def test_a_fail_beats_incomparable_in_the_overall():
    runs = drained(300000, 180000) + [dict(r, scenario="drain-syscollector")
                                      for r in drained(300000, 300000, ratio=0.5)]
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


def test_collect_keeps_docs_drained_and_the_provenance_hash(tmp_path):
    (tmp_path / "provenance.txt").write_text("side: v1\n" + "ab" * 32 + "  /x/bin/a\n")
    write_probe(tmp_path / "probe.csv", [0, 0, 0, 100, 200, 200, 200])
    (tmp_path / "drain.json").write_text(json.dumps({
        "t_pause": 999.0, "t_resume": 1002.0, "drain_end": "quiet", "docs_final": 200, "expected_docs": 300}))
    doc = ab.collect(str(tmp_path), "v1", "drain-engine", "1", "drain", False, ["docs_per_s_drain"])
    assert doc["metrics"]["docs_drained"] == 200
    assert doc["provenance_sha256"] == ab.provenance_hash(str(tmp_path / "provenance.txt"))
    assert doc["drain_end"] == "quiet" and doc["expected_docs"] == 300


def test_expected_docs_by_mode(tmp_path):
    (tmp_path / "sender_summary.json").write_text(json.dumps({"totals": {
        "stateless": {"events_sent": 300000}, "sessions": {"documents_sent": 64000}}}))
    assert ab.expected_docs(str(tmp_path), "agent") == 300000
    assert ab.expected_docs(str(tmp_path), "uds") == 64000
    assert ab.expected_docs(str(tmp_path / "nowhere"), "agent") == 0


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
        env=dict(os.environ, AB_MEASURE_LOCK=str(lock), AB_REEXEC_PRINT="1"))
    assert out.returncode == 0, out.stderr
    line = [l for l in out.stdout.splitlines() if l.startswith("REEXEC")][0]
    assert line.endswith("[--scenario] [drain-engine] [--n] [2] [--snapshots] [%s] [--no-warmup] [--locked]"
                         % (tmp_path / "snaps"))
    assert f"flock {lock} bash " in line


def test_the_lock_is_really_taken_and_the_child_gets_its_arguments(tmp_path):
    """The same branch without the hook, end to end: flock is real, the child is the script itself.
    A copy of the scripts whose prepare_manager.sh is a stub records what it is asked to restore;
    it fails on purpose so that nothing after the first restore runs."""
    work = tmp_path / "bench"
    work.mkdir()
    for name in ("ab_indexer.sh", "ab_report.py", "indexer_ingest_probe.sh"):
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
                 AB_RAW_PATTERN="", PYTHON=sys.executable))
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
    bindir.mkdir()
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
               INDEXER_USER="admin", INDEXER_PASSWORD='s3cr"et\\pw', PYTHON=sys.executable)
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
    for name in ("ab_indexer.sh", "ab_report.py", "indexer_ingest_probe.sh"):
        (work / name).write_text(open(os.path.join(BENCH, name)).read())
        (work / name).chmod(0o755)
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
               AB_RAW_PATTERN="", AB_STUB_OUT=str(tmp_path / "stub.out"), **(extra_env or {}))
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


def probe_harness(tmp_path, sequence, quiet=2, timeout=30, expected=0, floor=1):
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
              f'wait_quiet "p*" {expected}; echo "rc=$? end=$DRAIN_END final=$DRAIN_FINAL"\n')
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120,
                         env=dict(os.environ, AB_SEQ=str(seq), AB_STATE=str(state), AB_TEST_QUIET_FLOOR_S=str(floor)))
    line = [l for l in out.stdout.splitlines() if l.startswith("rc=")]
    assert line, out.stdout + out.stderr
    fields = dict(kv.split("=") for kv in line[0].split())
    return fields, int(state.read_text())


def test_wait_quiet_ends_on_expected(tmp_path):
    fields, calls = probe_harness(tmp_path, [1, 2, 3, 3, 3, 3], expected=3)
    assert fields == {"rc": "0", "end": "expected", "final": "3"} and calls == 3


def test_wait_quiet_expected_is_not_reached_by_a_failed_probe_or_zero(tmp_path):
    # expected 0 means unknown: it ends on quiet, never on `expected`
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    fields, _ = probe_harness(tmp_path / "a", [5, 5, 5], expected=0)
    assert fields["end"] == "quiet"
    # a probe that fails keeps the loop waiting (-1 is never >= expected)
    fields, _ = probe_harness(tmp_path / "b", ["fail"], expected=1, timeout=3)
    assert fields["end"] == "timeout"


def test_wait_quiet_ends_on_quiet_after_the_count_stops_growing(tmp_path):
    fields, calls = probe_harness(tmp_path, [5, 5, 6, 7, 7, 7], quiet=2, expected=100)
    assert fields == {"rc": "0", "end": "quiet", "final": "7"}
    assert calls == 6            # the window restarts at every change: 7, 7, 7 -> two stable samples


def test_wait_quiet_a_failing_probe_is_not_quiet(tmp_path):
    fields, _ = probe_harness(tmp_path, [4, "fail"], quiet=2, timeout=4)
    assert fields["end"] == "timeout" and fields["rc"] == "1"


def test_wait_quiet_times_out_while_the_count_keeps_growing(tmp_path):
    fields, _ = probe_harness(tmp_path, ["grow"], quiet=2, timeout=3, expected=0)
    assert fields["rc"] == "1" and fields["end"] == "timeout" and int(fields["final"]) >= 2


def test_a_failed_docker_pause_aborts_the_drain_run(tmp_path):
    """P3: a drain run whose `docker pause` fails measures nothing: abort, no sender, no drain.json."""
    work = bench_copy(tmp_path)
    write_stub(work / "prepare_manager.sh", 'exit 0\n')
    write_stub(work / "run_benchmark.sh", 'touch "$AB_BENCH_MARK"\n')
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    write_stub(bindir / "docker", 'echo "docker $*" >> "$AB_DOCKER_LOG"\n[[ "$1" == pause ]] && exit 1\nexit 0\n')
    write_stub(bindir / "curl", 'cat >/dev/null\necho \'{"count":0}\'\n')
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
    assert "wazuh_modules.indexer_client_global_quota_bytes=2147483648" in v2
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
                         env=dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", PYTHON=sys.executable))
    assert res.stdout.strip() == "100", res.stderr
