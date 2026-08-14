#!/usr/bin/env python3
"""Build LOAD_REPORT.md's tables straight from the run artifacts.

Run after run_matrix.sh: it reads every results_<label>/ directory and prints the
environment, status, latency, throughput and /control tables in the report's order.

    ./run_matrix.sh --cluster <name>
    ./make_report_tables.py > tables.md

Environment facts it cannot read from the artifacts (CPU, indexer version, the
manager build under test) come from an optional env file, one `key: value` per
line, given by BENCH_ENV (default: ./bench_env.txt). Anything missing is skipped
rather than guessed."""
import json, glob, os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
ORDER = ["syscollector_uds", "syscollector_agent", "fim_uds", "fim_agent", "vd_uds",
         "first_connect_uds", "first_connect_agent",
         "burst_uds", "burst_agent", "ramp_503", "session_storm", "control_storm", "contract_400", "contract_413"]


def load(label):
    p = f"{BASE}/results_{label}/sender_summary.json"
    if not os.path.exists(p):
        return None
    return json.load(open(p))


def srv(label, key):
    p = f"{BASE}/results_{label}/summary.json"
    if not os.path.exists(p):
        return None
    d = json.load(open(p)).get("server_metrics", {}).get("delta", {})
    return d.get(key)


def fnum(v, nd=1):
    return "—" if v is None else f"{v:.{nd}f}"


def table_status():
    head = ("| run | mode | agents | dur (s) | sent | 200 | 400 | 401 | 403 | 409 | 413 | 500 | 503 | other |\n"
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
    rows = ""
    for lab in ORDER:
        j = load(lab)
        if not j:
            continue
        m, s = j["meta"], j["totals"]["sessions"]
        rows += (f"| `{lab}` | {m['mode']} | {m['agents_enrolled']} | {m['duration_sec']:.1f} | "
                 f"{s['sent']} | {s['ok']} | {s['s400']} | {s.get('s401', 0)} | {s['s403']} | "
                 f"{s['s409']} | {s['s413']} | {s['s500']} | {s['s503']} | {s['other']} |\n")
    return head + rows


def table_latency():
    head = ("| run | p50 | p90 | p99 | max | avg | n |\n|---|---:|---:|---:|---:|---:|---:|\n")
    rows = ""
    for lab in ORDER:
        j = load(lab)
        if not j:
            continue
        L = j["latency_ms"].get("session") or {}
        if not L.get("count"):
            continue
        rows += (f"| `{lab}` | {fnum(L['p50'])} | {fnum(L['p90'])} | {fnum(L['p99'])} | "
                 f"{fnum(L['max'])} | {fnum(L['avg'])} | {L['count']} |\n")
    return head + rows


def table_throughput():
    head = ("| run | sessions/s | documents/s | MiB/s | server bulk flushes | server bytes flushed |\n"
            "|---|---:|---:|---:|---:|---:|\n")
    rows = ""
    for lab in ORDER:
        j = load(lab)
        if not j:
            continue
        th = j["throughput"]
        # Column names come from the monitor's wide CSV; the dotted metric names
        # are the fallback scraper's long format. Try both so a report can be
        # built from either producer.
        fl = srv(lab, "bulk_flushes") or srv(lab, "sync.bulk.flushes")
        by = srv(lab, "bulk_bytes_total") or srv(lab, "sync.bulk.bytes.total")
        rows += (f"| `{lab}` | {fnum(th['sessions_per_second'])} | {fnum(th['documents_per_second'], 0)} | "
                 f"{fnum(th['mib_per_second'], 2)} | {fnum(fl, 0)} | "
                 f"{'—' if by is None else f'{by/1048576:.1f} MiB'} |\n")
    return head + rows


def table_control():
    head = "| run | startup ok/total | notify ok/total | shutdown ok/total | notify p50 | notify p99 |\n|---|---:|---:|---:|---:|---:|\n"
    rows = ""
    for lab in ORDER:
        j = load(lab)
        if not j:
            continue
        c = j["totals"]["control"]
        tot = sum(c.values())
        if not tot:
            continue
        N = j["latency_ms"].get("notify") or {}
        rows += (f"| `{lab}` | {c['startup_ok']}/{c['startup_ok']+c['startup_err']} | "
                 f"{c['notify_ok']}/{c['notify_ok']+c['notify_err']} | "
                 f"{c['shutdown_ok']}/{c['shutdown_ok']+c['shutdown_err']} | "
                 f"{fnum(N.get('p50'))} | {fnum(N.get('p99'))} |\n")
    return head + rows


def env_table():
    env = {}
    path = os.environ.get("BENCH_ENV", os.path.join(BASE, "bench_env.txt"))
    if not os.path.exists(path):
        return {}
    for line in open(path):
        if ":" in line and not line.startswith("  "):
            k, _, v = line.partition(":")
            env[k.strip()] = v.strip()
    return env


if __name__ == "__main__":
    print("## Environment\n")
    e = env_table()
    print("| | |\n|---|---|")
    for k in ("cpu", "cores", "mem_total", "kernel", "indexer", "git_head", "sender_go"):
        if k in e:
            print(f"| {k} | {e[k]} |")
    print(f"| manager build | {e.get('manager_installed_at','')} |")
    print("\nServer configuration was left at defaults; the values that matter here:\n")
    print("| setting | value |\n|---|---|")
    print("| `max_inflight_bytes` (shed → 503) | 256 MiB |")
    print("| `max_body_size` | unlimited (so 413 needs explicit config) |")
    print("| sharded pipeline workers | `cpp_get_nproc()` = 32 |")
    print("| `vd_workers` | 1 |")
    print("| `remoted.downstream_stateful_response_timeout` | 20 s |")
    print("| `remoted.keyupdate_interval` | 10 s (nominal) |")
    print("\n## Status distribution\n")
    print(table_status())
    print("\n## Session latency (ms)\n")
    print(table_latency())
    print("\n## Throughput\n")
    print(table_throughput())
    print("\n## `/control` traffic\n")
    print(table_control())
