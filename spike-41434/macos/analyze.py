"""Compare every collector with the driver ground truth. Usage: analyze.py <out dir>."""
import json, os, sys
from statistics import median

d = sys.argv[1]


def jl(name):
    p = os.path.join(d, name)
    rows = []
    for line in open(p, errors="replace") if os.path.exists(p) else []:
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def lat(v):
    v = sorted(v)
    return f"p50 {median(v) * 1000:.0f} ms, p95 {v[int(.95 * len(v))] * 1000:.0f} ms, max {v[-1] * 1000:.0f} ms" if v else "n/a"


def text(f):
    p = os.path.join(d, f)
    return open(p, errors="replace").read().strip() if os.path.exists(p) else "-"


print("# " + " · ".join(text("env.txt").split("\n")))
truth = jl("truth.jsonl")
procs = [t for t in truth if t["kind"] == "proc"]
ports = [t for t in truth if t["kind"] == "port"]
n = len(procs)

# Endpoint Security, own client.
es = jl("es.jsonl")
ev = [r for r in es if "time" in r]
execs, exits, binds = {}, {}, []
for r in ev:
    if r["t"] == "exec":
        execs.setdefault(r["tpid"], []).append(r)
    elif r["t"] == "exit":
        exits.setdefault(r["pid"], []).append(r)
    elif r["t"] == "bind":
        binds.append(r)
g = sorted(r["gseq"] for r in ev)
ok = dict(s=0, u=0, e=0, c=0)
for p in procs:
    w = lambda r: p["t0"] - 0.05 <= r["time"] <= p["t1"] + 0.5
    s = [r for r in execs.get(p["pid"], []) if w(r)]
    e = [r for r in exits.get(p["pid"], []) if w(r)]
    ok["s"] += bool(s)
    ok["u"] += bool(s) and s[-1]["teuid"] == p["euid"]
    ok["e"] += bool(e)
    ok["c"] += bool(e) and (e[-1]["stat"] >> 8) & 0xFF == p["code"]
print(f"\n## Endpoint Security (own client, exec/fork/exit)\n- {[r for r in es if r.get('t') in ('init', 'subscribe')]}")
print(f"- RESERVED_* (148-156) subscribable: {[r['event'] for r in es if r.get('t') == 'probe' and r['ok']]}")
print(f"- events {len(ev)}, lost (global_seq gaps) {sum(b - a - 1 for a, b in zip(g, g[1:]))}, delivery latency {lat([r['recv'] - r['time'] for r in ev])}")
print(f"- processes {n}: start {ok['s']}/{n}, right euid {ok['u']}/{n}, exit {ok['e']}/{n}, right exit code {ok['c']}/{n}")
print(f"- shortest truth process: {min(p['t1'] - p['t0'] for p in procs) * 1000:.1f} ms; user-change cases right euid: "
      f"{sum(any(r['teuid'] == p['euid'] for r in execs.get(p['pid'], [])) for p in procs if p['code'] in (3, 4) and p['euid'] != procs[0]['euid'])}"
      f"/{sum(1 for p in procs if p['code'] in (3, 4) and p['euid'] != procs[0]['euid'])}")
print(f"- {next((r for r in es if r.get('t') == 'stats'), {})}")
for hold in (0.3, 3.0):
    tp = [p for p in ports if p["hold"] == hold]
    m = [(p, b) for p in tp for b in binds if b["port"] == p["port"] and b["pid"] == p["pid"] and b["euid"] == p["uid"]]
    print(f"- bind event 152, held {hold}s: {len({p['port'] for p, _ in m})}/{len(tp)} with right port, PID and euid; "
          f"latency {lat([b['recv'] - b['time'] for _, b in m])}")
print(f"- other events: {sorted({(r['t'], r.get('path')) for r in ev if r['t'].startswith('ev')})[:5]}")
if binds:
    print(f"- sample bind: {binds[-1]}")

# Ports: libproc polling.
print("\n## Ports (truth: %d sockets, 300 ms and 3 s, TCP listen / UDP bind, v4/v6, user and root)" % len(ports))
for f in ("ports_1000.jsonl", "ports_100.jsonl"):
    rows = jl(f)
    seen = [r for r in rows if r.get("op") == "+"]
    st = next((r for r in rows if r.get("op") == "stats"), {})
    for hold in (0.3, 3.0):
        tp = [p for p in ports if p["hold"] == hold]
        hit = [p for p in tp if any(r["port"] == p["port"] and r["proto"] == p["proto"] and r["pid"] == p["pid"] and r["uid"] == p["uid"]
                                     for r in seen)]
        print(f"- libproc every {st.get('interval_ms')} ms, held {hold}s: {len(hit)}/{len(tp)} with right PID and uid")
    print(f"  - scan {st.get('avg_scan_ms')} ms avg, {st.get('sockets')} sockets, cpu {st.get('cpu_s')} s over {st.get('scans')} scans, rss {st.get('maxrss_kb')} KB")

# NetworkStatistics.
rows = jl("nstat.jsonl")
descs = [r for r in rows if r.get("ev") == "desc"]
rms = {r["src"]: r["ts"] for r in rows if r.get("ev") == "rm"}  # src is a unique id per source
print(f"\n## NetworkStatistics\n- {rows[0] if rows else text('nstat.err')[:300]}")
for hold in (0.3, 3.0):
    tp = [p for p in ports if p["hold"] == hold]
    hit, closed, ol, cl, listen = 0, 0, [], [], 0
    for p in tp:
        m = [r for r in descs if r.get("localAddress", "").endswith(f"|{p['port']}") and r.get("processID") == p["pid"]]
        if m:
            hit += 1
            ol.append(m[0]["ts"] - p["t0"])
            listen += p["proto"] == "tcp" and any(r.get("TCPState") == "Listen" for r in m)
            if m[0]["src"] in rms:
                closed += 1
                cl.append(rms[m[0]["src"]] - p["t1"])
    print(f"- held {hold}s: {hit}/{len(tp)} with port and PID ({listen} TCP in Listen state), {closed} with close; "
          f"open latency {lat(ol)}; close latency {lat(cl)}")
print(f"- {next((r for r in rows if r.get('ev') == 'stats'), {})}")

for f in ("es_unsigned.txt", "nstat_user.txt", "kqueue.txt", "cpu.txt", "sdk_headers.txt", "openbsm.txt"):
    print(f"\n## {f}\n```\n{text(f)[-2500:]}\n```")
