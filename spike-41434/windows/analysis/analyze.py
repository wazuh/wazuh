#!/usr/bin/env python3
"""Analyze one etwpoc 'full' run: python3 analyze.py <etw_file> <truth_csv> <label>"""
import collections
import csv
import re
import sys

fn, truth_fn, label = sys.argv[1], sys.argv[2], sys.argv[3]
evs, cur = [], None
for line in open(fn, errors="replace"):
    line = line.rstrip("\r\n")
    m = re.match(r"\[(\S+)\] (id|opcode)=(\d+) ver=(\d+) hdr_pid=(\d+) lat_ms=([-\d.]+)(.*)", line)
    if m:
        task = re.search(r"task=(\S+)", m[7])
        cur = {"prov": m[1], "id": int(m[3]), "ver": int(m[4]), "hdr": int(m[5]), "lat": float(m[6]),
               "task": task[1] if task else "", "p": {}}
        evs.append(cur)
        continue
    m = re.match(r"\s{4}(\w+)=(.*)", line)
    if m and cur:
        cur["p"][m[1]] = m[2]


def num(v):
    v = (v or "0").strip()
    return int(v, 16) if v.startswith("0x") else int(v or 0)


truth = list(csv.DictReader(open(truth_fn)))
expected = sum(int(r["count"]) for r in truth if r["kind"].endswith("_quick")) + 5
qs = [e for e in evs if e["prov"] == "Classic-Process" and e["id"] == 1 and e["p"].get("ImageFileName") == "quick.exe"]
qe = [e for e in evs if e["prov"] == "Classic-Process" and e["id"] == 2 and e["p"].get("ImageFileName") == "quick.exe"]
print(f"## {label}")
print(f"quick.exe expected={expected} starts={len(qs)} ends={len(qe)} ends_exit7={sum(1 for e in qe if e['p'].get('ExitStatus') == '7')}")
print("users:", dict(collections.Counter(e["p"].get("UserSID") for e in qs)))
print("cmdline sample:", qs[0]["p"].get("CommandLine") if qs else None)
lat = sorted(e["lat"] for e in evs if e["prov"] == "Classic-Process")
if lat:
    print(f"proc latency ms p50={lat[len(lat)//2]:.0f} p95={lat[int(len(lat)*.95)]:.0f} max={lat[-1]:.0f}")
print("classic process versions:", dict(collections.Counter((e["id"], e["ver"]) for e in evs if e["prov"] == "Classic-Process")))
tcpip = [e for e in evs if e["prov"] == "TCPIP"]
print("TCPIP events:", dict(collections.Counter((e["id"], e["ver"], e["task"]) for e in tcpip)))
for i in sorted({e["id"] for e in tcpip}):
    sample = next(e for e in tcpip if e["id"] == i)
    print(f"  TCPIP {i} fields: {','.join(sample['p'].keys())}")
starts = [(i, num(e["p"].get("ProcessId")), e["p"].get("UserSID"), e["p"].get("ImageFileName"))
          for i, e in enumerate(evs) if e["prov"] == "Classic-Process" and e["id"] in (1, 3)]
endpoint_pid = {}
for i, e in enumerate(evs):
    if e["prov"] == "TCPIP" and e["id"] == 1391 and e["p"].get("Endpoint"):
        endpoint_pid[e["p"]["Endpoint"]] = num(e["p"].get("ProcessId") or e["p"].get("Pid"))
for i, e in enumerate(evs):
    if e["prov"] == "TCPIP" and e["id"] in (1123, 1396):
        pid = num(e["p"].get("ProcessId") or e["p"].get("Pid"))
        via = "field"
        if not pid and e["p"].get("Endpoint") in endpoint_pid:
            pid, via = endpoint_pid[e["p"]["Endpoint"]], "1391-endpoint"
        if not pid:
            pid, via = e["hdr"], "header"
        m = [s for s in starts if s[1] == pid and s[0] < i]
        who = (m[-1][3], m[-1][2]) if m else "no process start seen"
        print(f"  port {e['id']} {e['p'].get('SocketAddress') or e['p'].get('LocalAddress')} pid={pid} ({via}) -> {who}")
print("truth ports:", [(r["kind"], r["detail"]) for r in truth if r["kind"].startswith("listen")])
for line in open(fn, errors="replace"):
    if line.startswith(("RESOURCES", "SUMMARY", "SESSION", "PROCESSTRACE")):
        print(line.strip())
