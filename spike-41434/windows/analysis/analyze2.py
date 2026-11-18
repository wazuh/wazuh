#!/usr/bin/env python3
"""Round 4: python3 analyze2.py <etw_file> <truth_csv> <label>
Checks full image path (Kernel-Process 1 joined to classic start by PID), fast TCP/UDP v4/v6 ports with PID, user and close event."""
import csv
import re
import sys

fn, truth_fn, label = sys.argv[1:4]
evs, cur = [], None
for line in open(fn, errors="replace"):
    line = line.rstrip("\r\n")
    m = re.match(r"\[(\S+)\] (id|opcode)=(\d+) ver=(\d+) hdr_pid=(\d+) lat_ms=([-\d.]+)", line)
    if m:
        cur = {"prov": m[1], "id": int(m[3]), "ver": int(m[4]), "hdr": int(m[5]), "lat": float(m[6]), "p": {}}
        evs.append(cur)
        continue
    m = re.match(r"\s{4}(\w+)=(.*?)( \(raw\))?$", line)
    if m and cur:
        cur["p"][m[1]] = m[2]


def num(v):
    v = (v or "0").strip()
    return int(v, 16) if v.startswith("0x") else int(v or 0)


def port_of(a):
    m = re.search(r":(\d+)$", a or "")
    return int(m[1]) if m else None


truth = list(csv.DictReader(open(truth_fn)))
print(f"## {label}")
starts = [(i, num(e["p"].get("ProcessId")), e["p"].get("UserSID"), e["p"].get("ImageFileName"), e["p"].get("CommandLine"))
          for i, e in enumerate(evs) if e["prov"] == "Classic-Process" and e["id"] in (1, 3)]
kp = {}
for e in evs:
    if e["prov"] == "Kernel-Process" and e["id"] == 1:
        kp.setdefault(num(e["p"].get("ProcessID")), []).append(e["p"].get("ImageName", ""))
q = [s for s in starts if s[3] == "quick.exe"]
qe = [e for e in evs if e["prov"] == "Classic-Process" and e["id"] == 2 and e["p"].get("ImageFileName") == "quick.exe"]
expected = sum(int(r["count"]) for r in truth if r["kind"].endswith("_quick"))
with_path = [s for s in q if any(p.lower().endswith("\\poc41434\\quick.exe") for p in kp.get(s[1], []))]
print(f"quick.exe expected={expected} starts={len(q)} ends={len(qe)} exit7={sum(1 for e in qe if e['p'].get('ExitStatus') == '7')} "
      f"users={sorted({s[2] for s in q})}")
print(f"full path (Kernel-Process 1, same PID): {len(with_path)}/{len(q)} sample={next(iter(kp.get(q[0][1], [''])), '') if q else ''}")
kp_lat = sorted(e["lat"] for e in evs if e["prov"] == "Kernel-Process")
cl_lat = sorted(e["lat"] for e in evs if e["prov"] == "Classic-Process")
for n, l in (("classic", cl_lat), ("kernel-process", kp_lat)):
    if l:
        print(f"latency {n} p50={l[len(l)//2]:.0f} p95={l[int(len(l)*.95)]:.0f} max={l[-1]:.0f} ms (n={len(l)})")


def endpoint_pid(i, ep):
    """PID of the latest 1391 (UDP endpoint created) with this Endpoint before event i: kernel addresses are reused."""
    for j in range(i - 1, -1, -1):
        e = evs[j]
        if e["prov"] == "TCPIP" and e["id"] == 1391 and e["p"].get("Endpoint") == ep:
            return num(e["p"].get("ProcessId") or e["p"].get("Pid"))
    return 0


ok = 0
rows = [r for r in truth if re.match(r"(tcp|udp)[46]_(listen|bind)", r["kind"])]
for r in rows:
    tpid, tport = (int(x) for x in r["detail"].split("/"))
    tcp = r["kind"].startswith("tcp")
    open_ids, close_id = ((1123,), 1009) if tcp else ((1396,), 1397)
    op = [(i, e) for i, e in enumerate(evs) if e["prov"] == "TCPIP" and e["id"] in open_ids
          and port_of(e["p"].get("SocketAddress") or e["p"].get("LocalAddress")) == tport]
    cl = [e for e in evs if e["prov"] == "TCPIP" and e["id"] == close_id and port_of(e["p"].get("LocalAddress")) == tport]
    if not op and not tcp:
        # Server 2012 R2: no TCPIP 1396/1397; UDP bind comes from Winsock-AFD 1030, close from AFD 1001 on the same Endpoint
        op = [(i, e) for i, e in enumerate(evs) if e["prov"] == "Winsock-AFD" and e["id"] == 1030
              and port_of(e["p"].get("Address")) == tport]
        if op:
            ep = op[0][1]["p"].get("Endpoint")
            cl = [e for e in evs[op[0][0]:] if e["prov"] == "Winsock-AFD" and e["id"] == 1001 and e["p"].get("Endpoint") == ep]
    if not op:
        print(f"  {r['kind']:20} port={tport} MISSING open event; close={len(cl)}")
        continue
    i, e = op[0]
    pid, via = num(e["p"].get("ProcessId") or e["p"].get("Pid")), "field"
    if not pid and e["p"].get("Endpoint"):
        pid, via = endpoint_pid(i, e["p"]["Endpoint"]), "1391"
    if not pid:
        print(f"    (header pid of the open event: {e['hdr']})")
    if not pid:
        pid, via = e["hdr"], "header" if e["prov"] == "TCPIP" else "afd-header"
    m = [s for s in starts if s[1] == pid and s[0] < i]
    user = m[-1][2] if m else None
    good = pid == tpid and bool(cl) and user is not None
    ok += good
    print(f"  {r['kind']:20} port={tport} addr={e['p'].get('SocketAddress') or e['p'].get('LocalAddress')} pid={pid} via={via} "
          f"truth_pid={tpid} user={user} close_events={len(cl)} {'OK' if good else 'FAIL'}")
print(f"ports OK {ok}/{len(rows)}")
print("missing system:", [r for r in truth if r["kind"] == "system_missing"])
for line in open(fn, errors="replace"):
    if line.startswith(("RESOURCES", "SUMMARY", "SESSION")):
        print(line.strip())
