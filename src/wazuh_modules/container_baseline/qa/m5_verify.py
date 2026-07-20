#!/usr/bin/env python3
"""Spike #37532 remaining-collectors oracle checker: compares m5_runner output
(row files under /tmp/m5_evidence) against each container's own os-release and
`ip` tooling, exec'd purely as a validation oracle (never a shipped mechanism)."""
import json
import subprocess
import sys

EVIDENCE_DIR = "/tmp/m5_evidence"


def rows(rows_file, index):
    out = []
    for line in open(f"{EVIDENCE_DIR}/{rows_file}"):
        if f"| {index} |" not in line:
            continue
        out.append(json.loads(line.split(" | ", 2)[2]))
    return out


def oracle(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def check_os(rows_file, cont):
    r = rows(rows_file, "wazuh-states-inventory-system")
    if len(r) != 1:
        print(f"{cont} os: scanner emitted {len(r)} rows -> MISMATCH")
        return
    os = r[0]["os"]
    o_id = oracle(f"docker exec {cont} sh -c '. /etc/os-release; echo $ID'")
    o_ver = oracle(f"docker exec {cont} sh -c '. /etc/os-release; echo $VERSION_ID'")
    ok = os["platform"] == o_id and os["version"] == o_ver
    print(f"{cont} os: scanner={os['platform']}/{os['version']} "
          f"oracle={o_id}/{o_ver} -> {'MATCH' if ok else 'MISMATCH'}")


def check_ifaces(rows_file, cont):
    mine = sorted(r["interface"]["name"] for r in rows(rows_file, "wazuh-states-inventory-interfaces"))
    orc = oracle(f"docker exec {cont} sh -c \"ls /sys/class/net\"").split()
    orc = sorted(orc)
    status = "MATCH" if mine == orc else "MISMATCH"
    print(f"{cont} interfaces: scanner={mine} oracle={orc} -> {status}")


def check_addrs(rows_file, cont):
    mine = sorted((r["network"]["interface"], r["network"]["ip"])
                  for r in rows(rows_file, "wazuh-states-inventory-networks"))
    # container's own view via /proc/net addressing is awkward; use `ip -o addr`
    # when iproute2 is present, else just report the scanner set.
    raw = oracle(f"docker exec {cont} sh -c \"ip -o addr show 2>/dev/null\"")
    if not raw:
        print(f"{cont} addresses: scanner={mine} (no iproute2 in image, scanner-only)")
        return
    orc = set()
    for line in raw.split("\n"):
        f = line.split()
        if len(f) >= 4 and f[2] in ("inet", "inet6"):
            orc.add((f[1], f[3].split("/")[0]))
    orc = sorted(orc)
    status = "MATCH" if sorted(mine) == orc else "MISMATCH"
    print(f"{cont} addresses: scanner={mine} oracle={orc} -> {status}")


def main():
    targets = [
        ("m5-debian.rows", "m5-debian"),
        ("m5-alpine.rows", "m5-alpine"),
        ("m5-ubi9.rows", "m5-ubi9"),
    ]
    for rows_file, cont in targets:
        check_os(rows_file, cont)
    for rows_file, cont in targets:
        check_ifaces(rows_file, cont)
    for rows_file, cont in targets:
        check_addrs(rows_file, cont)
    return 0


if __name__ == "__main__":
    sys.exit(main())
