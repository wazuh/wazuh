#!/usr/bin/env python3
"""Spike #37532 remaining-collectors round 2 oracle checker: compares m6_runner
output (row files under /tmp/m6_evidence) against each container's own routing
table, docker cgroup limits, and rootfs unit files — read purely as a validation
oracle (docker exec/inspect are never a shipped mechanism)."""
import json
import math
import subprocess
import sys

EVIDENCE_DIR = "/tmp/m6_evidence"


def rows(rows_file, index):
    out = []
    for line in open(f"{EVIDENCE_DIR}/{rows_file}"):
        if f"| {index} |" not in line:
            continue
        out.append(json.loads(line.split(" | ", 2)[2]))
    return out


def oracle(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def check_protocols(rows_file, cont):
    r = rows(rows_file, "wazuh-states-inventory-protocols")
    mine = sorted((x["interface"]["name"], x["network"].get("gateway", "")) for x in r)
    # Oracle: default routes from the container's own /proc/net/route (hex gw).
    raw = oracle(f"docker exec {cont} cat /proc/net/route")
    orc = []
    for line in raw.splitlines()[1:]:
        f = line.split()
        if len(f) >= 3 and f[1] == "00000000":
            gw = int(f[2], 16)
            ip = ".".join(str((gw >> (8 * b)) & 0xFF) for b in range(4))
            orc.append((f[0], ip))
    orc = sorted(orc)
    status = "MATCH" if mine == orc else "MISMATCH"
    print(f"{cont} protocols: scanner={mine} oracle={orc} -> {status}")


def check_hardware(rows_file, cont):
    r = rows(rows_file, "wazuh-states-inventory-hardware")
    if len(r) != 1:
        print(f"{cont} hardware: scanner emitted {len(r)} rows -> MISMATCH")
        return
    hw = r[0]["host"]
    mem = int(oracle(f'docker inspect -f "{{{{.HostConfig.Memory}}}}" {cont}'))
    nanocpus = int(oracle(f'docker inspect -f "{{{{.HostConfig.NanoCpus}}}}" {cont}'))
    if mem > 0:  # explicit --memory limit
        ok_mem = hw["memory"]["total"] == mem
        exp_mem = mem
    else:  # unlimited -> host MemTotal (bytes)
        kb = int(oracle("awk '/MemTotal/{print $2}' /proc/meminfo"))
        exp_mem = kb * 1024
        ok_mem = hw["memory"]["total"] == exp_mem
    if nanocpus > 0:
        exp_cores = math.ceil(nanocpus / 1_000_000_000)
    else:
        exp_cores = int(oracle("grep -c ^processor /proc/cpuinfo"))
    ok_cpu = hw["cpu"]["cores"] == exp_cores
    status = "MATCH" if ok_mem and ok_cpu else "MISMATCH"
    print(f"{cont} hardware: mem={hw['memory']['total']} (exp {exp_mem}) "
          f"cores={hw['cpu']['cores']} (exp {exp_cores}) -> {status}")


def check_services(rows_file, cont):
    mine = sorted(x["service"]["name"] for x in rows(rows_file, "wazuh-states-inventory-services"))
    raw = oracle(f"docker exec {cont} sh -c "
                 f"'ls /etc/systemd/system/*.service /usr/lib/systemd/system/*.service "
                 f"/lib/systemd/system/*.service 2>/dev/null'")
    orc = set()
    for path in raw.split():
        base = path.rsplit("/", 1)[-1]
        if base.endswith(".service"):
            orc.add(base[:-8])
    orc = sorted(orc)
    status = "MATCH" if mine == orc else "MISMATCH"
    print(f"{cont} services: scanner={len(mine)} units oracle={len(orc)} units -> {status}")
    if status == "MISMATCH":
        print(f"  only-scanner: {sorted(set(mine) - set(orc))}")
        print(f"  only-oracle:  {sorted(set(orc) - set(mine))}")


def main():
    check_protocols("m6-debian.rows", "m6-debian")
    check_hardware("m6-limited.rows", "m6-limited")
    check_hardware("m6-debian.rows", "m6-debian")
    check_services("m6-ubi9.rows", "m6-ubi9")
    return 0


if __name__ == "__main__":
    sys.exit(main())
