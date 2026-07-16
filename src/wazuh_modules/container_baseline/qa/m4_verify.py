#!/usr/bin/env python3
"""Spike #37532 M4 oracle checker: compares m4_runner output (row files under
/tmp/m4_evidence) against each container's own package/user tooling, exec'd
purely as a validation oracle (never a shipped mechanism)."""
import json
import subprocess
import sys

EVIDENCE_DIR = "/tmp/m4_evidence"


def scanner_packages(rows_file):
    pkgs = {}
    for line in open(f"{EVIDENCE_DIR}/{rows_file}"):
        if "| wazuh-states-inventory-packages |" not in line:
            continue
        pkg = json.loads(line.split(" | ", 2)[2])["package"]
        pkgs[pkg["name"]] = pkg
    return pkgs


def oracle_lines(cmd):
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    return sorted(l for l in out.split("\n") if l.strip())


def diff(label, mine, oracle):
    missing = sorted(set(oracle) - set(mine))
    extra = sorted(set(mine) - set(oracle))
    status = "MATCH" if not missing and not extra else "MISMATCH"
    print(f"{label}: scanner={len(mine)} oracle={len(oracle)} -> {status}")
    if missing:
        print(f"  missing from scanner: {missing[:5]}")
    if extra:
        print(f"  extra in scanner: {extra[:5]}")


def main():
    diff("debian dpkg names", scanner_packages("m4-debian.rows"),
         oracle_lines("docker exec m4-debian dpkg-query -W -f '${Package}\\n'"))
    diff("alpine apk names", scanner_packages("m4-alpine.rows"),
         oracle_lines("docker exec m4-alpine sh -c 'apk info 2>/dev/null'"))
    diff("ubi9 rpm-sqlite names", scanner_packages("m4-ubi9.rows"),
         oracle_lines("docker exec m4-ubi9 bash -c 'rpm -qa --qf \"%{NAME}\\n\" | grep -v gpg-pubkey'"))
    diff("rocky8 rpm-bdb names", scanner_packages("m4-rocky8.rows"),
         oracle_lines("docker exec m4-rocky8 bash -c 'rpm -qa --qf \"%{NAME}\\n\" | grep -v gpg-pubkey'"))

    for rows_file, cont in [("m4-ubi9.rows", "m4-ubi9"), ("m4-rocky8.rows", "m4-rocky8")]:
        pkgs = scanner_packages(rows_file)
        for name in list(pkgs)[:3]:
            mine = pkgs[name]
            res = subprocess.run(
                f"docker exec {cont} rpm -q --qf '%{{EVR}}|%{{ARCH}}' {name}",
                shell=True, capture_output=True, text=True).stdout.strip()
            evr, arch = res.split("|")
            ok = mine["version"] == evr and mine["architecture"] == arch
            print(f"{cont} {name}: scanner={mine['version']}/{mine['architecture']} "
                  f"oracle={evr}/{arch} -> {'MATCH' if ok else 'MISMATCH'}")

    for cont, rows_file in [("m4-debian", "m4-debian.rows"), ("m4-alpine", "m4-alpine.rows"),
                            ("m4-ubi9", "m4-ubi9.rows"), ("m4-rocky8", "m4-rocky8.rows")]:
        mine = sorted(json.loads(l.split(" | ", 2)[2])["user"]["name"]
                      for l in open(f"{EVIDENCE_DIR}/{rows_file}")
                      if "| wazuh-states-inventory-users |" in l)
        shell = "sh" if cont == "m4-alpine" else "bash"
        orc = oracle_lines(f"docker exec {cont} {shell} -c 'cut -d: -f1 /etc/passwd'")
        diff(f"{cont} user names", mine, orc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
