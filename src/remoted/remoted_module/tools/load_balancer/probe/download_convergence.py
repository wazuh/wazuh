#!/usr/bin/env python3
"""
Does the /download 403 converge the way the 401s do?

The key-propagation 401s close on their own: the cluster replicates client.keys and every
node ends up able to answer. The question this answers is whether the /download 403 behaves
the same, because if it does it is the same class of transient and nothing more.

It is NOT the same mechanism: nothing replicates the AgentRegistry. A node can only learn
an agent by serving it a /control itself. So convergence here is driven by the agent's own
notify cycle walking onto every node, not by wazuh-clusterd.

This enrolls a fresh agent and then alternates, through the balancer:
    one /control notify   (which registers the agent on whichever node takes it)
    a few /download config attempts
recording the 403 rate per round, so the convergence curve is visible.
"""
import argparse
import collections
import json
import sys
import time

import requests
import urllib3

# wire_jwt.py is the repository's own signer, mounted from ../ (the parent tools/
# directory) rather than copied here, so the wire format can never drift.
sys.path.insert(0, "/tools")

from wire_jwt import auth_headers, enroll_auth_headers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def enroll(url, prefix, name, password, ca, timeout):
    r = requests.post(url.rstrip("/") + prefix + "enroll",
                      headers={**enroll_auth_headers(password), "Content-Type": "application/json"},
                      data=json.dumps({"name": name, "version": "5.0.0"}).encode(),
                      verify=ca, timeout=timeout)
    r.raise_for_status()
    return r.json()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="https://wazuh-lb-haproxy:1518")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--password", required=True)
    p.add_argument("--rounds", type=int, default=10)
    p.add_argument("--downloads", type=int, default=6)
    p.add_argument("--timeout", type=float, default=20.0)
    args = p.parse_args()

    ident = enroll(args.url, args.prefix, f"conv-{int(time.time())}", args.password,
                   args.ca, args.timeout)
    a, k = ident["id"], ident["key"]
    print(f"enrolled {a}; waiting for the key to reach every node before starting")
    # Separate the two effects: wait out the key window so what we see is registry-only.
    time.sleep(20)

    base = args.url.rstrip("/") + args.prefix
    nodes_seen = set()
    print()
    print("  round  control->node   downloads (403/total)   nodes registered so far")
    for rnd in range(1, args.rounds + 1):
        r = requests.post(base + "control",
                          headers={**auth_headers(a, k), "Content-Type": "application/json"},
                          data=json.dumps({"type": "notify", "agent": {"version": "5.0.0"}}).encode(),
                          verify=args.ca, timeout=args.timeout)
        node = r.headers.get("X-Lab-Node", "?")
        if r.status_code == 200:
            nodes_seen.add(node)

        tally = collections.Counter()
        for _ in range(args.downloads):
            d = requests.post(base + "download",
                              headers={**auth_headers(a, k), "Content-Type": "application/json"},
                              data=json.dumps({"resource_type": "config",
                                               "resource_id": "default"}).encode(),
                              verify=args.ca, timeout=args.timeout)
            tally[d.status_code] += 1
        denied = tally.get(403, 0)
        total = sum(tally.values())
        bar = "#" * denied + "." * (total - denied)
        print(f"  {rnd:>5}  {node:<14}  {denied}/{total} {bar:<10}       {len(nodes_seen)}/3")
        time.sleep(1)

    print()
    print("  A round with 0/N means every node can serve this agent's configuration.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
