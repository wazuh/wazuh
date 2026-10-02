#!/usr/bin/env python3
"""
One config download against one node, timed: its status, how long it took and the body's sha256,
printed as one JSON line. The building block of the checks that need a single answer from a node in
a given state (its wazuh-manager-db frozen, remoted just restarted).

Agent: --agent-id/--key, or --password to enroll a fresh one. Its key is printed only with --emit-key
(for a later call to reuse the same agent): captures of this output must never carry it.
  --wait-key   before downloading, wait until the node has the agent's key; probed with a /control
               shutdown, which records activity but never establishes a membership, so the download
               that follows still has to read the agent's groups from the node's database
  --fresh      before downloading, /control startup + notify on the node, so the download is answered
               from a fresh cached membership without asking the database
"""
import argparse
import hashlib
import json
import sys
import time

import requests
import urllib3

sys.path.insert(0, "/tools")

from cross_node_download import control, download
from download_convergence import enroll

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--node", required=True, help="node URL, e.g. https://wazuh-worker2:1517")
    p.add_argument("--agent-id")
    p.add_argument("--key")
    p.add_argument("--password", help="enrollment password, to enroll a fresh agent")
    p.add_argument("--enroll-url", default="https://wazuh-lb-haproxy:1518")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--resource-id", default="default")
    p.add_argument("--wait-key", action="store_true")
    p.add_argument("--fresh", action="store_true")
    p.add_argument("--emit-key", action="store_true", help="include the agent key in the output")
    p.add_argument("--no-download", action="store_true",
                   help="stop after enrolling / waiting: an agent the node knows but holds no membership for")
    p.add_argument("--within", type=float, default=180.0)
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args()

    pre, ca, node = args.prefix, args.ca, args.node
    if args.agent_id:
        a, k = args.agent_id, args.key
    else:
        ident = enroll(args.enroll_url, pre, f"status-{int(time.time() * 1000)}", args.password, ca, 20)
        a, k = ident["id"], ident["key"]

    deadline = time.monotonic() + args.within
    if args.wait_key:
        while control(node, pre, a, k, ca, "shutdown").status_code == 401 and time.monotonic() < deadline:
            time.sleep(2)
    if args.fresh:
        while control(node, pre, a, k, ca, "startup").status_code != 200 and time.monotonic() < deadline:
            time.sleep(2)
        control(node, pre, a, k, ca, "notify")

    if args.no_download:
        result = {"agent_id": a, "node": node, "status": None}
        if args.emit_key:
            result["key"] = k
        print(json.dumps(result))
        return 0

    started = time.monotonic()
    try:
        r = download(node, pre, a, k, ca, "config", args.resource_id, timeout=args.timeout)
        status, body = r.status_code, r.content
    except requests.RequestException as exc:
        status, body = f"error: {exc.__class__.__name__}", b""
    elapsed = time.monotonic() - started

    result = {"agent_id": a, "node": node, "status": status, "elapsed": round(elapsed, 3),
              "sha256": hashlib.sha256(body).hexdigest() if status == 200 else None}
    if args.emit_key:
        result["key"] = k
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
