#!/usr/bin/env python3
"""
The decisive per-node-state test: POST /control on one node, POST /download on another.

remoted authorizes a CONFIG download against its in-memory AgentRegistry, which is
populated only by /control on that same node and is never replicated
(src/remoted/remoted_module/src/control/agentRegistry.hpp, .../endpoints/downloadEndpoint.cpp:549).
So:

    /control on worker A  ->  /download on worker B  ->  403

Behind a non-sticky balancer that is not an edge case, it is the normal routing.

The script also checks the WPK path, which is deliberately NOT gated by the registry
(downloadEndpoint.cpp:547-548), to show the two resource types behave differently.
"""
import argparse
import json
import sys

import requests
import urllib3

# wire_jwt.py is the repository's own signer, mounted from ../ (the parent tools/
# directory) rather than copied here, so the wire format can never drift.
sys.path.insert(0, "/tools")

from wire_jwt import auth_headers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def control(url, prefix, agent_id, key, ca, ctype="startup", timeout=15):
    body = json.dumps({"type": ctype, "version": "5.0.0"}
                      if ctype == "startup" else
                      {"type": ctype, "agent": {"version": "5.0.0"}}).encode()
    r = requests.post(url.rstrip("/") + prefix + "control",
                      headers={**auth_headers(agent_id, key), "Content-Type": "application/json"},
                      data=body, verify=ca, timeout=timeout)
    return r


def download(url, prefix, agent_id, key, ca, resource_type, resource_id, timeout=15):
    body = json.dumps({"resource_type": resource_type, "resource_id": resource_id}).encode()
    r = requests.post(url.rstrip("/") + prefix + "download",
                      headers={**auth_headers(agent_id, key), "Content-Type": "application/json"},
                      data=body, verify=ca, timeout=timeout)
    return r


def brief(r):
    body = (r.text or "").strip().replace("\n", " ")
    if len(body) > 90:
        body = body[:90] + "..."
    return f"{r.status_code} {body}"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agent-id", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--node", action="append", required=True, metavar="NAME=URL")
    p.add_argument("--control-on", required=True, help="node name that receives /control")
    p.add_argument("--json-out", default=None)
    args = p.parse_args()

    nodes = dict(spec.partition("=")[::2] for spec in args.node)
    a, k, pre, ca = args.agent_id, args.key, args.prefix, args.ca
    out = {"agent_id": a, "control_on": args.control_on, "steps": []}

    def record(step, node, r):
        out["steps"].append({"step": step, "node": node, "status": r.status_code,
                             "body": (r.text or "")[:200]})

    print(f"agent {a}\n")

    # 0. Baseline: every node BEFORE any /control. A node that never saw this agent
    #    must refuse a config download, including the node that will receive /control.
    print("0. config download on every node, before any /control anywhere")
    for n, url in nodes.items():
        r = download(url, pre, a, k, ca, "config", "default")
        record("baseline_download", n, r)
        print(f"     {n:9s} {brief(r)}")

    # 1. /control on exactly one node.
    print(f"\n1. POST /control (startup) on {args.control_on} ONLY")
    r = control(nodes[args.control_on], pre, a, k, ca, "startup")
    record("control_startup", args.control_on, r)
    print(f"     {args.control_on:9s} {brief(r)}")
    ctoken = None
    try:
        ctoken = r.json().get("config_token")
        print(f"     config_token = {ctoken!r}")
        print(f"     config_hash  = {r.json().get('config_hash')!r}")
        print(f"     settings_hash= {r.json().get('settings_hash')!r}")
        print(f"     vd_feed_offset={r.json().get('vd_feed_offset')!r}")
    except Exception:
        pass

    # 2. The same config download, now on every node.
    rid = ctoken or "default"
    print(f"\n2. config download of {rid!r} on every node, after /control on {args.control_on}")
    for n, url in nodes.items():
        r = download(url, pre, a, k, ca, "config", rid)
        record("download_after_control", n, r)
        marker = "  <-- the node that got /control" if n == args.control_on else ""
        print(f"     {n:9s} {brief(r)}{marker}")

    # 3. WPK on every node: deliberately not registry-gated, so it must NOT 403.
    print("\n3. wpk download on every node (not registry-gated by design)")
    for n, url in nodes.items():
        r = download(url, pre, a, k, ca, "wpk", "does-not-exist.wpk")
        record("download_wpk", n, r)
        print(f"     {n:9s} {brief(r)}")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwritten: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
