#!/usr/bin/env python3
"""
Is an agent's configuration served by every node, whichever node its /control went to?

remoted authorizes a CONFIG download against the agent's group membership. A node that holds a
fresh membership for the agent (read from its local wazuh-manager-db by its own /control or an
earlier download) answers from memory; any other node -- or one whose membership the local cluster
daemon withdrew after applying agent groups -- reads the agent's groups from its local
wazuh-manager-db before answering. So behind a non-sticky balancer:

    /control on worker A  ->  /download on worker B  ->  200, the same merged.mg

A node whose database does not have the agent's row yet (a freshly enrolled agent, before the
master's agent-group sync reaches it) answers 503 -- retry, never a denial -- and so does a node
that does not have the agent's key yet (401). Both close on their own. A 403 is always a failure:
it means a node refused an agent its own configuration.

Steps:
    0. config download on every download node BEFORE any /control anywhere (the cold node,
       the restarted remoted): each must end at 200
    1. /control (startup + notify) on one node, for config_token and config_hash
    2. the same download on every download node: each must end at 200 with sha256(body) ==
       config_hash
    3. a WPK download on every node: not membership-gated by design, so never 403

Exit status 0 when every assertion holds, 1 otherwise; --json-out writes the per-node record.
"""
import argparse
import hashlib
import json
import sys
import time

import requests
import urllib3

# wire_jwt.py is the repository's own signer, mounted from ../ (the parent tools/
# directory) rather than copied here, so the wire format can never drift.
sys.path.insert(0, "/tools")

from wire_jwt import auth_headers

from download_convergence import enroll

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Answers that close on their own and are retried: the key not replicated yet (401), the agent's
# row not in the node's database yet (503), a merged.mg not synced yet (404).
TRANSIENT = (401, 404, 503)


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


def served(url, prefix, agent_id, key, ca, resource_id, within):
    """Download until 200 (or a 403, or `within` seconds). Returns (response, transient counts)."""
    counts = {}
    deadline = time.monotonic() + within
    while True:
        r = download(url, prefix, agent_id, key, ca, "config", resource_id)
        if r.status_code in TRANSIENT and time.monotonic() < deadline:
            counts[r.status_code] = counts.get(r.status_code, 0) + 1
            time.sleep(2)
            continue
        return r, counts


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agent-id", help="an enrolled agent; omit to enroll a fresh one with --password")
    p.add_argument("--key")
    p.add_argument("--password", help="enrollment password, to enroll a fresh agent")
    p.add_argument("--enroll-url", default="https://wazuh-lb-haproxy:1518")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--node", action="append", required=True, metavar="NAME=URL")
    p.add_argument("--control-on", required=True, help="node name that receives /control")
    p.add_argument("--download-on", default=None, help="comma-separated node names (default: all)")
    p.add_argument("--within", type=float, default=180.0,
                   help="seconds a node may keep answering 401/404/503 before it must serve")
    p.add_argument("--json-out", default=None)
    args = p.parse_args()

    nodes = dict(spec.partition("=")[::2] for spec in args.node)
    targets = args.download_on.split(",") if args.download_on else list(nodes)
    pre, ca = args.prefix, args.ca
    if args.agent_id:
        a, k = args.agent_id, args.key
    else:
        ident = enroll(args.enroll_url, pre, f"xnode-{int(time.time())}", args.password, ca, 20)
        a, k = ident["id"], ident["key"]
    out = {"agent_id": a, "control_on": args.control_on, "download_on": targets, "steps": [],
           "failures": []}

    def record(step, node, r, counts=None):
        out["steps"].append({"step": step, "node": node, "status": r.status_code,
                             "sha256": hashlib.sha256(r.content).hexdigest() if r.status_code == 200 else None,
                             "transient": counts or {}, "body": (r.text or "")[:120]
                             if r.status_code != 200 else None})

    def fail(message):
        out["failures"].append(message)
        print(f"     !! {message}")

    print(f"agent {a}\n")

    # 0. Before any /control anywhere: the node must read the agent's groups from its own
    #    database, whichever node that is -- the cold node, and the restarted one.
    print(f"0. config download of 'default' before any /control, on {', '.join(targets)}")
    baseline = {}
    for n in targets:
        r, counts = served(nodes[n], pre, a, k, ca, "default", args.within)
        record("baseline_download", n, r, counts)
        baseline[n] = r
        print(f"     {n:9s} {brief(r)}  (transient before it: {counts or 'none'})")
        if r.status_code != 200:
            fail(f"{n}: baseline download answered {r.status_code}, not 200")

    # 1. /control on exactly one node; the notify carries the token and the hash.
    print(f"\n1. POST /control (startup + notify) on {args.control_on} ONLY")
    ctoken = chash = None
    r = control(nodes[args.control_on], pre, a, k, ca, "startup")
    record("control_startup", args.control_on, r)
    print(f"     {args.control_on:9s} startup {brief(r)}")
    r = control(nodes[args.control_on], pre, a, k, ca, "notify")
    record("control_notify", args.control_on, r)
    try:
        ctoken = r.json()["agent"]["config_token"]
        chash = r.json()["agent"]["config_hash"]
        print(f"     config_token = {ctoken!r}\n     config_hash  = {chash!r}")
    except Exception:
        fail(f"{args.control_on}: notify gave no config_token/config_hash: {brief(r)}")

    for n, r in baseline.items():
        if r.status_code == 200 and chash and hashlib.sha256(r.content).hexdigest() != chash:
            fail(f"{n}: the baseline body is not the file config_hash names")

    # 2. The same download everywhere: served, and the very file /control told the agent to expect.
    rid = ctoken or "default"
    print(f"\n2. config download of {rid!r} on {', '.join(targets)}, after /control on {args.control_on}")
    for n in targets:
        r, counts = served(nodes[n], pre, a, k, ca, rid, args.within)
        record("download_after_control", n, r, counts)
        marker = "  <-- the node that got /control" if n == args.control_on else ""
        print(f"     {n:9s} {brief(r)}{marker}")
        if r.status_code != 200:
            fail(f"{n}: download after /control answered {r.status_code}, not 200")
        elif chash and hashlib.sha256(r.content).hexdigest() != chash:
            fail(f"{n}: served a body whose sha256 is not config_hash")

    # 3. WPK on every node: deliberately not membership-gated, so it must NOT 403.
    print("\n3. wpk download on every node (not membership-gated by design)")
    for n, url in nodes.items():
        r = download(url, pre, a, k, ca, "wpk", "does-not-exist.wpk")
        record("download_wpk", n, r)
        print(f"     {n:9s} {brief(r)}")
        if r.status_code == 403:
            fail(f"{n}: a WPK download was refused with 403")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwritten: {args.json_out}")
    print(f"\nresult: {'PASS' if not out['failures'] else 'FAIL'} ({len(out['failures'])} failure(s))")
    return 0 if not out["failures"] else 1


if __name__ == "__main__":
    sys.exit(main())
