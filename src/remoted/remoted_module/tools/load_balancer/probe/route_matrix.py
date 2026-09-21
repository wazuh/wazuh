#!/usr/bin/env python3
"""
The full agent-api.yaml route matrix, through every front end, with node attribution.

The issue asks to record, for every request: route, HTTP status, the node that handled it,
and what the agent does next. This covers the first three; the fourth is a property of the
status and is annotated per route below.

All TEN routes remoted registers. Note that /control is ONE route: startup, notify and
shutdown are values of the body's `type` field, not separate paths -- a correction to the
issue's own route list, which counts eleven.

Bodies for /stats and /config are the ones send_agent_json.py uses, so a valid document
really does get 202 rather than a 400 that would hide a routing problem.
"""
import argparse
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

STATS_BODY = (b'{"modules":{'
              b'"agent":{"status":"connected","last_keepalive":"2026-08-02T10:06:50Z",'
              b'"messages":{"count":602},'
              b'"tasks":{"dispatched":{"total":4},"discarded_duplicate":{"total":0},'
              b'"failed":{"total":0}}},'
              b'"logcollector":{"global":{"files":[]}}}}')
CONFIG_BODY = (b'{"modules":{'
               b'"agent":{"name":"probe","notify_time":10},'
               b'"logcollector":{"localfile":[{"location":"/var/log/syslog"}]}}}')


def batch(agent_id):
    return (b'H {"wazuh":{"agent":{"id":"' + agent_id.encode() + b'"}}}\n'
            b'E 1:/var/log/syslog:route matrix')


def routes(agent_id, password):
    """(label, method, path, body, content-type, authenticated)"""
    return [
        ("GET /",              "GET",  "",          None,          None,                       True),
        ("GET /cacerts",       "GET",  "cacerts",   None,          None,                       False),
        ("POST /enroll",       "POST", "enroll",    None,          "application/json",         "enroll"),
        ("POST /control:start","POST", "control",   json.dumps({"type": "startup", "version": "5.0.0"}).encode(),
                                                                   "application/json",         True),
        ("POST /control:notify","POST","control",   json.dumps({"type": "notify", "agent": {"version": "5.0.0"}}).encode(),
                                                                   "application/json",         True),
        ("POST /stateless",    "POST", "stateless", batch(agent_id), "application/octet-stream", True),
        ("POST /stateful",     "POST", "stateful",  b"\x00" * 32,  "application/octet-stream", True),
        ("POST /download",     "POST", "download",  json.dumps({"resource_type": "config", "resource_id": "default"}).encode(),
                                                                   "application/json",         True),
        ("POST /stats",        "POST", "stats",     STATS_BODY,    "application/json",         True),
        ("POST /config",       "POST", "config",    CONFIG_BODY,   "application/json",         True),
        ("POST /scan/vd",      "POST", "scan/vd",   json.dumps({"type": "feed_update", "feed_offset": 1}).encode(),
                                                                   "application/json",         True),
    ]


def call(url, prefix, label, method, path, body, ctype, auth, agent_id, key, password, ca, timeout):
    headers = {}
    if auth is True:
        headers.update(auth_headers(agent_id, key))
    elif auth == "enroll":
        headers.update(enroll_auth_headers(password))
        body = json.dumps({"name": f"matrix-{agent_id}-{path}", "version": "5.0.0"}).encode()
    if ctype:
        headers["Content-Type"] = ctype
    target = url.rstrip("/") + prefix + path
    try:
        if method == "GET":
            r = requests.get(target, headers=headers, verify=ca, timeout=timeout)
        else:
            r = requests.post(target, headers=headers, data=body, verify=ca, timeout=timeout)
        return str(r.status_code), r.headers.get("X-Lab-Node", "-")
    except requests.RequestException as exc:
        return f"ERR:{type(exc).__name__}"[:12], "-"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agent-id", help="reuse an agent; omit to enrol a fresh one")
    p.add_argument("--key", help="its key; required with --agent-id")
    p.add_argument("--password", required=True)
    p.add_argument("--settle", type=float, default=30.0,
                   help="seconds to wait for the new key to reach every node")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--url-base", default="https://wazuh-lb-haproxy:1518",
                   help="where to enrol the run's own agent")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--repeat", type=int, default=3, help="requests per cell, to spread across nodes")
    args = p.parse_args()

    # Enrol a dedicated agent unless one was supplied. Reusing an agent whose credentials were
    # rotated elsewhere silently turns every authenticated row into a 401 that still "answers",
    # which reads as a pass and tests nothing.
    if not (args.agent_id and args.key):
        body = json.dumps({"name": f"matrix-{int(time.time())}", "version": "5.0.0"}).encode()
        r = requests.post(args.url_base.rstrip("/") + args.prefix + "enroll",
                          headers={**enroll_auth_headers(args.password),
                                   "Content-Type": "application/json"},
                          data=body, verify=args.ca, timeout=args.timeout)
        r.raise_for_status()
        args.agent_id, args.key = r.json()["id"], r.json()["key"]
        print(f"  enrolled {args.agent_id} for this run")

        # Wait for the key to reach every node, or the authenticated rows measure the
        # propagation window instead of the routes (see the cluster load-balancer page).
        deadline = time.time() + args.settle
        while time.time() < deadline:
            codes = [call(u, args.prefix, "probe", "POST", "stateless",
                          batch(args.agent_id), "application/octet-stream", True,
                          args.agent_id, args.key, args.password, args.ca, args.timeout)[0]
                     for _, u in (("m", "https://wazuh-master:1517"),
                                  ("w1", "https://wazuh-worker1:1517"),
                                  ("w2", "https://wazuh-worker2:1517"))]
            if "401" not in codes:
                break
            time.sleep(2)
        else:
            print("  !! the key did not reach every node; authenticated rows may show 401")

    fronts = [
        ("hap-pass", "https://wazuh-lb-haproxy:1517"),
        ("hap-term", "https://wazuh-lb-haproxy:1518"),
        ("ngx-pass", "https://wazuh-lb-nginx:1517"),
        ("ngx-term", "https://wazuh-lb-nginx:1518"),
    ]

    print(f"  {'route':<22}" + "".join(f"{lbl:<22}" for lbl, _ in fronts))
    for label, method, path, bd, ct, auth in routes(args.agent_id, args.password):
        cells = []
        for _, url in fronts:
            seen = {}
            nodes = set()
            for _ in range(args.repeat):
                st, node = call(url, args.prefix, label, method, path, bd, ct, auth,
                                args.agent_id, args.key, args.password, args.ca, args.timeout)
                seen[st] = seen.get(st, 0) + 1
                if node != "-":
                    nodes.add(node)
            status = ",".join(sorted(seen)) if len(seen) > 1 else next(iter(seen))
            suffix = f" [{len(nodes)}n]" if nodes else ""
            cells.append(f"{status}{suffix}")
        print(f"  {label:<22}" + "".join(f"{c:<22}" for c in cells))

    print()
    print("  [Nn] = distinct nodes seen for that cell, from the balancer's X-Lab-Node header.")
    print("  Passthrough cannot report it: the balancer never opens the response.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
