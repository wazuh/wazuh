#!/usr/bin/env python3
"""
Measures the cluster key-propagation window an agent actually observes.

Enrolls a new agent through the balancer, then immediately starts sending authenticated
requests to EACH node directly, timestamping every answer, until every node accepts the
key. That is the measurement the issue asks for and nobody has taken:

  enrollment succeeds -> agent reports at once -> request reaches a worker without the
  key yet -> 401.

The probe route is POST /stateless used purely as an AUTHENTICATION ORACLE, the same
trick the existing remoted lab uses:

    401  -> this node does not have the key yet
    202  -> accepted
    503  -> the key was accepted; only the downstream engine is unavailable

Only 202 and 503 prove the key arrived, and only 401 proves it had not: both are answers
the MANAGER gave, so neither depends on a working indexer. Anything else -- a connection
refused, a read timeout, a TLS failure -- never reached the manager and says nothing about
the key. Those are inconclusive: they must not stop the clock, or a node that is merely
unreachable for a moment is recorded as having accepted the key at that moment, and the
window comes out shorter than it was. They are counted and reported separately instead.
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

from wire_jwt import auth_headers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# One minimal stateless batch. The H line is the agent-supplied metadata header; the body
# is forwarded verbatim by remoted, so its content does not matter to authentication.
def batch(agent_id: str) -> bytes:
    """Format taken verbatim from send_stateless.py's default_body(): one H line naming the
    authenticated agent, one E event line."""
    return (b'H {"wazuh":{"agent":{"id":"' + agent_id.encode() + b'"}}}\n'
            b'E 1:/var/log/syslog:propagation probe')


def enroll(url: str, prefix: str, name: str, password: str, ca: str, timeout: float):
    from wire_jwt import enroll_auth_headers
    body = json.dumps({"name": name, "version": "5.0.0"}).encode()
    r = requests.post(url.rstrip("/") + prefix + "enroll",
                      headers={**enroll_auth_headers(password), "Content-Type": "application/json"},
                      data=body, verify=ca, timeout=timeout)
    r.raise_for_status()
    return r.json()


def probe(node_url: str, prefix: str, agent_id: str, key: str, ca: str, timeout: float):
    try:
        r = requests.post(node_url.rstrip("/") + prefix + "stateless",
                          headers={**auth_headers(agent_id, key),
                                   "Content-Type": "application/octet-stream"},
                          data=batch(agent_id), verify=ca, timeout=timeout)
        return r.status_code
    except requests.RequestException as exc:
        return f"ERR {type(exc).__name__}"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--enroll-url", default="https://wazuh-lb-haproxy:1518",
                   help="where to enroll (through the balancer, like a real agent)")
    p.add_argument("--node", action="append", required=True, metavar="NAME=URL",
                   help="a manager node to poll directly; repeat once per node")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--password", required=True)
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--name", default=None)
    p.add_argument("--budget", type=float, default=60.0, help="seconds to keep polling")
    p.add_argument("--interval", type=float, default=0.25)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json-out", default=None)
    args = p.parse_args()

    nodes = {}
    for spec in args.node:
        name, _, url = spec.partition("=")
        nodes[name] = url

    name = args.name or f"prop-{int(time.time())}"
    t_enroll_start = time.monotonic()
    ident = enroll(args.enroll_url, args.prefix, name, args.password, args.ca, args.timeout)
    t0 = time.monotonic()
    agent_id, key = ident["id"], ident["key"]
    print(f"enrolled {agent_id} ({name}) in {t0 - t_enroll_start:.3f}s via {args.enroll_url}")
    print(f"polling {', '.join(nodes)} every {args.interval}s for up to {args.budget}s\n")

    first_ok = {n: None for n in nodes}
    counts = {n: {} for n in nodes}
    # Requests that never reached the manager, per node. Reported separately so a reader can
    # tell whether a measurement was taken against a cleanly reachable cluster.
    errors: dict = {}
    timeline = []

    while time.monotonic() - t0 < args.budget and any(v is None for v in first_ok.values()):
        for n, url in nodes.items():
            if first_ok[n] is not None:
                continue
            st = probe(url, args.prefix, agent_id, key, args.ca, args.timeout)
            dt = time.monotonic() - t0
            counts[n][st] = counts[n].get(st, 0) + 1
            timeline.append({"t": round(dt, 3), "node": n, "status": st})
            if st in (202, 503):
                first_ok[n] = dt
                print(f"  [{dt:7.3f}s] {n:14s} ACCEPTED (status {st})")
            elif st != 401:
                # Inconclusive: the request never got an answer from the manager. Keep polling.
                errors[n] = errors.get(n, 0) + 1
                print(f"  [{dt:7.3f}s] {n:14s} inconclusive ({st}), still waiting")
        time.sleep(args.interval)

    print("\n--- result ---")
    for n in nodes:
        if first_ok[n] is None:
            print(f"  {n:14s} NEVER accepted the key within {args.budget}s   {counts[n]}")
        else:
            print(f"  {n:14s} accepted after {first_ok[n]:.3f}s   {counts[n]}")

    window = [v for v in first_ok.values() if v is not None]
    if window:
        print(f"\n  propagation window observed: {max(window):.3f}s "
              f"(fastest node {min(window):.3f}s)")
    total_401 = sum(c.get(401, 0) for c in counts.values())
    print(f"  total 401 answers while waiting: {total_401}")
    if errors:
        print("  INCONCLUSIVE requests (never reached the manager), per node: "
              + ", ".join(f"{n}={c}" for n, c in sorted(errors.items())))
        print("  Those nodes were unreachable for part of the run, so the window above covers"
              " only the nodes that answered: treat it as a measurement of them, not of the"
              " cluster.")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump({"agent_id": agent_id, "name": name, "first_ok": first_ok,
                       "inconclusive": errors,
                       "counts": {n: {str(k): v for k, v in c.items()} for n, c in counts.items()},
                       "timeline": timeline}, fh, indent=2)
        print(f"  written: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
