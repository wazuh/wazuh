#!/usr/bin/env python3
"""
What still works, and what does not, while nodes are down.

Probes four capabilities through the balancer and reports each independently, because
the issue's question is not "is it up" but "what stops and what continues":

  liveness    GET /            unauthenticated, any node
  report      POST /stateless  authenticated, any node
  control     POST /control    authenticated, any node, notify
  enroll      POST /enroll     creates identity -- authd forwards to the MASTER

Run it before, during and after a failure to see which of the four changes.
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


def batch(agent_id):
    """One H line naming the authenticated agent plus one E event line. The H line MUST name
    the authenticated agent or the manager answers 400 (payload_agent_mismatch). Format taken
    verbatim from send_stateless.py's default_body()."""
    return (b'H {"wazuh":{"agent":{"id":"' + agent_id.encode() + b'"}}}\n'
            b'E 1:/var/log/syslog:availability drill')


def attempt(kind, base, prefix, agent_id, key, password, ca, timeout):
    url = base.rstrip("/") + prefix
    try:
        if kind == "liveness":
            r = requests.get(url, verify=ca, timeout=timeout)
        elif kind == "report":
            r = requests.post(url + "stateless",
                              headers={**auth_headers(agent_id, key),
                                       "Content-Type": "application/octet-stream"},
                              data=batch(agent_id), verify=ca, timeout=timeout)
        elif kind == "control":
            r = requests.post(url + "control",
                              headers={**auth_headers(agent_id, key),
                                       "Content-Type": "application/json"},
                              data=json.dumps({"type": "notify",
                                               "agent": {"version": "5.0.0"}}).encode(),
                              verify=ca, timeout=timeout)
        elif kind == "enroll":
            name = f"drill-{int(time.time()*1000)%100000000}"
            r = requests.post(url + "enroll",
                              headers={**enroll_auth_headers(password),
                                       "Content-Type": "application/json"},
                              data=json.dumps({"name": name, "version": "5.0.0"}).encode(),
                              verify=ca, timeout=timeout)
        return r.status_code
    except requests.RequestException as exc:
        return f"ERR:{type(exc).__name__}"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="https://wazuh-lb-haproxy:1518")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--rounds", type=int, default=9)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--label", default="")
    p.add_argument("--kinds", default="liveness,report,control,enroll")
    args = p.parse_args()

    kinds = args.kinds.split(",")
    tally = {k: collections.Counter() for k in kinds}
    for _ in range(args.rounds):
        for k in kinds:
            tally[k][attempt(k, args.url, args.prefix, args.agent_id, args.key,
                             args.password, args.ca, args.timeout)] += 1

    if args.label:
        print(f"--- {args.label} ---")
    for k in kinds:
        counts = ", ".join(f"{v}x{s}" for s, v in sorted(tally[k].items(), key=lambda x: str(x[0])))
        ok = sum(v for s, v in tally[k].items() if isinstance(s, int) and 200 <= s < 300)
        verdict = "OK" if ok == args.rounds else ("DEGRADED" if ok else "FAILING")
        print(f"  {k:9s} {verdict:9s} {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
