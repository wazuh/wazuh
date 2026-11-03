#!/usr/bin/env python3
"""
Does each front end let the manager's own body limits decide?

Section 4.4 of the load-balancer guide says the proxy must allow what remoted allows.
The manager has two caps that must fire in this order:

  remoted.auth_max_body_size          -> clean 413, counted in remoted.auth.reject.body_too_large
  <remote><https><max_body_size>      -> RESTinio closes the connection, no HTTP response at all

Shipped defaults are 5 MiB and 10 MiB respectively; both are configurable, so the probe
reports what it observes rather than asserting a fixed boundary.

A proxy configured below either of those changes the answer the agent gets: instead of the
413 it knows how to act on (it splits the batch and retries, #37835), it sees the proxy's
own error, or a closed connection it cannot tell from a network fault.

So this sends the same bodies straight to a node and through every front end, and compares.
Read the caps from the node under test before judging a result:
    wazuh-manager-conf get remote.https.max_body_size
"""
import argparse
import sys

import requests
import urllib3

# wire_jwt.py is the repository's own signer, mounted from ../ (the parent tools/
# directory) rather than copied here, so the wire format can never drift.
sys.path.insert(0, "/tools")

from wire_jwt import auth_headers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MIB = 1024 * 1024


def body(agent_id: str, size: int) -> bytes:
    """A valid batch padded to `size`: one H line naming the agent, then one E line whose
    message is filler. Under the caps this really is accepted (202), so the comparison is
    between 'accepted' and 'refused', not between two kinds of rejection."""
    head = b'H {"wazuh":{"agent":{"id":"' + agent_id.encode() + b'"}}}\nE 1:/var/log/syslog:'
    pad = size - len(head)
    return head + (b"x" * max(pad, 1))


def attempt(url, prefix, agent_id, key, ca, size, timeout):
    try:
        r = requests.post(url.rstrip("/") + prefix + "stateless",
                          headers={**auth_headers(agent_id, key),
                                   "Content-Type": "application/octet-stream"},
                          data=body(agent_id, size), verify=ca, timeout=timeout)
        return str(r.status_code)
    except requests.RequestException as exc:
        return f"ERR:{type(exc).__name__}"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agent-id", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--timeout", type=float, default=60.0)
    p.add_argument("--sizes", default="1,4,6,11", help="MiB, comma separated")
    args = p.parse_args()

    fronts = [
        ("direct master",       "https://wazuh-master:1517"),
        ("haproxy passthrough", "https://wazuh-lb-haproxy:1517"),
        ("haproxy termination", "https://wazuh-lb-haproxy:1518"),
        ("nginx passthrough",   "https://wazuh-lb-nginx:1517"),
        ("nginx termination",   "https://wazuh-lb-nginx:1518"),
    ]
    sizes = [int(x) for x in args.sizes.split(",")]

    print("  body size ->        " + "  ".join(f"{s:>2d} MiB" for s in sizes))
    for label, url in fronts:
        row = []
        for s in sizes:
            row.append(attempt(url, args.prefix, args.agent_id, args.key, args.ca,
                               s * MIB, args.timeout))
        print(f"  {label:<20} " + "  ".join(f"{v:>6s}" for v in row))
    print()
    print("  Read the boundaries off the table, do not assume them: they are build- and")
    print("  configuration-dependent. What should hold on every build is the ORDER --")
    print("    accepted -> 413 (auth cap) -> connection closed (transport cap)")
    print("  and that the 413 arrives BEFORE the close, so the agent splits its batch")
    print("  instead of retrying the same bytes forever.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
