#!/usr/bin/env python3
"""
Sends signed POST /stats and POST /config requests to remoted's HTTPS auth endpoint
and shows what comes back, so the whole forwarding path can be exercised by hand:

    agent -> remoted (HTTPS, AES-CMAC) -> modulesd's inventory sync server (UDS) -> back

Both endpoints are DUMMIES today: modulesd only checks the body is a JSON object, stamps
`wazuh.agent.id` (from the authenticated identity, NOT from the document) and `@timestamp`
onto it, echoes it back and discards it. That echo is what makes this tool useful -- a
successful run prints the document with both stamps added, which is end-to-end proof that
the UDS hop and the header propagation work.

Signing is identical to send_stateless.py (see authMiddleware.cpp for the authoritative
canonical string):

  Authorization: Wazuh <agent-id>:<timestamp>:<mac>
  protocol-version: 1

  MAC = AES-CMAC(agent_key, b"WAZUH-REQUEST\\n" + version + b"\\n" + METHOD + b"\\n"
                            + request_target + b"\\n" + agent_id + b"\\n"
                            + str(timestamp) + b"\\n" + body)

NOTE: the signing helpers below are duplicated from send_stateless.py on purpose, so each
tool stays a single file you can scp onto a manager and run. If the canonical string ever
changes on the C++ side, both copies fail loudly with 401 InvalidMac rather than silently
mis-signing -- but keep them in step.

Unlike /stateless there is NO payload-identity cross-check here: these documents do not
carry an agent id at all, which is exactly why remoted forwards the authenticated one as an
`X-Wazuh-Agent-Id` header for modulesd to write in.

Requires: pip install requests cryptography
Requires: wazuh-manager-modulesd running with the inventory_sync_server module, otherwise
          every forwarded request answers 503 (remoted could not reach the downstream).

Examples:
  python3 send_agent_json.py                                  # one signed /stats -> 200
  python3 send_agent_json.py --endpoint config                # same, against /config
  python3 send_agent_json.py --body '{"cpu":42,"mem":128}'
  python3 send_agent_json.py --tamper                         # modified body -> 401 InvalidMac
  python3 send_agent_json.py --all                            # every scenario, both endpoints
"""
import argparse
import json
import sys
import time

import requests
import urllib3
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CLIENT_KEYS = "/var/wazuh-manager/etc/client.keys"
DEFAULT_BODY = b'{"cpu":42,"mem":128,"note":"hello from python"}'

ENDPOINTS = ("/stats", "/config")

# Must match AuthConfig's defaults (auth/authTypes.hpp) unless the manager overrides them --
# only used to pick offsets that reliably land on the wrong side of each window.
MAX_REQUEST_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30
MAX_BODY_SIZE = 10 * 1024 * 1024


def read_agent_key(agent_id: str, client_keys_path: str) -> bytes:
    """Parses client.keys the same way Keystore does: 'id name ip key' lines, '#'/' '-prefixed
    lines are comments, a name starting with '#'/'!' means removed. Returns raw key bytes."""
    with open(client_keys_path, "r") as f:
        for line in f:
            if not line or line[0] in ("#", " "):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            line_id, name, _ip, key_hex = parts[0], parts[1], parts[2], parts[3]
            if name.startswith("#") or name.startswith("!"):
                continue
            if line_id == agent_id:
                return bytes.fromhex(key_hex)
    raise SystemExit(f"agent id {agent_id!r} not found (or removed) in {client_keys_path}")


def sign_request(agent_key: bytes, protocol_version: str, method: str,
                 request_target: str, agent_id: str, timestamp: int, body: bytes) -> str:
    """Builds the canonical byte sequence and returns its lowercase-hex AES-CMAC."""
    if len(agent_key) not in (16, 24, 32):
        raise SystemExit(f"agent key must be 16, 24 or 32 bytes (got {len(agent_key)})")

    c = cmac.CMAC(algorithms.AES(agent_key))
    c.update(b"WAZUH-REQUEST\n")
    c.update(protocol_version.encode() + b"\n")
    c.update(method.upper().encode() + b"\n")
    c.update(request_target.encode() + b"\n")
    c.update(agent_id.encode() + b"\n")
    c.update(str(timestamp).encode() + b"\n")
    c.update(body)

    return c.finalize().hex()


def _auth_header(agent_id: str, agent_key: bytes, protocol_version: str, method: str,
                 target: str, timestamp: int, body: bytes) -> dict:
    mac = sign_request(agent_key, protocol_version, method, target, agent_id, timestamp, body)
    return {"protocol-version": protocol_version,
            "Content-Type": "application/json",
            "Authorization": f"Wazuh {agent_id}:{timestamp}:{mac}"}


# --- Scenarios -------------------------------------------------------------
# Each returns (headers, body_to_send). The target is supplied by the caller so every
# scenario runs against BOTH endpoints -- they are deliberate near-duplicates in the C++,
# so running both is what proves the duplication is actually wired up on each path.
#
# Deliberately NOT covered here: the transport-level limits (oversized URL/header/count)
# that make RESTinio drop the connection with no response. They are endpoint-independent
# and already covered by send_stateless.py --all.

def scenario_valid(agent_id, agent_key, target):
    body = DEFAULT_BODY
    return _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body), body


def scenario_nested_document(agent_id, agent_key, target):
    # A document that already has a `wazuh` object: modulesd must add agent.id underneath it
    # without destroying the sibling, and must override any id claimed in the document.
    body = b'{"wazuh":{"cluster":{"name":"mycluster"},"agent":{"id":"999999"}},"payload":true}'
    return _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body), body


def scenario_empty_body(agent_id, agent_key, target):
    # Short-circuited by remoted itself (no deferred-work slot, no UDS round trip).
    body = b""
    return _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body), body


def scenario_not_an_object(agent_id, agent_key, target):
    # Valid JSON, but not an object -> modulesd 400 -> remoted 400.
    body = b'["not","an","object"]'
    return _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body), body


def scenario_malformed_json(agent_id, agent_key, target):
    body = b'{"unterminated":'
    return _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body), body


def scenario_missing_protocol_version(agent_id, agent_key, target):
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    del headers["protocol-version"]
    return headers, body


def scenario_missing_authorization(_agent_id, _agent_key, _target):
    return {"protocol-version": "1", "Content-Type": "application/json"}, DEFAULT_BODY


def scenario_malformed_authorization(_agent_id, _agent_key, _target):
    return ({"protocol-version": "1", "Content-Type": "application/json",
             "Authorization": "Wazuh not-even-close"}, DEFAULT_BODY)


def scenario_unknown_agent(_agent_id, _agent_key, target):
    body = DEFAULT_BODY
    fake_id, fake_key = "999999", bytes(32)  # an id that (almost certainly) isn't enrolled
    return _auth_header(fake_id, fake_key, "1", "POST", target, int(time.time()), body), body


def scenario_expired_request(agent_id, agent_key, target):
    body = DEFAULT_BODY
    ts = int(time.time()) - (MAX_REQUEST_AGE_SECONDS + 1)
    return _auth_header(agent_id, agent_key, "1", "POST", target, ts, body), body


def scenario_future_request(agent_id, agent_key, target):
    body = DEFAULT_BODY
    ts = int(time.time()) + (MAX_FUTURE_SKEW_SECONDS + 1)
    return _auth_header(agent_id, agent_key, "1", "POST", target, ts, body), body


def scenario_invalid_mac(agent_id, agent_key, target):
    signed_body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), signed_body)
    return headers, b'{"tampered":true}'  # transmit different bytes than what was signed


def scenario_body_too_large(agent_id, agent_key, target):
    # Over AuthConfig's cap (10 MiB) but under the transport's (16 MiB), so AuthMiddleware
    # rejects it with a clean 413 instead of RESTinio dropping the connection.
    body = b'{"pad":"' + b"A" * (MAX_BODY_SIZE + 1024 * 1024) + b'"}'
    return _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body), body


SCENARIOS = [
    ("valid_request", 200, scenario_valid),
    ("nested_document", 200, scenario_nested_document),
    ("empty_body", 400, scenario_empty_body),
    ("body_not_an_object", 400, scenario_not_an_object),
    ("malformed_json", 400, scenario_malformed_json),
    ("missing_protocol_version", 400, scenario_missing_protocol_version),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("malformed_authorization", 401, scenario_malformed_authorization),
    ("unknown_agent", 401, scenario_unknown_agent),
    ("expired_request", 401, scenario_expired_request),
    ("future_request", 401, scenario_future_request),
    ("invalid_mac_tampered_body", 401, scenario_invalid_mac),
    ("body_too_large", 413, scenario_body_too_large),
]


def check_enrichment(response_text: str, agent_id: str) -> str:
    """For a 200, confirms modulesd actually stamped the document. Returns '' when the
    enrichment is correct, or a human-readable reason when it is not."""
    try:
        document = json.loads(response_text)
    except ValueError as exc:
        return f"response is not JSON ({exc})"
    if not isinstance(document, dict):
        return "response is not a JSON object"

    stamped_id = document.get("wazuh", {}).get("agent", {}).get("id")
    if stamped_id is None:
        return "wazuh.agent.id is missing from the echoed document"
    # remoted forwards the id exactly as it appeared in the Authorization header, so compare
    # numerically -- "001" and "1" are the same agent.
    try:
        same_agent = int(stamped_id) == int(agent_id)
    except (TypeError, ValueError):
        same_agent = str(stamped_id) == str(agent_id)
    if not same_agent:
        return f"wazuh.agent.id is {stamped_id!r}, expected the authenticated {agent_id!r}"

    timestamp = document.get("@timestamp")
    if not isinstance(timestamp, str) or len(timestamp) != 24 or timestamp[10] != "T" \
            or not timestamp.endswith("Z"):
        return f"@timestamp is not ISO8601-with-milliseconds: {timestamp!r}"

    return ""


def run_scenario(base_url, agent_id, agent_key, target, name, expected_status, build):
    headers, body = build(agent_id, agent_key, target)
    url = base_url.rstrip("/") + target
    label = f"{target} {name}"
    try:
        response = requests.post(url, headers=headers, data=body, verify=False, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] {label}: expected {expected_status}, but the request failed instead: {e}")
        return False

    if response.status_code != expected_status:
        hint = ""
        if response.status_code == 503:
            hint = ("  <- 503 means remoted could not reach the downstream: is "
                    "wazuh-manager-modulesd running with inventory_sync_server?")
        print(f"[FAIL] {label}: expected {expected_status}, got {response.status_code} "
              f"({len(body)} byte body) -- {response.text[:160]}{hint}")
        return False

    # A 200 that is not actually enriched would otherwise look like a pass.
    if expected_status == 200:
        problem = check_enrichment(response.text, agent_id)
        if problem:
            print(f"[FAIL] {label}: got 200 but {problem} -- {response.text[:160]}")
            return False

    print(f"[PASS] {label}: expected {expected_status}, got {response.status_code} "
          f"({len(body)} byte body) -- {response.text[:160]}")
    return True


def run_all(base_url, agent_id, agent_key):
    total = len(SCENARIOS) * len(ENDPOINTS)
    print(f"Running {total} scenarios against {base_url} (agent {agent_id})\n")

    results = []
    for target in ENDPOINTS:
        for name, expected, build in SCENARIOS:
            results.append(run_scenario(base_url, agent_id, agent_key, target, name, expected, build))
        print()

    passed = sum(results)
    print(f"{passed}/{len(results)} scenarios passed.")
    return passed == len(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:9443", help="Base URL of the HTTPS server.")
    parser.add_argument("--agent-id", default="1001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS, help="Path to client.keys.")
    parser.add_argument("--endpoint", default="stats", choices=("stats", "config"),
                        help="Which endpoint to send to (ignored with --all, which runs both).")
    parser.add_argument("--body", default=DEFAULT_BODY.decode(),
                        help="Raw request body to sign and send. Must be a JSON OBJECT for a 200.")
    parser.add_argument("--tamper", action="store_true",
                        help="Transmit a different body than the one signed, to prove the server "
                             "rejects a modified body with 401 InvalidMac.")
    parser.add_argument("--all", action="store_true",
                        help="Ignore --body/--tamper/--endpoint and run every scenario against "
                             "BOTH /stats and /config.")
    args = parser.parse_args()

    agent_key = read_agent_key(args.agent_id, args.client_keys)

    if args.all:
        return 0 if run_all(args.url, args.agent_id, agent_key) else 1

    method, target, protocol_version = "POST", f"/{args.endpoint}", "1"
    signed_body = args.body.encode()
    timestamp = int(time.time())
    headers = _auth_header(args.agent_id, agent_key, protocol_version, method, target, timestamp, signed_body)
    sent_body = b'{"tampered":true}' if args.tamper else signed_body

    url = args.url.rstrip("/") + target
    print(f"--> {method} {url}")
    print(f"    Authorization: {headers['Authorization']}")
    print(f"    body sent ({len(sent_body)} bytes): {sent_body!r}")

    try:
        response = requests.post(url, headers=headers, data=sent_body, verify=False, timeout=30)
    except requests.exceptions.RequestException as e:
        # Distinct from a 503: this means remoted itself is unreachable, not that remoted could
        # not reach modulesd. A raw traceback here would bury that difference.
        print(f"<-- request failed: {type(e).__name__}: {e}")
        print(f"\n    Could not reach remoted at {args.url}. Is wazuh-manager-remoted running and "
              f"listening on that port?")
        return 1

    print(f"<-- {response.status_code} {response.reason}")
    try:
        print("    " + json.dumps(json.loads(response.text), indent=4, sort_keys=True).replace("\n", "\n    "))
    except ValueError:
        print(f"    {response.text}")

    if response.status_code == 503:
        print("\n    503 means remoted could not reach the downstream. Is wazuh-manager-modulesd "
              "running with the inventory_sync_server module?")
    elif response.ok:
        problem = check_enrichment(response.text, args.agent_id)
        print(f"\n    enrichment: {problem}" if problem
              else "\n    enrichment OK: wazuh.agent.id and @timestamp were added by modulesd.")

    return 0 if response.ok else 1


if __name__ == "__main__":
    sys.exit(main())
