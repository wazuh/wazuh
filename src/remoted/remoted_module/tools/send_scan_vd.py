#!/usr/bin/env python3
"""
Sends signed POST /scan/vd requests to remoted's HTTPS auth endpoint, exactly
the way AuthMiddleware (remoted_module/src/authMiddleware.cpp) expects them --
same envelope as send_control.py, see that script's docstring for the MAC
construction details.

/scan/vd is the on-demand VD re-scan endpoint: an agent that detects (via /control's vd_feed_offset)
that the manager's vulnerability feed has moved on asks THIS node to re-scan it. The manager
accepts the request only if the offset the agent quotes matches its own current feed offset --
otherwise it's a stale/ahead-of-node request and gets 409 with the manager's real offset, which is
exactly what a real agent uses to retry with the corrected value.

The agent key is read straight out of client.keys (same file Keystore reads), so this always
matches whatever agent is currently enrolled -- no need to copy/paste keys by hand.

Requires: pip install requests cryptography

Examples:
  python3 send_scan_vd.py --auto-offset                    # queries /control for the current
                                                             # offset, then sends a matching request -> 200
  python3 send_scan_vd.py --feed-offset 12345               # send an explicit offset
  python3 send_scan_vd.py --feed-offset 1 --agent-id 1001   # deliberately stale -> 409, prints the
                                                             # manager's real current_version
  python3 send_scan_vd.py --all                             # run every scenario below
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
DEFAULT_AGENT_VERSION = "5.0.0"

# Must match AuthConfig's defaults (interface/authTypes.hpp) unless the manager
# overrides them -- only used to pick offsets that reliably land on the wrong
# side of each window.
MAX_REQUEST_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30

# Hardcoded in RestinioHttpServer.cpp's incoming_http_msg_limits(); not exposed
# through HttpServerConfig, so these are fixed regardless of manager config.
MAX_URL_SIZE = 2048
MAX_FIELD_VALUE_SIZE = 8192

# /scan/vd specific limit (kMaxScanVdBodySize, scanVdEndpoint.cpp) -- much
# tighter than /control's 64 KiB, since a scan request only ever carries type
# + feed_offset.
MAX_SCAN_VD_BODY_SIZE = 4 * 1024

# Sentinel "expected status": these violations make RESTinio's HTTP parser
# abort and close the connection outright -- no status code is ever sent back.
CONN_CLOSED = "CONN_CLOSED"


def read_agent_key(agent_id: str, client_keys_path: str) -> bytes:
    """Parses client.keys the same way Keystore does: 'id name ip key'
    lines, '#'/' '-prefixed lines are comments, a name starting with '#'/'!' means
    removed. Returns the raw key bytes (hex-decoded)."""
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
    return {"protocol-version": protocol_version, "Authorization": f"Wazuh {agent_id}:{timestamp}:{mac}"}


def query_current_offset(base_url: str, agent_id: str, agent_key: bytes) -> int:
    """Sends a /control (type: notify) request and reads vd_feed_offset back -- the same way a
    real agent discovers the manager's current feed offset before ever calling /scan/vd."""
    target = "/control"
    body_dict = {"type": "notify", "agent": {"version": DEFAULT_AGENT_VERSION}}
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    url = base_url.rstrip("/") + target
    response = requests.post(url, headers=headers, data=body, verify=False, timeout=10)
    if not response.ok:
        raise SystemExit(f"could not query current offset: {response.status_code} {response.text}")
    offset = response.json().get("vd_feed_offset")
    if offset is None:
        raise SystemExit(f"/control response has no vd_feed_offset field: {response.text}")
    return int(offset)


# --- Scenarios -------------------------------------------------------------
# Each returns (headers, body_to_send, target). Every distinct error that
# scanVdEndpoint.cpp and authMiddleware.cpp can return is covered here.
# Scenarios that need the manager's real current offset take it as a parameter
# rather than guessing, so --all stays deterministic against a live manager.

def scenario_matching_offset(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    body_dict = {"type": "feed_update", "feed_offset": current_offset}
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_mismatched_offset(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    # Deliberately different from current_offset in both directions is unnecessary here -- any
    # value that isn't an exact match takes the same 409 path.
    body_dict = {"type": "feed_update", "feed_offset": current_offset + 999999}
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_missing_type(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    body_dict = {"feed_offset": current_offset}
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_invalid_type(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    body_dict = {"type": "manual", "feed_offset": current_offset}  # only "feed_update" is accepted
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_missing_feed_offset(agent_id, agent_key, _current_offset):
    target = "/scan/vd"
    body_dict = {"type": "feed_update"}
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_negative_feed_offset(agent_id, agent_key, _current_offset):
    target = "/scan/vd"
    body_dict = {"type": "feed_update", "feed_offset": -1}  # must be an unsigned integer
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_invalid_json(agent_id, agent_key, _current_offset):
    target = "/scan/vd"
    body = b'{not valid json}'
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_empty_body(agent_id, agent_key, _current_offset):
    target = "/scan/vd"
    body = b''
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_body_too_large(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    body_dict = {"type": "feed_update", "feed_offset": current_offset, "padding": "A" * MAX_SCAN_VD_BODY_SIZE}
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_invalid_mac(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    signed_body = json.dumps({"type": "feed_update", "feed_offset": current_offset}).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), signed_body)
    tampered_body = json.dumps({"type": "feed_update", "feed_offset": current_offset + 1}).encode()
    return headers, tampered_body, target


def scenario_missing_authorization(_agent_id, _agent_key, current_offset):
    target = "/scan/vd"
    body = json.dumps({"type": "feed_update", "feed_offset": current_offset}).encode()
    return {"protocol-version": "1"}, body, target


def scenario_expired_request(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    body = json.dumps({"type": "feed_update", "feed_offset": current_offset}).encode()
    ts = int(time.time()) - (MAX_REQUEST_AGE_SECONDS + 1)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, ts, body)
    return headers, body, target


def scenario_future_request(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    body = json.dumps({"type": "feed_update", "feed_offset": current_offset}).encode()
    ts = int(time.time()) + (MAX_FUTURE_SKEW_SECONDS + 1)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, ts, body)
    return headers, body, target


def scenario_url_too_large(agent_id, agent_key, current_offset):
    target = "/scan/vd?pad=" + ("a" * (MAX_URL_SIZE + 100))
    body = json.dumps({"type": "feed_update", "feed_offset": current_offset}).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_header_value_too_large(agent_id, agent_key, current_offset):
    target = "/scan/vd"
    body = json.dumps({"type": "feed_update", "feed_offset": current_offset}).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    headers["X-Test"] = "v" * (MAX_FIELD_VALUE_SIZE + 500)
    return headers, body, target


SCENARIOS = [
    ("matching_offset", 200, scenario_matching_offset),
    ("mismatched_offset", 409, scenario_mismatched_offset),
    ("missing_type", 400, scenario_missing_type),
    ("invalid_type", 400, scenario_invalid_type),
    ("missing_feed_offset", 400, scenario_missing_feed_offset),
    ("negative_feed_offset", 400, scenario_negative_feed_offset),
    ("invalid_json", 400, scenario_invalid_json),
    ("empty_body", 400, scenario_empty_body),
    ("body_too_large", 400, scenario_body_too_large),
    ("invalid_mac_tampered_body", 401, scenario_invalid_mac),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("expired_request", 401, scenario_expired_request),
    ("future_request", 401, scenario_future_request),
    ("url_too_large", CONN_CLOSED, scenario_url_too_large),
    ("header_value_too_large", CONN_CLOSED, scenario_header_value_too_large),
]


def run_scenario(base_url, agent_id, agent_key, current_offset, name, expected_status, build):
    headers, body, target = build(agent_id, agent_key, current_offset)
    url = base_url.rstrip("/") + target
    try:
        response = requests.post(url, headers=headers, data=body, verify=False, timeout=20)
    except requests.exceptions.RequestException as e:
        if expected_status == CONN_CLOSED:
            print(f"[PASS] {name}: connection dropped as expected ({type(e).__name__})")
            return True
        print(f"[FAIL] {name}: expected {expected_status}, but the request failed instead: {e}")
        return False

    if expected_status == CONN_CLOSED:
        print(f"[FAIL] {name}: expected the connection to be dropped (no response), but got "
              f"{response.status_code} -- {response.text[:120]}")
        return False

    ok = response.status_code == expected_status
    status_label = "PASS" if ok else "FAIL"
    print(f"[{status_label}] {name}: expected {expected_status}, got {response.status_code} "
          f"({len(body)} byte body) -- {response.text[:200]}")
    return ok


def run_all(base_url, agent_id, agent_key):
    current_offset = query_current_offset(base_url, agent_id, agent_key)
    print(f"Manager's current vd_feed_offset: {current_offset}")
    print(f"Running {len(SCENARIOS)} scenarios against {base_url} (agent {agent_id})\n")
    results = [run_scenario(base_url, agent_id, agent_key, current_offset, name, expected, build)
               for name, expected, build in SCENARIOS]

    passed, total = sum(results), len(results)
    print(f"\n{passed}/{total} scenarios passed.")
    return passed == total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:9443", help="Base URL of the HTTPS server.")
    parser.add_argument("--agent-id", default="1001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS, help="Path to client.keys.")
    parser.add_argument("--feed-offset", type=int,
                        help="Feed offset to send. Omit and pass --auto-offset to have this "
                             "script look it up first via /control.")
    parser.add_argument("--auto-offset", action="store_true",
                        help="Query /control (type: notify) first and use its vd_feed_offset -- "
                             "the same discovery a real agent does before calling /scan/vd.")
    parser.add_argument("--all", action="store_true",
                        help="Ignore --feed-offset/--auto-offset and run every scenario "
                             "(queries the current offset once, up front, for the ones that need it).")
    args = parser.parse_args()

    agent_key = read_agent_key(args.agent_id, args.client_keys)

    if args.all:
        return 0 if run_all(args.url, args.agent_id, agent_key) else 1

    if args.feed_offset is None and not args.auto_offset:
        parser.error("either --feed-offset N or --auto-offset is required (or use --all)")

    feed_offset = query_current_offset(args.url, args.agent_id, agent_key) if args.auto_offset else args.feed_offset
    if args.auto_offset:
        print(f"Discovered current vd_feed_offset via /control: {feed_offset}")

    target = "/scan/vd"
    body_dict = {"type": "feed_update", "feed_offset": feed_offset}
    body = json.dumps(body_dict).encode()
    timestamp = int(time.time())
    headers = _auth_header(args.agent_id, agent_key, "1", "POST", target, timestamp, body)

    url = args.url.rstrip("/") + target
    print(f"--> POST {url}")
    print(f"    Authorization: {headers['Authorization']}")
    print(f"    body sent ({len(body)} bytes): {body.decode()}")

    response = requests.post(url, headers=headers, data=body, verify=False, timeout=10)

    print(f"<-- {response.status_code} {response.reason}")
    print(f"    {response.text}")
    if response.status_code == 409:
        print("    (409 is expected when --feed-offset doesn't match the manager's current "
              "offset -- current_version in the body above is the value to retry with.)")
    return 0 if response.ok else 1


if __name__ == "__main__":
    sys.exit(main())
