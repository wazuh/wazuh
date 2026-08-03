#!/usr/bin/env python3
"""
Sends signed POST /control requests to remoted's HTTPS auth endpoint, exactly
the way AuthMiddleware (remoted_module/src/authMiddleware.cpp) expects them:

  Authorization: Wazuh <agent-id>:<timestamp>:<mac>
  protocol-version: 1

MAC = AES-CMAC(agent_key, canonical_bytes), where:

  canonical_bytes = b"WAZUH-REQUEST\n"
                   + protocol_version + b"\n"
                   + method.upper()   + b"\n"
                   + request_target   + b"\n"   (raw path+query, exactly as sent)
                   + agent_id         + b"\n"
                   + str(timestamp)   + b"\n"
                   + body                        (exact request body bytes, no trailing \n)

The agent key is read straight out of client.keys (same file
Keystore reads), so this always matches whatever agent is
currently enrolled -- no need to copy/paste keys by hand.

Requires: pip install requests cryptography

Examples:
  python3 send_control.py --type startup                              # valid startup request
  python3 send_control.py --type notify --agent-id 1001               # valid notify request
  python3 send_control.py --type notify --with-host                   # notify with host info
  python3 send_control.py --type shutdown                             # valid shutdown request
  python3 send_control.py --type startup --tamper                     # modified body -> 401 InvalidMac
  python3 send_control.py --all                                       # run all test scenarios
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
MAX_BODY_SIZE = 10 * 1024 * 1024  # AuthConfig default; transport cap (16 MiB) sits above it on purpose.

# Hardcoded in RestinioHttpServer.cpp's incoming_http_msg_limits(); not exposed
# through HttpServerConfig, so these are fixed regardless of manager config.
MAX_URL_SIZE = 2048
MAX_FIELD_NAME_SIZE = 256
MAX_FIELD_VALUE_SIZE = 8192
MAX_FIELD_COUNT = 64
TRANSPORT_MAX_BODY_SIZE = 16 * 1024 * 1024

# Control endpoint specific limits (from controlEndpoint.cpp)
MAX_CONTROL_BODY_SIZE = 64 * 1024

# Sentinel "expected status": these violations make RESTinio's HTTP parser
# abort and close the connection outright (see RestinioHttpServer.cpp /
# incoming_http_msg_limits.hpp) -- no status code is ever sent back, unlike
# every AuthError case above, which always gets a clean JSON response.
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


# --- Scenarios -------------------------------------------------------------
# Each returns (headers, body_to_send, target). Every distinct error that
# controlEndpoint.cpp and authMiddleware.cpp can return is covered here.

def scenario_valid_startup(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_valid_notify(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "notify",
        "agent": {
            "version": DEFAULT_AGENT_VERSION
        }
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_valid_notify_with_host(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "notify",
        "agent": {
            "version": DEFAULT_AGENT_VERSION
        },
        "host": {
            "hostname": "test-host",
            "architecture": "x86_64",
            "ip": "192.168.1.100",
            "os": {
                "name": "Ubuntu",
                "version": "22.04",
                "platform": "ubuntu",
                "type": "linux"
            }
        }
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_valid_shutdown(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "shutdown"
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_invalid_json(agent_id, agent_key):
    target = "/control"
    body = b'{not valid json}'
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_empty_body(agent_id, agent_key):
    target = "/control"
    body = b''
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_unknown_message_type(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "unknown_type"
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_invalid_version_startup(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": "999.0.0"  # version higher than manager's
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_malformed_version(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": "not-a-version"
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_oversized_hostname(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "notify",
        "agent": {
            "version": DEFAULT_AGENT_VERSION
        },
        "host": {
            "hostname": "h" * 300,  # exceeds kMaxHostnameLength (255)
            "architecture": "x86_64",
            "ip": "192.168.1.100"
        }
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_invalid_mac(agent_id, agent_key):
    target = "/control"
    signed_body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    signed_body = json.dumps(signed_body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), signed_body)

    tampered_body_dict = {
        "type": "startup",
        "version": "4.9.0"  # different from what was signed
    }
    return headers, json.dumps(tampered_body_dict).encode(), target


def scenario_missing_protocol_version(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    del headers["protocol-version"]
    return headers, body, target


def scenario_missing_authorization(_agent_id, _agent_key):
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    return {"protocol-version": "1"}, body, target


def scenario_expired_request(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    ts = int(time.time()) - (MAX_REQUEST_AGE_SECONDS + 1)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, ts, body)
    return headers, body, target


def scenario_future_request(agent_id, agent_key):
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    ts = int(time.time()) + (MAX_FUTURE_SKEW_SECONDS + 1)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, ts, body)
    return headers, body, target


def scenario_body_too_large(agent_id, agent_key):
    # Between control endpoint's body cap (64 KiB) and AuthConfig's cap (10 MiB)
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION,
        "padding": "A" * (MAX_CONTROL_BODY_SIZE + 1024)
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_url_too_large(agent_id, agent_key):
    # max_url_size is 2048 -- this target (path+query) is comfortably over it
    target = "/control?pad=" + ("a" * (MAX_URL_SIZE + 100))
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_header_value_too_large(agent_id, agent_key):
    # max_field_value_size is 8192
    target = "/control"
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    headers["X-Test"] = "v" * (MAX_FIELD_VALUE_SIZE + 500)
    return headers, body, target


SCENARIOS = [
    ("valid_startup", 200, scenario_valid_startup),
    ("valid_notify", 200, scenario_valid_notify),
    ("valid_notify_with_host", 200, scenario_valid_notify_with_host),
    ("valid_shutdown", 200, scenario_valid_shutdown),
    ("invalid_json", 400, scenario_invalid_json),
    ("empty_body", 400, scenario_empty_body),
    ("unknown_message_type", 400, scenario_unknown_message_type),
    ("invalid_version_startup", 400, scenario_invalid_version_startup),
    ("malformed_version", 400, scenario_malformed_version),
    ("oversized_hostname", 400, scenario_oversized_hostname),
    ("invalid_mac_tampered_body", 401, scenario_invalid_mac),
    ("missing_protocol_version", 400, scenario_missing_protocol_version),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("expired_request", 401, scenario_expired_request),
    ("future_request", 401, scenario_future_request),
    ("body_too_large", 400, scenario_body_too_large),
    ("url_too_large", CONN_CLOSED, scenario_url_too_large),
    ("header_value_too_large", CONN_CLOSED, scenario_header_value_too_large),
]


def run_scenario(base_url, agent_id, agent_key, name, expected_status, build):
    headers, body, target = build(agent_id, agent_key)
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
          f"({len(body)} byte body) -- {response.text[:120]}")
    return ok


def run_all(base_url, agent_id, agent_key):
    print(f"Running {len(SCENARIOS)} scenarios against {base_url} (agent {agent_id})\n")
    results = [run_scenario(base_url, agent_id, agent_key, name, expected, build)
               for name, expected, build in SCENARIOS]

    passed, total = sum(results), len(results)
    print(f"\n{passed}/{total} scenarios passed.")
    return passed == total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:9443", help="Base URL of the HTTPS server.")
    parser.add_argument("--agent-id", default="1001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS, help="Path to client.keys.")
    parser.add_argument("--type", choices=["startup", "notify", "shutdown"],
                        help="Control message type (startup, notify, or shutdown).")
    parser.add_argument("--version", default=DEFAULT_AGENT_VERSION, help="Agent version to send.")
    parser.add_argument("--with-host", action="store_true",
                        help="Include host info in notify messages.")
    parser.add_argument("--tamper", action="store_true",
                        help="Transmit a different body than the one signed, to prove the server "
                             "rejects a modified body with 401 InvalidMac.")
    parser.add_argument("--all", action="store_true",
                        help="Ignore other options and run every success/failure scenario "
                             "(one per distinct error reachable through this endpoint).")
    args = parser.parse_args()

    agent_key = read_agent_key(args.agent_id, args.client_keys)

    if args.all:
        return 0 if run_all(args.url, args.agent_id, agent_key) else 1

    if not args.type:
        parser.error("--type is required (or use --all to run all scenarios)")

    method, target, protocol_version = "POST", "/control", "1"

    # Build the appropriate body based on the type
    body_dict = {"type": args.type}

    if args.type == "startup":
        body_dict["version"] = args.version
    elif args.type == "notify":
        body_dict["agent"] = {"version": args.version}
        if args.with_host:
            body_dict["host"] = {
                "hostname": "test-host",
                "architecture": "x86_64",
                "ip": "192.168.1.100",
                "os": {
                    "name": "Ubuntu",
                    "version": "22.04",
                    "platform": "ubuntu",
                    "type": "linux"
                }
            }

    signed_body = json.dumps(body_dict).encode()
    timestamp = int(time.time())
    headers = _auth_header(args.agent_id, agent_key, protocol_version, method, target, timestamp, signed_body)

    if args.tamper:
        body_dict["version"] = "tampered.0.0"
        sent_body = json.dumps(body_dict).encode()
    else:
        sent_body = signed_body

    url = args.url.rstrip("/") + target
    print(f"--> {method} {url}")
    print(f"    Authorization: {headers['Authorization']}")
    print(f"    body sent ({len(sent_body)} bytes): {sent_body.decode()}")

    response = requests.post(url, headers=headers, data=sent_body, verify=False, timeout=10)

    print(f"<-- {response.status_code} {response.reason}")
    print(f"    {response.text}")
    return 0 if response.ok else 1


if __name__ == "__main__":
    sys.exit(main())
