#!/usr/bin/env python3
"""
Sends signed POST /stateless requests to remoted's HTTPS auth endpoint, exactly
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

Requires: pip install -r requirements.txt

Examples:
  python3 send_stateless.py                       # one valid signed request -> 202
  python3 send_stateless.py --agent-id 1001 --body 'hello'
  python3 send_stateless.py --tamper              # modified body -> 401 InvalidMac
  python3 send_stateless.py --all                 # run every success/failure scenario below
"""
import argparse
import sys
import time

import requests
import urllib3
import zstandard
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CLIENT_KEYS = "/var/wazuh-manager/etc/client.keys"
DEFAULT_BODY = b'H {"wazuh":{"agent":{"id":"1001"}}}\nE 1:/var/log/syslog:hello from python'

# Must match AuthConfig's defaults (interface/authTypes.hpp) unless the manager
# overrides them -- only used to pick offsets that reliably land on the wrong
# side of each window.
MAX_REQUEST_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30
MAX_BODY_SIZE = 10 * 1024 * 1024  # AuthConfig default; transport cap (20 MiB) sits above it on purpose.

# Hardcoded in RestinioHttpServer.cpp's incoming_http_msg_limits(); not exposed
# through HttpServerConfig, so these are fixed regardless of manager config.
MAX_URL_SIZE = 2048
MAX_FIELD_NAME_SIZE = 256
MAX_FIELD_VALUE_SIZE = 8192
MAX_FIELD_COUNT = 64
TRANSPORT_MAX_BODY_SIZE = 20 * 1024 * 1024  # httpServerConfig.cpp's DEFAULT_MAX_BODY_SIZE

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
# Each returns (headers, body_to_send, target). Every distinct AuthError that
# publicErrorFor() (authMiddleware.cpp) maps to a distinct status is covered
# here, including PayloadAgentMismatch (400): /stateless cross-checks the H
# line's wazuh.agent.id against the authenticated agent-id before forwarding
# (statelessEndpoint.cpp). Also covers every transport-level limit RESTinio
# itself enforces (RestinioHttpServer.cpp), which fail differently: see
# CONN_CLOSED.

def scenario_valid(agent_id, agent_key):
    target = "/stateless"
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_missing_protocol_version(agent_id, agent_key):
    target = "/stateless"
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    del headers["protocol-version"]
    return headers, body, target


def scenario_unsupported_protocol_version(agent_id, agent_key):
    target = "/stateless"
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "2", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_missing_authorization(_agent_id, _agent_key):
    target = "/stateless"
    return {"protocol-version": "1"}, DEFAULT_BODY, target


def scenario_malformed_authorization(_agent_id, _agent_key):
    target = "/stateless"
    return {"protocol-version": "1", "Authorization": "Wazuh not-even-close"}, DEFAULT_BODY, target


def scenario_unknown_agent(_agent_id, _agent_key):
    target = "/stateless"
    body = DEFAULT_BODY
    fake_id, fake_key = "999999", bytes(32)  # an id that (almost certainly) isn't enrolled
    headers = _auth_header(fake_id, fake_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_expired_request(agent_id, agent_key):
    target = "/stateless"
    body = DEFAULT_BODY
    ts = int(time.time()) - (MAX_REQUEST_AGE_SECONDS + 1)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, ts, body)
    return headers, body, target


def scenario_future_request(agent_id, agent_key):
    target = "/stateless"
    body = DEFAULT_BODY
    ts = int(time.time()) + (MAX_FUTURE_SKEW_SECONDS + 1)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, ts, body)
    return headers, body, target


def scenario_invalid_mac(agent_id, agent_key):
    target = "/stateless"
    signed_body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), signed_body)
    return headers, b"tampered!", target  # transmit different bytes than what was signed


def scenario_body_too_large(agent_id, agent_key):
    # Between AuthConfig's body cap (10 MiB) and the transport's own hard cap
    # (16 MiB, see httpServerConfig.cpp) on purpose: big enough for AuthMiddleware
    # to reject it with a clean 413, not so big RESTinio drops the connection
    # first with no response at all.
    target = "/stateless"
    body = b"A" * (MAX_BODY_SIZE + 1024 * 1024)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_url_too_large(agent_id, agent_key):
    # max_url_size is 2048 -- this target (path+query) is comfortably over it,
    # so the parser must abort before routing/auth ever run.
    target = "/stateless?pad=" + ("a" * (MAX_URL_SIZE + 100))
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_header_name_too_large(agent_id, agent_key):
    # max_field_name_size is 256.
    target = "/stateless"
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    headers["X-" + ("n" * (MAX_FIELD_NAME_SIZE + 50))] = "value"
    return headers, body, target


def scenario_header_value_too_large(agent_id, agent_key):
    # max_field_value_size is 8192.
    target = "/stateless"
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    headers["X-Test"] = "v" * (MAX_FIELD_VALUE_SIZE + 500)
    return headers, body, target


def scenario_too_many_headers(agent_id, agent_key):
    # max_field_count is 64; protocol-version + Authorization already count as
    # 2, so this many extra custom headers comfortably pushes the total over.
    target = "/stateless"
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    for i in range(MAX_FIELD_COUNT + 10):
        headers[f"X-Test-{i}"] = "v"
    return headers, body, target


def scenario_payload_agent_mismatch(agent_id, agent_key):
    # The Authorization header (and its MAC) are for the real, signing agent; the H line's
    # wazuh.agent.id claims a different one. statelessEndpoint.cpp rejects the mismatch with a
    # plain 400 before ever forwarding the batch to the engine.
    target = "/stateless"
    claimed_id = str(int(agent_id) + 1)
    body = f'H {{"wazuh":{{"agent":{{"id":"{claimed_id}"}}}}}}\nE 1:/var/log/syslog:hello from python'.encode()
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_transport_body_too_large(agent_id, agent_key):
    # The transport's own hard cap (20 MiB) rather than AuthConfig's (10 MiB,
    # see scenario_body_too_large): this one must never reach AuthMiddleware
    # at all, so it gets no clean 413 -- RESTinio drops the connection as
    # soon as it sees a too-large Content-Length, before any body is read.
    target = "/stateless"
    body = b"A" * (TRANSPORT_MAX_BODY_SIZE + 1024 * 1024)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    return headers, body, target


def scenario_zstd_encoded(agent_id, agent_key):
    # Content-Encoding: zstd -- sign over the COMPRESSED (wire) bytes, exactly like the manager
    # does: the MAC always covers what was actually sent, compressed or not.
    target = "/stateless"
    plain = DEFAULT_BODY
    compressed = zstandard.ZstdCompressor().compress(plain)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), compressed)
    headers["Content-Encoding"] = "zstd"
    return headers, compressed, target


def scenario_unsupported_content_encoding(agent_id, agent_key):
    # gzip was intentionally dropped -- zstd is the only supported Content-Encoding now. Any other
    # value, including a once-supported one, must be rejected as 415.
    target = "/stateless"
    body = DEFAULT_BODY
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    headers["Content-Encoding"] = "gzip"
    return headers, body, target


def scenario_malformed_zstd(agent_id, agent_key):
    # Claims zstd, but the body is not a zstd frame at all.
    target = "/stateless"
    body = b"definitely not a zstd frame"
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), body)
    headers["Content-Encoding"] = "zstd"
    return headers, body, target


def scenario_zstd_body_beyond_the_auth_cap(agent_id, agent_key):
    # auth_max_body_size (10 MiB) bounds the WIRE body only. A DECOMPRESSED body is bounded by the
    # server's live in-flight capacity instead (max_inflight_bytes, 256 MiB by default), so a batch
    # that decompresses well past 10 MiB is accepted -- that is the behavior change zstd support
    # introduced, and what this scenario pins down.
    #
    # There is deliberately no e2e scenario for the 413 that capacity exhaustion produces: with the
    # default 256 MiB budget a single request cannot realistically reach it, and forcing it would
    # mean making the manager allocate hundreds of MiB. Both 413 paths (the decoder's buffers and
    # the growing output) are covered by bodyDecoder_test.cpp, and the concurrent-pressure case by
    # authGateway_test.cpp's 50-request test.
    target = "/stateless"
    event = b"E 1:/var/log/syslog:" + b"x" * 1000 + b"\n"
    header = b'H {"wazuh":{"agent":{"id":"1001"}}}\n'
    plain = header + event * ((MAX_BODY_SIZE + 1024 * 1024) // len(event) + 1)
    compressed = zstandard.ZstdCompressor().compress(plain)
    headers = _auth_header(agent_id, agent_key, "1", "POST", target, int(time.time()), compressed)
    headers["Content-Encoding"] = "zstd"
    return headers, compressed, target


SCENARIOS = [
    ("valid_request", 202, scenario_valid),
    ("missing_protocol_version", 400, scenario_missing_protocol_version),
    ("unsupported_protocol_version", 400, scenario_unsupported_protocol_version),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("malformed_authorization", 401, scenario_malformed_authorization),
    ("unknown_agent", 401, scenario_unknown_agent),
    ("expired_request", 401, scenario_expired_request),
    ("future_request", 401, scenario_future_request),
    ("invalid_mac_tampered_body", 401, scenario_invalid_mac),
    ("payload_agent_mismatch", 400, scenario_payload_agent_mismatch),
    ("body_too_large", 413, scenario_body_too_large),
    ("url_too_large", CONN_CLOSED, scenario_url_too_large),
    ("header_name_too_large", CONN_CLOSED, scenario_header_name_too_large),
    ("header_value_too_large", CONN_CLOSED, scenario_header_value_too_large),
    ("too_many_headers", CONN_CLOSED, scenario_too_many_headers),
    ("transport_body_too_large", CONN_CLOSED, scenario_transport_body_too_large),
    ("zstd_encoded_valid_request", 202, scenario_zstd_encoded),
    ("unsupported_content_encoding_gzip", 415, scenario_unsupported_content_encoding),
    ("malformed_zstd_body", 400, scenario_malformed_zstd),
    ("zstd_body_beyond_the_auth_cap", 202, scenario_zstd_body_beyond_the_auth_cap),
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
    parser.add_argument("--url", default="https://127.0.0.1:1517", help="Base URL of the HTTPS server.")
    parser.add_argument("--agent-id", default="1001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS, help="Path to client.keys.")
    parser.add_argument("--body", default=DEFAULT_BODY.decode(), help="Raw request body to sign and send.")
    parser.add_argument("--tamper", action="store_true",
                         help="Transmit a different body than the one signed, to prove the server "
                              "rejects a modified body with 401 InvalidMac.")
    parser.add_argument("--all", action="store_true",
                         help="Ignore --body/--tamper and run every success/failure scenario "
                              "(one per distinct AuthError reachable through this endpoint).")
    args = parser.parse_args()

    agent_key = read_agent_key(args.agent_id, args.client_keys)

    if args.all:
        return 0 if run_all(args.url, args.agent_id, agent_key) else 1

    method, target, protocol_version = "POST", "/stateless", "1"
    signed_body = args.body.encode()
    timestamp = int(time.time())
    headers = _auth_header(args.agent_id, agent_key, protocol_version, method, target, timestamp, signed_body)
    sent_body = b"tampered!" if args.tamper else signed_body

    url = args.url.rstrip("/") + target
    print(f"--> {method} {url}")
    print(f"    Authorization: {headers['Authorization']}")
    print(f"    body sent ({len(sent_body)} bytes): {sent_body!r}")

    response = requests.post(url, headers=headers, data=sent_body, verify=False, timeout=10)

    print(f"<-- {response.status_code} {response.reason}")
    print(f"    {response.text}")
    return 0 if response.ok else 1


if __name__ == "__main__":
    sys.exit(main())
