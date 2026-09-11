#!/usr/bin/env python3
"""
Sends signed POST /stateless requests to remoted's HTTPS auth endpoint, exactly
the way AuthMiddleware (remoted_module/src/authMiddleware.cpp) expects them:

  protocol-version: 1
  Authorization: Bearer <wazuh-agent+jwt token>

The token is a JWT (HS256) the agent self-signs with its client.keys secret -- exactly the closed
profile wire_jwt.py mints (header {alg,kid,typ}, six claims, 60 s lifetime, fresh jti per request).
It binds the agent's identity only: method, target, body and compression are NOT part of
authentication; the manager answers every credential failure with a uniform 401 +
WWW-Authenticate: Bearer. See wire_jwt.py (and `python3 wire_jwt.py --self-test`).

The agent key is read straight out of client.keys (same file
Keystore reads), so this always matches whatever agent is
currently enrolled -- no need to copy/paste keys by hand.

Requires: pip install -r requirements.txt

Examples:
  python3 send_stateless.py                       # one valid signed request -> 202
  python3 send_stateless.py --agent-id 1001 --body 'hello'
  python3 send_stateless.py --tamper              # corrupted token -> 401
  python3 send_stateless.py --all                 # run every success/failure scenario below
"""
import argparse
import re
import sys
import time

import requests
import urllib3
from wire_jwt import (EXPIRED_IAT_OFFSET, FUTURE_IAT_OFFSET, auth_headers, make_jwt, read_agent_key,
                      tamper_token)  # the shared wazuh-agent+jwt signer (same directory)
import zstandard

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CLIENT_KEYS = "/var/wazuh-manager/etc/client.keys"


def default_body(agent_id: str) -> bytes:
    """One H line naming `agent_id` + one event. The H line MUST name the authenticated agent: the
    manager answers 400 (payload_agent_mismatch) to a batch that claims another id."""
    return b'H {"wazuh":{"agent":{"id":"' + agent_id.encode() + b'"}}}\nE 1:/var/log/syslog:hello from python'


DEFAULT_BODY = default_body("1001")  # re-derived from --agent-id in main()

# Must match AuthConfig's defaults (interface/authTypes.hpp) unless the manager
# overrides them -- only used to pick offsets that reliably land on the wrong
# side of each window.
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



# --- Global endpoint prefix (<remote><https><global_prefix>) ---------------------------------
# Applied to every target when building the URL. Authentication does not cover the target (the
# bearer token binds the agent's identity only), so a mismatch with the manager's configured
# prefix surfaces as 404 (route not found), never as 401.
#
# Resolved like run_benchmark.sh resolves --cluster: the value belongs to the manager under
# test, so when --global-prefix is not given it is read from that manager's own configuration
# instead of making every invocation repeat it -- a default installation needs no flag. An
# explicit value always wins; pass '/' to force the unprefixed paths against a prefixed manager.

DEFAULT_MANAGER_CONF = "/var/wazuh-manager/etc/wazuh-manager.conf"

GLOBAL_PREFIX = ""


def normalize_global_prefix(raw: str) -> str:
    """'' and '/' mean no prefix; otherwise ensure a leading '/' and strip trailing '/'."""
    stripped = raw.strip("/") if raw else ""
    return "/" + stripped if stripped else ""


def global_prefix_from_conf(conf_path: str = DEFAULT_MANAGER_CONF) -> str:
    """Reads <remote><https><global_prefix> out of the manager's configuration.

    Scoped to the <https> block so a <global_prefix> elsewhere in the file cannot be picked
    up by mistake. Returns "" when the file is missing or unreadable and when the tag is
    absent -- an absent tag is exactly what "no prefix" means to the manager too, so the
    caller needs no separate "not detected" case.
    """
    try:
        with open(conf_path, "r") as handle:
            text = handle.read()
    except OSError:
        return ""
    block = re.search(r"<https>(.*?)</https>", text, re.S)
    if not block:
        return ""
    tag = re.search(r"<global_prefix>(.*?)</global_prefix>", block.group(1), re.S)
    return tag.group(1).strip() if tag else ""


def resolve_global_prefix(cli_value, conf_path: str = DEFAULT_MANAGER_CONF) -> str:
    """An explicit --global-prefix wins; None (flag not given) reads the manager's config."""
    if cli_value is not None:
        return normalize_global_prefix(cli_value)
    return normalize_global_prefix(global_prefix_from_conf(conf_path))


def prefixed(path: str) -> str:
    """Serves `path` under the configured global prefix (signed AND sent)."""
    return GLOBAL_PREFIX + path

# --- Scenarios -------------------------------------------------------------
# Each returns (headers, body_to_send, target). Every distinct AuthError that
# publicErrorFor() (authMiddleware.cpp) maps to a distinct status is covered
# here, including PayloadAgentMismatch (400): /stateless cross-checks the H
# line's wazuh.agent.id against the authenticated agent-id before forwarding
# (statelessEndpoint.cpp). Also covers every transport-level limit RESTinio
# itself enforces (RestinioHttpServer.cpp), which fail differently: see
# CONN_CLOSED.

def scenario_valid(agent_id, agent_key):
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_missing_protocol_version(agent_id, agent_key):
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key)
    del headers["protocol-version"]
    return headers, body, target


def scenario_unsupported_protocol_version(agent_id, agent_key):
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key, protocol_version="2")
    return headers, body, target


def scenario_missing_authorization(_agent_id, _agent_key):
    target = prefixed("/stateless")
    return {"protocol-version": "1"}, DEFAULT_BODY, target


def scenario_malformed_authorization(_agent_id, _agent_key):
    target = prefixed("/stateless")
    return {"protocol-version": "1", "Authorization": "Wazuh not-even-close"}, DEFAULT_BODY, target


def scenario_unknown_agent(_agent_id, _agent_key):
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    fake_id, fake_key = "999999", "00" * 32  # an id that (almost certainly) isn't enrolled
    headers = auth_headers(fake_id, fake_key)
    return headers, body, target


def scenario_expired_request(agent_id, agent_key):
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    ts = int(time.time()) + EXPIRED_IAT_OFFSET  # older than jwt_max_age + jwt_clock_skew
    headers = auth_headers(agent_id, agent_key, now=ts)
    return headers, body, target


def scenario_future_request(agent_id, agent_key):
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    ts = int(time.time()) + FUTURE_IAT_OFFSET  # issued further ahead than jwt_clock_skew
    headers = auth_headers(agent_id, agent_key, now=ts)
    return headers, body, target


def _valid_with(agent_id, agent_key, **jwt_kwargs):
    """The valid scenario with its Authorization replaced by a deliberately deviant token:
    every keyword goes to wire_jwt.make_jwt (see there). The manager must answer 401."""
    result = list(scenario_valid(agent_id, agent_key))
    result[0] = auth_headers(agent_id, agent_key, **jwt_kwargs)
    return tuple(result)


def scenario_invalid_signature(agent_id, agent_key):
    result = list(scenario_valid(agent_id, agent_key))
    token = result[0]["Authorization"].split(" ", 1)[1]
    result[0] = dict(result[0], Authorization="Bearer " + tamper_token(token))
    return tuple(result)


def scenario_alg_none(agent_id, agent_key):
    return _valid_with(agent_id, agent_key, alg="none")


def scenario_aud_present(agent_id, agent_key):
    return _valid_with(agent_id, agent_key, extra_claims={"aud": "wazuh-manager"})


def scenario_non_canonical_kid(agent_id, agent_key):
    return _valid_with(agent_id, agent_key, kid="0" + f"{int(agent_id):03d}")


def scenario_ascii_key(agent_id, agent_key):
    # The classic interoperability mistake: HMAC with the 64 hex chars instead of the 32 bytes.
    return _valid_with(agent_id, agent_key, sign_with=agent_key.encode())


def scenario_body_too_large(agent_id, agent_key):
    # Between AuthConfig's body cap (10 MiB) and the transport's own hard cap
    # (16 MiB, see httpServerConfig.cpp) on purpose: big enough for AuthMiddleware
    # to reject it with a clean 413, not so big RESTinio drops the connection
    # first with no response at all.
    target = prefixed("/stateless")
    body = b"A" * (MAX_BODY_SIZE + 1024 * 1024)
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_url_too_large(agent_id, agent_key):
    # max_url_size is 2048 -- this target (path+query) is comfortably over it,
    # so the parser must abort before routing/auth ever run.
    target = prefixed("/stateless?pad=" + ("a" * (MAX_URL_SIZE + 100)))
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_header_name_too_large(agent_id, agent_key):
    # max_field_name_size is 256.
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key)
    headers["X-" + ("n" * (MAX_FIELD_NAME_SIZE + 50))] = "value"
    return headers, body, target


def scenario_header_value_too_large(agent_id, agent_key):
    # max_field_value_size is 8192.
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key)
    headers["X-Test"] = "v" * (MAX_FIELD_VALUE_SIZE + 500)
    return headers, body, target


def scenario_too_many_headers(agent_id, agent_key):
    # max_field_count is 64; protocol-version + Authorization already count as
    # 2, so this many extra custom headers comfortably pushes the total over.
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key)
    for i in range(MAX_FIELD_COUNT + 10):
        headers[f"X-Test-{i}"] = "v"
    return headers, body, target


def scenario_payload_agent_mismatch(agent_id, agent_key):
    # The bearer token names the real agent; the H line's
    # wazuh.agent.id claims a different one. statelessEndpoint.cpp rejects the mismatch with a
    # plain 400 before ever forwarding the batch to the engine.
    target = prefixed("/stateless")
    claimed_id = str(int(agent_id) + 1)
    body = f'H {{"wazuh":{{"agent":{{"id":"{claimed_id}"}}}}}}\nE 1:/var/log/syslog:hello from python'.encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_transport_body_too_large(agent_id, agent_key):
    # The transport's own hard cap (20 MiB) rather than AuthConfig's (10 MiB,
    # see scenario_body_too_large): this one must never reach AuthMiddleware
    # at all, so it gets no clean 413 -- RESTinio drops the connection as
    # soon as it sees a too-large Content-Length, before any body is read.
    target = prefixed("/stateless")
    body = b"A" * (TRANSPORT_MAX_BODY_SIZE + 1024 * 1024)
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_zstd_encoded(agent_id, agent_key):
    # Content-Encoding: zstd -- the token does not cover the body, compressed or not; only the
    # manager's decoder cares about these bytes.
    target = prefixed("/stateless")
    plain = DEFAULT_BODY
    compressed = zstandard.ZstdCompressor().compress(plain)
    headers = auth_headers(agent_id, agent_key)
    headers["Content-Encoding"] = "zstd"
    return headers, compressed, target


def scenario_unsupported_content_encoding(agent_id, agent_key):
    # gzip was intentionally dropped -- zstd is the only supported Content-Encoding now. Any other
    # value, including a once-supported one, must be rejected as 415.
    target = prefixed("/stateless")
    body = DEFAULT_BODY
    headers = auth_headers(agent_id, agent_key)
    headers["Content-Encoding"] = "gzip"
    return headers, body, target


def scenario_malformed_zstd(agent_id, agent_key):
    # Claims zstd, but the body is not a zstd frame at all.
    target = prefixed("/stateless")
    body = b"definitely not a zstd frame"
    headers = auth_headers(agent_id, agent_key)
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
    target = prefixed("/stateless")
    event = b"E 1:/var/log/syslog:" + b"x" * 1000 + b"\n"
    header = b'H {"wazuh":{"agent":{"id":"' + agent_id.encode() + b'"}}}\n'
    plain = header + event * ((MAX_BODY_SIZE + 1024 * 1024) // len(event) + 1)
    compressed = zstandard.ZstdCompressor().compress(plain)
    headers = auth_headers(agent_id, agent_key)
    headers["Content-Encoding"] = "zstd"
    return headers, compressed, target


SCENARIOS = [
    ("valid_request", 202, scenario_valid),
    ("missing_protocol_version", 400, scenario_missing_protocol_version),
    ("unsupported_protocol_version", 400, scenario_unsupported_protocol_version),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("malformed_authorization", 401, scenario_malformed_authorization),
    ("unknown_agent", 401, scenario_unknown_agent),
    ("expired_token", 401, scenario_expired_request),
    ("future_token", 401, scenario_future_request),
    ("invalid_signature_tampered_token", 401, scenario_invalid_signature),
    ("alg_none", 401, scenario_alg_none),
    ("aud_present", 401, scenario_aud_present),
    ("non_canonical_kid", 401, scenario_non_canonical_kid),
    ("ascii_key", 401, scenario_ascii_key),
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
    global GLOBAL_PREFIX, DEFAULT_BODY
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:1517", help="Base URL of the HTTPS server.")
    parser.add_argument("--global-prefix", default=None,
                        help="URL path prefix the manager serves every endpoint under "
                             "(<remote><https><global_prefix>). Used only when "
                             "building the URL (authentication does not cover the target). Read from "
                             + DEFAULT_MANAGER_CONF + " when not given; pass '/' to force the "
                             "unprefixed paths.")
    parser.add_argument("--agent-id", default="1001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS, help="Path to client.keys.")
    parser.add_argument("--body", default=None,
                        help="Raw request body to send (default: one H line naming --agent-id plus one event).")
    parser.add_argument("--tamper", action="store_true",
                         help="Corrupt the token's signature before sending, to prove the server "
                              "rejects it with 401 (invalid_signature).")
    parser.add_argument("--all", action="store_true",
                         help="Ignore --body/--tamper and run every success/failure scenario "
                              "(one per distinct AuthError reachable through this endpoint).")
    args = parser.parse_args()
    GLOBAL_PREFIX = resolve_global_prefix(args.global_prefix)
    if args.global_prefix is None and GLOBAL_PREFIX:
        print(f"Global prefix not given; using '{GLOBAL_PREFIX}' from {DEFAULT_MANAGER_CONF}")

    agent_key = read_agent_key(args.agent_id, args.client_keys)
    DEFAULT_BODY = default_body(args.agent_id)

    if args.all:
        return 0 if run_all(args.url, args.agent_id, agent_key) else 1

    method, target, protocol_version = "POST", prefixed("/stateless"), "1"
    signed_body = args.body.encode() if args.body is not None else DEFAULT_BODY
    timestamp = int(time.time())
    headers = auth_headers(args.agent_id, agent_key, now=timestamp, protocol_version=protocol_version)
    sent_body = signed_body
    if args.tamper:
        # Corrupt the token's signature: the manager must answer 401 (invalid_signature).
        headers["Authorization"] = "Bearer " + tamper_token(headers["Authorization"].split(" ", 1)[1])

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
