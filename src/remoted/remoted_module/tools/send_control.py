#!/usr/bin/env python3
"""
Sends signed POST /control requests to remoted's HTTPS auth endpoint, exactly
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

Requires: pip install requests

Examples:
  python3 send_control.py --type startup                              # valid startup request
  python3 send_control.py --type notify --agent-id 1001               # valid notify request
  python3 send_control.py --type notify --with-host                   # notify with host info
  python3 send_control.py --type shutdown                             # valid shutdown request
  python3 send_control.py --type startup --tamper                     # corrupted token -> 401
  python3 send_control.py --all                                       # run all test scenarios
"""
import argparse
import json
import re
import sys
import time

import requests
import urllib3
from wire_jwt import (EXPIRED_IAT_OFFSET, FUTURE_IAT_OFFSET, auth_headers, make_jwt, read_agent_key,
                      tamper_token)  # the shared wazuh-agent+jwt signer (same directory)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CLIENT_KEYS = "/var/wazuh-manager/etc/client.keys"
DEFAULT_AGENT_VERSION = "5.0.0"

# Must match AuthConfig's defaults (interface/authTypes.hpp) unless the manager
# overrides them -- only used to pick offsets that reliably land on the wrong
# side of each window.
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
# Each returns (headers, body_to_send, target). Every distinct error that
# controlEndpoint.cpp and authMiddleware.cpp can return is covered here.

def scenario_valid_startup(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_valid_notify(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "notify",
        "agent": {
            "version": DEFAULT_AGENT_VERSION
        }
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_valid_notify_with_host(agent_id, agent_key):
    target = prefixed("/control")
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
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_valid_shutdown(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "shutdown"
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_invalid_json(agent_id, agent_key):
    target = prefixed("/control")
    body = b'{not valid json}'
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_empty_body(agent_id, agent_key):
    target = prefixed("/control")
    body = b''
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_unknown_message_type(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "unknown_type"
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_invalid_version_startup(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": "999.0.0"  # version higher than manager's
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_malformed_version(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": "not-a-version"
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_oversized_hostname(agent_id, agent_key):
    target = prefixed("/control")
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
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def _valid_with(agent_id, agent_key, **jwt_kwargs):
    """The valid scenario with its Authorization replaced by a deliberately deviant token:
    every keyword goes to wire_jwt.make_jwt (see there). The manager must answer 401."""
    result = list(scenario_valid_startup(agent_id, agent_key))
    result[0] = auth_headers(agent_id, agent_key, **jwt_kwargs)
    return tuple(result)


def scenario_invalid_signature(agent_id, agent_key):
    result = list(scenario_valid_startup(agent_id, agent_key))
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


def scenario_missing_protocol_version(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    del headers["protocol-version"]
    return headers, body, target


def scenario_missing_authorization(_agent_id, _agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    return {"protocol-version": "1"}, body, target


def scenario_expired_request(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    ts = int(time.time()) + EXPIRED_IAT_OFFSET  # older than jwt_max_age + jwt_clock_skew
    headers = auth_headers(agent_id, agent_key, now=ts)
    return headers, body, target


def scenario_future_request(agent_id, agent_key):
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    ts = int(time.time()) + FUTURE_IAT_OFFSET  # issued further ahead than jwt_clock_skew
    headers = auth_headers(agent_id, agent_key, now=ts)
    return headers, body, target


def scenario_body_too_large(agent_id, agent_key):
    # Between control endpoint's body cap (64 KiB) and AuthConfig's cap (10 MiB)
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION,
        "padding": "A" * (MAX_CONTROL_BODY_SIZE + 1024)
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_url_too_large(agent_id, agent_key):
    # max_url_size is 2048 -- this target (path+query) is comfortably over it
    target = prefixed("/control?pad=" + ("a" * (MAX_URL_SIZE + 100)))
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
    return headers, body, target


def scenario_header_value_too_large(agent_id, agent_key):
    # max_field_value_size is 8192
    target = prefixed("/control")
    body_dict = {
        "type": "startup",
        "version": DEFAULT_AGENT_VERSION
    }
    body = json.dumps(body_dict).encode()
    headers = auth_headers(agent_id, agent_key)
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
    # A well-formed but too-high version is a conflict (409); a malformed one is a bad request (400).
    ("invalid_version_startup", 409, scenario_invalid_version_startup),
    ("malformed_version", 400, scenario_malformed_version),
    ("oversized_hostname", 400, scenario_oversized_hostname),
    ("invalid_signature_tampered_token", 401, scenario_invalid_signature),
    ("alg_none", 401, scenario_alg_none),
    ("aud_present", 401, scenario_aud_present),
    ("non_canonical_kid", 401, scenario_non_canonical_kid),
    ("ascii_key", 401, scenario_ascii_key),
    ("missing_protocol_version", 400, scenario_missing_protocol_version),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("expired_token", 401, scenario_expired_request),
    ("future_token", 401, scenario_future_request),
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
    parser.add_argument("--global-prefix", default=None,
                        help="URL path prefix the manager serves every endpoint under "
                             "(<remote><https><global_prefix>). Used only when "
                             "building the URL (authentication does not cover the target). Read from "
                             + DEFAULT_MANAGER_CONF + " when not given; pass '/' to force the "
                             "unprefixed paths.")
    parser.add_argument("--agent-id", default="1001", help="Agent id, as it appears in client.keys.")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS, help="Path to client.keys.")
    parser.add_argument("--type", choices=["startup", "notify", "shutdown"],
                        help="Control message type (startup, notify, or shutdown).")
    parser.add_argument("--version", default=DEFAULT_AGENT_VERSION, help="Agent version to send.")
    parser.add_argument("--with-host", action="store_true",
                        help="Include host info in notify messages.")
    parser.add_argument("--tamper", action="store_true",
                        help="Corrupt the token's signature before sending, to prove the server "
                             "rejects it with 401 (invalid_signature).")
    parser.add_argument("--all", action="store_true",
                        help="Ignore other options and run every success/failure scenario "
                             "(one per distinct error reachable through this endpoint).")
    args = parser.parse_args()
    global GLOBAL_PREFIX
    GLOBAL_PREFIX = resolve_global_prefix(args.global_prefix)
    if args.global_prefix is None and GLOBAL_PREFIX:
        print(f"Global prefix not given; using '{GLOBAL_PREFIX}' from {DEFAULT_MANAGER_CONF}")

    agent_key = read_agent_key(args.agent_id, args.client_keys)

    if args.all:
        return 0 if run_all(args.url, args.agent_id, agent_key) else 1

    if not args.type:
        parser.error("--type is required (or use --all to run all scenarios)")

    method, target, protocol_version = "POST", prefixed("/control"), "1"

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
    headers = auth_headers(args.agent_id, agent_key, now=timestamp, protocol_version=protocol_version)

    sent_body = signed_body
    if args.tamper:
        # Corrupt the token's signature: the manager must answer 401 (invalid_signature).
        headers["Authorization"] = "Bearer " + tamper_token(headers["Authorization"].split(" ", 1)[1])

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
