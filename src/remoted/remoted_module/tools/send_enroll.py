#!/usr/bin/env python3
"""
Sends POST /enroll requests to remoted's HTTPS enrollment bridge, in any of the three modes
the manager can be configured for (see the "Enrollment endpoint" chapter of remoted_module/README.md
and docs/ref/modules/remoted/https-events-api.md#enrollment-endpoint-post-enroll):

  - Open        -- no credential at all. Just send the request.
  - Password    -- Authorization: Bearer <wazuh-enroll+jwt> (issue #38582): an HS256 JWT whose
                   header is exactly {"alg":"HS256","typ":"wazuh-enroll+jwt"} (no kid) and whose
                   claims are exactly {exp, iat, jti, nbf} (exp = iat + 60, nbf = iat, jti = 16
                   CSPRNG bytes base64url), signed with
                     key = HKDF-SHA256(password, salt = 32 x 0x00, info = b"WAZUH-ENROLL-JWT-KEY" + 0x01, 32 bytes).
                   The token binds time only -- not the method, target or body (TLS protects those);
                   one fresh token per attempt. Same core as the agent bearer of wire_jwt.py, minus
                   the identity claims: an enrolling agent doesn't have an id yet.
  - mTLS        -- a client certificate presented during the TLS handshake IS the credential; pass
                   --client-cert/--client-key and this script sends no Authorization header at all.

Unlike every other tool in this directory, there is no agent already enrolled to borrow a key
from: for Password mode, pass the manager's actual enrollment password (--password, or
--password-file to read it from wherever the operator copied /var/wazuh-manager/etc/authd.pass).

Requires: pip install requests   (the token is pure stdlib via wire_jwt.py)

Examples:
  python3 send_enroll.py --name web-01                                    # Open mode
  python3 send_enroll.py --name web-01 --password Secret123               # Password mode
  python3 send_enroll.py --name web-01 --password Secret123 --tamper      # -> 401 (invalid_signature)
  python3 send_enroll.py --name web-01 --client-cert agent.pem --client-key agent.key  # mTLS mode
  python3 send_enroll.py --password Secret123 --all                       # run every scenario
"""
import argparse
import json
import re
import sys
import time

import requests
import urllib3

from wire_jwt import (CLOCK_SKEW_SECONDS, EXPIRED_IAT_OFFSET, FUTURE_IAT_OFFSET, MAX_AGE_SECONDS,
                      derive_enroll_key, enroll_auth_headers, tamper_token)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PASSWORD_FILE = "/var/wazuh-manager/etc/authd.pass"

# The only value the manager accepts (remoted::auth::kSupportedProtocolVersion). Validated before
# the bearer, in every mode.
PROTOCOL_VERSION = "1"

# The manager's time policy defaults (remoted.jwt_max_age / remoted.jwt_clock_skew, profile maxima
# 60 / 30) come from wire_jwt: MAX_AGE_SECONDS, CLOCK_SKEW_SECONDS and the two offsets that land
# reliably on the wrong side of each window.
_ = (MAX_AGE_SECONDS, CLOCK_SKEW_SECONDS)


def derive_key(password: str) -> bytes:
    """HKDF-SHA256 of the password: the 32-byte HS256 key (see PasswordKeySource / wire_jwt)."""
    return derive_enroll_key(password)


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
    """Serves `path` under the configured global prefix (routing only: the bearer does not bind it)."""
    return GLOBAL_PREFIX + path

def _auth_header(key: bytes, timestamp: int, **jwt_kwargs) -> dict:
    """One fresh wazuh-enroll+jwt bearer (iat = timestamp) signed with the derived key."""
    return {"Authorization": enroll_auth_headers(key, now=timestamp, **jwt_kwargs)["Authorization"]}


def read_password(args) -> str:
    if args.password is not None:
        return args.password
    path = args.password_file or DEFAULT_PASSWORD_FILE
    with open(path, "r") as f:
        return f.readline().rstrip("\r\n")


def build_body(name: str, version: str, groups: str = None, ip: str = None, key_hash: str = None) -> bytes:
    body = {"name": name, "version": version}
    if groups is not None:
        body["groups"] = groups
    if ip is not None:
        body["ip"] = ip
    if key_hash is not None:
        body["key_hash"] = key_hash
    return json.dumps(body).encode()


# A worker-node manager's AuthdClient can legitimately take up to authd_response_timeout's
# worker-aware default (15 s, authdClient.hpp) before answering -- and much longer than that if an
# operator raised authd_connect_timeout/authd_response_timeout. 10 s used to be below even the
# unconfigured worker default, so this tool could report a local timeout for a request the server
# was still legitimately processing. 20 s covers the default comfortably; --timeout raises it
# further for a manager configured with non-default (larger) authd_* timeouts.
DEFAULT_TIMEOUT_SECONDS = 20


def send(base_url, body, headers, cert=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    url = base_url.rstrip("/") + prefixed("/enroll")
    # protocol-version first so a scenario can override it (pass a different value) or drop it
    # (pass None) -- every other scenario gets the valid one without having to say so. /enroll
    # validates this header before anything else, so omitting it here would turn every scenario
    # into the same 400.
    headers = {"protocol-version": PROTOCOL_VERSION, **headers, "Content-Type": "application/json"}
    headers = {k: v for k, v in headers.items() if v is not None}
    return requests.post(url, headers=headers, data=body, cert=cert, verify=False, timeout=timeout)


# --- Scenarios (Password mode only -- these all need a key to sign/tamper with) -------------

def scenario_valid(key, name, timestamp):
    # Unique per run: this is the one scenario that can actually SUCCEED and persist an agent
    # record. Reusing a fixed name would make every run after the first collide with the previous
    # run's own agent and get rejected 409 (EDUPNAME) instead of the 200 this scenario expects --
    # a tool meant for repeatable testing must not require a fresh client.keys between runs.
    unique_name = f"{name}-{timestamp}"
    body = build_body(unique_name, "5.0.0")
    return _auth_header(key, timestamp), body


def scenario_tampered_token(key, name, timestamp):
    # The bearer does not cover the body (TLS does), so "tampering" means the token itself: a
    # well-formed token whose signature no longer verifies -> 401, never 400.
    body = build_body(name, "5.0.0")
    headers = _auth_header(key, timestamp)
    headers["Authorization"] = "Bearer " + tamper_token(headers["Authorization"][len("Bearer "):])
    return headers, body


def scenario_wrong_key(_key, name, timestamp):
    wrong_key = bytes(32)  # all-zero key -- never the real derived key
    body = build_body(name, "5.0.0")
    return _auth_header(wrong_key, timestamp), body


def scenario_missing_authorization(_key, name, _timestamp):
    body = build_body(name, "5.0.0")
    return {}, body


def scenario_malformed_authorization(_key, name, _timestamp):
    # Not a Bearer -> MalformedAuthorization.
    body = build_body(name, "5.0.0")
    return {"Authorization": "Basic dXNlcjpwYXNz"}, body


def scenario_agent_profile_token(key, name, timestamp):
    # A correctly signed token of the OTHER profile (typ wazuh-agent+jwt, with kid/iss/sub): the exact
    # header set rejects it before the signature is even looked at -> 401 (bad_token).
    body = build_body(name, "5.0.0")
    headers = _auth_header(key, timestamp, typ="wazuh-agent+jwt", extra_header={"kid": "001"},
                           extra_claims={"iss": "wazuh-agent/001", "sub": "001"})
    return headers, body


def scenario_expired(key, name, _timestamp):
    ts = int(time.time()) + EXPIRED_IAT_OFFSET  # older than max_age + skew
    body = build_body(name, "5.0.0")
    return _auth_header(key, ts), body


def scenario_future(key, name, _timestamp):
    ts = int(time.time()) + FUTURE_IAT_OFFSET  # issued further ahead than the skew
    body = build_body(name, "5.0.0")
    return _auth_header(key, ts), body


def scenario_missing_name(key, _name, timestamp):
    body = json.dumps({"version": "5.0.0"}).encode()
    headers = _auth_header(key, timestamp) if key else {}
    return headers, body


def scenario_invalid_ip(key, name, timestamp):
    body = build_body(name, "5.0.0", ip="not-an-ip")
    headers = _auth_header(key, timestamp) if key else {}
    return headers, body


def scenario_malformed_json(key, _name, timestamp):
    body = b"not valid json{{{"
    headers = _auth_header(key, timestamp) if key else {}
    return headers, body


def scenario_missing_protocol_version(key, name, timestamp):
    # Otherwise a fully valid request: None drops the header in send(). Rejected before the
    # credential check, so this is a 400 in every mode -- including Open, where there is no
    # credential to check at all.
    body = build_body(name, "5.0.0")
    headers = _auth_header(key, timestamp) if key else {}
    return {**headers, "protocol-version": None}, body


def scenario_unsupported_protocol_version(key, name, timestamp):
    # A version this manager does not implement. Must be its own 400, never an opaque 401: the
    # bearer below is valid, so a credential failure here would mean the version is being checked
    # as part of the credential instead of on its own.
    body = build_body(name, "5.0.0")
    headers = _auth_header(key, timestamp) if key else {}
    return {**headers, "protocol-version": "999"}, body


AUTH_SCENARIOS = [
    ("valid_bearer", 200, scenario_valid),
    ("tampered_token", 401, scenario_tampered_token),
    ("wrong_key", 401, scenario_wrong_key),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("malformed_authorization", 401, scenario_malformed_authorization),
    ("agent_profile_token", 401, scenario_agent_profile_token),
    ("stale_token_expired", 401, scenario_expired),
    ("stale_token_future", 401, scenario_future),
]

VALIDATION_SCENARIOS = [
    ("missing_name", 400, scenario_missing_name),
    ("invalid_ip", 400, scenario_invalid_ip),
    ("malformed_json", 400, scenario_malformed_json),
    ("missing_protocol_version", 400, scenario_missing_protocol_version),
    ("unsupported_protocol_version", 400, scenario_unsupported_protocol_version),
]


def run_scenario(base_url, key, name, scenario_name, expected_status, build, cert=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    headers, body = build(key, name, int(time.time()))
    response = send(base_url, body, headers, cert=cert, timeout=timeout)
    ok = response.status_code == expected_status
    label = "PASS" if ok else "FAIL"
    print(f"[{label}] {scenario_name}: expected {expected_status}, got {response.status_code} "
          f"-- {response.text[:200]}")
    return ok


def run_all(base_url, key, name, cert=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    scenarios = AUTH_SCENARIOS + VALIDATION_SCENARIOS if key else VALIDATION_SCENARIOS
    if not key:
        print("No --password given: skipping the bearer/timing scenarios (they need a key to "
              "mint or tamper with) and running only the body-validation ones, which work "
              "regardless of the manager's configured auth mode -- as long as this manager "
              "doesn't itself require a credential.\n")
    if cert:
        print(f"Presenting client certificate {cert[0]} on every request (mTLS mode).\n")
    print(f"Running {len(scenarios)} scenario(s) against {base_url}{prefixed('/enroll')}\n")
    results = [run_scenario(base_url, key, name, scenario_name, expected, build, cert=cert, timeout=timeout)
               for scenario_name, expected, build in scenarios]
    passed, total = sum(results), len(results)
    print(f"\n{passed}/{total} scenarios passed.")
    return passed == total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:1517", help="Base URL of the HTTPS server.")
    parser.add_argument("--global-prefix", default=None,
                        help="URL path prefix the manager serves every endpoint under "
                             "(<remote><https><global_prefix>). A routing matter only -- the bearer "
                             "does not bind the target (a wrong prefix is a 404). Read from "
                             + DEFAULT_MANAGER_CONF + " when not given; pass '/' to force the "
                             "unprefixed paths.")
    parser.add_argument("--name", default="test-agent", help="Agent name to enroll.")
    parser.add_argument("--version", default="5.0.0", help="Agent version to report.")
    parser.add_argument("--groups", help="Comma-separated centralized group(s).")
    parser.add_argument("--ip", help="Agent IP override (or 'any').")
    parser.add_argument("--key-hash", help="Hash of the agent's current key, if re-enrolling.")
    parser.add_argument("--password", help="Enrollment password -- mints the wazuh-enroll+jwt bearer "
                                            "(Password mode). Omit entirely for Open mode.")
    parser.add_argument("--password-file", help=f"Read the password from this file instead of "
                                                 f"--password (default {DEFAULT_PASSWORD_FILE}).")
    parser.add_argument("--client-cert", help="Client certificate PEM (mTLS mode).")
    parser.add_argument("--client-key", help="Client private key PEM (mTLS mode).")
    parser.add_argument("--tamper", action="store_true",
                        help="Corrupt the bearer's signature (token stays well-formed) -> 401 "
                             "invalid_signature (Password mode only).")
    parser.add_argument("--all", action="store_true",
                        help="Run every scenario instead of sending one request. Uses --password "
                             "if given (adds signature/timing scenarios on top of the body-"
                             "validation ones); otherwise runs only the auth-agnostic ones. If "
                             "--client-cert/--client-key are also given, every scenario request "
                             "presents that certificate too (mTLS mode).")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS,
                        help=f"Per-request timeout, seconds (default {DEFAULT_TIMEOUT_SECONDS}, "
                             "comfortably above authd_response_timeout's unconfigured worker-node "
                             "default of 15s -- raise this if the manager's authd_connect_timeout/"
                             "authd_response_timeout were themselves raised).")
    args = parser.parse_args()
    global GLOBAL_PREFIX
    GLOBAL_PREFIX = resolve_global_prefix(args.global_prefix)
    if args.global_prefix is None and GLOBAL_PREFIX:
        print(f"Global prefix not given; using '{GLOBAL_PREFIX}' from {DEFAULT_MANAGER_CONF}")

    if args.password_file and args.password is not None:
        parser.error("--password and --password-file are mutually exclusive")

    key = None
    if args.password is not None or args.password_file:
        key = derive_key(read_password(args))

    # Computed BEFORE the --all branch: --all used to return early here, so --client-cert/
    # --client-key were silently ignored and mTLS was never actually exercised by --all.
    cert = (args.client_cert, args.client_key) if args.client_cert or args.client_key else None
    if cert and (not args.client_cert or not args.client_key):
        parser.error("--client-cert and --client-key must be given together")

    if args.all:
        return 0 if run_all(args.url, key, args.name, cert=cert, timeout=args.timeout) else 1

    timestamp = int(time.time())
    sent_body = build_body(args.name, args.version, args.groups, args.ip, args.key_hash)

    headers = {}
    if key:
        headers = _auth_header(key, timestamp)

    if args.tamper:
        if not key:
            parser.error("--tamper only makes sense with --password (nothing to tamper with otherwise)")
        headers["Authorization"] = "Bearer " + tamper_token(headers["Authorization"][len("Bearer "):])

    print(f"--> POST {args.url.rstrip('/')}{prefixed('/enroll')}")
    if headers:
        print(f"    Authorization: {headers['Authorization']}")
    elif cert:
        print(f"    (mTLS: presenting {args.client_cert})")
    else:
        print("    (Open mode: no credential)")
    print(f"    body sent ({len(sent_body)} bytes): {sent_body.decode()}")

    response = send(args.url, sent_body, headers, cert=cert, timeout=args.timeout)

    print(f"<-- {response.status_code} {response.reason}")
    print(f"    {response.text}")
    return 0 if response.ok else 1


if __name__ == "__main__":
    sys.exit(main())
