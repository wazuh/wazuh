#!/usr/bin/env python3
"""
Sends POST /enroll requests to remoted's HTTPS enrollment bridge, in any of the three modes
the manager can be configured for (see the "Enrollment endpoint" chapter of remoted_module/README.md
and docs/ref/modules/remoted/https-events-api.md#enrollment-endpoint-post-enroll):

  - Open        -- no credential at all. Just send the request.
  - Password    -- Authorization: WazuhEnroll <unix-ts>:<mac>, where
                   mac = AES-256-CMAC(hkdf_key, canonical_bytes) and
                   hkdf_key = HKDF-SHA256(password, salt=b"", info=b"WAZUH-ENROLL-CMAC-KEY"+0x01, 32 bytes):

                     canonical_bytes = b"WAZUH-ENROLL\n"
                                      + b"1\n"
                                      + method.upper()  + b"\n"
                                      + request_target  + b"\n"   (raw path+query, exactly as sent)
                                      + str(timestamp)  + b"\n"
                                      + body                       (exact request body bytes, no trailing \\n)

                   Deliberately similar to send_control.py's "Wazuh <agent-id>:..." scheme, minus the
                   agent-id field -- an enrolling agent doesn't have one yet.
  - mTLS        -- a client certificate presented during the TLS handshake IS the credential; pass
                   --client-cert/--client-key and this script sends no Authorization header at all.

Unlike every other tool in this directory, there is no agent already enrolled to borrow a key
from: for Password mode, pass the manager's actual enrollment password (--password, or
--password-file to read it from wherever the operator copied /var/wazuh-manager/etc/authd.pass).

Requires: pip install requests cryptography

Examples:
  python3 send_enroll.py --name web-01                                    # Open mode
  python3 send_enroll.py --name web-01 --password Secret123               # Password mode
  python3 send_enroll.py --name web-01 --password Secret123 --tamper      # -> 401 InvalidMac
  python3 send_enroll.py --name web-01 --client-cert agent.pem --client-key agent.key  # mTLS mode
  python3 send_enroll.py --password Secret123 --all                       # run every scenario
"""
import argparse
import json
import sys
import time

import requests
import urllib3
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PASSWORD_FILE = "/var/wazuh-manager/etc/authd.pass"
HKDF_INFO = b"WAZUH-ENROLL-CMAC-KEY" + bytes([1])

# Must match EnrollmentAuthConfig's defaults (enrollmentAuthenticator.hpp) unless the manager
# overrides them via remoted.auth_max_request_age/_future_skew -- only used to pick timestamps
# that reliably land on the wrong side of each window.
MAX_REQUEST_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30


def derive_key(password: str) -> bytes:
    """HKDF-SHA256(password, salt=b"", info=HKDF_INFO, 32 bytes) -- see PasswordKeySource."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=HKDF_INFO)
    return hkdf.derive(password.encode())


def sign_request(key: bytes, method: str, request_target: str, timestamp: int, body: bytes) -> str:
    """Builds the WazuhEnroll canonical byte sequence and returns its lowercase-hex AES-CMAC."""
    c = cmac.CMAC(algorithms.AES(key))
    c.update(b"WAZUH-ENROLL\n")
    c.update(b"1\n")
    c.update(method.upper().encode() + b"\n")
    c.update(request_target.encode() + b"\n")
    c.update(str(timestamp).encode() + b"\n")
    c.update(body)
    return c.finalize().hex()


def _auth_header(key: bytes, method: str, target: str, timestamp: int, body: bytes) -> dict:
    mac = sign_request(key, method, target, timestamp, body)
    return {"Authorization": f"WazuhEnroll {timestamp}:{mac}"}


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


def send(base_url, body, headers, cert=None, timeout=10):
    url = base_url.rstrip("/") + "/enroll"
    headers = {**headers, "Content-Type": "application/json"}
    return requests.post(url, headers=headers, data=body, cert=cert, verify=False, timeout=timeout)


# --- Scenarios (Password mode only -- these all need a key to sign/tamper with) -------------

def scenario_valid(key, name, timestamp):
    body = build_body(name, "5.0.0")
    return _auth_header(key, "POST", "/enroll", timestamp, body), body


def scenario_tampered_body(key, name, timestamp):
    signed_body = build_body(name, "5.0.0")
    headers = _auth_header(key, "POST", "/enroll", timestamp, signed_body)
    tampered_body = build_body(name + "-tampered", "5.0.0")
    return headers, tampered_body


def scenario_wrong_key(_key, name, timestamp):
    wrong_key = bytes(32)  # all-zero key -- never the real derived key
    body = build_body(name, "5.0.0")
    return _auth_header(wrong_key, "POST", "/enroll", timestamp, body), body


def scenario_missing_authorization(_key, name, _timestamp):
    body = build_body(name, "5.0.0")
    return {}, body


def scenario_malformed_authorization(_key, name, _timestamp):
    body = build_body(name, "5.0.0")
    return {"Authorization": "WazuhEnroll not-a-valid-header"}, body


def scenario_expired(key, name, _timestamp):
    ts = int(time.time()) - (MAX_REQUEST_AGE_SECONDS + 5)
    body = build_body(name, "5.0.0")
    return _auth_header(key, "POST", "/enroll", ts, body), body


def scenario_future(key, name, _timestamp):
    ts = int(time.time()) + (MAX_FUTURE_SKEW_SECONDS + 5)
    body = build_body(name, "5.0.0")
    return _auth_header(key, "POST", "/enroll", ts, body), body


def scenario_missing_name(key, _name, timestamp):
    body = json.dumps({"version": "5.0.0"}).encode()
    headers = _auth_header(key, "POST", "/enroll", timestamp, body) if key else {}
    return headers, body


def scenario_invalid_ip(key, name, timestamp):
    body = build_body(name, "5.0.0", ip="not-an-ip")
    headers = _auth_header(key, "POST", "/enroll", timestamp, body) if key else {}
    return headers, body


def scenario_malformed_json(key, _name, timestamp):
    body = b"not valid json{{{"
    headers = _auth_header(key, "POST", "/enroll", timestamp, body) if key else {}
    return headers, body


AUTH_SCENARIOS = [
    ("valid_signature", 200, scenario_valid),
    ("tampered_body", 401, scenario_tampered_body),
    ("wrong_key", 401, scenario_wrong_key),
    ("missing_authorization", 401, scenario_missing_authorization),
    ("malformed_authorization", 401, scenario_malformed_authorization),
    ("expired_request", 401, scenario_expired),
    ("future_request", 401, scenario_future),
]

VALIDATION_SCENARIOS = [
    ("missing_name", 400, scenario_missing_name),
    ("invalid_ip", 400, scenario_invalid_ip),
    ("malformed_json", 400, scenario_malformed_json),
]


def run_scenario(base_url, key, name, scenario_name, expected_status, build):
    headers, body = build(key, name, int(time.time()))
    response = send(base_url, body, headers)
    ok = response.status_code == expected_status
    label = "PASS" if ok else "FAIL"
    print(f"[{label}] {scenario_name}: expected {expected_status}, got {response.status_code} "
          f"-- {response.text[:200]}")
    return ok


def run_all(base_url, key, name):
    scenarios = AUTH_SCENARIOS + VALIDATION_SCENARIOS if key else VALIDATION_SCENARIOS
    if not key:
        print("No --password given: skipping the signature/timing scenarios (they need a key to "
              "sign or tamper with) and running only the body-validation ones, which work "
              "regardless of the manager's configured auth mode -- as long as this manager "
              "doesn't itself require a credential.\n")
    print(f"Running {len(scenarios)} scenario(s) against {base_url}/enroll\n")
    results = [run_scenario(base_url, key, name, scenario_name, expected, build)
               for scenario_name, expected, build in scenarios]
    passed, total = sum(results), len(results)
    print(f"\n{passed}/{total} scenarios passed.")
    return passed == total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:1517", help="Base URL of the HTTPS server.")
    parser.add_argument("--name", default="test-agent", help="Agent name to enroll.")
    parser.add_argument("--version", default="5.0.0", help="Agent version to report.")
    parser.add_argument("--groups", help="Comma-separated centralized group(s).")
    parser.add_argument("--ip", help="Agent IP override (or 'any').")
    parser.add_argument("--key-hash", help="Hash of the agent's current key, if re-enrolling.")
    parser.add_argument("--password", help="Enrollment password -- signs the request (Password mode). "
                                            "Omit entirely for Open mode.")
    parser.add_argument("--password-file", help=f"Read the password from this file instead of "
                                                 f"--password (default {DEFAULT_PASSWORD_FILE}).")
    parser.add_argument("--client-cert", help="Client certificate PEM (mTLS mode).")
    parser.add_argument("--client-key", help="Client private key PEM (mTLS mode).")
    parser.add_argument("--tamper", action="store_true",
                        help="Sign the body, then send a different one -> 401 InvalidMac "
                             "(Password mode only).")
    parser.add_argument("--all", action="store_true",
                        help="Run every scenario instead of sending one request. Uses --password "
                             "if given (adds signature/timing scenarios on top of the body-"
                             "validation ones); otherwise runs only the auth-agnostic ones.")
    args = parser.parse_args()

    if args.password_file and args.password is not None:
        parser.error("--password and --password-file are mutually exclusive")

    key = None
    if args.password is not None or args.password_file:
        key = derive_key(read_password(args))

    if args.all:
        return 0 if run_all(args.url, key, args.name) else 1

    cert = (args.client_cert, args.client_key) if args.client_cert or args.client_key else None
    if cert and (not args.client_cert or not args.client_key):
        parser.error("--client-cert and --client-key must be given together")

    timestamp = int(time.time())
    signed_body = build_body(args.name, args.version, args.groups, args.ip, args.key_hash)

    headers = {}
    if key:
        headers = _auth_header(key, "POST", "/enroll", timestamp, signed_body)

    sent_body = signed_body
    if args.tamper:
        if not key:
            parser.error("--tamper only makes sense with --password (nothing to tamper against otherwise)")
        sent_body = build_body(args.name + "-tampered", args.version, args.groups, args.ip, args.key_hash)

    print(f"--> POST {args.url.rstrip('/')}/enroll")
    if headers:
        print(f"    Authorization: {headers['Authorization']}")
    elif cert:
        print(f"    (mTLS: presenting {args.client_cert})")
    else:
        print("    (Open mode: no credential)")
    print(f"    body sent ({len(sent_body)} bytes): {sent_body.decode()}")

    response = send(args.url, sent_body, headers, cert=cert)

    print(f"<-- {response.status_code} {response.reason}")
    print(f"    {response.text}")
    return 0 if response.ok else 1


if __name__ == "__main__":
    sys.exit(main())
