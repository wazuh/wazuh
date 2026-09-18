#!/usr/bin/env python3
"""
The enrollment credential modes the issue lists, through the balancer.

Derivations taken from src/shared_modules/utils/jwt/jwtEnrollProfileV1.hpp:

  shared password   no `kid`; key = HKDF(password,        info "WAZUH-ENROLL-JWT-KEY"  || 0x01)
  enrollment token  `kid` = token id (22 b64url chars)
                    key = HKDF(16-byte token secret,      info "WAZUH-ENROLL-TOKEN-KEY" || 0x01)
  re-enrollment     `kid` = canonical agent id ("001")
                    key = HKDF(32-byte reenroll_secret,   info "WAZUH-REENROLL-KEY"     || 0x01)

salt is 32 zero bytes in all three, L = 32.

The point of running these through the balancer is that only ONE of them is master-owned in a
way the agent can feel: the re-enrollment secret exists on the master alone, so remoted forwards
that bearer verbatim and unverified (agent-api.yaml:1100). The token store and authd.pass are
cluster-replicated instead, so they have a propagation window rather than a hard dependency.
"""
import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SALT = bytes(32)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def ub64(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(SALT, ikm, hashlib.sha256).digest()
    out, prev, counter = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]


def bearer(key: bytes, kid: str | None) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "wazuh-enroll+jwt"}
    if kid:
        header = {"alg": "HS256", "kid": kid, "typ": "wazuh-enroll+jwt"}
    claims = {"exp": now + 60, "iat": now, "jti": b64(secrets.token_bytes(16)), "nbf": now}
    signing_input = (b64(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + b64(json.dumps(claims, separators=(",", ":")).encode()))
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64(sig)


def enroll(url, prefix, token, name, ca, timeout=25, agent_id=None):
    body = {"name": name, "version": "5.0.0"}
    if agent_id:
        body["id"] = agent_id
    headers = {"protocol-version": "1", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = requests.post(url.rstrip("/") + prefix + "enroll", headers=headers,
                      data=json.dumps(body).encode(), verify=ca, timeout=timeout)
    return r


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="https://wazuh-lb-haproxy:1518")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--password", required=True)
    p.add_argument("--store", default="/probe/store.json",
                   help="copy of etc/enrollment_tokens.json, to read a token's secret")
    p.add_argument("--token-address", default="wazuh-lb-haproxy")
    args = p.parse_args()

    stamp = int(time.time()) % 100000

    # 1. No credential at all. use_password is on, so this must fail closed.
    r = enroll(args.url, args.prefix, None, f"nocred-{stamp}", args.ca)
    print(f"  no credential        -> {r.status_code} {r.text[:90]}")

    # 2. Shared password.
    key = hkdf(args.password.encode(), b"WAZUH-ENROLL-JWT-KEY" + bytes([1]))
    r = enroll(args.url, args.prefix, bearer(key, None), f"pass-{stamp}", args.ca)
    print(f"  shared password      -> {r.status_code} {r.text[:90]}")
    reenroll = None
    if r.status_code == 200:
        body = r.json()
        reenroll = (body.get("id"), body.get("reenroll_secret"))
        # The key is shown once and nowhere else. Emit it on its own line so a caller can reuse
        # this agent instead of enrolling another one, without parsing the truncated preview.
        print(f"  CREDENTIALS id={body.get('id')} key={body.get('key')}")

    # 3. Enrollment token.
    try:
        tokens = json.load(open(args.store))["tokens"]
        tok = next(t for t in tokens
                   if t["adr"] == args.token_address and not t["revoked"] and t["uses"] < t["max_uses"])
        tkey = hkdf(ub64(tok["secret"]), b"WAZUH-ENROLL-TOKEN-KEY" + bytes([1]))
        r = enroll(args.url, args.prefix, bearer(tkey, tok["id"]), f"token-{stamp}", args.ca)
        print(f"  enrollment token     -> {r.status_code} {r.text[:90]}")
    except StopIteration:
        print("  enrollment token     -> (no usable token in the store)")
    except FileNotFoundError:
        print(f"  enrollment token     -> (store not found at {args.store})")

    # 4. Unknown token id: must fail closed, and is the case that also covers a token
    #    minted on the master but not yet replicated to this node.
    r = enroll(args.url, args.prefix, bearer(secrets.token_bytes(32), b64(secrets.token_bytes(16))),
               f"unknown-{stamp}", args.ca)
    print(f"  unknown token id     -> {r.status_code} {r.text[:90]}")

    # 5. Re-enrollment: the agent keeps its id and rotates its credentials.
    if reenroll and reenroll[1]:
        agent_id, secret_hex = reenroll
        rkey = hkdf(bytes.fromhex(secret_hex), b"WAZUH-REENROLL-KEY" + bytes([1]))
        r = enroll(args.url, args.prefix, bearer(rkey, agent_id), f"pass-{stamp}", args.ca,
                   agent_id=agent_id)
        print(f"  re-enrollment ({agent_id})  -> {r.status_code} {r.text[:90]}")
    else:
        print("  re-enrollment        -> (no reenroll_secret captured)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
