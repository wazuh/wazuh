#!/usr/bin/env python3
"""
The `wazuh-agent+jwt` bearer token every remoted HTTPS request carries, in pure stdlib -- the shared
signer behind send_stateless.py, send_control.py, send_agent_json.py, send_scan_vd.py,
send_download.py and load_balancer/send_signed_request.py (send_enroll.py keeps the WazuhEnroll
scheme until /enroll moves to its own JWT profile).

  protocol-version: 1
  Authorization: Bearer <compact JWS>

  header  {"alg":"HS256","kid":"<agent-id>","typ":"wazuh-agent+jwt"}           exactly these three
  claims  {"exp":<iat+60>,"iat":<now>,"iss":"wazuh-agent/<agent-id>","jti":"<22 base64url chars>",
           "nbf":<iat>,"sub":"<agent-id>"}                                       exactly these six
  key     the 32 bytes obtained by hex-decoding the 64-char client.keys secret -- never the ASCII

The manager (src/shared_modules/utils/jwt/jwtRequestTokenVerifier.hpp) rejects any deviation with
a uniform 401 + WWW-Authenticate: Bearer. It accepts a token while now - iat <= jwt_max_age +
jwt_clock_skew (60 + 30 s by default) and iat <= now + jwt_clock_skew. The token binds the agent's
identity only: method, target, query string, body and compression are NOT part of authentication.

Self-test (interoperability with the manager's C++ library and the Go simulator, no manager
needed -- reproduces the frozen vector byte for byte):

  python3 wire_jwt.py --self-test

The frozen vectors live in tools/manager_benchmark/tool_simulator/internal/wire/testdata/
jwt_vectors.json (mirror of src/shared_modules/utils/jwt/testVectors.hpp).
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

PROTOCOL_VERSION = "1"
TOKEN_TYPE = "wazuh-agent+jwt"
ALGORITHM = "HS256"
ISSUER_PREFIX = "wazuh-agent/"
TOKEN_LIFETIME_SECONDS = 60      # exp - iat: a profile constant, not a choice
AGENT_KEY_BYTES = 32
JTI_BYTES = 16

# The manager's defaults (remoted.jwt_max_age / remoted.jwt_clock_skew, profile maxima). Only used
# to pick timestamps that land reliably on the wrong side of each window in the negative scenarios.
MAX_AGE_SECONDS = 60
CLOCK_SKEW_SECONDS = 30
EXPIRED_IAT_OFFSET = -(MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS + 5)   # older than max_age + skew
FUTURE_IAT_OFFSET = CLOCK_SKEW_SECONDS + 5                          # issued further ahead than skew

DEFAULT_CLIENT_KEYS = "/var/wazuh-manager/etc/client.keys"


def b64url(raw: bytes) -> str:
    """base64url without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_agent_key(key_hex: str) -> bytes:
    """The client.keys secret (exactly 64 lowercase hex chars) -> the 32-byte HS256 key."""
    if len(key_hex) != 2 * AGENT_KEY_BYTES or any(c not in "0123456789abcdef" for c in key_hex):
        raise ValueError(f"agent key must be {2 * AGENT_KEY_BYTES} lowercase hex chars, got {key_hex!r}")
    return bytes.fromhex(key_hex)


def canonical_agent_id(agent_id: str) -> str:
    """The id as client.keys spells it: decimal, zero-padded to at least three digits ("1" -> "001").
    The manager accepts no other spelling in kid/sub/iss."""
    if not agent_id.isdigit():
        raise ValueError(f"agent id must be decimal digits, got {agent_id!r}")
    return f"{int(agent_id):03d}"


def read_agent_key(agent_id: str, client_keys_path: str = DEFAULT_CLIENT_KEYS) -> str:
    """Parses client.keys the same way the manager's Keystore does ('id name ip key' lines,
    '#'/' '-prefixed lines are comments, a name starting with '#'/'!' means removed) and returns
    the agent's 64-hex secret. A key of any other shape is refused here, as the manager refuses it
    (the agent must re-enroll to get a 32-byte key)."""
    with open(client_keys_path, "r", encoding="utf-8") as f:
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
                try:
                    decode_agent_key(key_hex)
                except ValueError as e:
                    raise SystemExit(f"agent {agent_id} in {client_keys_path}: {e}. The manager rejects such "
                                     "a key too (MissingKey -> 401): re-enroll the agent.") from e
                return key_hex
    raise SystemExit(f"agent id {agent_id!r} not found (or removed) in {client_keys_path}")


def new_jti() -> str:
    return b64url(secrets.token_bytes(JTI_BYTES))


def make_jwt(agent_id: str, key, now: int = None, jti: str = None, *,
             alg: str = ALGORITHM, typ: str = TOKEN_TYPE, lifetime: int = TOKEN_LIFETIME_SECONDS,
             kid: str = None, sub: str = None, iss: str = None, nbf: int = None,
             extra_header: dict = None, extra_claims: dict = None, drop_claims=(),
             sign_with: bytes = None) -> str:
    """Mints one wazuh-agent+jwt token. Defaults produce exactly the profile; every keyword beyond
    `now`/`jti` exists ONLY to build the negative scenarios (a token the manager must reject).

    key: the 64-hex client.keys secret (str) or the 32 raw bytes. sign_with overrides the HMAC key
    bytes (e.g. the ASCII text of the secret, the classic interoperability mistake)."""
    key_bytes = decode_agent_key(key) if isinstance(key, str) else bytes(key)
    agent = canonical_agent_id(agent_id)
    iat = int(time.time()) if now is None else int(now)
    header = {"alg": alg, "kid": agent if kid is None else kid, "typ": typ}
    header.update(extra_header or {})
    claims = {
        "exp": iat + lifetime,
        "iat": iat,
        "iss": ISSUER_PREFIX + agent if iss is None else iss,
        "jti": jti or new_jti(),
        "nbf": iat if nbf is None else nbf,
        "sub": agent if sub is None else sub,
    }
    claims.update(extra_claims or {})
    for name in drop_claims:
        claims.pop(name, None)
    # Compact, keys sorted: byte-identical to the manager's own signer and to the frozen vectors.
    signing_input = (b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()) + "."
                     + b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()))
    if alg == "none":
        return signing_input + "."
    mac = hmac.new(sign_with if sign_with is not None else key_bytes, signing_input.encode(),
                   hashlib.sha256).digest()
    return signing_input + "." + b64url(mac)


def auth_headers(agent_id: str, key, now: int = None, protocol_version: str = PROTOCOL_VERSION,
                 **jwt_kwargs) -> dict:
    """The two headers every authenticated request carries. Call it once per request: every attempt
    gets a fresh token (new jti, new iat)."""
    return {"protocol-version": protocol_version,
            "Authorization": "Bearer " + make_jwt(agent_id, key, now, **jwt_kwargs)}


def tamper_token(token: str) -> str:
    """Corrupts the signature (one char in the middle of the third segment) while keeping the token
    well-formed: the manager answers 401 (invalid_signature), never 400."""
    head, _, sig = token.rpartition(".")
    i = len(sig) // 2
    return head + "." + sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i + 1:]


# --- self-test against the frozen vectors -------------------------------------------------------

def _default_vectors_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "..", "..", "tools", "manager_benchmark",
                                         "tool_simulator", "internal", "wire", "testdata", "jwt_vectors.json"))


def self_test(vectors_path: str) -> int:
    with open(vectors_path, "r", encoding="utf-8") as f:
        v = json.load(f)
    failures = []

    def check(name, cond):
        print(f"[{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    key = decode_agent_key(v["key"]["hex"])
    check("key decodes to 32 bytes, 0x00 first, 0xff last", len(key) == 32 and key[0] == 0 and key[-1] == 0xFF)
    token = make_jwt(v["agent_id"], v["key"]["hex"], now=v["iat"], jti=v["jti"])
    check("token reproduces the frozen vector byte for byte", token == v["token"])
    h64, p64, s64 = token.split(".")
    check("header text is the vector's", base64.urlsafe_b64decode(h64 + "==").decode() == v["header_json"])
    check("claims text is the vector's", base64.urlsafe_b64decode(p64 + "==").decode() == v["payload_json"])
    check("signature is the vector's", s64 == v["signature_b64url"] and h64 + "." + p64 == v["signing_input"])
    check("exp - iat is the profile lifetime", v["exp"] - v["iat"] == TOKEN_LIFETIME_SECONDS)
    ascii_token = make_jwt(v["agent_id"], v["key"]["hex"], now=v["iat"], jti=v["jti"],
                           sign_with=v["key"]["hex"].encode())
    check("signing with the ASCII key gives the frozen NEGATIVE vector",
          ascii_token == v["negative"]["ascii_key_token"]["token"] and ascii_token != v["token"])
    aud_token = make_jwt(v["agent_id"], v["key"]["hex"], now=v["iat"], jti=v["jti"],
                         extra_claims={"aud": "wazuh-manager"})
    check("adding aud gives the frozen aud-present vector", aud_token == v["negative"]["aud_present_token"]["token"])
    a, b = make_jwt("1", v["key"]["hex"]), make_jwt("001", v["key"]["hex"])
    check("two tokens in the same second differ (fresh jti) and '1' canonicalises to '001'",
          a != b and a.split(".")[0] == b.split(".")[0])
    check("jti is 22 canonical chars", len(new_jti()) == 22)
    check("tamper_token keeps the shape and changes the signature",
          tamper_token(token).rpartition(".")[0] == token.rpartition(".")[0] and tamper_token(token) != token)
    for bad in ("", "2b7e151628aed2a6abf7158809cf4f3c", v["key"]["hex"].upper(), v["key"]["hex"][:63]):
        try:
            decode_agent_key(bad)
            check(f"decode_agent_key rejects {bad[:16]!r}...", False)
        except ValueError:
            check(f"decode_agent_key rejects {bad[:16]!r}...", True)
    print(f"\n{len(failures)} failure(s).")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="Reproduce the frozen vectors and exit.")
    parser.add_argument("--vectors", default=_default_vectors_path(), help="Path to jwt_vectors.json.")
    parser.add_argument("--agent-id", default="1001", help="With --client-keys: print a fresh Bearer for this agent.")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS)
    args = parser.parse_args()
    if args.self_test:
        return self_test(args.vectors)
    print(auth_headers(args.agent_id, read_agent_key(args.agent_id, args.client_keys))["Authorization"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
