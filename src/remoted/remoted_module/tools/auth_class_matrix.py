#!/usr/bin/env python3
"""#39064 DoD: all eight 401 authentication classes exercised against a REAL manager.

Extended for #39315 with a POST /enroll/secret section: the route an agent that already holds a
client.keys key uses to obtain its re-enrollment secret. It is an ordinary authenticated route, so
it takes the `wazuh-agent+jwt` REQUEST profile (sign_agent()) and not the `wazuh-enroll+jwt` of
/enroll -- a distinction the section asserts in both directions.

Runs on the manager itself (the listener certificate's SAN is 127.0.0.1, and minting requires
an address in that SAN). Asserts, for every case, the three things the agent actually reads:

  - the HTTP status,
  - `error.code` inside /enroll's NESTED envelope, and
  - the RFC 6750 s3 WWW-Authenticate challenge.

Self-contained on purpose: stdlib + requests, no wazuh_testing import, so a framework bug cannot
make the manager look correct. The profile it implements is pinned by jwt_enroll.py's frozen
vectors on the framework side.

Two cases mutate manager state and put it back:

  - token_expired / token_revoked mint real tokens through authd's local socket. They stay in the
    store, revoked or expired; `token_purge` clears them when you are done.
  - enrollment_key_unavailable moves the password file aside for one request, then restores it
    from a mode-preserving copy and deletes the copy. It prints whether the restored bytes are
    identical, and re-runs a password enrollment to prove the manager recovered.

Run it ON the manager, as root: it reads the password file and authd's socket, and `token_create`
refuses any address outside the listener certificate's SAN.

  sudo python3 auth_class_matrix.py
  sudo python3 auth_class_matrix.py --url https://127.0.0.1:1517 --global-prefix /wazuh-manager
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import socket
import subprocess
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_URL = "https://127.0.0.1:1517"
DEFAULT_GLOBAL_PREFIX = "/wazuh-manager"
DEFAULT_AUTH_SOCK = "/var/wazuh-manager/queue/sockets/auth.sock"
DEFAULT_PASSWORD_FILE = "/var/wazuh-manager/etc/authd.pass"
DEFAULT_ADDRESS = "127.0.0.1"

# Filled in by main() from the command line.
BASE = ""
AUTH_SOCK = DEFAULT_AUTH_SOCK
PASSWORD_FILE = DEFAULT_PASSWORD_FILE
MINT_ADDRESS = DEFAULT_ADDRESS
LISTENER_PORT = 1517
GLOBAL_PREFIX = DEFAULT_GLOBAL_PREFIX

ALG, TYP = "HS256", "wazuh-enroll+jwt"
LIFETIME = 60
SALT = bytes(32)
PASSWORD_INFO = b"WAZUH-ENROLL-JWT-KEY" + b"\x01"
TOKEN_INFO = b"WAZUH-ENROLL-TOKEN-KEY" + b"\x01"
REENROLL_INFO = b"WAZUH-REENROLL-KEY" + b"\x01"

# Offsets that land outside remoted.jwt_max_age (60) +/- remoted.jwt_clock_skew (30).
EXPIRED_OFFSET = -(60 + 30 + 5)
FUTURE_OFFSET = 30 + 5


def b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hkdf(ikm, info, length=32):
    prk = hmac.new(SALT, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def sign(key, kid=None, now=None, jti=None):
    iat = int(time.time()) if now is None else int(now)
    jti = jti or b64e(os.urandom(16))
    header = f'{{"alg":"{ALG}","typ":"{TYP}"}}' if kid is None \
        else f'{{"alg":"{ALG}","kid":"{kid}","typ":"{TYP}"}}'
    payload = f'{{"exp":{iat + LIFETIME},"iat":{iat},"jti":"{jti}","nbf":{iat}}}'
    si = f"{b64e(header.encode())}.{b64e(payload.encode())}"
    return f"{si}.{b64e(hmac.new(key, si.encode(), hashlib.sha256).digest())}"


AGENT_TYP = "wazuh-agent+jwt"


def sign_agent(key_hex, agent_id, now=None, jti=None):
    """The REQUEST profile (`wazuh-agent+jwt`), for POST /enroll/secret (#39315).

    A different credential from sign()'s above, and the distinction matters: a `wazuh-enroll+jwt`
    whose kid is an agent id already means "re-enrollment bearer", so /enroll/secret -- an ordinary
    authenticated route behind AuthMiddleware -- would reject it. This one is the same bearer the
    control stream presents: the 64-hex client.keys secret decoded verbatim into the 32-byte HS256
    key, six claims including `iss` and `sub`.
    """
    key = bytes.fromhex(key_hex)
    iat = int(time.time()) if now is None else int(now)
    jti = jti or b64e(os.urandom(16))
    header = f'{{"alg":"{ALG}","kid":"{agent_id}","typ":"{AGENT_TYP}"}}'
    payload = (f'{{"exp":{iat + LIFETIME},"iat":{iat},"iss":"wazuh-agent/{agent_id}",'
               f'"jti":"{jti}","nbf":{iat},"sub":"{agent_id}"}}')
    si = f"{b64e(header.encode())}.{b64e(payload.encode())}"
    return f"{si}.{b64e(hmac.new(key, si.encode(), hashlib.sha256).digest())}"


def authd(payload):
    raw = json.dumps(payload).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(AUTH_SOCK)
    s.sendall(struct.pack("<I", len(raw)) + raw)
    (length,) = struct.unpack("<I", s.recv(4))
    body = b""
    while len(body) < length:
        body += s.recv(length - len(body))
    s.close()
    return json.loads(body.decode())


def mint(ttl, uses=10, description="39064 matrix"):
    reply = authd({"function": "token_create",
                   "arguments": {"address": MINT_ADDRESS, "port": LISTENER_PORT,
                                 "prefix": GLOBAL_PREFIX, "ttl": ttl, "max_uses": uses,
                                 "description": description}})
    if reply.get("error"):
        raise RuntimeError(f"mint failed: {reply}")
    blob = json.loads(b64d(reply["data"]["token"]))
    raw = b64d(blob["key"])
    return reply["data"]["id"], raw[16:]          # id, 16-byte credential secret


def post(body, headers, name="matrix-agent"):
    hdrs = {"Content-Type": "application/json", "protocol-version": "1"}
    hdrs.update({k: v for k, v in headers.items() if v is not None})
    for key, value in headers.items():
        if value is None:
            hdrs.pop(key, None)
    return requests.post(f"{BASE}/enroll", data=body, headers=hdrs, verify=False, timeout=15)


def post_secret(headers):
    """POST /enroll/secret: no arguments at all -- the id comes from the verified bearer."""
    hdrs = {"Content-Type": "application/json", "protocol-version": "1"}
    hdrs.update({k: v for k, v in headers.items() if v is not None})
    return requests.post(f"{BASE}/enroll/secret", data=b"{}", headers=hdrs, verify=False, timeout=15)


def enroll_body(name):
    return json.dumps({"name": name, "version": "5.0.0"}).encode()


RESULTS = []


def check(label, response, expect_status, expect_code, expect_challenge):
    try:
        parsed = response.json()
    except Exception:
        parsed = {}
    error = parsed.get("error")
    code = error.get("code") if isinstance(error, dict) else error
    challenge = response.headers.get("WWW-Authenticate")
    ok = (response.status_code == expect_status and code == expect_code
          and (expect_challenge is None or challenge == expect_challenge))
    RESULTS.append((ok, label))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")
    print(f"         status {response.status_code} (want {expect_status}) | "
          f"code {code!r} (want {expect_code!r})")
    if expect_challenge is not None:
        print(f"         challenge {challenge!r}")
        if challenge != expect_challenge:
            print(f"         WANTED    {expect_challenge!r}")
    return ok


CH_INVALID_REQUEST = 'Bearer error="invalid_request"'
CH_BARE = "Bearer"


def ch(cls):
    return f'Bearer error="invalid_token", error_description="{cls}"'


def main():
    global BASE, AUTH_SOCK, PASSWORD_FILE, MINT_ADDRESS, LISTENER_PORT, GLOBAL_PREFIX

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=DEFAULT_URL, help="Base URL of the HTTPS listener.")
    parser.add_argument("--global-prefix", default=DEFAULT_GLOBAL_PREFIX,
                        help="<remote><https><global_prefix> of the manager under test.")
    parser.add_argument("--auth-sock", default=DEFAULT_AUTH_SOCK, help="authd's local socket.")
    parser.add_argument("--password-file", default=DEFAULT_PASSWORD_FILE,
                        help="File holding the shared enrollment password.")
    parser.add_argument("--mint-address", default=DEFAULT_ADDRESS,
                        help="Address recorded in minted tokens. MUST be in the listener "
                             "certificate's SAN or authd refuses to mint (9025).")
    args = parser.parse_args()

    GLOBAL_PREFIX = "/" + args.global_prefix.strip("/") if args.global_prefix.strip("/") else ""
    BASE = args.url.rstrip("/") + GLOBAL_PREFIX
    AUTH_SOCK = args.auth_sock
    PASSWORD_FILE = args.password_file
    MINT_ADDRESS = args.mint_address
    LISTENER_PORT = int(args.url.rsplit(":", 1)[-1]) if ":" in args.url.rsplit("/", 1)[-1] else 1517

    print(f"Manager under test: {BASE}/enroll\n")
    password = open(PASSWORD_FILE).read().strip()
    pkey = hkdf(password.encode(), PASSWORD_INFO)
    stamp = int(time.time())

    print("=" * 78)
    print("Sanity: the happy paths")
    print("=" * 78)

    r = post(enroll_body(f"matrix-pw-{stamp}"), {"Authorization": f"Bearer {sign(pkey)}"})
    body = r.json()
    ok = r.status_code == 200 and "reenroll_secret" in body
    RESULTS.append((ok, "200 shared-password enrollment issues a reenroll_secret"))
    print(f"[{'PASS' if ok else 'FAIL'}] 200 shared-password enrollment issues a reenroll_secret")
    print(f"         status {r.status_code} | keys {sorted(body)}")
    agent_id = body.get("id")
    agent_key = body.get("key")
    agent_secret = body.get("reenroll_secret")

    token_id, token_secret = mint(ttl=3600, uses=10, description="matrix valid")
    tkey = hkdf(token_secret, TOKEN_INFO)
    r = post(enroll_body(f"matrix-tok-{stamp}"), {"Authorization": f"Bearer {sign(tkey, kid=token_id)}"})
    ok = r.status_code == 200
    RESULTS.append((ok, "200 enrollment-token enrollment"))
    print(f"[{'PASS' if ok else 'FAIL'}] 200 enrollment-token enrollment")
    print(f"         status {r.status_code} | kid {token_id}")

    print()
    print("=" * 78)
    print("The eight 401 classes")
    print("=" * 78)

    # 1. invalid_request -- nothing to judge.
    check("invalid_request: no Authorization header",
          post(enroll_body("matrix-x"), {"Authorization": None}),
          401, "invalid_request", CH_INVALID_REQUEST)

    check("invalid_request: malformed Authorization",
          post(enroll_body("matrix-x"), {"Authorization": "Basic bm90LWEtYmVhcmVy"}),
          401, "invalid_request", CH_INVALID_REQUEST)

    # 2. invalid_signature -- a credential that does not verify.
    bad = sign(hkdf(b"not-the-password", PASSWORD_INFO))
    check("invalid_signature: password bearer signed with the wrong key",
          post(enroll_body("matrix-x"), {"Authorization": f"Bearer {bad}"}),
          401, "invalid_signature", ch("invalid_signature"))

    good = sign(pkey)
    tampered = good[:-1] + ("A" if good[-1] != "A" else "B")
    check("invalid_signature: tampered signature",
          post(enroll_body("matrix-x"), {"Authorization": f"Bearer {tampered}"}),
          401, "invalid_signature", ch("invalid_signature"))

    # 3. stale_token -- outside max_age +/- skew, both directions.
    check("stale_token: bearer issued too long ago",
          post(enroll_body("matrix-x"),
               {"Authorization": f"Bearer {sign(pkey, now=time.time() + EXPIRED_OFFSET)}"}),
          401, "stale_token", ch("stale_token"))

    check("stale_token: bearer issued in the future",
          post(enroll_body("matrix-x"),
               {"Authorization": f"Bearer {sign(pkey, now=time.time() + FUTURE_OFFSET)}"}),
          401, "stale_token", ch("stale_token"))

    # 4. token_unknown -- a well-formed token kid the store has never held.
    unknown_kid = b64e(os.urandom(16))
    check("token_unknown: a kid the store has never held",
          post(enroll_body("matrix-x"),
               {"Authorization": f"Bearer {sign(hkdf(os.urandom(16), TOKEN_INFO), kid=unknown_kid)}"}),
          401, "token_unknown", ch("token_unknown"))

    # 5. token_expired -- a real token, correctly signed, past its expiry.
    short_id, short_secret = mint(ttl=5, uses=10, description="matrix expiring")
    short_key = hkdf(short_secret, TOKEN_INFO)
    print("         (waiting 8s for the minted token to pass its 5s expiry)")
    time.sleep(8)
    check("token_expired: a correctly signed bearer for an expired token",
          post(enroll_body("matrix-x"), {"Authorization": f"Bearer {sign(short_key, kid=short_id)}"}),
          401, "token_expired", ch("token_expired"))

    # 6. token_revoked -- a real token the operator revoked.
    rev_id, rev_secret = mint(ttl=3600, uses=10, description="matrix revoked")
    rev_key = hkdf(rev_secret, TOKEN_INFO)
    reply = authd({"function": "token_revoke", "arguments": {"id": rev_id}})
    print(f"         (revoked {rev_id}: {reply.get('error')}; waiting 13s for the replica re-read)")
    time.sleep(13)
    check("token_revoked: a correctly signed bearer for a revoked token",
          post(enroll_body("matrix-x"), {"Authorization": f"Bearer {sign(rev_key, kid=rev_id)}"}),
          401, "token_revoked", ch("token_revoked"))

    # 7. unknown_agent -- a re-enrollment bearer whose agent the manager does not know.
    ghost_key = hkdf(bytes.fromhex("ab" * 32), REENROLL_INFO)
    check("unknown_agent: re-enrollment bearer for an agent id the manager never issued",
          post(enroll_body("matrix-x"), {"Authorization": f"Bearer {sign(ghost_key, kid='999')}"}),
          401, "unknown_agent", ch("unknown_agent"))

    # 8. enrollment_key_unavailable -- password mode active, key not loadable. Fail closed:
    #    the manager must NOT silently fall back to open enrollment.
    backup = PASSWORD_FILE + ".matrixbak"
    print("         (moving the password file aside to force the key-unavailable path)")
    subprocess.run(["cp", "-p", PASSWORD_FILE, backup], check=True)
    try:
        os.remove(PASSWORD_FILE)
        time.sleep(13)  # PasswordKeySource refresh interval
        check("enrollment_key_unavailable: password mode with no loadable key (fails closed)",
              post(enroll_body("matrix-x"), {"Authorization": f"Bearer {sign(pkey)}"}),
              401, "enrollment_key_unavailable", CH_BARE)
    finally:
        subprocess.run(["cp", "-p", backup, PASSWORD_FILE], check=True)
        os.remove(backup)  # never leave a second copy of the password in etc/
        restored = open(PASSWORD_FILE).read().strip()
        print(f"         (restored authd.pass: identical={restored == password})")
        time.sleep(13)
        r = post(enroll_body(f"matrix-restored-{stamp}"), {"Authorization": f"Bearer {sign(pkey)}"})
        ok = r.status_code == 200
        RESULTS.append((ok, "password enrollment works again after restoring the key"))
        print(f"[{'PASS' if ok else 'FAIL'}] password enrollment works again after restoring the key"
              f" (status {r.status_code})")

    # Re-enrollment with the secret the manager actually issued, to prove the loop closes.
    if agent_id and agent_secret:
        rkey = hkdf(bytes.fromhex(agent_secret), REENROLL_INFO)
        r = post(enroll_body(f"matrix-pw-{stamp}"), {"Authorization": f"Bearer {sign(rkey, kid=agent_id)}"})
        ok = r.status_code == 200
        RESULTS.append((ok, f"re-enrollment with the issued secret for agent {agent_id}"))
        print()
        print(f"[{'PASS' if ok else 'FAIL'}] re-enrollment with the issued secret for agent {agent_id}"
              f" (status {r.status_code})")
        if ok:
            print(f"         rotated secret: {'reenroll_secret' in r.json()}")

    # POST /enroll/secret (#39315): the route an agent that ALREADY holds a key uses to obtain the
    # re-enrollment secret its enrollment never gave it. Exercised with the agent enrolled at the
    # top of this run -- it does have a secret, which is fine and is the point of the reissue case:
    # the operation is idempotent, because a one-shot gate would strand any agent whose answer was
    # lost in flight.
    print()
    print("=" * 78)
    print("POST /enroll/secret")
    print("=" * 78)

    if agent_id and agent_key:
        r = post_secret({"Authorization": f"Bearer {sign_agent(agent_key, agent_id)}"})
        issued = r.json() if r.status_code == 200 else {}
        ok = (r.status_code == 200 and issued.get("id") == agent_id
              and len(issued.get("reenroll_secret", "")) == 64)
        RESULTS.append((ok, "200 /enroll/secret issues a secret for the verified identity"))
        print(f"[{'PASS' if ok else 'FAIL'}] 200 /enroll/secret issues a secret for the verified identity")
        print(f"         status {r.status_code} | keys {sorted(issued)}")

        # Reissue: accepted, and a DIFFERENT secret. The key is untouched either way -- the answer
        # carries none, and the agent goes on signing with the one it already has, which is exactly
        # why a lost answer here is harmless.
        second = post_secret({"Authorization": f"Bearer {sign_agent(agent_key, agent_id)}"})
        reissued = second.json() if second.status_code == 200 else {}
        ok = (second.status_code == 200
              and reissued.get("reenroll_secret") not in (None, issued.get("reenroll_secret")))
        RESULTS.append((ok, "/enroll/secret reissues on a second call (idempotent, new secret)"))
        print(f"[{'PASS' if ok else 'FAIL'}] /enroll/secret reissues on a second call"
              f" (status {second.status_code})")

        # The key still signs: proof that nothing was rotated under the agent.
        third = post_secret({"Authorization": f"Bearer {sign_agent(agent_key, agent_id)}"})
        ok = third.status_code == 200
        RESULTS.append((ok, "the agent's key still authenticates after two issuances"))
        print(f"[{'PASS' if ok else 'FAIL'}] the agent's key still authenticates after two issuances"
              f" (status {third.status_code})")

        # And the newest secret is the one that re-enrolls, on /enroll, with the enroll profile.
        newest = third.json().get("reenroll_secret") if third.status_code == 200 else None
        if newest:
            rkey = hkdf(bytes.fromhex(newest), REENROLL_INFO)
            r = post(enroll_body(f"matrix-pw-{stamp}"), {"Authorization": f"Bearer {sign(rkey, kid=agent_id)}"})
            ok = r.status_code == 200
            RESULTS.append((ok, "the newest issued secret re-enrolls the agent on /enroll"))
            print(f"[{'PASS' if ok else 'FAIL'}] the newest issued secret re-enrolls the agent"
                  f" (status {r.status_code})")
            # The re-enrollment rotated the key, so keep the fresh pair for anything after this.
            if ok:
                agent_key = r.json().get("key", agent_key)

    # No credential at all: the SAME 401 class every other authenticated route answers. (Under a
    # drained bucket this route answers 429 instead -- the limit is charged before authentication --
    # which is why this case is run against an otherwise idle manager.)
    check("invalid_request: /enroll/secret with no Authorization",
          post_secret({}), 401, "invalid_request", CH_INVALID_REQUEST)

    # The enroll profile on this route: right key, wrong credential type. `kid` = an agent id means
    # "re-enrollment bearer" there, which AuthMiddleware does not accept here.
    if agent_id and agent_secret:
        wrong_profile = sign(hkdf(bytes.fromhex(agent_secret), REENROLL_INFO), kid=agent_id)
        r = post_secret({"Authorization": f"Bearer {wrong_profile}"})
        ok = r.status_code == 401
        RESULTS.append((ok, "/enroll/secret refuses a wazuh-enroll+jwt bearer"))
        print(f"[{'PASS' if ok else 'FAIL'}] /enroll/secret refuses a wazuh-enroll+jwt bearer"
              f" (status {r.status_code})")

    # An id the manager never issued, signed with a key it never held: unknown_agent, decided by the
    # middleware before authd is ever asked.
    check("unknown_agent: /enroll/secret for an agent id the manager never issued",
          post_secret({"Authorization": f"Bearer {sign_agent('ab' * 32, '999')}"}),
          401, "unknown_agent", ch("unknown_agent"))

    print()
    print("=" * 78)
    passed = sum(1 for ok, _ in RESULTS if ok)
    print(f"{passed}/{len(RESULTS)} passed")
    for ok, label in RESULTS:
        if not ok:
            print(f"  FAILED: {label}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
