#!/usr/bin/env python3
"""
Drives the #38283 signed-WPK-identifier PoC against a running manager.

The whole point of the shape under test is that it is NOT a new protocol. The manager replaces the
WPK filename in the task payload with `wpk1.<base64url>.wpk`, which is a legal WPK filename by
construction, so:

  * the manager's existing `resource_id` validator accepts it with no change, and
  * a deployed agent treats it as an opaque package name -- it sends it back on `/download` and
    stages the reply under that name, both of which already work.

This script therefore checks two different things. That the mechanism is sound (the identifier
binds an agent and an expiry, and everything else is refused), and that the drop-in property
actually holds (the issued value satisfies the filename grammar, and plain names still work).

The codec is reimplemented here against the cluster key, so a value this script signs and the
manager verifies -- and the reverse -- shows the format is a format, and that any node deriving
from the same cluster key redeems what another issued.

Requires: pip install requests cryptography.  Run as root on the manager.
"""
import argparse
import base64
import json
import os
import re
import struct
import sys
import time

import requests
import urllib3
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import hmac as chmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CONFIG = "/var/wazuh-manager/etc/wazuh-manager.conf"
DEFAULT_CLIENT_KEYS = "/var/wazuh-manager/etc/client.keys"
DEFAULT_WPK_DIR = "/var/wazuh-manager/var/upgrade"
PROTOCOL_VERSION = "1"

ID_PREFIX = "wpk1."
ID_SUFFIX = ".wpk"
MAC_LABEL = b"WAZUH-WPK-ID\n1\n"
HKDF_INFO = b"WAZUH-WPK-ID-v1"
REFUSED_CLUSTER_KEY = "fd3350b86d239654e34866ab3c4988a8"

# The manager's own grammar, from isValidWpkFilename() in downloadEndpoint.cpp.
WPK_NAME = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def passes_manager_filename_grammar(value):
    return bool(WPK_NAME.match(value)) and not value.startswith(".") and value.endswith(".wpk")


# --- Auth (identical to send_control.py / send_stateless.py) ----------------

def read_agent_key(agent_id, path):
    with open(path) as f:
        for line in f:
            if not line or line[0] in ("#", " "):
                continue
            parts = line.split()
            if len(parts) < 4 or parts[1].startswith(("#", "!")):
                continue
            if parts[0] == agent_id:
                return bytes.fromhex(parts[3])
    raise SystemExit(f"agent {agent_id!r} not in {path}")


def auth_headers(agent_id, agent_key, method, target, body):
    ts = int(time.time())
    c = cmac.CMAC(algorithms.AES(agent_key))
    for part in (b"WAZUH-REQUEST\n", PROTOCOL_VERSION.encode() + b"\n", method.upper().encode() + b"\n",
                 target.encode() + b"\n", agent_id.encode() + b"\n", str(ts).encode() + b"\n"):
        c.update(part)
    c.update(body)
    return {"protocol-version": PROTOCOL_VERSION,
            "Authorization": f"Wazuh {agent_id}:{ts}:{c.finalize().hex()}"}


# --- Codec, mirroring src/remoted/remoted_module/src/auth/wpkSeal.cpp -------

def cluster_key(config_path):
    """`<cluster><key>` only. `<https>` has a <key> too, holding the TLS private key path."""
    xml = open(config_path).read()
    start = xml.find("<cluster>")
    if start < 0:
        return None
    end = xml.find("</cluster>", start)
    m = re.search(r"<key>(.*?)</key>", xml[start:end if end > 0 else len(xml)], re.S)
    return m.group(1).strip() if m else None


def derive(secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(secret.encode())


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(key, subject, exp, task_id):
    """subject(4) || exp(4) || task_id(16), then a 16-byte truncated HMAC over the label + those."""
    body = struct.pack("!I", subject) + struct.pack("!I", exp) + task_id
    h = chmac.HMAC(key, hashes.SHA256())
    h.update(MAC_LABEL + body)
    return ID_PREFIX + b64url(body + h.finalize()[:16]) + ID_SUFFIX


def task_id_bytes(task_id_str):
    return bytes.fromhex(task_id_str.replace("-", ""))


def body_of(value):
    return value[len(ID_PREFIX):-len(ID_SUFFIX)]


def tamper(value):
    raw = bytearray(unb64url(body_of(value)))
    raw[-1] ^= 0x01          # last byte of the tag
    return ID_PREFIX + b64url(bytes(raw)) + ID_SUFFIX


# --- Requests ----------------------------------------------------------------

def notify(url, agent_id, agent_key):
    body = json.dumps({"type": "notify", "agent": {"version": "5.0.0"}}).encode()
    h = auth_headers(agent_id, agent_key, "POST", "/control", body)
    h["Content-Type"] = "application/json"
    r = requests.post(f"{url}/control", data=body, headers=h, verify=False, timeout=20)
    r.raise_for_status()
    return r.json()


def download(url, agent_id, agent_key, resource_id, resource_type="wpk"):
    body = json.dumps({"resource_type": resource_type, "resource_id": resource_id},
                      separators=(",", ":")).encode()
    h = auth_headers(agent_id, agent_key, "POST", "/download", body)
    h["Content-Type"] = "application/json"
    return requests.post(f"{url}/download", data=body, headers=h, verify=False, timeout=120, stream=True)


def upgrade_task(url, agent_id, agent_key, attempts=4):
    """The task client marks its connection for reconnect after a failed query, so the first notify
    against a freshly started task manager can legitimately return nothing."""
    for _ in range(attempts):
        for task in notify(url, agent_id, agent_key).get("tasks", []):
            if task.get("task_type") == "remote_upgrade":
                return task
    return None


def upgrade_payload(url, agent_id, agent_key, attempts=4):
    t = upgrade_task(url, agent_id, agent_key, attempts)
    return (t or {}).get("payload")


class Runner:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, name, ok, detail=""):
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""), flush=True)
        setattr(self, "passed" if ok else "failed", getattr(self, "passed" if ok else "failed") + 1)
        return ok

    def status(self, name, resp, expected):
        return self.check(name, resp.status_code == expected, f"got {resp.status_code} {resp.text[:90]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="https://127.0.0.1:1517")
    ap.add_argument("--agent-id", default="001")
    ap.add_argument("--other-agent-id", default="002")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS)
    ap.add_argument("--wpk-dir", default=DEFAULT_WPK_DIR)
    ap.add_argument("--wpk-file", required=True)
    args = ap.parse_args()

    agent_key = read_agent_key(args.agent_id, args.client_keys)
    other_key = read_agent_key(args.other_agent_id, args.client_keys)
    ck = cluster_key(args.config)
    if not ck or ck == REFUSED_CLUSTER_KEY:
        raise SystemExit(f"cluster key missing or still the documented default in {args.config}")
    key = derive(ck)
    expected = open(os.path.join(args.wpk_dir, args.wpk_file), "rb").read()
    subject, now, r = int(args.agent_id), int(time.time()), Runner()

    print("\n== The drop-in property ==", flush=True)
    task = upgrade_task(args.url, args.agent_id, agent_key)
    payload = (task or {}).get("payload", {})
    issued = payload.get("wpk_file")
    task_id = (task or {}).get("task_id", "")
    r.check("a remote_upgrade task is delivered", task is not None)
    r.check("wpk_file now holds a signed identifier, not a name",
            isinstance(issued, str) and issued.startswith(ID_PREFIX) and issued.endswith(ID_SUFFIX),
            f"{str(issued)}")
    if issued:
        r.check("it satisfies the manager's existing filename grammar unchanged",
                passes_manager_filename_grammar(issued), f"{len(issued)} chars, cap is 255")
        r.check("it is short", len(issued) < 80, f"{len(issued)} chars")
        r.check("it carries no filename at all",
                args.wpk_file not in issued and args.wpk_file.encode() not in unb64url(body_of(issued)))
    r.check("the payload gained no new field",
            sorted(payload.keys()) == ["installer", "wpk_file", "wpk_sha1"], f"keys={sorted(payload.keys())}")

    print("\n== Resolution is a hard link, not a lookup ==", flush=True)
    alias = os.path.join(args.wpk_dir, f"{task_id}.wpk")
    r.check("the package is linked under its task id", os.path.exists(alias), alias)
    if os.path.exists(alias):
        st = os.stat(alias)
        r.check("it is a hard link, not a symlink (O_NOFOLLOW would refuse one)",
                not os.path.islink(alias) and st.st_nlink >= 2, f"nlink={st.st_nlink}")
        r.check("it is the same inode as the real package",
                st.st_ino == os.stat(os.path.join(args.wpk_dir, args.wpk_file)).st_ino)

    print("\n== Redemption ==", flush=True)
    if issued:
        resp = download(args.url, args.agent_id, agent_key, issued)
        r.check("the issued identifier serves the file",
                resp.status_code == 200 and resp.content == expected,
                f"{resp.status_code}, {len(resp.content)} of {len(expected)} bytes")
        r.check("the transfer is chunked, not buffered",
                resp.headers.get("Transfer-Encoding") == "chunked" and "Content-Length" not in resp.headers)
        r.check("it is reusable within its window (retries must work)",
                download(args.url, args.agent_id, agent_key, issued).status_code == 200)
        r.status("another agent presenting it gets 404", download(args.url, args.other_agent_id, other_key, issued), 404)
        r.status("a tampered identifier gets 404", download(args.url, args.agent_id, agent_key, tamper(issued)), 404)

    print("\n== Locally signed (cross-implementation, cross-node) ==", flush=True)
    tid = task_id_bytes(task_id)
    mine = sign(key, subject, now + 900, tid)
    resp = download(args.url, args.agent_id, agent_key, mine)
    r.check("one signed by another holder of the cluster key is accepted",
            resp.status_code == 200 and resp.content == expected, str(resp.status_code))
    r.status("an expired one gets 404",
             download(args.url, args.agent_id, agent_key, sign(key, subject, now - 1, tid)), 404)
    r.status("one signed for another subject gets 404",
             download(args.url, args.agent_id, agent_key, sign(key, subject + 5000, now + 900, tid)), 404)
    r.status("one naming a task with no package gets 404",
             download(args.url, args.agent_id, agent_key, sign(key, subject, now + 900, os.urandom(16))), 404)
    r.status("one signed under an unrelated key gets 404",
             download(args.url, args.agent_id, agent_key,
                      sign(derive("some other cluster"), subject, now + 900, tid)), 404)

    print("\n== Plain filenames still work beside it ==", flush=True)
    resp = download(args.url, args.agent_id, agent_key, args.wpk_file)
    r.check("a byte-identical legacy request still succeeds",
            resp.status_code == 200 and resp.content == expected, str(resp.status_code))
    r.status("a real file whose name merely starts with the prefix is read as a name",
             download(args.url, args.agent_id, agent_key, "wpk1.notsigned.wpk"), 404)
    r.status("a name outside the grammar is still rejected",
             download(args.url, args.agent_id, agent_key, "../escape.wpk"), 400)
    r.status("an unknown resource type is still rejected",
             download(args.url, args.agent_id, agent_key, args.wpk_file, resource_type="nonsense"), 400)

    print(f"\n{r.passed} passed, {r.failed} failed", flush=True)
    return 1 if r.failed else 0


if __name__ == "__main__":
    sys.exit(main())
