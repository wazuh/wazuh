# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Helpers shared by the enrollment token tests (issue #38993) and their fixtures.

Three things are needed by both the master and the worker suite, and by `conftest.py`:

* the two doors into the daemon -- the `token_*` verbs over auth.sock and the
  `wazuh-manager-authd --*-enrollment-token` utility mode, which is a thin client of those same
  verbs, so both are exercised;
* the client side of the token codec, to prove from the outside that the token an operator is
  handed decodes to exactly the fields the format defines and that neither the listing nor
  `--show-token` ever echoes its credential;
* the store file `etc/enrollment_tokens.json`, read as an operator would to check what was
  persisted (and written, in the worker suite, to stand in for a cluster sync).
"""
import base64
import grp
import json
import os
import pwd
import subprocess

from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.binaries import BIN_PATH
from wazuh_testing.constants.paths.sockets import AUTHD_SOCKET_PATH
from wazuh_testing.tools.socket_controller import SocketController


# The store authd persists the tokens in. Not created until the first token is minted.
ENROLLMENT_TOKENS_PATH = os.path.join(WAZUH_PATH, 'etc', 'enrollment_tokens.json')

# authd writes the store after dropping privileges, and the secrets in it must never be world
# readable: the daemon user owns it, group readable at most.
STORE_OWNER = 'wazuh-manager'
STORE_MODE = 0o640

# The daemon binary doubles as the enrollment token CLI.
AUTHD_BINARY_PATH = os.path.join(BIN_PATH, 'wazuh-manager-authd')
CLI_TIMEOUT = 30

# A name in the listener certificate's SAN (IP:127.0.0.1, DNS:wazuh-manager, DNS:localhost,
# DNS:host.docker.internal, DNS:wazuh-1), so minting for it is accepted...
ENDPOINT_ADDRESS = 'wazuh-manager'
# ...and one that is not, so minting for it is refused.
FOREIGN_ADDRESS = 'evil'
# In the SAN as an IP entry: accepted, but with a warning (the agent cannot verify a name it was
# never given).
IP_ADDRESS = '127.0.0.1'

# Characters of a base64url encoded 16 byte token identifier (ETOKEN_ID_CHARS).
TOKEN_ID_CHARS = 22

# A fixed token planted in the store to stand in for one the cluster synced from the master. The
# bytes are deliberately trivial (0..15 identifier, 16..31 secret, 0..31 pin) so the expected
# base64url spellings are reproducible by hand.
SYNCED_TOKEN_ID = 'AAECAwQFBgcICQoLDA0ODw'
SYNCED_TOKEN_SECRET = 'EBESExQVFhcYGRobHB0eHw'
SYNCED_TOKEN_PIN = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'


def b64url_encode(raw):
    """Encode bytes the way the token format spells them: base64url with the padding stripped."""
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def b64url_decode(text):
    """Decode an unpadded base64url string."""
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def decode_token(text):
    """Decode a token exactly as an agent would: base64url of a compact JSON object.

    Returns the parsed object, with `ver`, `adr`, one anchor (`pin` or `ca`) and, unless the token
    was minted `--no-credential`, a `key`.
    """
    return json.loads(b64url_decode(text.strip()))


def token_key_halves(token):
    """Split a token's `key` into the two base64url halves the store keeps apart.

    The key is the concatenation of the 16 identifier bytes and the 16 secret bytes. The first half
    spelled on its own is the token id (what the listing shows); the second half is the secret
    (what nothing but the token itself may ever show).
    """
    material = b64url_decode(token['key'])
    return b64url_encode(material[:16]), b64url_encode(material[16:])


def redacted(data):
    """A copy of a `token_create` answer with the token text elided.

    The token is the one place a secret is ever readable, and a failure message ends up in a report:
    everything else in the answer is safe to print, so only that field is dropped.
    """
    return {**data, 'token': '<redacted>'} if 'token' in data else data


def answer_summary(response):
    """The parts of an authd answer that are safe to put in a failure message.

    A successful answer can carry a token or a fresh agent key; the code and the message never can.
    """
    return {field: response[field] for field in ('error', 'message') if field in response}


def socket_request(controller, payload):
    """Send one request to auth.sock through `controller` and return the parsed answer.

    The socket is reopened first: authd closes the connection after answering, so a controller that
    has already been used cannot be reused as it stands (the same reason `test_authd_local.py`
    reopens before every message).
    """
    controller.open()
    controller.send(json.dumps(payload), size=True)
    answer = controller.receive(size=True).decode()

    if not answer:
        raise ConnectionResetError(f'authd closed the connection without answering to {payload}')

    return json.loads(answer)


def authd_socket_request(payload):
    """Same as `socket_request`, over a connection of its own.

    For callers with no `receiver_sockets` to borrow -- a fixture tearing down after the test, for
    instance, whose own socket is already gone.
    """
    controller = SocketController(address=AUTHD_SOCKET_PATH, family='AF_UNIX',
                                  connection_protocol='TCP', open_at_start=False)
    try:
        return socket_request(controller, payload)
    finally:
        controller.close()


def run_authd_cli(arguments, stdin=None):
    """Run the enrollment token utility mode of wazuh-manager-authd and return the finished process.

    Text mode: the token, the listing and the metadata authd reports are all text, and every
    assertion in these tests is on that text.
    """
    return subprocess.run([AUTHD_BINARY_PATH, *arguments], input=stdin, capture_output=True,
                          text=True, timeout=CLI_TIMEOUT)


def file_remove_quietly(path):
    """Remove `path` if it is there, and say nothing when it is not."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def read_store():
    """Return the parsed store file, or None when it does not exist yet."""
    if not os.path.exists(ENROLLMENT_TOKENS_PATH):
        return None

    with open(ENROLLMENT_TOKENS_PATH, encoding='utf-8') as store_file:
        return json.load(store_file)


def store_owner(store_stat):
    """Return the (user, group) names of an `os.stat` result, by name rather than by id."""
    return pwd.getpwuid(store_stat.st_uid).pw_name, grp.getgrgid(store_stat.st_gid).gr_name


def store_entry(token_id):
    """Return the store entry of `token_id`, or None when the store does not hold it."""
    store = read_store() or {'tokens': []}

    return next((entry for entry in store['tokens'] if entry['id'] == token_id), None)
