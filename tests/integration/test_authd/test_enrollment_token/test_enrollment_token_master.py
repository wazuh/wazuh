'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the enrollment token lifecycle of 'wazuh-manager-authd' on a master node
       (issue #38993): minting, listing, describing, consuming and revoking a token, through both
       doors that reach it -- the 'token_*' verbs over auth.sock and the
       'wazuh-manager-authd --*-enrollment-token' utility mode, which is a thin client of those
       verbs. It also covers what must NOT happen: a token minted for an address the listener
       certificate does not name, a secret echoed back by the listing or by '--show-token', a use
       still honoured after the token was revoked, and an endpoint given as an IP address passing
       without a warning.

components:
    - authd

suite: enrollment_token

targets:
    - manager

daemons:
    - wazuh-manager-authd
    - wazuh-manager-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://github.com/wazuh/wazuh/issues/38993

tags:
    - enrollment
    - enrollment_token
'''
import os
import re
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.daemons import AUTHD_DAEMON
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.sockets import AUTHD_SOCKET_PATH
from wazuh_testing.modules.authd.configuration import AUTHD_DEBUG_CONFIG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH, utils

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_enrollment_token_master.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_enrollment_token_master.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
receiver_sockets_params = [(AUTHD_SOCKET_PATH, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [(AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures

daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {AUTHD_DEBUG_CONFIG: '2'}

# 'mwarn' from etoken_mint_prepare(): re.match is what the framework applies, hence the leading '.*'.
IP_ADDRESS_WARNING = rf".*Enrollment token address '{re.escape(utils.IP_ADDRESS)}' is an IP address.*"
IP_ADDRESS_WARNING_TIMEOUT = 10

# 64 hexadecimal characters: the SHA-256 of the CA public key, in the form an operator can compare
# against `openssl x509 -pubkey | openssl dgst -sha256`.
PIN_HEX_PATTERN = re.compile(r'[0-9a-f]{64}')

# Error codes answered by local-server.c for the token verbs.
ERROR_TOKEN_NOT_FOUND = 9022
ERROR_MINT_REFUSED = 9025


def _mint_over_socket(sock, **arguments):
    """Mint a token with `token_create` and return its `data`, failing the test on a refusal."""
    arguments.setdefault('address', utils.ENDPOINT_ADDRESS)
    response = utils.socket_request(sock, {'function': 'token_create', 'arguments': arguments})

    assert response['error'] == 0, f'token_create was refused: {utils.answer_summary(response)}'

    return response['data']


def _mint_over_cli(*arguments):
    """Mint a token with the CLI and return (token text, finished process), failing on a refusal."""
    result = utils.run_authd_cli(['--create-enrollment-token', '--address', utils.ENDPOINT_ADDRESS,
                                  *arguments])

    assert result.returncode == 0, f'The CLI could not mint a token: {result.stderr}'

    return result.stdout.strip(), result


def _case_socket_mint(sock, test_metadata, created_agents):
    """A token minted over auth.sock is complete, and the store that keeps it is not world readable.

    Everything the answer reports is checked against the token itself: the pin is the same anchor in
    both spellings (64 hex characters and 43 base64url ones), the endpoint is the address that was
    asked for, and the key is the 32 bytes of identifier plus secret. The store must then exist,
    hold the new id, and belong to the daemon user with mode 0640 -- the secrets in it have the same
    weight as the keys in client.keys.
    """
    data = _mint_over_socket(sock)

    assert PIN_HEX_PATTERN.fullmatch(data['pin_hex']), \
        f"'pin_hex' is not 64 hex characters: {utils.redacted(data)}"
    assert len(data['id']) == utils.TOKEN_ID_CHARS, \
        f"'id' is not {utils.TOKEN_ID_CHARS} characters: {utils.redacted(data)}"
    assert data['adr'].startswith(utils.ENDPOINT_ADDRESS), \
        f"'adr' does not name the address: {utils.redacted(data)}"
    assert data['expires'] > time.time(), f'The token is already expired: {utils.redacted(data)}'

    token = utils.decode_token(data['token'])

    assert token['ver'] == 1, f"Unexpected token version: {token['ver']}"
    assert token['adr'] == data['adr'], \
        f"The token endpoint does not match the answer: {token['adr']} != {data['adr']}"
    assert 'pin' in token and 'ca' not in token, \
        f'The token does not carry exactly one anchor: {sorted(token)}'
    assert utils.b64url_decode(token['pin']) == bytes.fromhex(data['pin_hex']), \
        'The pin in the token and the one reported by authd are different anchors'
    assert 'key' in token, f'The token carries no credential: {sorted(token)}'
    assert len(utils.b64url_decode(token['key'])) == 32, \
        f"The key is not 32 bytes: {len(utils.b64url_decode(token['key']))}"
    assert utils.token_key_halves(token)[0] == data['id'], \
        'The first half of the key is not the identifier authd reported'

    store_stat = os.stat(utils.ENROLLMENT_TOKENS_PATH)

    assert store_stat.st_mode & 0o777 == utils.STORE_MODE, \
        f'The store is {oct(store_stat.st_mode & 0o777)} instead of {oct(utils.STORE_MODE)}'
    assert utils.store_owner(store_stat) == (utils.STORE_OWNER, utils.STORE_OWNER), \
        f'The store belongs to {utils.store_owner(store_stat)} instead of the daemon user'

    store = utils.read_store()

    assert store['version'] == 1, f'Unexpected store version: {store["version"]}'
    # Only the ids: the store keeps the secret of every token it holds.
    assert utils.store_entry(data['id']) is not None, \
        f'The store holds {[entry["id"] for entry in store["tokens"]]}, not {data["id"]}'


def _case_cli_mint(sock, test_metadata, created_agents):
    """The CLI puts the token, and nothing else, on stdout, and its metadata on stderr.

    That split is the whole point of the interface: `token=$(wazuh-manager-authd
    --create-enrollment-token --address ...)` has to capture a token that can be handed straight to
    an agent, while the operator still sees the id, the endpoint, the expiry, the pin and whether the
    token carries a credential.
    """
    token_text, result = _mint_over_cli('--ttl', '1h', '--max-uses', '3', '--description', 'it')

    assert result.stdout.count('\n') == 1, f'stdout is not exactly one line: {result.stdout!r}'

    token = utils.decode_token(token_text)

    assert 'key' in token, f'The token carries no credential: {sorted(token)}'
    assert token['adr'].startswith(utils.ENDPOINT_ADDRESS), \
        f"The token names another endpoint: {token['adr']}"

    for label in ('id: ', 'endpoint: ', 'expires: ', 'pin: ', 'credential: '):
        assert label in result.stderr, f'The CLI did not report {label!r}: {result.stderr!r}'


def _case_cli_list_hides_secret(sock, test_metadata, created_agents):
    """The listing names every token by id and cannot be used to recover one.

    The secret is only ever readable in the token text itself, so it is recomputed here from that
    text (the second half of the key) and looked for in the listing: an operator must be able to
    audit the tokens without the listing becoming a way to enroll.
    """
    token_text, _ = _mint_over_cli()
    token = utils.decode_token(token_text)
    token_id, secret = utils.token_key_halves(token)

    result = utils.run_authd_cli(['--list-enrollment-tokens'])

    assert result.returncode == 0, f'The CLI could not list the tokens: {result.stderr}'
    assert result.stdout.splitlines()[0].startswith('ID'), f'No header row: {result.stdout!r}'
    assert token_id in result.stdout, f'The listing does not name the token {token_id}'
    assert secret not in result.stdout, 'The listing leaks the token secret'
    assert 'secret' not in result.stdout.lower(), 'The listing has a secret column'


def _case_cli_show_token(sock, test_metadata, created_agents):
    """'--show-token' describes a token without its credential, and refuses one it cannot parse.

    This is the command an operator runs on a token someone sent them, so it must be safe to run
    where the output can be read: it says which manager the token points at and which CA it pins,
    and never repeats the key or either of its halves. Anything that is not a token is a plain
    failure, not an empty description.
    """
    token_text, _ = _mint_over_cli()
    token = utils.decode_token(token_text)
    token_id, secret = utils.token_key_halves(token)

    result = utils.run_authd_cli(['--show-token'], stdin=token_text + '\n')

    assert result.returncode == 0, f'--show-token failed: {result.stderr}'
    assert 'ver: 1' in result.stdout, f'No version line: {result.stdout!r}'
    assert f"adr: {token['adr']}" in result.stdout, f'No endpoint line: {result.stdout!r}'
    assert re.search(r'^pin: [0-9a-f]{64}$', result.stdout, re.MULTILINE), \
        f'No pin line of 64 hex characters: {result.stdout!r}'
    assert 'credential: present' in result.stdout, f'The credential is not reported: {result.stdout!r}'
    assert 'key:' not in result.stdout, '--show-token prints the key field'
    assert token['key'] not in result.stdout, '--show-token prints the key'
    assert token_id not in result.stdout, '--show-token prints the identifier half of the key'
    assert secret not in result.stdout, '--show-token prints the secret half of the key'

    garbage = utils.run_authd_cli(['--show-token'], stdin='garbage\n')

    assert garbage.returncode == 1, f'--show-token accepted garbage: {garbage.stdout!r}'
    assert 'malformed token' in garbage.stderr, f'Unexpected diagnostic: {garbage.stderr!r}'


def _case_add_consumes_then_revoke_blocks(sock, test_metadata, created_agents):
    """An enrollment counts a use against the token, and revoking it stops the next one.

    Both halves are the reason the store is written at all: the use count has to survive in the file
    (so a restart or a worker sees it), and a revocation has to take effect on the very next
    enrollment, without waiting for the token to expire or run out of uses.
    """
    data = _mint_over_socket(sock, max_uses=3)
    token_id = data['id']

    enrolled = utils.socket_request(sock, {'function': 'add',
                                           'arguments': {'name': 'etoken-agent-1', 'ip': 'any',
                                                         'token_id': token_id}})

    # 'error' and 'message' only: a successful answer carries the new agent's key.
    assert enrolled['error'] == 0, \
        f"The enrollment with a valid token failed: {enrolled.get('error')} {enrolled.get('message')}"
    created_agents.append(enrolled['data']['id'])

    entry = utils.store_entry(token_id)

    assert entry is not None, f'The store does not hold the token {token_id}'
    # The counters and flags only: the entry itself holds the secret.
    counters = {field: entry[field] for field in ('uses', 'max_uses', 'revoked')}

    assert entry['uses'] == 1, f'The use was not counted in the store: {counters}'
    assert entry['max_uses'] == 3, f'The store does not keep the requested limit: {counters}'
    assert entry['revoked'] is False, f'The token is already revoked: {counters}'

    revoked = utils.run_authd_cli(['--revoke-enrollment-token', token_id])

    assert revoked.returncode == 0, f'The CLI could not revoke the token: {revoked.stderr}'
    assert f'Enrollment token {token_id} revoked.' in revoked.stdout, \
        f'The revocation was not confirmed: {revoked.stdout!r}'

    blocked = utils.socket_request(sock, {'function': 'add',
                                          'arguments': {'name': 'etoken-agent-2', 'ip': 'any',
                                                        'token_id': token_id}})

    # Recorded before the assertion so that an agent the revoked token should not have created is
    # still cleaned up when this fails.
    if blocked['error'] == 0:
        created_agents.append(blocked['data']['id'])

    assert blocked['error'] == ERROR_TOKEN_NOT_FOUND, \
        f"A revoked token was not refused: {blocked.get('error')} {blocked.get('message')}"


def _case_refusals(sock, test_metadata, created_agents):
    """An address the listener certificate does not name is refused, with the reason, on both doors.

    Minting anyway would produce a token that only fails in the field, after it has been
    distributed: the agent verifies the manager's name against the certificate SAN and has nothing
    else to fall back on. The refusal must also leave nothing behind -- a refused mint that had
    already drawn a secret and written the store would be worse than no answer at all.
    """
    response = utils.socket_request(sock, {'function': 'token_create',
                                           'arguments': {'address': utils.FOREIGN_ADDRESS}})

    assert response['error'] == ERROR_MINT_REFUSED, \
        f'Unexpected answer to a foreign address: {utils.answer_summary(response)}'
    assert 'SAN' in response['message'], \
        f'The refusal does not name the reason: {utils.answer_summary(response)}'

    result = utils.run_authd_cli(['--create-enrollment-token', '--address', utils.FOREIGN_ADDRESS])

    assert result.returncode == 1, f'The CLI minted a token for a foreign address: {result.stdout!r}'
    assert f'ERROR {ERROR_MINT_REFUSED}' in result.stderr, f'Unexpected diagnostic: {result.stderr!r}'
    assert 'SAN' in result.stderr, f'The diagnostic does not name the reason: {result.stderr!r}'
    assert result.stdout == '', f'The CLI printed something on a refusal: {result.stdout!r}'

    store = utils.read_store()

    persisted = [] if store is None else [entry['id'] for entry in store['tokens']]

    assert persisted == [], f'A refused mint persisted the token(s) {persisted}'


def _case_ip_address_warns(sock, test_metadata, created_agents):
    """An endpoint given as an IP address is accepted, and warned about.

    Sometimes it is the only option, so it is not a refusal; but it ties the token to an address a
    re-deployment changes, and the agent cannot follow a name it was never given. The operator has
    to be told, which is why the warning is asserted rather than assumed.
    """
    data = _mint_over_socket(sock, address=utils.IP_ADDRESS)

    assert data['adr'].startswith(utils.IP_ADDRESS), \
        f"'adr' does not name the address: {utils.redacted(data)}"

    monitor = FileMonitor(WAZUH_LOG_PATH)
    monitor.start(timeout=IP_ADDRESS_WARNING_TIMEOUT, encoding='utf-8',
                  callback=generate_callback(IP_ADDRESS_WARNING))

    assert monitor.callback_result, \
        f'authd minted a token for an IP address without warning about it ({IP_ADDRESS_WARNING})'


def _case_purge_drops_the_unusable(sock, test_metadata, created_agents):
    """A purge removes the tokens that can no longer enrol anybody, and only those.

    Revoking and purging are different acts and this is where the difference shows on a running
    manager: after a revoke the token is still in the file, marked; after a purge it is not in the
    file at all, and the live token minted alongside it still is.
    """
    keep_text, _ = _mint_over_cli('--description', 'purge-keeps-me')
    drop_text, _ = _mint_over_cli('--description', 'purge-takes-me')
    keep_id, _ = utils.token_key_halves(utils.decode_token(keep_text))
    drop_id, _ = utils.token_key_halves(utils.decode_token(drop_text))

    assert utils.run_authd_cli(['--revoke-enrollment-token', drop_id]).returncode == 0

    stored = {token['id'] for token in utils.read_store()['tokens']}
    assert {keep_id, drop_id} <= stored, 'The store does not hold both tokens before the purge'

    result = utils.run_authd_cli(['--purge-enrollment-tokens'])

    assert result.returncode == 0, f'The CLI could not purge: {result.stderr}'
    assert 'Removed' in result.stdout, f'The purge said nothing about what it removed: {result.stdout!r}'

    stored = {token['id'] for token in utils.read_store()['tokens']}
    assert drop_id not in stored, 'The revoked token survived the purge'
    assert keep_id in stored, 'The purge took a token that was still usable'


def _case_purge_all_empties_the_store(sock, test_metadata, created_agents):
    """'--purge-enrollment-tokens --all --force' leaves an empty store the manager still reads.

    The file has to stay valid: remoted reloads it as soon as it changes, and an empty store is a
    manager that refuses every token, not one that fails to parse its own file.
    """
    _mint_over_cli('--description', 'purge-all-1')
    _mint_over_cli('--description', 'purge-all-2')

    assert len(utils.read_store()['tokens']) >= 2

    # Without --force the CLI would ask, and there is no terminal here: that refusal is the point
    # of the flag, and the case would hang without it.
    result = utils.run_authd_cli(['--purge-enrollment-tokens', '--all', '--force'])

    assert result.returncode == 0, f'The CLI could not empty the store: {result.stderr}'

    store = utils.read_store()
    assert store['tokens'] == [], f'The store is not empty after --all: {store}'
    assert store['version'] == 1, 'The purge broke the store format'

    # And the manager still answers on the socket with the file it just wrote.
    listing = utils.authd_socket_request({'function': 'token_list'})
    assert listing['error'] == 0 and listing['data'] == [], f'The listing does not match the store: {listing}'


# One entry per case of cases_enrollment_token_master.yaml, keyed by its 'action'.
CASES = {
    'socket_mint': _case_socket_mint,
    'cli_mint': _case_cli_mint,
    'cli_list_hides_secret': _case_cli_list_hides_secret,
    'cli_show_token': _case_cli_show_token,
    'add_consumes_then_revoke_blocks': _case_add_consumes_then_revoke_blocks,
    'refusals': _case_refusals,
    'ip_address_warns': _case_ip_address_warns,
    'purge_drops_the_unusable': _case_purge_drops_the_unusable,
    'purge_all_empties_the_store': _case_purge_all_empties_the_store,
}


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata),
                         ids=test_cases_ids)
def test_enrollment_token_master(test_configuration, test_metadata, clean_enrollment_tokens,
                                 set_wazuh_configuration, truncate_monitored_files,
                                 configure_local_internal_options, daemons_handler,
                                 wait_for_authd_startup, connect_to_sockets, remove_created_agents):
    '''
    description:
        Checks the enrollment token lifecycle on a master node. Each case is one step of that
        lifecycle, driven by its 'action' metadata and implemented by the '_case_*' function of the
        same name: minting over auth.sock and over the CLI, listing, describing with '--show-token',
        consuming a token with an 'add' and revoking it, refusing an address the listener
        certificate does not name, and warning about an endpoint given as an IP address.

        'clean_enrollment_tokens' is requested first on purpose: it removes 'etc/enrollment_tokens.json'
        while authd is still stopped, so every case starts from a daemon that has loaded no tokens.

    wazuh_min_version:
        5.0.0

    tier: 1

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata, including the 'action' that selects the case.
        - clean_enrollment_tokens:
            type: fixture
            brief: Remove the enrollment token store before and after the test.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the wazuh-manager.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - daemons_handler:
            type: fixture
            brief: Restarts wazuh or a specific daemon passed.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - remove_created_agents:
            type: fixture
            brief: Delete the agents the test enrolled once it is over.

    assertions:
        - A minted token decodes to version 1, the requested endpoint, one anchor and a 32 byte key
        - The pin authd reports in hexadecimal is the same anchor the token carries in base64url
        - The store exists after the first mint, holds the new id, and is 0640 wazuh-manager:wazuh-manager
        - The CLI prints the token alone on stdout and its metadata on stderr
        - Neither the listing nor '--show-token' ever echoes a secret or the key
        - An 'add' with a token counts one use in the store, and a revoked token is refused with 9022
        - An address outside the listener certificate SAN is refused with 9025, naming the SAN, and persists nothing
        - An endpoint given as an IP address is accepted and warned about in the log

    input_description:
        Different test cases are contained in an external YAML file (cases_enrollment_token_master.yaml)
        which selects, through its 'action' metadata, the step of the lifecycle to exercise. The
        configuration is a single 'auth' section (config_enrollment_token_master.yaml) with the local
        server enabled and no shared password.

    expected_output:
        - Answers to the 'token_*' and 'add' verbs on the authd local socket
        - Output and exit status of 'wazuh-manager-authd --*-enrollment-token' / '--show-token'
        - r'.*Enrollment token address .* is an IP address.*'
    '''
    CASES[test_metadata['action']](receiver_sockets[0], test_metadata, remove_created_agents)
