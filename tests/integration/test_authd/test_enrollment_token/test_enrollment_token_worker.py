'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies what 'wazuh-manager-authd' does with enrollment tokens on a worker node
       (issue #38993). Minting and revoking write the store, and only the master writes it, so a
       worker answers 9015 to those -- over auth.sock and through the CLI alike. What a worker DOES
       do is forward the token id of an enrollment to the master untouched (the master resolves it
       and counts the use), and answer a listing from the replica of the store the cluster synced to
       it, picking the file up by its modification time without being restarted. The master is a
       'WorkerMID' man in the middle on the cluster internal socket, so the cluster answer is fixed
       by the test case.

components:
    - authd

suite: enrollment_token

targets:
    - manager

daemons:
    - wazuh-manager-authd
    - wazuh-manager-clusterd

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
    - cluster
'''
import json
from pathlib import Path

import pytest

from wazuh_testing.constants.daemons import AUTHD_DAEMON, CLUSTER_DAEMON
from wazuh_testing.constants.paths.sockets import AUTHD_SOCKET_PATH, MODULESD_C_INTERNAL_SOCKET_PATH
from wazuh_testing.tools.mitm import WorkerMID
from wazuh_testing.utils.cluster import CLUSTER_DATA_HEADER_SIZE
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH, utils

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_enrollment_token_worker.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_enrollment_token_worker.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
# The request goes in through auth.sock, not port 1515: these are the local server verbs, which is
# where the token id reaches a worker from (the API, manage_agents, the agent bridge).
receiver_sockets_params = [(AUTHD_SOCKET_PATH, 'AF_UNIX', 'TCP')]

mitm_master = WorkerMID(address=MODULESD_C_INTERNAL_SOCKET_PATH, family='AF_UNIX',
                        connection_protocol='TCP')
monitored_sockets_params = [(CLUSTER_DAEMON, mitm_master, True), (AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures

daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}

# 'Cannot execute this request on a worker node'
ERROR_NO_MASTER = 9015

# The forwarded message is already in the man in the middle's queue by the time it is read back
# (the answer the worker gave came through it), so this only has to be long enough not to be flaky.
CLUSTER_QUEUE_TIMEOUT = 10


def _case_worker_socket_mint_9015(sock, test_metadata, write_store):
    """A worker refuses to mint over auth.sock rather than mint a token the master does not know.

    The store is written by the master alone and reaches the workers by cluster sync, so a token a
    worker minted locally would be honoured by that worker and by nobody else -- and would vanish
    on the next sync. The check happens before the arguments are even parsed, so a worker never
    reads the listener certificate for nothing.
    """
    response = utils.socket_request(sock, {'function': 'token_create',
                                           'arguments': {'address': utils.ENDPOINT_ADDRESS}})

    assert response['error'] == ERROR_NO_MASTER, \
        f'A worker answered something else to a mint: {utils.answer_summary(response)}'
    assert 'worker' in response['message'], \
        f'The refusal does not say why: {utils.answer_summary(response)}'


def _case_worker_cli_mint_9015(sock, test_metadata, write_store):
    """The CLI reports the same refusal, and says where the token can be minted.

    The CLI is a thin client of the same verb, so it cannot do better than the daemon -- but it is
    what an operator runs, so its diagnostic has to be actionable: the code plus the node they
    should have run it on.
    """
    result = utils.run_authd_cli(['--create-enrollment-token', '--address', utils.ENDPOINT_ADDRESS])

    assert result.returncode == 1, f'The CLI minted a token on a worker: {result.stdout!r}'
    assert str(ERROR_NO_MASTER) in result.stderr, f'Unexpected diagnostic: {result.stderr!r}'
    assert 'master node' in result.stderr, \
        f'The diagnostic does not name the master node: {result.stderr!r}'


def _case_worker_forwards_token_id(sock, test_metadata, write_store):
    """A worker forwards the token id to the master untouched and returns what the master created.

    Only the id travels: the worker neither resolves the token nor counts the use, because its
    replica of the store may be behind the master's and two nodes counting the same use would let a
    single-use token enroll twice. The fake master's answer is what the worker must hand back, and
    the message it received is read out of the man in the middle's queue to prove the id crossed
    the cluster unchanged.
    """
    response = utils.socket_request(sock, json.loads(test_metadata['local_input']))

    assert response['error'] == 0, \
        f'The forwarded enrollment failed: {utils.answer_summary(response)}'
    assert response['data']['id'] == test_metadata['expected_agent_id'], \
        f"The worker returned the agent {response['data']['id']}, not {test_metadata['expected_agent_id']}"

    clusterd_queue = monitored_sockets[0]
    # The callback takes the message as it is; the cluster header is stripped below.
    clusterd_queue.start(callback=(lambda message: message), timeout=CLUSTER_QUEUE_TIMEOUT,
                         accumulations=2)
    results = clusterd_queue.callback_result
    forwarded = results[0][CLUSTER_DATA_HEADER_SIZE:]

    assert f'"token_id":"{test_metadata["expected_token_id"]}"' in forwarded, \
        f'The token id did not reach the master as it was given: {forwarded}'


def _case_worker_reads_synced_store(sock, test_metadata, write_store):
    """A worker lists the tokens of a store that appeared under it, without being restarted.

    This is how a worker learns about the master's tokens: the cluster renames a freshly downloaded
    copy over 'etc/enrollment_tokens.json', and authd notices by modification time on the next
    request. Planting the file while the daemon is already running is therefore the case itself, not
    just its setup.
    """
    token_id = write_store(token_id=test_metadata['expected_token_id'])

    response = utils.socket_request(sock, {'function': 'token_list'})

    assert response['error'] == 0, f'token_list failed on a worker: {utils.answer_summary(response)}'

    listed = {entry['id']: entry for entry in response['data']}

    assert token_id in listed, f'The worker did not pick up the synced store: {sorted(listed)}'
    assert listed[token_id]['adr'] == utils.ENDPOINT_ADDRESS, f'Unexpected endpoint: {listed[token_id]}'
    assert listed[token_id]['credential'] is True, \
        f'The token was synced without its credential: {listed[token_id]}'
    assert 'secret' not in listed[token_id], f'token_list leaks the secret: {listed[token_id]}'


# One entry per case of cases_enrollment_token_worker.yaml, keyed by its 'action'.
CASES = {
    'worker_socket_mint_9015': _case_worker_socket_mint_9015,
    'worker_cli_mint_9015': _case_worker_cli_mint_9015,
    'worker_forwards_token_id': _case_worker_forwards_token_id,
    'worker_reads_synced_store': _case_worker_reads_synced_store,
}


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata),
                         ids=test_cases_ids)
def test_enrollment_token_worker(test_configuration, test_metadata, clean_enrollment_tokens,
                                 set_wazuh_configuration, truncate_monitored_files, daemons_handler,
                                 configure_sockets_environment, wait_for_authd_startup,
                                 connect_to_sockets, write_enrollment_token_store):
    '''
    description:
        Checks how a worker node handles enrollment tokens: it refuses to mint one (9015) whichever
        door the request comes through, it forwards the token id of an enrollment to the master
        untouched and returns the agent the master created, and it answers a listing from the replica
        of the store the cluster synced to it. Each case is selected by its 'action' metadata and
        implemented by the '_case_*' function of the same name.

        'clean_enrollment_tokens' is requested first so the store is absent while authd is still
        stopped: a worker that had loaded tokens would not prove that the last case picked up the
        file that appeared under it.

    wazuh_min_version:
        5.0.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata, including the 'action' that selects the case and the cluster messages.
        - clean_enrollment_tokens:
            type: fixture
            brief: Remove the enrollment token store before and after the test.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the wazuh-manager.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - write_enrollment_token_store:
            type: fixture
            brief: Factory that plants a valid store file under the running daemon, as a cluster sync would.

    assertions:
        - 'token_create' over auth.sock is answered 9015 on a worker
        - The CLI reports 9015 and names the master node
        - The 'token_id' of an enrollment reaches the fake master unchanged
        - The worker returns the agent id and key the master answered with
        - 'token_list' on a worker shows a token that was planted while the daemon was running
        - 'token_list' never carries the secret of a token

    input_description:
        Different test cases are contained in an external YAML file (cases_enrollment_token_worker.yaml)
        which selects the case through its 'action' metadata and, for the forwarding case, fixes the
        message the worker must send ('cluster_input') and the answer the fake master gives
        ('cluster_output'). The configuration is an 'auth' section plus a worker 'cluster' section
        (config_enrollment_token_worker.yaml).

    expected_output:
        - Answers to the 'token_*' and 'add' verbs on the authd local socket
        - The 'add' request, carrying the token id, on the cluster internal socket
        - Output and exit status of 'wazuh-manager-authd --create-enrollment-token'
    '''
    # Push the expected exchange to the man in the middle's queue, as test_authd_worker.py does. The
    # cases that never reach the master leave it unused.
    mitm_master.set_cluster_messages(test_metadata['cluster_input'], test_metadata['cluster_output'])
    mitm_master.restart()

    CASES[test_metadata['action']](receiver_sockets[0], test_metadata, write_enrollment_token_store)
