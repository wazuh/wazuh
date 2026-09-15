'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The macOS agent collects Unified Logging System records through a predicate that
       'log stream' applies on the endpoint, so a record the predicate does not match is
       discarded before it ever leaves the agent and no decoder or rule can recover it.
       These tests read the predicate shipped in the darwin configuration template and
       assert that the graphical-login authentication clauses and the pre-existing SSH
       clauses are still present, so a future edit to the template cannot silently drop
       either. This is a static check of the shipped template; it does not exercise
       'log stream'.

components:
    - logcollector

suite: configuration

targets:
    - agent

daemons:
    - wazuh-logcollector

os_platform:
    - linux
    - macos
    - windows

os_version:
    - Ubuntu Focal
    - macOS Sequoia
    - macOS Sonoma
    - Windows 10

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#query
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html

tags:
    - logcollector_configuration
'''
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

TEMPLATE_PATH = Path(__file__).parents[4] / 'etc' / 'templates' / 'config' / 'darwin' / 'localfile-extra.template'

GUI_AUTHENTICATION_CLAUSES = [
    'process == "authd"',
    'eventMessage contains "system.login.console"',
    'eventMessage contains "builtin:login-success"',
    'process == "authorizationhost"',
    'eventMessage contains "authtok is incorrect"',
    'eventMessage contains "Failed to authenticate"',
    'process == "loginwindow"',
    'eventMessage contains "attempting login for user"',
    'eventMessage contains "is logged in"',
    'eventMessage contains "loginwindow.logoutNoReturn"',
    'process == "sessionlogoutd"',
    'eventMessage contains "lastUserName"',
]

NOISE_GATED_CLAUSES = [
    'process == "sudo" and sender == "sudo"',
    'sender == "sudo" and not (eventMessage contains "Using original path")',
    'sender == "sshd"',
    'sender == "sshd-session"',
    'sender == "sshd-auth"',
]

AUTHENTICATION_LIBRARY_CLAUSES = [
    'sender == "libpam.2.dylib"',
    'and not (eventMessage contains "doesn\'t have a"',
    'or eventMessage contains "Unable to retrieve")',
]

UNGATED_CLAUSES = [
    '(process == "sudo") or',
    '(process == "sshd") or',
    '(process == "sshd-session") or',
    '(process == "sshd-auth") or',
]

PREEXISTING_CLAUSES = [
    'process == "sudo"',
    'process == "sshd"',
    'process == "sshd-session"',
    'process == "sshd-auth"',
    'process == "sessionlogoutd"',
    'process == "tccd"',
    'process == "screensharingd"',
    'process == "securityd"',
    'eventMessage contains "SessionAgentNotificationCenter"',
]


@pytest.fixture(scope='module')
def macos_query() -> str:
    query = ET.parse(TEMPLATE_PATH).getroot().find('query')
    assert query is not None, f'No <query> element in {TEMPLATE_PATH}'
    return query.text


@pytest.mark.parametrize('clause', GUI_AUTHENTICATION_CLAUSES)
def test_macos_uls_default_query_collects_gui_authentication(clause, macos_query):
    '''
    description: Check that the predicate shipped for macOS still matches the graphical
                 login, logout and failed-password records emitted by 'authd',
                 'authorizationhost' and 'loginwindow'.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - clause:
            type: str
            brief: Predicate fragment that must be present in the shipped query.
        - macos_query:
            type: str
            brief: Text of the <query> element in the darwin configuration template.

    assertions:
        - Verify that each graphical-login authentication fragment is present.

    input_description: The <query> element of etc/templates/config/darwin/localfile-extra.template.

    expected_output:
        - Every fragment listed in GUI_AUTHENTICATION_CLAUSES.

    tags:
        - settings
    '''
    assert clause in macos_query, f'Missing clause in shipped macOS predicate: {clause}'


@pytest.mark.parametrize('clause', PREEXISTING_CLAUSES)
def test_macos_uls_default_query_keeps_preexisting_clauses(clause, macos_query):
    '''
    description: Check that expanding the predicate did not drop any clause the macOS
                 agent already relied on, SSH authentication in particular.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - clause:
            type: str
            brief: Predicate fragment that must be present in the shipped query.
        - macos_query:
            type: str
            brief: Text of the <query> element in the darwin configuration template.

    assertions:
        - Verify that each pre-existing fragment is still present.

    input_description: The <query> element of etc/templates/config/darwin/localfile-extra.template.

    expected_output:
        - Every fragment listed in PREEXISTING_CLAUSES.

    tags:
        - settings
    '''
    assert clause in macos_query, f'Clause dropped from shipped macOS predicate: {clause}'


def test_macos_uls_default_query_uses_event_message_key(macos_query):
    '''
    description: Check that every message test in the shipped predicate uses the
                 documented 'eventMessage' key. 'log stream' does not honour the
                 undocumented 'message' key when it is combined with a 'process'
                 comparison, which silently discards the matching records.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - macos_query:
            type: str
            brief: Text of the <query> element in the darwin configuration template.

    assertions:
        - Verify that the predicate contains no bare 'message contains' test.

    input_description: The <query> element of etc/templates/config/darwin/localfile-extra.template.

    expected_output:
        - No occurrence of 'message contains' outside 'eventMessage contains'.

    tags:
        - settings
    '''
    assert 'message contains' not in macos_query, \
        "Shipped macOS predicate uses the undocumented 'message' key; use 'eventMessage'"


@pytest.mark.parametrize('clause', NOISE_GATED_CLAUSES)
def test_macos_uls_default_query_gates_sudo_and_ssh_on_sender(clause, macos_query):
    '''
    description: Check that the 'sudo' and 'sshd' clauses only match records the monitored
                 binary emitted itself. Without the 'sender' gate those clauses also match
                 everything the supporting libraries log under the same process -
                 'libsystem_info.dylib' group resolution, 'libpam.2.dylib', 'Heimdal',
                 'libxpc.dylib' - which carries no principal, no verdict and no command,
                 and accounted for most of the macOS event volume.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - clause:
            type: str
            brief: Predicate fragment that must be present in the shipped query.
        - macos_query:
            type: str
            brief: Text of the <query> element in the darwin configuration template.

    assertions:
        - Verify that each sender-gated fragment is present.

    input_description: The <query> element of etc/templates/config/darwin/localfile-extra.template.

    expected_output:
        - Every fragment listed in NOISE_GATED_CLAUSES.

    tags:
        - settings
    '''
    assert clause in macos_query, f'Missing sender gate in shipped macOS predicate: {clause}'


@pytest.mark.parametrize('clause', UNGATED_CLAUSES)
def test_macos_uls_default_query_has_no_ungated_process_clause(clause, macos_query):
    '''
    description: Check that no 'sudo' or 'sshd' clause tests the process alone. The gated
                 forms contain the ungated ones as a substring, so the presence tests
                 above cannot detect a revert on their own.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - clause:
            type: str
            brief: Ungated predicate fragment that must be absent from the shipped query.
        - macos_query:
            type: str
            brief: Text of the <query> element in the darwin configuration template.

    assertions:
        - Verify that no bare process-only clause is present.

    input_description: The <query> element of etc/templates/config/darwin/localfile-extra.template.

    expected_output:
        - No fragment listed in UNGATED_CLAUSES.

    tags:
        - settings
    '''
    assert clause not in macos_query, f'Ungated clause in shipped macOS predicate: {clause}'


@pytest.mark.parametrize('clause', AUTHENTICATION_LIBRARY_CLAUSES)
def test_macos_uls_default_query_keeps_pam_verdicts(clause, macos_query):
    '''
    description: Check that PAM records under 'sudo' and 'sshd' survive the sender gate.
                 'pam_opendirectory.so' is 'auth required' for both services and is what
                 verifies the password, so the account verdicts - locked after incorrect
                 attempts, disabled or inactive, expired authtok, incorrect authtok - are
                 written by 'libpam.2.dylib' rather than by the monitored binary. The same
                 module and the same message are an acceptance record under
                 'authorizationhost', so gating them out under 'sudo' and 'sshd' would
                 discard a verdict the predicate collects elsewhere. Only the two families
                 that carry no verdict are excluded by message.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - clause:
            type: str
            brief: Predicate fragment that must be present in the shipped query.
        - macos_query:
            type: str
            brief: Text of the <query> element in the darwin configuration template.

    assertions:
        - Verify that the PAM carve-out and both of its message exclusions are present.

    input_description: The <query> element of etc/templates/config/darwin/localfile-extra.template.

    expected_output:
        - Every fragment listed in AUTHENTICATION_LIBRARY_CLAUSES.

    tags:
        - settings
    '''
    assert clause in macos_query, f'Missing PAM carve-out in shipped macOS predicate: {clause}'
