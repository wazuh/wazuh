'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The container_images module reads images from Amazon Elastic Container Registry. A public
       repository needs no credential. A private one needs an AWS access key pair read from the
       agent credential store: the module signs a request to the AWS API with it (AWS Signature
       Version 4), receives a registry token, and sends that token to the registry.
       These tests drive a real agent against a registry served on this host that answers as the
       ECR hosts and as the AWS API endpoint, so the whole conversation is exercised without
       reaching the network. The API endpoint verifies the signature with an implementation
       written independently of the module's, in Python.

components:
    - modulesd

suite: container_images

targets:
    - agent

daemons:
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Ubuntu Jammy
'''
from pathlib import Path

import pytest
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG

from framework_module import patterns
from framework_module.db import query_table, PACKAGES_TABLE, REFERENCES_TABLE

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# Variables
daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}
local_internal_options = {MODULESD_DEBUG: '2'}

# T1: a public ECR reference is inventoried with no credential, and matches the saved archive.
t1_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_container_images_ecr_public.yaml')
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_ecr_public_reference.yaml')
t1_params, t1_metadata, t1_ids = configuration.get_test_cases_data(t1_cases_path)
t1_configurations = configuration.load_configuration_template(t1_config_path, t1_params, t1_metadata)

# T2: a private ECR reference is inventoried with a valid credential, reusing one token.
private_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_container_images_ecr_private.yaml')
t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_ecr_private_valid.yaml')
t2_params, t2_metadata, t2_ids = configuration.get_test_cases_data(t2_cases_path)
t2_configurations = configuration.load_configuration_template(private_config_path, t2_params, t2_metadata)

# T3: a missing, invalid or unknown credential is reported.
t3_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_ecr_private_invalid.yaml')
t3_params, t3_metadata, t3_ids = configuration.get_test_cases_data(t3_cases_path)
t3_configurations = configuration.load_configuration_template(private_config_path, t3_params, t3_metadata)


def _wait_for_scan_ended(monitor: file_monitor.FileMonitor, timeout: int = 60, scans: int = 1) -> None:
    """Block until the log holds @scans 'Scan ended.' lines. This is the race-free scan barrier.

    The monitor reads the whole file before it waits for new lines, so a wait that follows an
    earlier scan in the same log has to count that scan too. These cases scan once.
    """
    monitor.start(callback=callbacks.generate_callback(patterns.CB_SCAN_ENDED), timeout=timeout,
                  accumulations=scans)
    assert monitor.callback_result, 'No "Scan ended." line was logged within the timeout.'


def _log() -> str:
    return Path(WAZUH_LOG_PATH).read_text(errors='replace')


def _packages_of(reference_type: str) -> dict:
    return {row['name']: row['version_'] for row in query_table(PACKAGES_TABLE)
            if row['reference_type'] == reference_type}


def _assert_no_credential_in_log(registry) -> None:
    """The acceptance criterion on credential hygiene, checked against the whole log.

    Covers the key pair as stored, and every value derived from it that the test can know: the
    registry token and its password, the signature header, and the text AWS quotes in an error.
    """
    from framework_module.registry import ECR_ACCESS_KEY_ID, ECR_SECRET_ACCESS_KEY

    log = _log()
    forbidden = [ECR_ACCESS_KEY_ID, ECR_SECRET_ACCESS_KEY, 'NotTheSecretAccessKey', 'AKIDUNKNOWNTESTKEY',
                 'AWS4-HMAC-SHA256', 'Signature=', 'Credential=', 'Authorization:', 'Basic ',
                 'The request signature we calculated']

    if registry.issued_token:
        forbidden += [registry.issued_token, registry.issued_password]

    for request in registry.api_requests:
        forbidden.append(request['authorization'])

    for value in filter(None, forbidden):
        assert value not in log, f'A value that must never be logged appears in the log: {value[:12]}...'


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_metadata), ids=t1_ids)
def test_public_ecr_reference_is_inventoried_without_a_credential(test_configuration, test_metadata,
                                                                  local_ecr_registry,
                                                                  set_wazuh_configuration,
                                                                  configure_local_internal_options,
                                                                  truncate_monitored_files, daemons_handler):
    '''
    description: Check that a reference to a public ECR repository is resolved with no credential
                 configured, and that the packages stored for it match the ones stored for the
                 same image scanned from a saved archive.

    assertions:
        - The scan completes and the reference is stored.
        - The token was requested anonymously, and the AWS API was never called.
        - A layer was retrieved through the redirect the registry answers with, without the token.
        - The packages stored for the registry reference equal those stored for the archive.
    '''
    registry, expected_packages = local_ecr_registry

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    assert 'requesting an anonymous token' in _log(), \
        'The module did not request an anonymous token for a public repository.'
    assert not registry.api_requests, 'The AWS API was called for a public repository.'

    stored = {(row['reference_type'], row['reference_value']) for row in query_table(REFERENCES_TABLE)}
    assert ('ref', test_metadata['reference']) in stored, f'The reference was not stored: {stored}.'

    assert any(path.startswith('/content/') for path in registry.requests), \
        'The layer was not retrieved through the redirect the registry answered with.'
    assert registry.redirect_authorization is None, \
        'The access token was carried across the redirect to the content host.'

    assert _packages_of('ref') == expected_packages
    assert _packages_of('ref') == _packages_of('archive'), \
        'The packages stored for the registry reference differ from those of the same image as an archive.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t2_configurations, t2_metadata), ids=t2_ids)
def test_private_ecr_reference_is_inventoried_with_a_signed_token(test_configuration, test_metadata,
                                                                  local_ecr_registry,
                                                                  set_wazuh_configuration,
                                                                  configure_local_internal_options,
                                                                  truncate_monitored_files, daemons_handler):
    '''
    description: Check that a private ECR reference is resolved with a registry token obtained by a
                 signed request to the AWS API, that the token is reused across the references of
                 the registry, and that nothing derived from the credential reaches the log.

    assertions:
        - The signature of the one API request verifies, checked independently of the module.
        - Exactly one token was requested for every reference of the registry, or two when the
          case kills the token while the first image is being read: the registry refuses the
          layer, the module confirms with the manifest that the token is the cause, asks for
          one new token, repeats the layer, and the second reference reuses the new token.
        - The references that could be read are stored, and one that cannot is reported without
          stopping the scan.
        - No credential value and nothing derived from one appears in the log.
    '''
    registry, expected_packages = local_ecr_registry

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    expected_requests = test_metadata.get('expected_api_requests', 1)

    assert len(registry.api_requests) == expected_requests, \
        f'Expected {expected_requests} signed token request(s), found {len(registry.api_requests)}.'

    for api_request in registry.api_requests:
        assert api_request['outcome'] == 'ok', f"The signature did not verify: {api_request['outcome']}."
        assert api_request['host'] == 'api.ecr.us-east-1.amazonaws.com'

    # Zero unless the case kills the token on purpose. Then the layer request and the manifest
    # request that identifies the token as the cause are the two refusals.
    assert registry.refused_tokens == test_metadata.get('expected_refused_tokens', 0), \
        f'The registry refused {registry.refused_tokens} request(s) for a token.'

    references = [row['reference_value'] for row in query_table(REFERENCES_TABLE)]
    assert len(references) == test_metadata['expected_references'], f'Stored references: {references}.'
    assert test_metadata['reference'] in references
    assert _packages_of('ref') == expected_packages

    if 'second_reference' in test_metadata and test_metadata['expected_references'] == 1:
        assert test_metadata['second_reference'] in _log(), 'The failing reference was not named in the log.'

    _assert_no_credential_in_log(registry)


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t3_configurations, t3_metadata), ids=t3_ids)
def test_private_ecr_reference_with_a_bad_credential_is_reported(test_configuration, test_metadata,
                                                                 local_ecr_registry,
                                                                 set_wazuh_configuration,
                                                                 configure_local_internal_options,
                                                                 truncate_monitored_files, daemons_handler):
    '''
    description: Check that a private ECR reference whose credential is missing, invalid or unknown
                 to AWS is reported with one clear line naming the reference and the reason, that
                 the registry is never asked, and that the scan still completes.

    assertions:
        - The scan completes.
        - The reference and the reason are named in the log.
        - AWS answered the way the case expects, and the registry received no request.
        - Nothing is stored for the reference.
        - No credential value and no text AWS quoted appears in the log.
    '''
    registry, _ = local_ecr_registry

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    log = _log()

    assert test_metadata['reference'] in log, 'The failing reference was not named in the log.'
    assert test_metadata['expected_reason'] in log, \
        f"The reason {test_metadata['expected_reason']!r} was not reported."

    outcomes = [request['outcome'] for request in registry.api_requests]

    if test_metadata['expected_outcome'] == 'none':
        assert not outcomes, f'AWS was called with no credential to call it with: {outcomes}.'
    else:
        assert outcomes and set(outcomes) == {test_metadata['expected_outcome']}, \
            f"Expected AWS to answer {test_metadata['expected_outcome']}, got {outcomes}."

    assert not registry.requests, f'The registry was asked for something without a token: {registry.requests}.'
    assert query_table(PACKAGES_TABLE) == [], 'Packages were stored for a reference that could not be read.'

    _assert_no_credential_in_log(registry)
