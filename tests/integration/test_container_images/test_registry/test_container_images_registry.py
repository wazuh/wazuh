'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The container_images module resolves a `<ref>` reference in GitHub Container Registry,
       authenticates against it with a credential read from the agent credential store, selects
       the image variant matching the agent, and streams the layers without unpacking them.
       These tests drive a real agent against a registry served on this host, so the whole
       conversation is exercised without reaching the network.

       The registry answers as `ghcr.io`: the module accepts no other registry and builds its
       URLs without a port, so a local registry has to hold that name. The fixture serves a
       certificate issued for it by a throwaway authority, adds a hosts entry, and points
       `<ca_bundle>` at that authority.

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

config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_container_images_registry.yaml')

# T1: a public reference is inventoried with no credential configured.
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_public_reference.yaml')
t1_params, t1_metadata, t1_ids = configuration.get_test_cases_data(t1_cases_path)
t1_configurations = configuration.load_configuration_template(config_path, t1_params, t1_metadata)

# T2: a private reference is inventoried with a credential from the store.
t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_authenticated_reference.yaml')
t2_params, t2_metadata, t2_ids = configuration.get_test_cases_data(t2_cases_path)
t2_configurations = configuration.load_configuration_template(config_path, t2_params, t2_metadata)

# T3: a wrong or missing credential is reported.
t3_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_wrong_credential.yaml')
t3_params, t3_metadata, t3_ids = configuration.get_test_cases_data(t3_cases_path)
t3_configurations = configuration.load_configuration_template(config_path, t3_params, t3_metadata)

# T4: platform variant selection.
t4_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_platform_variants.yaml')
t4_params, t4_metadata, t4_ids = configuration.get_test_cases_data(t4_cases_path)
t4_configurations = configuration.load_configuration_template(config_path, t4_params, t4_metadata)

# T5: an unchanged reference retrieves no image contents on the next scan.
t5_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_unchanged_reference.yaml')
t5_params, t5_metadata, t5_ids = configuration.get_test_cases_data(t5_cases_path)
t5_configurations = configuration.load_configuration_template(config_path, t5_params, t5_metadata)


def _wait_for_scan_ended(monitor: file_monitor.FileMonitor, timeout: int = 60) -> None:
    """Block until the next 'Scan ended.' line. This is the race-free scan barrier."""
    monitor.start(callback=callbacks.generate_callback(patterns.CB_SCAN_ENDED), timeout=timeout)
    assert monitor.callback_result, 'No "Scan ended." line was logged within the timeout.'


def _stored_packages() -> dict:
    return {row['name']: row['version_'] for row in query_table(PACKAGES_TABLE)}


def _stored_references() -> list:
    return query_table(REFERENCES_TABLE)


def _log_contains(fragment: str) -> bool:
    return fragment in Path(WAZUH_LOG_PATH).read_text(errors='replace')


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_metadata), ids=t1_ids)
def test_public_reference_is_inventoried_without_a_credential(test_configuration, test_metadata, local_registry,
                                                              set_wazuh_configuration,
                                                              configure_local_internal_options,
                                                              truncate_monitored_files, daemons_handler):
    '''
    description: Check that a reference to a public repository is resolved with no credential
                 configured, and that its packages are stored.

    assertions:
        - The scan completes.
        - The token was requested anonymously.
        - The reference and the packages its layer carries are stored.
        - A layer was retrieved through the redirect the registry answers with.
    '''
    registry, expected_packages = local_registry

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    assert _log_contains('requesting an anonymous token'), \
        'The module did not request an anonymous token for a repository with no credential configured.'

    references = _stored_references()
    assert len(references) == 1, f'Expected one stored reference, found {references}.'
    assert references[0]['reference_value'] == test_metadata['reference']

    assert _stored_packages() == expected_packages, \
        f'Stored packages {_stored_packages()} do not match the image contents {expected_packages}.'

    assert registry.blob_requests(), 'No image content was retrieved.'
    assert any(path.startswith('/content/') for path in registry.requests), \
        'The layer was not retrieved through the redirect the registry answered with.'
    assert registry.redirect_authorization is None, \
        'The access token was carried across the redirect to the content host.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t2_configurations, t2_metadata), ids=t2_ids)
def test_private_reference_is_inventoried_with_a_stored_credential(test_configuration, test_metadata, local_registry,
                                                                   set_wazuh_configuration,
                                                                   configure_local_internal_options,
                                                                   truncate_monitored_files, daemons_handler):
    '''
    description: Check that a reference to a private repository is resolved with the credential
                 the agent credential store holds, and that no credential value reaches the log.

    assertions:
        - The scan completes and the packages are stored.
        - The registry accepted the credential.
        - Neither the user name nor the access token appears anywhere in the log.
    '''
    registry, expected_packages = local_registry

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    assert not registry.rejected_credentials, \
        f'The registry refused the credential: {registry.rejected_credentials}.'

    assert _stored_packages() == expected_packages, \
        f'Stored packages {_stored_packages()} do not match the image contents {expected_packages}.'

    # The acceptance criterion on credential hygiene, checked against the whole log rather
    # than against the lines this test happened to wait for.
    assert not _log_contains('a-secret-token'), 'The access token was written to the log.'
    assert not _log_contains('Bearer '), 'A bearer token was written to the log.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t3_configurations, t3_metadata), ids=t3_ids)
def test_a_bad_credential_is_reported_and_the_scan_continues(test_configuration, test_metadata, local_registry,
                                                             set_wazuh_configuration,
                                                             configure_local_internal_options,
                                                             truncate_monitored_files, daemons_handler):
    '''
    description: Check that a private reference whose credential is wrong or absent is reported
                 in the log, stores nothing, and does not stop the scan from completing.

    assertions:
        - The scan still completes, so one bad reference does not abort it.
        - The reference is reported.
        - No image content was retrieved.
        - No credential value appears in the log.
    '''
    registry, _ = local_registry

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    assert _log_contains(test_metadata['reference']), \
        'The failing reference was not named in the log.'

    assert not registry.blob_requests(), \
        f'Image content was retrieved despite the credential failing: {registry.blob_requests()}.'

    assert _stored_packages() == {}, 'Packages were stored for a reference that could not be read.'

    assert not _log_contains('not-the-token'), 'The rejected credential was written to the log.'

    if test_metadata['credential'] == 'missing':
        assert _log_contains('missing from the agent credential store'), \
            'A credential absent from the store was not reported as such.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t4_configurations, t4_metadata), ids=t4_ids)
def test_the_platform_variant_matching_the_agent_is_inventoried(test_configuration, test_metadata, local_registry,
                                                                set_wazuh_configuration,
                                                                configure_local_internal_options,
                                                                truncate_monitored_files, daemons_handler):
    '''
    description: Check that a reference offering several platform variants is inventoried from
                 the one matching the agent, and that a reference offering none is reported
                 without any layer being retrieved.

    assertions:
        - When a matching variant exists, it is the one stored.
        - When none matches, the reference is reported and no image content is fetched.
    '''
    registry, expected_packages = local_registry

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    if test_metadata['expected_packages'] == 0:
        assert _log_contains('no image variant matches'), \
            'A reference with no matching variant was not reported.'

        # No layer, ever. Whether a *configuration* blob is read depends on the shape the
        # registry serves: an index carries each entry's platform, so the reference is
        # declined from the index alone, while a manifest outside an index names no platform
        # and its configuration blob is the only thing that can confirm one.
        assert not registry.layer_requests(), \
            f'A layer was retrieved for a reference with no matching platform variant: ' \
            f'{registry.layer_requests()}.'

        if test_metadata.get('expect_no_blob_at_all'):
            assert not registry.blob_requests(), \
                f'An index named its platforms, so no blob should have been read: ' \
                f'{registry.blob_requests()}.'
        else:
            assert len(registry.blob_requests()) == 1, \
                f'Exactly the configuration blob should have been read, found ' \
                f'{registry.blob_requests()}.'

        return

    references = _stored_references()
    assert len(references) == 1, f'Expected one stored reference, found {references}.'
    assert references[0]['platform_architecture'] == test_metadata['expected_architecture']
    assert _stored_packages() == expected_packages


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t5_configurations, t5_metadata), ids=t5_ids)
def test_an_unchanged_reference_retrieves_no_image_contents(test_configuration, test_metadata, local_registry,
                                                            set_wazuh_configuration,
                                                            configure_local_internal_options,
                                                            truncate_monitored_files, daemons_handler):
    '''
    description: Check that a second scan of a reference whose image has not changed reads only
                 the metadata and retrieves no image contents at all.

    assertions:
        - The first scan stores the packages.
        - The second scan reports the reference as unchanged.
        - No blob is requested during the second scan, which is the acceptance criterion stated
          as a count rather than as a duration.
        - The stored inventory is unchanged.
    '''
    registry, expected_packages = local_registry
    monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    _wait_for_scan_ended(monitor)
    assert _stored_packages() == expected_packages

    # Everything the second scan asks for is measured from here.
    registry.requests.clear()

    # A restart is the deterministic way to force another scan without waiting the interval.
    from wazuh_testing.tools import services
    services.control_service('restart', daemon='wazuh-modulesd')

    _wait_for_scan_ended(file_monitor.FileMonitor(WAZUH_LOG_PATH))

    assert _log_contains('so no image contents were retrieved'), \
        'The unchanged reference was not recognised as unchanged.'

    assert not registry.blob_requests(), \
        f'The second scan retrieved image content: {registry.blob_requests()}.'

    assert _stored_packages() == expected_packages, \
        'The stored inventory changed on a scan that retrieved nothing.'
