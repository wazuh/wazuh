'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The container_images module scans the configured image inputs, extracts the packages their
       layers contain, stores the inventory in a local database and updates it when an image
       changes. These tests check that a scan persists the references and their packages for both
       supported inputs, that the layer composition rules are applied, that an image whose package
       format is not implemented yet is still inventoried, and that an image rebuilt between scans
       is detected on the next scan.

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

config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_container_images_inventory.yaml')

# T1: scan on start stores the inventory.
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_scan_and_store.yaml')
t1_params, t1_metadata, t1_ids = configuration.get_test_cases_data(t1_cases_path)
t1_configurations = configuration.load_configuration_template(config_path, t1_params, t1_metadata)

# T2: an image rebuilt between scans is detected on the next scan.
t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_image_update.yaml')
t2_params, t2_metadata, t2_ids = configuration.get_test_cases_data(t2_cases_path)
t2_configurations = configuration.load_configuration_template(config_path, t2_params, t2_metadata)

# T3: a saved image archive is inventoried.
t3_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_saved_archive.yaml')
t3_params, t3_metadata, t3_ids = configuration.get_test_cases_data(t3_cases_path)
t3_configurations = configuration.load_configuration_template(config_path, t3_params, t3_metadata)

# T4: the last layer that provides a package database wins.
t4_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_layer_override.yaml')
t4_params, t4_metadata, t4_ids = configuration.get_test_cases_data(t4_cases_path)
t4_configurations = configuration.load_configuration_template(config_path, t4_params, t4_metadata)

# T5: a package database deleted in a later layer is not reported.
t5_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_layer_whiteout.yaml')
t5_params, t5_metadata, t5_ids = configuration.get_test_cases_data(t5_cases_path)
t5_configurations = configuration.load_configuration_template(config_path, t5_params, t5_metadata)

# T6: an image whose package format is not implemented yet is inventoried with zero packages.
t6_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_unsupported_package_format.yaml')
t6_params, t6_metadata, t6_ids = configuration.get_test_cases_data(t6_cases_path)
t6_configurations = configuration.load_configuration_template(config_path, t6_params, t6_metadata)

# T7: an rpm sqlite database is inventoried.
t7_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_rpm_sqlite.yaml')
t7_params, t7_metadata, t7_ids = configuration.get_test_cases_data(t7_cases_path)
t7_configurations = configuration.load_configuration_template(config_path, t7_params, t7_metadata)

# T8: an rpm ndb database is inventoried.
t8_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_rpm_ndb.yaml')
t8_params, t8_metadata, t8_ids = configuration.get_test_cases_data(t8_cases_path)
t8_configurations = configuration.load_configuration_template(config_path, t8_params, t8_metadata)


def _wait_for_scan_ended(monitor: file_monitor.FileMonitor, timeout: int = 60) -> None:
    """Block until the next 'Scan ended.' line. This is the race-free scan barrier."""
    monitor.start(callback=callbacks.generate_callback(patterns.CB_SCAN_ENDED), timeout=timeout)
    assert monitor.callback_result, 'No "Scan ended." line was logged within the timeout.'


def _stored_packages() -> dict:
    """The stored packages as ``{name: version}``, which is what the tests assert on."""
    return {row['name']: row['version_'] for row in query_table(PACKAGES_TABLE)}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_metadata), ids=t1_ids)
def test_container_images_scan_stores_inventory(test_configuration, test_metadata, prepare_local_image,
                                                set_wazuh_configuration, configure_local_internal_options,
                                                truncate_monitored_files, daemons_handler):
    '''
    description: Check that the scan on start discovers the configured OCI image layout and stores
                 the reference and the packages its layer contains.

    test_phases:
        - setup: write an OCI layout on disk, set the configuration, enable debug, restart daemons.
        - test: wait for "Scan ended.", then confirm the reference and its packages are stored.
        - teardown: remove the layout, restore configuration and logs, stop daemons.

    assertions:
        - The scan completes (deterministic "Scan ended." line).
        - The references table contains the discovered image.
        - The packages of the dpkg database are stored with the versions the database holds.

    expected_result: PASS when the scan completes and the inventory is stored.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    references = query_table(REFERENCES_TABLE)
    assert references, 'The references table is empty after the scan; the image was not stored.'

    packages = _stored_packages()
    assert packages.get('curl') == '7.88.1-10', f'curl is missing or has the wrong version: {packages}.'
    assert packages.get('tar') == '1.34+dfsg-1', f'tar is missing or has the wrong version: {packages}.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t2_configurations, t2_metadata), ids=t2_ids)
def test_container_images_update_detected_on_next_scan(test_configuration, test_metadata, prepare_local_image,
                                                       set_wazuh_configuration, configure_local_internal_options,
                                                       truncate_monitored_files, daemons_handler):
    '''
    description: Check that an image rebuilt between scans is detected on the next interval scan and
                 that the reference table is updated (the stored config digest changes).

    test_phases:
        - setup: write the initial OCI layout, configure a short interval, restart daemons.
        - test:
            - wait for the first "Scan ended." and snapshot the stored config digest;
            - rebuild the image (new config digest) via the prepare_local_image callable;
            - wait for the next "Scan ended." (the interval scan);
            - confirm the module logged a reference modification and the stored digest changed.
        - teardown: remove the layout, restore configuration and logs, stop daemons.

    assertions:
        - The first scan stores the image.
        - After the rebuild, the next scan logs a reference MODIFY for the references table.
        - The stored config digest differs from the one captured after the first scan.

    expected_result: PASS when the rebuild is detected on the next scan and the reference is updated.
    '''
    update_image = prepare_local_image

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # First scan: capture the initial digest.
    _wait_for_scan_ended(log_monitor)
    before = query_table(REFERENCES_TABLE)
    assert before, 'The references table is empty after the first scan.'
    digest_before = before[0].get('image_config_digest')

    # Rebuild the image (new config digest) and wait for the module to MODIFY the reference.
    update_image(seed='v2')

    modify_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    modify_pattern = patterns.CB_INVENTORY_MODIFIED.replace('{0}', REFERENCES_TABLE)
    modify_monitor.start(callback=callbacks.generate_callback(modify_pattern), timeout=60)
    assert modify_monitor.callback_result, 'The reference modification was not detected on the next scan.'

    after = query_table(REFERENCES_TABLE)
    assert after, 'The references table is empty after the update scan.'
    digest_after = after[0].get('image_config_digest')

    assert digest_after != digest_before, \
        f'The stored config digest did not change after the rebuild ({digest_before!r}).'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t3_configurations, t3_metadata), ids=t3_ids)
def test_container_images_saved_archive_is_inventoried(test_configuration, test_metadata, prepare_saved_archive,
                                                       set_wazuh_configuration, configure_local_internal_options,
                                                       truncate_monitored_files, daemons_handler):
    '''
    description: Check that a saved image archive is read and that the packages of its apk database
                 are stored.

    test_phases:
        - setup: write a saved image archive holding one apk layer, configure it, restart daemons.
        - test: wait for "Scan ended.", then confirm the reference and its packages are stored.
        - teardown: remove the archive, restore configuration and logs, stop daemons.

    assertions:
        - The reference is stored with the `archive` reference type.
        - The packages of the apk database are stored with the versions the database holds.

    expected_result: PASS when the archive is inventoried with its packages.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    references = query_table(REFERENCES_TABLE)
    assert references, 'The references table is empty after the scan; the archive was not read.'
    assert references[0].get('reference_type') == 'archive', \
        f"The reference type is not 'archive' ({references[0].get('reference_type')!r})."

    packages = _stored_packages()
    assert packages.get('busybox') == '1.36.1-r5', f'busybox is missing or has the wrong version: {packages}.'
    assert packages.get('musl') == '1.2.4-r2', f'musl is missing or has the wrong version: {packages}.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t4_configurations, t4_metadata), ids=t4_ids)
def test_container_images_later_layer_wins(test_configuration, test_metadata, prepare_layered_image,
                                           set_wazuh_configuration, configure_local_internal_options,
                                           truncate_monitored_files, daemons_handler):
    '''
    description: Check that a package upgraded in a later layer is stored with the later version.

    test_phases:
        - setup: write an image whose second layer upgrades a package, configure it, restart daemons.
        - test: wait for "Scan ended.", then confirm the stored version is the one of the last layer.
        - teardown: remove the image, restore configuration and logs, stop daemons.

    assertions:
        - The upgraded package is stored once, with the version the last layer provides.
        - The package the later layer keeps unchanged is stored as well.

    expected_result: PASS when the composition follows the manifest order.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    packages = _stored_packages()
    assert packages.get('curl') == '8.5.0-2', f'curl was not stored with the version of the last layer: {packages}.'
    assert packages.get('tar') == '1.34+dfsg-1', f'tar is missing from the inventory: {packages}.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t5_configurations, t5_metadata), ids=t5_ids)
def test_container_images_deleted_database_is_not_reported(test_configuration, test_metadata, prepare_whiteout_image,
                                                           set_wazuh_configuration, configure_local_internal_options,
                                                           truncate_monitored_files, daemons_handler):
    '''
    description: Check that a package database deleted in a later layer contributes no packages.

    test_phases:
        - setup: write an image whose second layer deletes the dpkg database and adds an apk one.
        - test: wait for "Scan ended.", then confirm only the apk packages are stored.
        - teardown: remove the image, restore configuration and logs, stop daemons.

    assertions:
        - The package of the deleted database is not stored.
        - The package of the database the later layer provides is stored.

    expected_result: PASS when the OverlayFS deletion marker is applied.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    packages = _stored_packages()
    assert 'curl' not in packages, f'The package of the deleted database was reported: {packages}.'
    assert packages.get('busybox') == '1.36.1-r5', f'busybox is missing from the inventory: {packages}.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t6_configurations, t6_metadata), ids=t6_ids)
def test_container_images_unsupported_package_format(test_configuration, test_metadata, prepare_unsupported_image,
                                                     set_wazuh_configuration, configure_local_internal_options,
                                                     truncate_monitored_files, daemons_handler):
    '''
    description: Check that an image whose package format is recognized but not implemented yet is
                 still inventoried, with zero packages, and that the scan continues.

    test_phases:
        - setup: write an image whose only package database is an RPM one, configure it, restart daemons.
        - test: wait for "Scan ended.", then confirm the reference is stored with no packages.
        - teardown: remove the image, restore configuration and logs, stop daemons.

    assertions:
        - The reference is stored.
        - No package row is stored for it.
        - The recognized but unimplemented format is reported with a warning.

    expected_result: PASS when the image is inventoried with zero packages.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    assert query_table(REFERENCES_TABLE), 'The image with an unsupported package format was not inventoried.'
    assert not query_table(PACKAGES_TABLE), 'An unsupported package format produced package rows.'

    # The format must also be reported, so the empty inventory is explained rather than silent.
    warning_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    warning_monitor.start(callback=callbacks.generate_callback(patterns.CB_UNSUPPORTED_PACKAGE_FORMAT),
                          timeout=30)
    assert warning_monitor.callback_result, 'The unsupported package format was not reported with a warning.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t7_configurations, t7_metadata), ids=t7_ids)
def test_container_images_rpm_sqlite_database(test_configuration, test_metadata, prepare_rpm_sqlite_image,
                                              set_wazuh_configuration, configure_local_internal_options,
                                              truncate_monitored_files, daemons_handler):
    '''
    description: Check that an image whose package database is an rpm sqlite one is inventoried
                 with its packages, and that a version carrying an epoch keeps it.

    test_phases:
        - setup: write an OCI layout holding an rpm sqlite database, configure it, restart daemons.
        - test: wait for "Scan ended.", then confirm the packages are stored.
        - teardown: remove the layout, restore configuration and logs, stop daemons.

    assertions:
        - The reference is stored.
        - The packages of the rpm database are stored with the versions the database holds.
        - A version carrying an epoch is stored with the epoch preserved.

    expected_result: PASS when the rpm sqlite database is inventoried.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    assert query_table(REFERENCES_TABLE), 'The references table is empty after the scan.'

    packages = _stored_packages()
    assert packages.get('bash') == '5.1.8-9.el9', f'bash is missing or has the wrong version: {packages}.'
    # rpm orders versions by epoch first, so a version that carries one is only correct with it.
    assert packages.get('gdbm-libs') == '1:1.19-4.el9', f'The epoch was not preserved: {packages}.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t8_configurations, t8_metadata), ids=t8_ids)
def test_container_images_rpm_ndb_database(test_configuration, test_metadata, prepare_rpm_ndb_image,
                                           set_wazuh_configuration, configure_local_internal_options,
                                           truncate_monitored_files, daemons_handler):
    '''
    description: Check that an image whose package database is an rpm ndb one, kept under /usr,
                 is inventoried with its packages.

    test_phases:
        - setup: write an OCI layout holding an rpm ndb database, configure it, restart daemons.
        - test: wait for "Scan ended.", then confirm the packages are stored.
        - teardown: remove the layout, restore configuration and logs, stop daemons.

    assertions:
        - The reference is stored.
        - The packages of the rpm database are stored with the versions the database holds.

    expected_result: PASS when the rpm ndb database is inventoried.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    assert query_table(REFERENCES_TABLE), 'The references table is empty after the scan.'

    packages = _stored_packages()
    assert packages.get('aaa_base') == '84.87-150300.10.20.1', \
        f'aaa_base is missing or has the wrong version: {packages}.'
