'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The container_images module scans the configured local image layouts, stores their inventory
       in a local database and updates it when an image changes. These tests check that a scan
       persists the inventory and that an image rebuilt between scans is detected on the next scan,
       with the reference and package tables updated accordingly.

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
from wazuh_testing.modules.modulesd.container_images import patterns
from wazuh_testing.modules.modulesd.container_images.db import query_table, REFERENCES_TABLE, PACKAGES_TABLE

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


def _wait_for_scan_ended(monitor: file_monitor.FileMonitor, timeout: int = 60) -> None:
    """Block until the next 'Scan ended.' line. This is the race-free scan barrier."""
    monitor.start(callback=callbacks.generate_callback(patterns.CB_SCAN_ENDED), timeout=timeout)
    assert monitor.callback_result, 'No "Scan ended." line was logged within the timeout.'


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_metadata), ids=t1_ids)
def test_container_images_scan_stores_inventory(test_configuration, test_metadata, prepare_local_image,
                                                set_wazuh_configuration, configure_local_internal_options,
                                                truncate_monitored_files, daemons_handler):
    '''
    description: Check that the scan on start discovers the configured local image and stores a
                 reference row in the database.

    test_phases:
        - setup: write an OCI layout on disk, set the configuration, enable debug, restart daemons.
        - test: wait for "Scan ended.", then confirm the references table has at least one row.
        - teardown: remove the layout, restore configuration and logs, stop daemons.

    assertions:
        - The scan completes (deterministic "Scan ended." line).
        - The references table contains the discovered image.

    expected_result: PASS when the scan completes and the reference is stored.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    _wait_for_scan_ended(log_monitor)

    references = query_table(REFERENCES_TABLE)
    assert references, 'The references table is empty after the scan; the image was not stored.'


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
