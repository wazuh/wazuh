# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module will contain all cases for the region test suite
"""
import pytest

# qa-integration-framework imports
from wazuh_testing import session_parameters
from wazuh_testing.constants.aws import RANDOM_ACCOUNT_ID
from wazuh_testing.constants.paths.aws import AWS_SERVICES_DB_PATH, S3_CLOUDTRAIL_DB_PATH
from wazuh_testing.modules.aws.utils import path_exist
from wazuh_testing.utils.db_queries.aws_db import (get_multiple_service_db_row, table_exists_or_has_values,
                                                   get_multiple_s3_db_row)

# Local module imports
from . import event_monitor
from .configurator import configurator
from .utils import ERROR_MESSAGE, TIMEOUT, ALL_REGIONS, local_internal_options

pytestmark = [pytest.mark.server]

# Set test configurator for the module
configurator.module = 'regions_test_module'

# ---------------------------------------------------- TEST_PATH -------------------------------------------------------
# Configure T1 test
configurator.configure_test(configuration_file='bucket_configuration_regions.yaml',
                            cases_file='cases_bucket_regions.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_regions(
        test_configuration, metadata, load_wazuh_basic_configuration,  create_test_bucket, manage_bucket_files,
        set_wazuh_configuration, clean_s3_cloudtrail_db, configure_local_internal_options_function,
        truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: Only the logs for the specified region are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - If a region that does not exist was specified, make sure that a message is displayed in the ossec.log
              warning the user.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket
              for the specified region.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.6.0
    parameters:
        - test_configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - create_test_bucket:
            type: fixture
            brief: Create temporal bucket.
        - manage_bucket_files:
            type: fixture
            brief: S3 buckets manager.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - clean_s3_cloudtrail_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check the expected number of events were forwarded to analysisd.
        - Check the database was created and updated accordingly, using the correct path for each entry.
    input_description:
        - The `configuration_regions` file provides the module configuration for this test.
        - The `cases_regions` file provides the test cases.
    """
    bucket_name = metadata['bucket_name']
    bucket_type = metadata['bucket_type']
    only_logs_after = metadata['only_logs_after']
    regions: str = metadata['regions']
    expected_results = metadata['expected_results']
    regions_list = regions.split(",")

    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--only_logs_after', only_logs_after,
        '--regions', regions,
        '--type', bucket_type,
        '--debug', '2'
    ]

    # Check AWS module started
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['failed_start']

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_parameters']

    if expected_results:
        log_monitor.start(
            timeout=TIMEOUT[50],
            callback=event_monitor.callback_detect_event_processed,
            accumulations=expected_results
        )
        assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_event_number']
        
        assert path_exist(path=S3_CLOUDTRAIL_DB_PATH)

        # Validate database updates
        for row in get_multiple_s3_db_row(table_name=bucket_type):
            if hasattr(row, "aws_region"):
                assert row.aws_region in regions_list
            else:
                assert row.log_key.split("/")[3] in regions_list

    else:
        invalid_region = None
        for region in regions_list:
            if region not in ALL_REGIONS:
                invalid_region = region
                break        
        log_monitor.start(
            timeout=session_parameters.default_timeout,
            callback=event_monitor.make_aws_callback(
                fr".*\+\+\+ ERROR: Invalid region '{invalid_region}'"
            ),
        )
        assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_no_region_found_message']

        assert not table_exists_or_has_values(table_name=bucket_type)

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )
    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']


# -------------------------------------------- TEST_CLOUDWATCH_REGIONS -------------------------------------------------
# Configure T2 test
configurator.configure_test(configuration_file='cloudwatch_configuration_regions.yaml',
                            cases_file='cases_cloudwatch_regions.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_cloudwatch_regions(
        test_configuration, metadata, load_wazuh_basic_configuration, create_test_log_group, create_test_log_stream,
        manage_log_group_events, set_wazuh_configuration, clean_aws_services_db,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: Only the logs for the specified region are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - If a region that does not exist was specified, make sure that a message is displayed in the ossec.log
              warning the user.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket
              for the specified region.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.6.0
    parameters:
        - test_configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - create_test_log_group:
            type: fixture
            brief: Create a log group.
        - create_test_log_stream:
            type: fixture
            brief: Create a log stream with events for the day of execution.
        - manage_log_group_events:
            type: fixture
            brief: Manage events for the created log stream and log group.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - clean_aws_services_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check the expected number of events were forwarded to analysisd.
        - Check the database was created and updated accordingly, using the correct path for each entry.
    input_description:
        - The `configuration_regions` file provides the module configuration for this test.
        - The `cases_regions` file provides the test cases.
    """
    service_type = metadata['service_type']
    log_group_name = metadata.get('log_group_name')
    only_logs_after = metadata['only_logs_after']
    regions: str = metadata['regions']
    expected_results = metadata['expected_results']
    regions_list = regions.split(",")

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--only_logs_after', only_logs_after,
        '--regions', regions,
        '--aws_log_groups', log_group_name,
        '--debug', '2'
    ]

    # Check AWS module started
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['failed_start']

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_parameters']

    if expected_results:
        log_monitor.start(
            timeout=TIMEOUT[20],
            callback=event_monitor.callback_detect_service_event_processed(expected_results, service_type),
            accumulations=len(regions_list)
        )
        assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_event_number']

    else:
        log_monitor.start(
            timeout=session_parameters.default_timeout,
            callback=event_monitor.make_aws_callback(
                fr".*\+\+\+ ERROR: Invalid region '{regions}'"
            ),
        )

        assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_non-existent_region_message']

    table_name = 'cloudwatch_logs'

    if expected_results:
        assert table_exists_or_has_values(table_name=table_name, db_path=AWS_SERVICES_DB_PATH)
        for row in get_multiple_service_db_row(table_name=table_name):
            assert (getattr(row, 'region', None) or getattr(row, 'aws_region')) in regions_list
    else:
        assert not table_exists_or_has_values(table_name=table_name, db_path=AWS_SERVICES_DB_PATH)

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']


# ------------------------------------------ TEST_INSPECTOR_PATH -------------------------------------------------------
# Configure T3 test
configurator.configure_test(configuration_file='inspector_configuration_regions.yaml',
                            cases_file='cases_inspector_regions.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_inspector_regions(
        test_configuration, metadata, load_wazuh_basic_configuration,
        set_wazuh_configuration, clean_aws_services_db, configure_local_internal_options_function,
        truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: Only the logs for the specified region are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - If a region that does not exist was specified, make sure that a message is displayed in the ossec.log
              warning the user.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket
              for the specified region.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.6.0
    parameters:
        - test_configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - clean_aws_services_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check the expected number of events were forwarded to analysisd.
        - Check the database was created and updated accordingly, using the correct path for each entry.
    input_description:
        - The `configuration_regions` file provides the module configuration for this test.
        - The `cases_regions` file provides the test cases.
    """
    service_type = metadata['service_type']
    only_logs_after = metadata['only_logs_after']
    regions: str = metadata['regions']
    expected_results = metadata['expected_results']
    regions_list = regions.split(",")

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--only_logs_after', only_logs_after,
        '--regions', regions,
        '--debug', '2'
    ]

    # Check AWS module started
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['failed_start']

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_parameters']

    if expected_results:
        log_monitor.start(
            timeout=TIMEOUT[20],
            callback=event_monitor.callback_detect_service_event_processed(expected_results, service_type),
            accumulations=len(regions_list)
        )
        assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_event_number']

    else:
        log_monitor.start(
            timeout=session_parameters.default_timeout,
            callback=event_monitor.make_aws_callback(
                fr".*\+\+\+ ERROR: Unsupported region '{regions}'"
            ),
        )

        assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_non-existent_region_message']

    table_name = 'aws_services'

    if expected_results:
        assert table_exists_or_has_values(table_name=table_name, db_path=AWS_SERVICES_DB_PATH)
        for row in get_multiple_service_db_row(table_name=table_name):
            assert (getattr(row, 'region', None) or getattr(row, 'aws_region')) in regions_list
    else:
        assert not table_exists_or_has_values(table_name=table_name, db_path=AWS_SERVICES_DB_PATH)

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']
