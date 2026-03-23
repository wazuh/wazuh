# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module will contain all cases for the remove from bucket test suite
"""

import pytest

# qa-integration-framework imports
from wazuh_testing import session_parameters
from wazuh_testing.modules.aws.utils import log_stream_exists, file_exists
from wazuh_testing.modules.aws.patterns import REMOVE_S3_FILE

# Local module imports
from . import event_monitor
from .configurator import configurator
from .utils import ERROR_MESSAGE, TIMEOUT, local_internal_options

pytestmark = [pytest.mark.server]

# Set test configurator for the module
configurator.module = 'remove_from_bucket_test_module'

# ---------------------------------------------------- TEST_REMOVE_FROM_BUCKET -----------------------------------------
# Configure T1 test
configurator.configure_test(configuration_file='configuration_remove_from_bucket.yaml',
                            cases_file='cases_remove_from_bucket.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_remove_from_bucket(
        test_configuration, metadata, mark_cases_as_skipped, create_test_bucket, manage_bucket_files, s3_client,
        load_wazuh_basic_configuration, set_wazuh_configuration, clean_s3_cloudtrail_db,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: The uploaded file was removed after the execution.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check that the uploaded log was removed by the module after the execution.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
    wazuh_min_version: 4.6.0
    parameters:
        - test_configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - mark_cases_as_skipped:
            type: fixture
            brief: Mark certain tests as skipped.
        - create_test_bucket:
            type: fixture
            brief: Create temporal bucket.
        - manage_bucket_files:
            type: fixture
            brief: Create and delete the resources for the test.
        - s3_client:
            type: fixture
            brief: S3 client to access AWS.
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
        - Check in the bucket that the uploaded log was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    bucket_name = metadata['bucket_name']
    path = metadata.get('path')
    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--remove',
        '--type', metadata['bucket_type'],
        '--debug', '2'
    ]

    if path is not None:
        parameters.insert(4, path)
        parameters.insert(4, '--trail_prefix')

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

    log_monitor.start(
        timeout=TIMEOUT[20],
        callback=event_monitor.make_aws_callback(pattern=fr"{REMOVE_S3_FILE}")
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_no_existent_log_group']

    assert not file_exists(filename=metadata['uploaded_file'], bucket_name=bucket_name, client=s3_client)

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']


# ---------------------------------------------------- TEST_REMOVE_LOG_STREAM ------------------------------------------
# Configure T2 test
configurator.configure_test(configuration_file='configuration_remove_log_stream.yaml',
                            cases_file='cases_remove_log_streams.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_remove_log_stream(
        test_configuration, metadata, create_test_log_group, create_test_log_stream, manage_log_group_events,
        logs_clients, load_wazuh_basic_configuration, set_wazuh_configuration, clean_aws_services_db,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: The created log stream was removed after the execution.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check that the created log stream was removed by the module after the execution.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
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
        - logs_clients:
            type: fixture
            brief: CloudWatch Logs client to check the log stream existence.
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
        - Check in the log group that the created stream was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    service_type = metadata['service_type']
    log_group_name = metadata['log_group_name']

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--regions', 'us-east-1',
        '--aws_log_groups', log_group_name,
        '--remove-log-streams',
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

    for log_client in logs_clients:
        assert not log_stream_exists(log_stream=metadata['log_stream_name'], log_group=log_group_name,
                                     client=log_client)

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']
