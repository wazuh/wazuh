# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module will contain all cases for the custom bucket test suite
"""
import pytest
import time

# qa-integration-framework imports
from wazuh_testing import session_parameters

# Local module imports
from . import event_monitor
from .utils import ERROR_MESSAGE, TIMEOUT, local_internal_options
from .configurator import configurator

pytestmark = [pytest.mark.server]

# Set test configurator for the module
configurator.module = "custom_bucket_test_module"

# -------------------------------------------- TEST_CUSTOM_BUCKETS_DEFAULTS -------------------------------------------
# Configure T1 test
configurator.configure_test(configuration_file='custom_bucket_configuration.yaml',
                            cases_file='cases_bucket_custom.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_custom_bucket_defaults(
        test_configuration, metadata, create_test_bucket, set_test_sqs_queue,
        load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files,
        restart_wazuh_function, file_monitoring
):
    """
    description: Test the AWS S3 custom bucket module is invoked with the expected parameters and no error occurs.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check in the ossec.log that no errors occurs.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.7.0
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
        - set_test_sqs_queue:
            type: fixture
            brief: Create temporal SQS queue.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_function:
            type: fixture
            brief: Restart the wazuh service.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check in the log that no errors occurs.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    parameters = [
        'wodles/aws/aws-s3',
        '--subscriber', 'buckets',
        '--queue', metadata['sqs_name'],
        '--debug', '2'
    ]

    log_header = 'Launching S3 Subscriber Command: '
    expected_log = log_header + " ".join(parameters)

    # Check AWS module started
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['failed_start']

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.make_aws_callback(expected_log, prefix='^.*')
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_parameters']

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']


# -------------------------------------------- TEST_CUSTOM_BUCKETS_LOGS -------------------------------------------
# Configure T2 test
configurator.configure_test(configuration_file='custom_bucket_configuration.yaml',
                            cases_file='cases_bucket_custom_logs.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_custom_bucket_logs(
        test_configuration, metadata, create_test_bucket, set_test_sqs_queue, manage_bucket_files,
        load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function,
        file_monitoring
):
    """
    description: Test the AWS S3 custom bucket module is invoked with the expected parameters and retrieve
    the messages from the SQS Queue.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
            - Uploads a file to the S3 Bucket.
        - test:
            - Check in the log that the module was called with correct parameters.
            - Check that the module retrieved a message from the SQS Queue.
            - Check that the module processed a message from the SQS Queue.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Deletes the file created in the S3 Bucket.

    wazuh_min_version: 4.7.0
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
        - set_test_sqs_queue:
            type: fixture
            brief: Create temporal SQS queue.
        - manage_bucket_files:
            type: fixture
            brief: S3 buckets manager.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_function:
            type: fixture
            brief: Restart the wazuh service.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check that the module retrieved a message from the SQS Queue.
        - Check that the module processed a message from the SQS Queue.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    sqs_name = metadata['sqs_name']

    parameters = [
        'wodles/aws/aws-s3',
        '--subscriber', 'buckets',
        '--queue', sqs_name,
        '--debug', '2'
    ]
    log_header = 'Launching S3 Subscriber Command: '
    expected_log = log_header + " ".join(parameters)

    # Check AWS module started
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['failed_start']

    # Give time to the queue to retrieve the messages.
    time.sleep(30)

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.make_aws_callback(expected_log, prefix='^.*')
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_parameters']

    retrieve_pattern = fr'.*Retrieving messages from: {sqs_name}'

    # Check if the message was retrieved from the queue
    log_monitor.start(
        timeout=TIMEOUT[10],
        callback=event_monitor.make_aws_callback(retrieve_pattern)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['failed_sqs_message_retrieval']

    message_pattern = fr'.*The message is: .*'

    # Check if it processes the created file
    log_monitor.start(
        timeout=TIMEOUT[10],
        callback=event_monitor.make_aws_callback(message_pattern)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['failed_message_handling']

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']
