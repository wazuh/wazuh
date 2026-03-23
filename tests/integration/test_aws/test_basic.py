# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module will contain all cases for the basic test suite
"""
import pytest

# qa-integration-framework imports
from wazuh_testing import session_parameters

# Local module imports
from . import event_monitor
from .utils import ERROR_MESSAGE, local_internal_options
from .configurator import configurator

pytestmark = [pytest.mark.server]

# Set module name
configurator.module = "basic_test_module"

# -------------------------------------------- TEST_BUCKET_DEFAULTS ----------------------------------------------------
# Configure T1 test
configurator.configure_test(configuration_file='bucket_configuration_defaults.yaml',
                            cases_file='cases_bucket_defaults.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_bucket_defaults(
        test_configuration, metadata, create_test_bucket, load_wazuh_basic_configuration, set_wazuh_configuration,
        clean_s3_cloudtrail_db, configure_local_internal_options_function, truncate_monitored_files,
        restart_wazuh_function, file_monitoring
):
    """
    description: The module is invoked with the expected parameters and no error occurs.
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
        - Check in the log that no errors occurs.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', metadata['bucket_name'],
        '--type', metadata['bucket_type'],
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

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']


# -------------------------------------------- TEST_CLOUDWATCH_DEFAULTS ------------------------------------------------
# Configure T2 test
configurator.configure_test(configuration_file='cloudwatch_configuration_defaults.yaml',
                            cases_file='cases_cloudwatch_defaults.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_service_defaults(
        test_configuration, metadata, create_test_log_group, load_wazuh_basic_configuration,
        set_wazuh_configuration, clean_aws_services_db, configure_local_internal_options_function,
        truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: The module is invoked with the expected parameters and no error occurs.
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
        - Check in the log that no errors occurs.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    log_groups = metadata.get('log_group_name')

    parameters = [
        'wodles/aws/aws-s3',
        '--service', metadata['service_type'],
        '--regions', 'us-east-1',
        '--aws_log_groups', log_groups,
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

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']


# ------------------------------------------ TEST_INSPECTOR_DEFAULTS ---------------------------------------------------
# Configure T3 test
configurator.configure_test(configuration_file='inspector_configuration_defaults.yaml',
                            cases_file='cases_inspector_defaults.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_inspector_defaults(
        test_configuration, metadata, create_test_log_group, load_wazuh_basic_configuration,
        set_wazuh_configuration, clean_aws_services_db, configure_local_internal_options_function,
        truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: The module is invoked with the expected parameters and no error occurs.
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
        - Check in the log that no errors occurs.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """

    parameters = [
        'wodles/aws/aws-s3',
        '--service', metadata['service_type'],
        '--regions', 'us-east-1',
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

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGE['error_found']
