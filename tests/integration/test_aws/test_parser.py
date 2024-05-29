# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module will contain all cases for the parser test suite
"""

import pytest

# qa-integration-framework imports
from wazuh_testing import session_parameters

# Local module imports
from . import event_monitor
from .configurator import configurator
from .utils import ERROR_MESSAGE, TIMEOUT, local_internal_options

pytestmark = [pytest.mark.server]

# Set test configurator for the module
configurator.module = 'parser_test_module'

# --------------------------------------------TEST_BUCKET_AND_SERVICE_MISSING ------------------------------------------
# Configure T1 test
configurator.configure_test(configuration_file='configuration_bucket_and_service_missing.yaml',
                            cases_file='cases_bucket_and_service_missing.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_bucket_and_service_missing(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: Command for bucket and service weren't invoked.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was not called.

    input_description:
        - The `configuration_bucket_and_service_missing` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_warning,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_warning']


# -------------------------------------------- TEST_TYPE_MISSING_IN_BUCKET ---------------------------------------------
# Configure T2 test
configurator.configure_test(configuration_file='configuration_type_missing_in_bucket.yaml',
                            cases_file='cases_type_missing_in_bucket.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_type_missing_in_bucket(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: A warning occurs and was displayed in `ossec.log`.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module displays the message about missing attributes.
    input_description:
        - The `configuration_type_missing_in_bucket` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_legacy_module_warning,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_legacy_warning']


# -------------------------------------------- TEST_TYPE_MISSING_IN_SERVICE --------------------------------------------
# Configure T3 test
configurator.configure_test(configuration_file='configuration_type_missing_in_service.yaml',
                            cases_file='cases_type_missing_in_service.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_type_missing_in_service(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: An error occurs and was displayed in `ossec.log`.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module displays the message about missing attributes.

    input_description:
        - The `configuration_type_missing_in_service` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_error_for_missing_type,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_error_message']


# -------------------------------------------- TEST_EMPTY_VALUES_IN_BUCKET ---------------------------------------------
# Configure T4 test
configurator.configure_test(configuration_file='configuration_values_in_bucket.yaml',
                            cases_file='cases_empty_values_in_bucket.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_empty_values_in_bucket(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: An error occurs and was displayed in `ossec.log`.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module displays the message about an empty value.
    input_description:
        - The `configuration_values_in_bucket` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_empty_value,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_empty_value_message']


# -------------------------------------------- TEST_EMPTY_VALUES_IN_SERVICE --------------------------------------------
# Configure T5 test
configurator.configure_test(configuration_file='configuration_values_in_service.yaml',
                            cases_file='cases_empty_values_in_service.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_empty_values_in_service(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: An error occurs and was displayed in `ossec.log`.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module displays the message about an empty value.

    input_description:
        - The `configuration_values_in_service` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_empty_value,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_empty_value_message']


# ------------------------------------------ TEST_INVALID_VALUES_IN_BUCKET ---------------------------------------------
# Configure T6 test
configurator.configure_test(configuration_file='configuration_values_in_bucket.yaml',
                            cases_file='cases_invalid_values_in_bucket.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_invalid_values_in_bucket(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: An error occurs and was displayed in `ossec.log`.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module displays the message about an invalid value.
    input_description:
        - The `configuration_values_in_bucket` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=TIMEOUT[20],
        callback=event_monitor.callback_detect_aws_invalid_value,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_invalid_value_message']


# ------------------------------------------ TEST_INVALID_VALUES_IN_BUCKET ---------------------------------------------
# Configure T7 test
configurator.configure_test(configuration_file='configuration_values_in_service.yaml',
                            cases_file='cases_invalid_values_in_service.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_invalid_values_in_service(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: An error occurs and was displayed in `ossec.log`.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module displays the message about an invalid value.
    input_description:
        - The `configuration_values_in_service` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_invalid_value,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_invalid_value_message']


# --------------------------------------- TEST_MULTIPLE_BUCKET_AND_SERVICE_TAGS ----------------------------------------
# Configure T8 test
configurator.configure_test(configuration_file='configuration_multiple_bucket_and_service_tags.yaml',
                            cases_file='cases_multiple_bucket_and_service_tags.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_multiple_bucket_and_service_tags(
        test_configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function_without_exception,
        file_monitoring
):
    """
    description: The command is invoked two times for buckets and two times for services.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has not appeared calling the module with correct parameters.
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
        - restart_wazuh_function_without_exception:
            type: fixture
            brief: Restart the wazuh service catching the exception.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was called the right amount of times.
    input_description:
        - The `configuration_multiple_bucket_and_service_tags` file provides the configuration for this test.
    """
    log_monitor.start(
        timeout=TIMEOUT[20],
        callback=event_monitor.callback_detect_bucket_or_service_call,
        accumulations=4
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_service_calls_amount']
