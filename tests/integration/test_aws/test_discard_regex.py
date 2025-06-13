# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module contains all the cases for the discard_regex test suite.
"""

import pytest

# qa-integration-framework imports
from wazuh_testing import session_parameters
from wazuh_testing.constants.paths.aws import S3_CLOUDTRAIL_DB_PATH, AWS_SERVICES_DB_PATH
from wazuh_testing.modules.aws.utils import path_exist

# Local module imports
from . import event_monitor
from .configurator import configurator
from .utils import ERROR_MESSAGE, TIMEOUT, local_internal_options

pytestmark = [pytest.mark.server]

# Set module name
configurator.module = "discard_regex_test_module"

# --------------------------------------------- TEST_BUCKET_DISCARD_REGEX ---------------------------------------------
# Configure T1 test
configurator.configure_test(configuration_file='configuration_bucket_discard_regex.yaml',
                            cases_file='cases_bucket_discard_regex.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_bucket_discard_regex(
        test_configuration, metadata, create_test_bucket, manage_bucket_files,
        load_wazuh_basic_configuration, set_wazuh_configuration, clean_s3_cloudtrail_db,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring,
):
    """
    description: Check that some bucket logs are excluded when the regex and field defined in <discard_regex>
                 match an event.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket and skips
              the ones that match with regex.
            - Check the database was created and updated accordingly.
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
        - Check the database was created and updated accordingly.
    input_description:
        - The `configuration_bucket_discard_regex` file provides the module configuration for this test.
        - The `cases_bucket_discard_regex` file provides the test cases.
    """
    bucket_name = metadata['bucket_name']
    bucket_type = metadata['bucket_type']
    only_logs_after = metadata['only_logs_after']
    discard_field = metadata['discard_field']
    discard_regex = metadata['discard_regex']
    expected_results = metadata['expected_results']
    skipped_logs = metadata['skipped_logs']
    path = metadata['path'] if 'path' in metadata else None

    pattern = fr'.*The "{discard_regex}" regex found a match in the "{discard_field}" field.' \
              ' The event will be skipped.'

    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--only_logs_after', only_logs_after,
        '--discard-field', discard_field,
        '--discard-regex', discard_regex,
        '--type', bucket_type,
        '--debug', '2'
    ]

    if path is not None:
        parameters.insert(3, path)
        parameters.insert(3, '--trail_prefix')

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
        callback=event_monitor.callback_detect_event_processed,
        accumulations=expected_results
    )

    log_monitor.start(
        timeout=TIMEOUT[20],
        callback=event_monitor.callback_detect_event_skipped(pattern),
        accumulations=skipped_logs
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_discard_regex_message']

    assert path_exist(path=S3_CLOUDTRAIL_DB_PATH)


# ----------------------------------------- TEST_CLOUDWATCH_DISCARD_REGEX_JSON ----------------------------------------
# Configure T2 test
configurator.configure_test(configuration_file='configuration_cloudwatch_discard_regex_json.yaml',
                            cases_file='cases_cloudwatch_discard_regex_json.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_cloudwatch_discard_regex_json(
        test_configuration, metadata, create_test_log_group, create_test_log_stream, manage_log_group_events,
        load_wazuh_basic_configuration, set_wazuh_configuration, clean_aws_services_db,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring,
):
    """
    description: Check that some CloudWatch JSON logs are excluded when the regex and field defined in <discard_regex>
                 match an event.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket and skips
              the ones that match with regex.
            - Check the database was created and updated accordingly.
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
        - Check the database was created and updated accordingly.
    input_description:
        - The `configuration_cloudwatch_discard_regex` file provides the module configuration for this test.
        - The `cases_cloudwatch_discard_regex` file provides the test cases.
    """
    log_group_name = metadata.get('log_group_name')
    service_type = metadata.get('service_type')
    only_logs_after = metadata.get('only_logs_after')
    regions: str = metadata.get('regions')
    discard_field = metadata.get('discard_field', None)
    discard_regex = metadata.get('discard_regex')
    skipped_logs = metadata.get('skipped_logs')

    pattern = fr'.*The "{discard_regex}" regex found a match in the "{discard_field}" field.' \
              ' The event will be skipped.'

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--only_logs_after', only_logs_after,
        '--regions', regions,
        '--aws_log_groups', log_group_name,
        '--discard-field', discard_field,
        '--discard-regex', discard_regex,
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

    log_monitor.start(
        timeout=TIMEOUT[20],
        callback=event_monitor.callback_detect_event_skipped(pattern),
        accumulations=skipped_logs
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_discard_regex_message']

    assert path_exist(path=AWS_SERVICES_DB_PATH)


# ------------------------------------- TEST_CLOUDWATCH_DISCARD_REGEX_SIMPLE_TEXT -------------------------------------
# Configure T3 test
configurator.configure_test(configuration_file='configuration_cloudwatch_discard_regex_simple_text.yaml',
                            cases_file='cases_cloudwatch_discard_regex_simple_text.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_cloudwatch_discard_regex_simple_text(
        test_configuration, metadata, create_test_log_group, create_test_log_stream, manage_log_group_events,
        load_wazuh_basic_configuration, set_wazuh_configuration, clean_aws_services_db,
        configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring,
):
    """
    description: Check that some CloudWatch simple text logs are excluded when the regex defined in <discard_regex>
                 matches an event.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket and skips
              the ones that match with regex.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file

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
        - Check the database was created and updated accordingly.
    input_description:
        - The `configuration_cloudwatch_discard_regex_simple_text` file provides
        the module configuration for this test.
        - The `cases_cloudwatch_discard_regex_simple_text` file provides the test cases.
    """
    log_group_name = metadata.get('log_group_name')
    service_type = metadata.get('service_type')
    only_logs_after = metadata.get('only_logs_after')
    regions: str = metadata.get('regions')
    discard_regex = metadata.get('discard_regex')
    skipped_logs = metadata.get('skipped_logs')

    pattern = fr'.*The "{discard_regex}" regex found a match. The event will be skipped.'

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--only_logs_after', only_logs_after,
        '--regions', regions,
        '--aws_log_groups', log_group_name,
        '--discard-regex', discard_regex,
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

    log_monitor.start(
        timeout=TIMEOUT[20],
        callback=event_monitor.callback_detect_event_skipped(pattern),
        accumulations=skipped_logs
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_discard_regex_message']

    assert path_exist(path=AWS_SERVICES_DB_PATH)


# ------------------------------------------- TEST_INSPECTOR_DISCARD_REGEX --------------------------------------------
# Configure T4 test
configurator.configure_test(configuration_file='configuration_inspector_discard_regex.yaml',
                            cases_file='cases_inspector_discard_regex.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.skip(reason="The Inspector Classic service was deprecated. A migration to Inspector v2 is required")
@pytest.mark.parametrize('test_configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_inspector_discard_regex(
        test_configuration, metadata, load_wazuh_basic_configuration,
        set_wazuh_configuration, clean_aws_services_db, configure_local_internal_options_function,
        truncate_monitored_files, restart_wazuh_function, file_monitoring,
):
    """
    description: Check that some Inspector logs are excluded when the regex and field defined in <discard_regex>
                 match an event.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket and skips
              the ones that match with regex.
            - Check the database was created and updated accordingly.
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
        - Check the database was created and updated accordingly.
    input_description:
        - The `configuration_inspector_discard_regex` file provides the module configuration for this test.
        - The `cases_inspector_discard_regex` file provides the test cases.
    """
    service_type = metadata.get('service_type')
    only_logs_after = metadata.get('only_logs_after')
    regions: str = metadata.get('regions')
    discard_field = metadata.get('discard_field', '')
    discard_regex = metadata.get('discard_regex')
    skipped_logs = metadata.get('skipped_logs')

    pattern = fr'.*The "{discard_regex}" regex found a match in the "{discard_field}" field.' \
              ' The event will be skipped.'

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--only_logs_after', only_logs_after,
        '--regions', regions,
        '--discard-field', discard_field,
        '--discard-regex', discard_regex,
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

    log_monitor.start(
        timeout=TIMEOUT[20],
        callback=event_monitor.callback_detect_event_skipped(pattern),
        accumulations=skipped_logs
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGE['incorrect_discard_regex_message']

    assert path_exist(path=AWS_SERVICES_DB_PATH)
