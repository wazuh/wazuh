import os
import pytest

from wazuh_testing import session_parameters
from wazuh_testing.constants.paths.configurations import TEMPLATE_DIR, TEST_CASES_DIR
from wazuh_testing.modules.aws import event_monitor, local_internal_options  # noqa: F401
from wazuh_testing.modules.aws.cloudwatch_utils import log_stream_exists
from wazuh_testing.modules.aws.s3_utils import file_exists
from wazuh_testing.utils.configuration import (
    get_test_cases_data,
    load_configuration_template,
)

pytestmark = [pytest.mark.server]


# Generic vars
MODULE = 'remove_from_bucket_test_module'
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, TEMPLATE_DIR, MODULE)
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, TEST_CASES_DIR, MODULE)

# ---------------------------------------------------- TEST_REMOVE_FROM_BUCKET -----------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_remove_from_bucket.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_remove_from_bucket.yaml')

t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(
    t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_remove_from_bucket(
    configuration, metadata, mark_cases_as_skipped, upload_and_delete_file_to_s3, load_wazuh_basic_configuration,
    set_wazuh_configuration, clean_s3_cloudtrail_db, configure_local_internal_options_function,
    truncate_monitored_files, restart_wazuh_function, file_monitoring
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
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - upload_and_delete_file_to_s3:
            type: fixture
            brief: Upload a file to S3 bucket for the day of the execution.
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
        '--aws_profile', 'qa',
        '--type', metadata['bucket_type'],
        '--debug', '2'
    ]

    if path is not None:
        parameters.insert(6, path)
        parameters.insert(6, '--trail_prefix')

    # Check AWS module started
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['failed_start']

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_parameters']

    assert not file_exists(filename=metadata['uploaded_file'], bucket_name=bucket_name)

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']


# ---------------------------------------------------- TEST_REMOVE_LOG_STREAM ------------------------------------------
# Configuration and cases data
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_remove_log_stream.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_remove_log_streams.yaml')

t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(
    t2_configurations_path, t2_configuration_parameters, t2_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_remove_log_stream(
    configuration, metadata, create_log_stream, load_wazuh_basic_configuration, set_wazuh_configuration,
    clean_aws_services_db, configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function,
    file_monitoring
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
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - create_log_stream:
            type: fixture
            brief: Create a log stream with events for the day of execution.
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
        '--aws_profile', 'qa',
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

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['failed_start']

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_parameters']

    assert not log_stream_exists(log_stream=metadata['log_stream'], log_group=log_group_name)

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']
