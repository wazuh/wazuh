import os

import pytest
from wazuh_testing import TEMPLATE_DIR, TEST_CASES_DIR, global_parameters, T_10
from wazuh_testing.modules.aws import event_monitor, local_internal_options
from wazuh_testing.tools.configuration import (
    get_test_cases_data,
    load_configuration_template,
)

pytestmark = [pytest.mark.server]

# Generic vars
# Name of the folder test module
MODULE = 'custom_bucket_test_module'
# Path of the data for the tests
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
# Path for the configuration of this module
CONFIGURATION_PATH = os.path.join(TEST_DATA_PATH, TEMPLATE_DIR, MODULE)
# Path for the test cases of this module
TEST_CASE_PATH = os.path.join(TEST_DATA_PATH, TEST_CASES_DIR, MODULE)

# -------------------------------------------- TEST_CUSTOM_BUCKETS_DEFAULTS -------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATION_PATH, 'custom_bucket_configuration.yaml')
t1_cases_path = os.path.join(TEST_CASE_PATH, 'cases_bucket_custom.yaml')

# Enabled test configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(
    t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_custom_bucket_defaults(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                                configure_local_internal_options_function, truncate_monitored_files,
                                restart_wazuh_function, file_monitoring):
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
        '--aws_profile', 'qa',
        '--debug', '2'
    ]
    log_header = 'Launching S3 Subscriber Command: '
    expected_log = log_header + " ".join(parameters)

    # Check AWS module started
    log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start,
        error_message='The AWS module did not start as expected',
    ).result()

    # Check command was called correctly
    log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.make_aws_callback(expected_log, prefix='^.*'),
        error_message='The AWS module was not called with the correct parameters',
    ).result()

    # Detect any ERROR message
    with pytest.raises(TimeoutError):
        log_monitor.start(
            timeout=global_parameters.default_timeout,
            callback=event_monitor.callback_detect_all_aws_err,
        ).result()


# -------------------------------------------- TEST_CUSTOM_BUCKETS_LOGS -------------------------------------------
# Configuration and cases data
t2_configurations_path = os.path.join(CONFIGURATION_PATH, 'custom_bucket_configuration.yaml')
t2_cases_path = os.path.join(TEST_CASE_PATH, 'cases_bucket_custom_logs.yaml')

# Enabled test configurations
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(
    t2_configurations_path, t2_configuration_parameters, t2_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_custom_bucket_logs(configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                            configure_local_internal_options_function, truncate_monitored_files,
                            restart_wazuh_function, file_monitoring, upload_and_delete_file_to_s3):
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
        - upload_and_delete_file_to_s3:
            type: fixture
            brief: Upload a file to S3 bucket for the day of the execution.

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
        '--aws_profile', 'qa',
        '--debug', '2'
    ]
    log_header = 'Launching S3 Subscriber Command: '
    expected_log = log_header + " ".join(parameters)

    # Check AWS module started
    log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start,
        error_message='The AWS module did not start as expected',
    ).result()

    # Check command was called correctly
    log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.make_aws_callback(expected_log, prefix='^.*'),
        error_message='The AWS module was not called with the correct parameters',
    ).result()

    retrieve_pattern = fr'.*Retrieving messages from: {sqs_name}'
    message_pattern = fr'.*The message is: .*'

    # Check if retrieves from the queue
    log_monitor.start(
        timeout=T_10,
        callback=event_monitor.make_aws_callback(retrieve_pattern),
        error_message='The AWS module did not retrieve from the SQS Queue',
    ).result()

    # Check if it processes the created file
    log_monitor.start(
        timeout=T_10,
        callback=event_monitor.make_aws_callback(message_pattern),
        error_message='The AWS module did not handle the message',
    ).result()
