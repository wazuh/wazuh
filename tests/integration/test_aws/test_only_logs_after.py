import os
import pytest
from datetime import datetime

# qa-integration-framework imports
from wazuh_testing import session_parameters
from wazuh_testing.constants.paths.configurations import TEMPLATE_DIR, TEST_CASES_DIR
from wazuh_testing.modules import aws as cons
from wazuh_testing.modules.aws import ONLY_LOGS_AFTER_PARAM, event_monitor, local_internal_options  # noqa: F401
from wazuh_testing.modules.aws.cli_utils import call_aws_module
from wazuh_testing.modules.aws.cloudwatch_utils import (
    create_log_events,
    create_log_stream,
)
from wazuh_testing.modules.aws.db_utils import (
    get_multiple_s3_db_row,
    get_service_db_row,
    s3_db_exists,
    services_db_exists,
    get_s3_db_row,
)
from wazuh_testing.modules.aws.s3_utils import get_last_file_key, upload_file
from wazuh_testing.utils.configuration import (
    get_test_cases_data,
    load_configuration_template,
)

from .utils import ERROR_MESSAGES, TIMEOUTS

pytestmark = [pytest.mark.server]


# Generic vars
MODULE = 'only_logs_after_test_module'
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, TEMPLATE_DIR, MODULE)
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, TEST_CASES_DIR, MODULE)

# --------------------------------------------- TEST_BUCKET_WITHOUT_ONLY_LOGS_AFTER ------------------------------------
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'bucket_configuration_without_only_logs_after.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_bucket_without_only_logs_after.yaml')

t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(
    t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_bucket_without_only_logs_after(
    configuration, metadata, upload_and_delete_file_to_s3, load_wazuh_basic_configuration, set_wazuh_configuration,
    clean_s3_cloudtrail_db, configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function,
    file_monitoring
):
    """
    description: Only the log uploaded during execution is processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
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
            brief: Upload a file for the day of the execution and delete after the test.
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
    bucket_type = metadata['bucket_type']
    expected_results = metadata['expected_results']
    table_name = metadata.get('table_name', bucket_type)
    path = metadata.get('path')

    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--aws_profile', 'qa',
        '--type', bucket_type,
        '--debug', '2'
    ]

    if path is not None:
        parameters.insert(5, path)
        parameters.insert(5, '--trail_prefix')

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

    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_event_processed,
        accumulations=expected_results
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_event_number']

    assert s3_db_exists()

    data = get_s3_db_row(table_name=table_name)

    assert bucket_name in data.bucket_path
    assert metadata['uploaded_file'] == data.log_key

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']


# -------------------------------------------- TEST_SERVICE_WITHOUT_ONLY_LOGS_AFTER ------------------------------------
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'service_configuration_without_only_logs_after.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_service_without_only_logs_after.yaml')

t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(
    t2_configurations_path, t2_configuration_parameters, t2_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_service_without_only_logs_after(
    configuration, metadata, create_log_stream_in_existent_group, load_wazuh_basic_configuration,
    set_wazuh_configuration, clean_aws_services_db, configure_local_internal_options_function, truncate_monitored_files,
    restart_wazuh_function, file_monitoring
):
    """
    description: Only the event created during execution is processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.6.0
    parameters:
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - create_log_stream_in_existent_group:
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
        - Check in the bucket that the uploaded log was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    service_type = metadata['service_type']
    log_group_name = metadata['log_group_name']
    expected_results = metadata['expected_results']

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--aws_profile', 'qa',
        '--regions', 'us-east-1',
        '--aws_log_groups', log_group_name,
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

    assert services_db_exists()

    data = get_service_db_row(table_name="cloudwatch_logs")

    assert log_group_name == data.aws_log_group

    assert metadata['log_stream'] == data.aws_log_stream

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']


# --------------------------------------------- TEST_BUCKET_WITH_ONLY_LOGS_AFTER ---------------------------------------
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'bucket_configuration_with_only_logs_after.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_bucket_with_only_logs_after.yaml')

t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(
    t3_configurations_path, t3_configuration_parameters, t3_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_bucket_with_only_logs_after(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration, clean_s3_cloudtrail_db,
    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: All logs with a timestamp greater than the only_logs_after value are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.6.0
    parameters:
        - configuration:
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
    bucket_type = metadata['bucket_type']
    only_logs_after = metadata['only_logs_after']
    expected_results = metadata['expected_results']
    table_name = metadata.get('table_name', bucket_type)
    path = metadata.get('path')

    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--aws_profile', 'qa',
        '--only_logs_after', only_logs_after,
        '--type', bucket_type,
        '--debug', '2'
    ]

    if path is not None:
        parameters.insert(5, path)
        parameters.insert(5, '--trail_prefix')

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

    log_monitor.start(
        timeout=TIMEOUTS[20],
        callback=event_monitor.callback_detect_event_processed,
        accumulations=expected_results
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_event_number']

    assert s3_db_exists()

    for row in get_multiple_s3_db_row(table_name=table_name):
        assert bucket_name in row.bucket_path
        assert (
            datetime.strptime(only_logs_after, '%Y-%b-%d') < datetime.strptime(str(row.created_date), '%Y%m%d')
        )

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']


# --------------------------------------------TEST_CLOUDWATCH_WITH_ONLY_LOGS_AFTER -------------------------------------
t4_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'cloudwatch_configuration_with_only_logs_after.yaml')
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_cloudwatch_with_only_logs_after.yaml')

t4_configuration_parameters, t4_configuration_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)
t4_configurations = load_configuration_template(
    t4_configurations_path, t4_configuration_parameters, t4_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t4_configurations, t4_configuration_metadata), ids=t4_case_ids)
def test_cloudwatch_with_only_logs_after(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration, clean_aws_services_db,
    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: All events with a timestamp greater than the only_logs_after value are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.6.0
    parameters:
        - configuration:
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
        - Check in the bucket that the uploaded log was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    table_name_map = {
        'inspector': 'aws_services',
        'cloudwatchlogs': 'cloudwatch_logs'
    }

    service_type = metadata['service_type']
    log_group_name = metadata.get('log_group_name')
    only_logs_after = metadata['only_logs_after']
    expected_results = metadata['expected_results']

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--aws_profile', 'qa',
        '--only_logs_after', only_logs_after,
        '--regions', 'us-east-1',
        '--aws_log_groups', log_group_name,
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

    log_monitor.start(
        timeout=TIMEOUTS[10],
        callback=event_monitor.callback_detect_service_event_processed(expected_results, service_type),
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_event_number']

    assert services_db_exists()

    data = get_service_db_row(table_name=table_name_map[service_type])

    assert log_group_name == data.aws_log_group
    assert metadata['log_stream'] == data.aws_log_stream

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']


# ------------------------------------------ TEST_INSPECTOR_WITH_ONLY_LOGS_AFTER ---------------------------------------
t5_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'inspector_configuration_with_only_logs_after.yaml')
t5_cases_path = os.path.join(TEST_CASES_PATH, 'cases_inspector_with_only_logs_after.yaml')

t5_configuration_parameters, t5_configuration_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)
t5_configurations = load_configuration_template(
    t5_configurations_path, t5_configuration_parameters, t5_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t5_configurations, t5_configuration_metadata), ids=t5_case_ids)
def test_inspector_with_only_logs_after(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration, clean_aws_services_db,
    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring
):
    """
    description: All events with a timestamp greater than the only_logs_after value are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.6.0
    parameters:
        - configuration:
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
        - Check in the bucket that the uploaded log was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    table_name_map = {
        'inspector': 'aws_services',
        'cloudwatchlogs': 'cloudwatch_logs'
    }

    service_type = metadata['service_type']
    only_logs_after = metadata['only_logs_after']
    expected_results = metadata['expected_results']

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--aws_profile', 'qa',
        '--only_logs_after', only_logs_after,
        '--regions', 'us-east-1',
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

    log_monitor.start(
        timeout=TIMEOUTS[10],
        callback=event_monitor.callback_detect_service_event_processed(expected_results, service_type),
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_event_number']

    assert services_db_exists()

    data = get_service_db_row(table_name=table_name_map[service_type])

    assert data.service == service_type
    assert (
        datetime.strptime(data.timestamp, '%Y-%m-%d %H:%M:%S.%f') == datetime.strptime(only_logs_after, '%Y-%b-%d')
    )


# ---------------------------------------------------- TEST_MULTIPLE_CALLS ---------------------------------------------
t5_cases_path = os.path.join(TEST_CASES_PATH, 'cases_bucket_multiple_calls.yaml')

_, t5_configuration_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('metadata', t5_configuration_metadata, ids=t5_case_ids)
def test_bucket_multiple_calls(
    metadata, clean_s3_cloudtrail_db, load_wazuh_basic_configuration, restart_wazuh_function, delete_file_from_s3
):
    """
    description: Call the AWS module multiple times with different only_logs_after values.
    test_phases:
        - setup:
            - Delete the `s3_cloudtrail.db`.

        - test:
            - Call the module without only_logs_after and check that no logs were processed.
            - Upload a log file for the day of the test execution and call the module with the same parameters as
              before, check that the uploaded logs were processed.
            - Call the module with the same parameters and check that no logs were processed, there were no duplicates.
            - Call the module with only_logs_after set in the past and check that the expected number of logs were
              processed.
            - Call the module with the same parameters in and check there were no duplicates.
            - Call the module with only_logs_after set with an older date check that old logs were processed without
              duplicates.
            - Call the module with only_logs_after set with an early date than setted previously and check that no logs
              were processed, there were no duplicates.

        - teardown:
            - Delete the `s3_cloudtrail.db`.
            - Delete the uploaded files.
    wazuh_min_version: 4.6.0
    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - clean_s3_cloudtrail_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - restart_wazuh_daemon:
            type: fixture
            brief: Restart the wazuh service.
        - delete_file_from_s3:
            type: fixture
            brief: Delete the a file after the test execution.
    input_description:
        - The `cases_multiple_calls` file provides the test cases.
    """

    bucket_type = metadata['bucket_type']
    bucket_name = metadata['bucket_name']
    path = metadata.get('path')

    base_parameters = [
        '--bucket', bucket_name,
        '--type', bucket_type,
        '--regions', 'us-east-1',
        '--aws_profile', 'qa',
        '--debug', '2'
    ]

    if path is not None:
        base_parameters.extend(['--trail_prefix', path])

    # Call the module without only_logs_after and check that no logs were processed
    last_marker_key = datetime.utcnow().strftime(cons.PATH_DATE_FORMAT)

    event_monitor.check_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters),
        bucket_type=bucket_type
    )

    # Call the module with only_logs_after set in the past and check that the expected number of logs were
    # processed
    event_monitor.check_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2022-NOV-20'),
        expected_results=3
    )

    # Call the module with the same parameters in and check there were no duplicates
    expected_skipped_logs_step_3 = metadata.get('expected_skipped_logs_step_3', 1)
    event_monitor.check_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2022-NOV-20'),
        bucket_type=bucket_type,
        expected_results=expected_skipped_logs_step_3
    )

    # Call the module with only_logs_after set with an early date than setted previously and check that no logs
    # were processed, there were no duplicates
    event_monitor.check_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2022-NOV-22'),
        bucket_type=bucket_type,
        expected_results=expected_skipped_logs_step_3 - 1 if expected_skipped_logs_step_3 > 1 else 1
    )

    # Upload a log file for the day of the test execution and call the module without only_logs_after and check that
    # only the uploaded logs were processed and the last marker is specified in the DB.
    last_marker_key = get_last_file_key(bucket_type, bucket_name, datetime.utcnow())
    metadata['filename'] = upload_file(bucket_type, bucket_name)

    event_monitor.check_marker_from_output(
        command_output=call_aws_module(*base_parameters),
        file_key=last_marker_key
    )


# -------------------------------------------- TEST_INSPECTOR_MULTIPLE_CALLS -------------------------------------------
t6_cases_path = os.path.join(TEST_CASES_PATH, 'cases_inspector_multiple_calls.yaml')

_, t6_configuration_metadata, t6_case_ids = get_test_cases_data(t6_cases_path)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('metadata', t6_configuration_metadata, ids=t6_case_ids)
@pytest.mark.xfail
def test_inspector_multiple_calls(
    metadata, clean_aws_services_db, load_wazuh_basic_configuration, restart_wazuh_function
):
    """
    description: Call the AWS module multiple times with different only_logs_after values.
    test_phases:
        - setup:
            - Delete the `aws_services.db`.
        - test:
            - Call the module without only_logs_after and check that no logs were processed.
            - Call the module with only_logs_after set in the past and check that the expected number of logs were
              processed.
            - Call the module with the same parameters in and check there were no duplicates.
            - Call the module with only_logs_after set with an early date than setted previously and check that no logs
              were processed, there were no duplicates.
        - teardown:
            - Delete the `aws_services.db`.
    wazuh_min_version: 4.6.0
    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - clean_aws_services_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - restart_wazuh_daemon:
            type: fixture
            brief: Restart the wazuh service.
    input_description:
        - The `cases_multiple_calls` file provides the test cases.
    """

    service_type = metadata['service_type']

    base_parameters = [
        '--service', service_type,
        '--regions', 'us-east-1',
        '--aws_profile', 'qa',
        '--debug', '2'
    ]

    # Call the module without only_logs_after and check that no logs were processed
    event_monitor.check_service_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters), service_type=service_type, expected_results=1
    )

    # Call the module with only_logs_after set in the past and check that the expected number of logs were
    # processed
    event_monitor.check_service_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-30'),
        service_type=service_type,
        events_sent=4
    )

    # Call the module with the same parameters in and check there were no duplicates
    event_monitor.check_service_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-30'),
        service_type=service_type,
        expected_results=1
    )

    # Call the module with only_logs_after set with an early date than setted previously and check that no logs
    # were processed, there were no duplicates
    event_monitor.check_service_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-31'),
        service_type=service_type,
        expected_results=1
    )


# ----------------------------------------- TEST_CLOUDWATCH_MULTIPLE_CALLS ---------------------------------------------
t7_cases_path = os.path.join(TEST_CASES_PATH, 'cases_cloudwatch_multiple_calls.yaml')

_, t7_configuration_metadata, t7_case_ids = get_test_cases_data(t7_cases_path)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('metadata', t7_configuration_metadata, ids=t7_case_ids)
def test_cloudwatch_multiple_calls(
    metadata, clean_aws_services_db, load_wazuh_basic_configuration, restart_wazuh_function, delete_log_stream
):
    """
    description: Call the AWS module multiple times with different only_logs_after values.
    test_phases:
        - setup:
            - Delete the `aws_services.db`.
        - test:
            - Call the module without only_logs_after and check that no logs were processed.
            - Upload a log file for the day of the test execution and call the module with the same parameters as
              before, check that the uploaded logs were processed.
            - Call the module with the same parameters and check that no logs were processed, there were no duplicates.
            - Call the module with only_logs_after set in the past and check that the expected number of logs were
              processed.
            - Call the module with the same parameters in and check there were no duplicates.
            - Call the module with only_logs_after set with an older date check that old logs were processed without
              duplicates.
            - Call the module with only_logs_after set with an early date than setted previously and check that no logs
              were processed, there were no duplicates.
        - teardown:
            - Delete the `aws_services.db`.
            - Delete the uploaded files.
    wazuh_min_version: 4.6.0
    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - clean_aws_services_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - restart_wazuh_daemon:
            type: fixture
            brief: Restart the wazuh service.
        - delete_log_stream:
            type: fixture
            brief: Delete the log stream after the test execution.
    input_description:
        - The `cases_multiple_calls` file provides the test cases.
    """

    service_type = metadata['service_type']
    log_group_name = metadata['log_group_name']

    base_parameters = [
        '--service', service_type,
        '--aws_log_groups', log_group_name,
        '--regions', 'us-east-1',
        '--aws_profile', 'qa',
        '--debug', '2'
    ]

    # Call the module without only_logs_after and check that no logs were processed
    event_monitor.check_service_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters), service_type=service_type, expected_results=0
    )

    # Call the module with only_logs_after set in the past and check that the expected number of logs were
    # processed
    event_monitor.check_service_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-12'),
        service_type=service_type,
        events_sent=3
    )

    # Call the module with the same parameters in and check there were no duplicates
    event_monitor.check_service_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-12'),
        service_type=service_type,
        expected_results=0
    )

    # Call the module with only_logs_after set with an early date than setted previously and check that no logs
    # were processed, there were no duplicates
    event_monitor.check_service_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-15'),
        service_type=service_type,
        expected_results=0
    )

    # Upload a log file for the day of the test execution and call the module without only_logs_after and check that
    # only the uploaded logs were processed.
    log_stream = create_log_stream()
    metadata['log_stream'] = log_stream
    create_log_events(log_stream)
    event_monitor.check_service_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters), service_type=service_type, events_sent=1
    )
