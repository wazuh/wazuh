import os
import pytest

# qa-integration-framework imports
from wazuh_testing import session_parameters
from wazuh_testing.constants.paths.configurations import TEMPLATE_DIR, TEST_CASES_DIR
from wazuh_testing.modules.aws import event_monitor, local_internal_options  # noqa: F401
from wazuh_testing.utils.configuration import (
    get_test_cases_data,
    load_configuration_template,
)
from wazuh_testing.modules.aws.db_utils import (
    get_multiple_service_db_row,
    services_db_exists,
    table_exists,
)

# Local module imports
from .utils import ERROR_MESSAGES, TIMEOUTS

pytestmark = [pytest.mark.server]


# Generic vars
MODULE = 'log_groups_test_module'
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, TEMPLATE_DIR, MODULE)
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, TEST_CASES_DIR, MODULE)

# ----------------------------------------------- TEST_AWS_LOG_GROUPS --------------------------------------------------
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_log_groups.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_log_groups.yaml')

t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(
    t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_log_groups(
    configuration, metadata, create_log_stream, load_wazuh_basic_configuration, set_wazuh_configuration,
    clean_aws_services_db, configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function,
    file_monitoring
):
    """
    description: Only the events for the specified log_group are processed.
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
        - Check the expected number of events were forwarded to analysisd.
        - Check the database was created and updated accordingly, using the correct path for each entry.
    input_description:
        - The `configuration_regions` file provides the module configuration for this test.
        - The `cases_regions` file provides the test cases.
    """
    service_type = metadata['service_type']
    log_group_names = metadata['log_group_name']
    expected_results = metadata['expected_results']

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--aws_profile', 'qa',
        '--only_logs_after', '2023-JAN-12',
        '--regions', 'us-east-1',
        '--aws_log_groups', log_group_names,
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

    if expected_results:
        log_monitor.start(
            timeout=TIMEOUTS[20],
            callback=event_monitor.callback_detect_service_event_processed(expected_results, service_type),
            accumulations=len(log_group_names.split(','))
        )
    else:
        log_monitor.start(
            timeout=TIMEOUTS[10],
            callback=event_monitor.make_aws_callback(r'.*The specified log group does not exist.'),
        )

        assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_no_existent_log_group']

    assert services_db_exists()

    if expected_results:
        log_group_list = log_group_names.split(",")
        for row in get_multiple_service_db_row(table_name='cloudwatch_logs'):
            assert row.aws_log_group in log_group_list
    else:
        assert not table_exists(table_name='cloudwatch_logs')

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']
