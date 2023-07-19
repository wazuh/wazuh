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

# Local module imports
from .utils import ERROR_MESSAGES, TIMEOUTS

pytestmark = [pytest.mark.server]


# Generic vars
MODULE = 'parser_test_module'
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, TEMPLATE_DIR, MODULE)
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, TEST_CASES_DIR, MODULE)

# --------------------------------------------TEST_BUCKET_AND_SERVICE_MISSING ------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_bucket_and_service_missing.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_bucket_and_service_missing.yaml')

# Enabled test configurations
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(
    t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_bucket_and_service_missing(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_warning']


# -------------------------------------------- TEST_TYPE_MISSING_IN_BUCKET ---------------------------------------------
# Configuration and cases data
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_type_missing_in_bucket.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_type_missing_in_bucket.yaml')

# Enabled test configurations
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(
    t2_configurations_path, t2_configuration_parameters, t2_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_type_missing_in_bucket(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_legacy_warning']


# -------------------------------------------- TEST_TYPE_MISSING_IN_SERVICE --------------------------------------------
# Configuration and cases data
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_type_missing_in_service.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_type_missing_in_service.yaml')

# Enabled test configurations
t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(
    t3_configurations_path, t3_configuration_parameters, t3_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_type_missing_in_service(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_error_message']

# -------------------------------------------- TEST_EMPTY_VALUES_IN_BUCKET ---------------------------------------------
# Configuration and cases data
t4_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_values_in_bucket.yaml')
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_empty_values_in_bucket.yaml')

# Enabled test configurations
t4_configuration_parameters, t4_configuration_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)
t4_configurations = load_configuration_template(
    t4_configurations_path, t4_configuration_parameters, t4_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t4_configurations, t4_configuration_metadata), ids=t4_case_ids)
def test_empty_values_in_bucket(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_empty_value_message']

# -------------------------------------------- TEST_EMPTY_VALUES_IN_SERVICE --------------------------------------------
# Configuration and cases data
t5_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_values_in_service.yaml')
t5_cases_path = os.path.join(TEST_CASES_PATH, 'cases_empty_values_in_service.yaml')

# Enabled test configurations
t5_configuration_parameters, t5_configuration_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)
t5_configurations = load_configuration_template(
    t5_configurations_path, t5_configuration_parameters, t5_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t5_configurations, t5_configuration_metadata), ids=t5_case_ids)
def test_empty_values_in_service(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_empty_value_message']


# ------------------------------------------ TEST_INVALID_VALUES_IN_BUCKET ---------------------------------------------
# Configuration and cases data
t6_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_values_in_bucket.yaml')
t6_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_values_in_bucket.yaml')

# Enabled test configurations
t6_configuration_parameters, t6_configuration_metadata, t6_case_ids = get_test_cases_data(t6_cases_path)
t6_configurations = load_configuration_template(
    t6_configurations_path, t6_configuration_parameters, t6_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t6_configurations, t6_configuration_metadata), ids=t6_case_ids)
def test_invalid_values_in_bucket(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_invalid_value,
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_invalid_value_message']


# ------------------------------------------ TEST_INVALID_VALUES_IN_BUCKET ---------------------------------------------
# Configuration and cases data
t7_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_values_in_service.yaml')
t7_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_values_in_service.yaml')

# Enabled test configurations
t7_configuration_parameters, t7_configuration_metadata, t7_case_ids = get_test_cases_data(t7_cases_path)
t7_configurations = load_configuration_template(
    t7_configurations_path, t7_configuration_parameters, t7_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t7_configurations, t7_configuration_metadata), ids=t7_case_ids)
def test_invalid_values_in_service(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_invalid_value_message']


# --------------------------------------- TEST_MULTIPLE_BUCKET_AND_SERVICE_TAGS ----------------------------------------
# Configuration and cases data
t8_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_multiple_bucket_and_service_tags.yaml')
t8_cases_path = os.path.join(TEST_CASES_PATH, 'cases_multiple_bucket_and_service_tags.yaml')

# Enabled test configurations
t8_configuration_parameters, t8_configuration_metadata, t8_case_ids = get_test_cases_data(t8_cases_path)
t8_configurations = load_configuration_template(
    t8_configurations_path, t8_configuration_parameters, t8_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t8_configurations, t8_configuration_metadata), ids=t8_case_ids)
def test_multiple_bucket_and_service_tags(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
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
        timeout=TIMEOUTS[20],
        callback=event_monitor.callback_detect_bucket_or_service_call,
        accumulations=4
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_service_calls_amount']
