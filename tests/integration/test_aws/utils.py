# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    This file contain constant and other utilities to be used in the AWS integration test module.
"""

# qa-integration-framework imports
from wazuh_testing.utils.configuration import (
    get_test_cases_data,
    load_configuration_template,
)
from wazuh_testing.modules.monitord import configuration as monitord_config

from os.path import join, dirname, realpath

# CONSTANTS
TEMPLATE_DIR = 'configuration_template'
TEST_CASES_DIR = 'test_cases'
WAZUH_MODULES_DEBUG = 'wazuh_modules.debug'

ERROR_MESSAGE = {

    "failed_start": "The AWS module did not start as expected",
    "incorrect_parameters": "The AWS module was not called with the correct parameters",
    "error_found": "Found error message on AWS module",
    "incorrect_event_number": "The AWS module did not process the expected number of events",
    "incorrect_non-existent_region_message": "The AWS module did not show correct message about non-existent region",
    "incorrect_no_existent_log_group": "The AWS module did not show correct message non-existent log group",
    "incorrect_empty_path_message": "The AWS module did not show correct message about empty path",
    "incorrect_empty_path_suffix_message": "The AWS module did not show correct message about empty path_suffix",
    "incorrect_error_message": "The AWS module did not show the expected error message",
    "incorrect_empty_value_message": "The AWS module did not show the expected message about empty value",
    "incorrect_legacy_warning": "The AWS module did not show the expected legacy warning",
    "incorrect_warning": "The AWS module did not show the expected warning",
    "incorrect_invalid_value_message": "The AWS module did not show the expected message about invalid value",
    "incorrect_service_calls_amount": "The AWS module was not called for bucket or service the right amount of times",
    "unexpected_number_of_events_found": "Some logs may have been processed, "
                                         "or the results found are more than expected",
    "incorrect_marker": "The AWS module did not use the correct marker",
    "incorrect_no_region_found_message": "The AWS module did not show correct message about non-existent region",
    "incorrect_discard_regex_message": "The AWS module did not show the correct message about discard regex or, "
                                       "did not process the expected amount of logs",
    "failed_sqs_message_retrieval": "The AWS module did not retrieve the expected message from the SQS Queue",
    "failed_message_handling": "The AWS module did not handle the expected message"
}

TIMEOUT = {
    10: 10,
    20: 20
}

# Paths
TEST_DATA_PATH = join(dirname(realpath(__file__)), 'data')


# Set local internal options
local_internal_options = {WAZUH_MODULES_DEBUG: '2',
                          monitord_config.MONITORD_ROTATE_LOG: '0'}


# Classes
class TestConfigurator:
    """
    TestConfigurator class is responsible for configuring test data and parameters for a specific test module.

    Attributes:
    - module (str): The name of the test module.
    - configuration_path (str): The path to the configuration directory for the test module.
    - test_cases_path (str): The path to the test cases directory for the test module.
    - metadata (list): Test metadata retrieved from the test cases.
    - parameters (list): Test parameters retrieved from the test cases.
    - cases_ids (list): Identifiers for the test cases.
    - test_configuration_template (list): The loaded configuration template for the test module.

    """
    def __init__(self, module):
        self.module = module
        self.configuration_path = join(TEST_DATA_PATH, TEMPLATE_DIR, self.module)
        self.test_cases_path = join(TEST_DATA_PATH, TEST_CASES_DIR, self.module)
        self.metadata = None
        self.parameters = None
        self.cases_ids = None
        self.test_configuration_template = None

    def configure_test(self, configuration_file="", cases_file=""):
        """
        Configures the test data and parameters for the given test module.

        Args:
        - configuration_file (str): The name of the configuration file.
        - cases_file (str): The name of the test cases file.

        Returns:
        None
        """
        # Set test cases path
        cases_path = join(self.test_cases_path, cases_file)

        # set test cases data
        self.parameters, self.metadata, self.cases_ids = get_test_cases_data(cases_path)

        # Set test configuration template for tests with config files
        if configuration_file != "":
            # Set config path
            configurations_path = join(self.configuration_path, configuration_file)

            # load configuration template
            self.test_configuration_template = load_configuration_template(
                configurations_path,
                self.parameters,
                self.metadata
            )
