# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    This file contain constant and other utilities to be used in the AWS integration test module.
"""

# qa-integration-framework imports
from wazuh_testing.modules.monitord import configuration as monitord_config

from os.path import join, dirname, realpath

# CONSTANTS
TEMPLATE_DIR = 'configuration_template'
TEST_CASES_DIR = 'test_cases'
WAZUH_MODULES_DEBUG = 'wazuh_modules.debug'

# DICTS
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
    "event_not_found": "The expected log pattern was not found",
    "incorrect_marker": "The AWS module did not use the correct marker",
    "incorrect_no_region_found_message": "The AWS module did not show correct message about non-existent region",
    "incorrect_discard_regex_message": "The AWS module did not show the correct message about discard regex or, "
                                       "did not process the expected amount of logs",
    "failed_sqs_message_retrieval": "The AWS module did not retrieve the expected message from the SQS Queue",
    "failed_message_handling": "The AWS module did not handle the expected message",
    "file_not_removed": "The AWS did not show the expected removed file from S3 message"
}

TIMEOUT = {
    10: 10,
    20: 20,
    30: 30,
    40: 40,
    50: 50
}

# Paths
TEST_DATA_PATH = join(dirname(realpath(__file__)), 'data')

# Set local internal options
local_internal_options = {WAZUH_MODULES_DEBUG: '2',
                          monitord_config.MONITORD_ROTATE_LOG: '0'}
