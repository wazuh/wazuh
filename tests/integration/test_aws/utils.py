# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
    This file contains constant and other utilities to be used in the AWS integration test module.
"""
from os.path import join, dirname, realpath

# CONSTANTS

ERROR_MESSAGES = {

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
    "incorrect_service_calls_amount": "The AWS module was not called for bucket or service the right amount of times"
}

TIMEOUTS = {

    10: 10,
    20: 20
}

# Paths
TEST_DATA_PATH = join(dirname(realpath(__file__)), 'data')
