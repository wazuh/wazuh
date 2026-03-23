# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module will contain all callback methods to monitor and event
"""

import re

# # qa-integration-framework imports
from wazuh_testing.modules.aws.patterns import (AWS_MODULE_STARTED_PARAMETRIZED,
                                                AWS_UNDEFINED_SERVICE_TYPE, AWS_DEPRECATED_CONFIG_DEFINED,
                                                AWS_NO_SERVICE_WARNING, AWS_MODULE_STARTED, INVALID_EMPTY_TYPE_ERROR,
                                                EMPTY_CONTENT_ERROR, EMPTY_CONTENT_WARNING,
                                                INVALID_EMPTY_SERVICE_TYPE_ERROR, INVALID_TAG_CONTENT_ERROR,
                                                PARSING_BUCKET_ERROR_WARNING,
                                                PARSING_SERVICE_ERROR_WARNING, SERVICE_ANALYSIS, BUCKET_ANALYSIS,
                                                MODULE_START, PARSER_ERROR, MODULE_ERROR, NEW_LOG_FOUND, DEBUG_MESSAGE,
                                                EVENTS_COLLECTED, DEBUG_ANALYSISD_MESSAGE, ANALYSISD_EVENT,
                                                AWS_EVENT_HEADER, NO_LOG_PROCESSED, NO_BUCKET_LOG_PROCESSED)
from wazuh_testing.constants.aws import INSPECTOR_TYPE


def make_aws_callback(pattern, prefix=''):
    """Create a callback function from a text pattern.

    Args:
        pattern (str): String to match on the log.
        prefix (str): Regular expression used as prefix before the pattern.

    Returns:
        lambda: Function that returns if there's a match in the file.
    """
    regex = re.compile(r'{}{}'.format(prefix, pattern))
    return lambda line: regex.match(line)


def callback_detect_aws_module_called(parameters):
    """Detect if aws module was called with correct parameters.

    Args:
        parameters (list): Values to check.

    Returns:
        Callable: Callback to match the line.
    """
    pattern = fr'{AWS_MODULE_STARTED_PARAMETRIZED}{" ".join(parameters)}\n*'
    regex = re.compile(pattern)
    return lambda line: regex.match(line)


def callback_detect_aws_error_for_missing_type(line):
    """Detect if the AWS module displays an error about missing type.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """
    if re.match(fr"{AWS_UNDEFINED_SERVICE_TYPE}", line):
        return line


def callback_detect_aws_legacy_module_warning(line):
    """Detect if the AWS module displays a warning about legacy config.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """
    if re.match(fr"{AWS_DEPRECATED_CONFIG_DEFINED}", line):
        return line


def callback_detect_aws_module_warning(line):
    """Detect if the AWS module displays a warning.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """
    if re.match(fr"{AWS_NO_SERVICE_WARNING}", line):
        return line


def callback_detect_aws_module_started(line):
    """Detect if the AWS module was called.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """
    if re.match(fr"{AWS_MODULE_STARTED}", line):
        return line


def callback_detect_aws_empty_value(line):
    """Detect if the AWS module displays a message about an empty value.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if (
            re.match(fr"{INVALID_EMPTY_TYPE_ERROR}", line) or
            re.match(fr"{EMPTY_CONTENT_ERROR}", line) or
            re.match(fr"{EMPTY_CONTENT_WARNING}", line)
    ):
        return line


def callback_detect_aws_invalid_value(line):
    """Detect if the AWS module displays a message about an invalid value.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if (
            re.match(fr"{INVALID_EMPTY_SERVICE_TYPE_ERROR}", line) or
            re.match(fr"{INVALID_TAG_CONTENT_ERROR}", line) or
            re.match(fr"{PARSING_BUCKET_ERROR_WARNING}", line),
            re.match(fr"{PARSING_SERVICE_ERROR_WARNING}", line)
    ):
        return line


def callback_detect_bucket_or_service_call(line):
    """Detect if bucket or service module was called.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if (
            re.match(fr"{SERVICE_ANALYSIS}", line) or
            re.match(fr"{BUCKET_ANALYSIS}", line)
    ):
        return line


def callback_detect_aws_module_start(line):
    """Search for the start message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """
    if re.match(fr"{MODULE_START}", line):
        return line


def callback_detect_all_aws_err(line):
    """Search for the parse or module error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if (re.match(fr"{PARSER_ERROR}", line) or
            re.match(fr"{MODULE_ERROR}", line)
    ):
        return line


def callback_detect_aws_read_err(line):
    """Search for the parser error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if re.match(fr"{PARSER_ERROR}", line):
        return line


def callback_detect_aws_wmodule_err(line):
    """Search for the module error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if re.match(fr"{MODULE_ERROR}", line):
        return line


def callback_detect_event_processed(line):
    """Search for the event processed message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if re.match(fr"{NEW_LOG_FOUND}", line):
        return line


def callback_detect_event_skipped(pattern):
    """Search for event processed or skipped message in the given line.

    Args:
        pattern (str): Pattern to match in line.
    Returns:
        Callable: Callback to match the given line.
    """
    pattern_regex = re.compile(pattern)
    return lambda line: pattern_regex.match(line)


def callback_detect_service_event_processed(expected_results, service_type):
    if service_type == INSPECTOR_TYPE:
        regex = re.compile(fr"{DEBUG_MESSAGE} {expected_results} {EVENTS_COLLECTED}")
    else:
        regex = re.compile(fr"{DEBUG_ANALYSISD_MESSAGE} {expected_results} {ANALYSISD_EVENT}")
    return lambda line: regex.match(line)


def callback_event_sent_to_analysisd(line):
    """Search for the module header message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if line.startswith(fr"{AWS_EVENT_HEADER}"):
        return line
