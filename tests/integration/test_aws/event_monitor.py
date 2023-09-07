import re

from wazuh_testing.modules.aws import VPC_FLOW_TYPE
from wazuh_testing.modules.aws.cli_utils import analyze_command_output
from wazuh_testing.modules.aws.patterns import patterns
from wazuh_testing.modules.aws.errors import errors
from wazuh_testing.constants.aws import INSPECTOR_TYPE


def make_aws_callback(pattern, prefix=''):
    """Create a callback function from a text pattern.

    Args:
        pattern (str): String to match on the log.
        prefix (str): Regular expression used as prefix before the pattern.

    Returns:
        lambda: Function that returns if there's a match in the file.
    """
    pattern = WHITESPACE_REGEX.join(pattern.split())
    regex = re.compile(CURLY_BRACE_MATCH.format(prefix, pattern))

    return lambda line: regex.match(line)


def callback_detect_aws_module_called(parameters):
    """Detect if aws module was called with correct parameters.

    Args:
        parameters (list): Values to check.

    Returns:
        Callable: Callback to match the line.
    """
    pattern = f'{AWS_MODULE_STARTED_PARAMETRIZED} {" ".join(parameters)}\n*'
    regex = re.compile(pattern)
    return lambda line: regex.match(line)


def callback_detect_aws_error_for_missing_type(line):
    """Detect if the AWS module displays an error about missing type.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if re.match(
        AWS_UNDEFINED_SERVICE_TYPE, line
    ):
        return line


def callback_detect_aws_legacy_module_warning(line):
    """Detect if the AWS module displays a warning about legacy config.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if re.match(
        AWS_DEPRECATED_CONFIG_DEFINED, line
    ):
        return line


def callback_detect_aws_module_warning(line):
    """Detect if the AWS module displays a warning.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if re.match(AWS_NO_SERVICE_WARNING, line):
        return line


def callback_detect_aws_module_started(line):
    """Detect if the AWS module was called.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if re.match(AWS_MODULE_STARTED, line):
        return line


def callback_detect_aws_empty_value(line):
    """Detect if the AWS module displays a message about an empty value.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if (
        re.match(INVALID_TYPE_ERROR, line) or
        re.match(EMPTY_CONTENT_ERROR, line) or
        re.match(EMPTY_CONTENT_WARNING, line)
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
        re.match(INVALID_EMPTY_SERVICE_TYPE_ERROR, line) or
        re.match(INVALID_TAG_CONTENT_ERROR, line) or
        re.match(PARSING_BUCKET_ERROR_WARNING, line),
        re.match(PARSING_SERVICE_ERROR_WARNING, line)
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
        re.match(SERVICE_ANALYSIS, line) or
        re.match(BUCKET_ANALYSIS, line)
    ):
        return line


def callback_detect_aws_module_start(line):
    """Search for the start message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: Line if it matches.
    """

    if re.match(MODULE_START, line):
        return line


def callback_detect_all_aws_err(line):
    """Search for the parse or module error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if re.match(PARSER_ERROR, line) or re.match(MODULE_ERROR, line):
        return line


def callback_detect_aws_read_err(line):
    """Search for the parser error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if re.match(PARSER_ERROR, line):
        return line


def callback_detect_aws_wmodule_err(line):
    """Search for the module error message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if re.match(MODULE_ERROR, line):
        return line


def callback_detect_event_processed(line):
    """Search for the event processed message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if re.match(NEW_LOG_FOUND, line):
        return line


def callback_detect_event_processed_or_skipped(pattern):
    """Search for event processed or skipped message in the given line.

    Args:
        pattern (str): Pattern to match in line.
    Returns:
        Callable: Callback to match the given line.
    """
    pattern_regex = re.compile(pattern)
    return lambda line: pattern_regex.match(line) or callback_detect_event_processed(line)


def callback_detect_service_event_processed(expected_results, service_type):
    if service_type == INSPECTOR_TYPE:
        regex = re.compile(f"{DEBUG_MESSAGE} {expected_results} {EVENTS_COLLECTED}")
    else:
        regex = re.compile(f"{DEBUG_ANALYSISD_MESSAGE} {expected_results} {ANALYSISD_EVENT}")
    return lambda line: regex.match(line)


def callback_event_sent_to_analysisd(line):
    """Search for the module header message in the given line.

    Args:
        line (str): Line to match.

    Returns:
        Optional[str]: line if it matches.
    """
    if line.startswith(AWS_EVENT_HEADER):
        return line


def check_processed_logs_from_output(command_output, expected_results=1):
    """Check for processed messages in the give output.

    Args:
        command_output (str): Output to analyze.
        expected_results (int, optional): Number of results to find. Default to 1.
    """
    analyze_command_output(
        command_output=command_output,
        callback=callback_detect_event_processed,
        expected_results=expected_results,
        error_message=INCORRECT_EVENT_NUMBER
    )


def check_non_processed_logs_from_output(command_output, bucket_type, expected_results=1):
    """Check for the non 'processed' messages in the give output.

    Args:
        command_output (str): Output to analyze.
        bucket_type (str): Bucket type to select the message.
        expected_results (int, optional): Number of results to find. Default to 1.
    """
    if bucket_type == VPC_FLOW_TYPE:
        pattern = NO_LOG_PROCESSED
    else:
        pattern = NO_BUCKET_LOG_PROCESSED

    analyze_command_output(
        command_output,
        callback=make_aws_callback(pattern),
        expected_results=expected_results,
        error_message=UNEXPECTED_NUMBER_OF_EVENTS_FOUND
    )


def check_marker_from_output(command_output, file_key, expected_results=1):
    """Check for the marker message in the given output.

    Args:
        command_output (str): Output to analyze.
        file_key (str): Value to check as a marker.
        expected_results (int, optional): Number of results to find. Default to 1.
    """
    pattern = f"{MARKER} {file_key}"

    analyze_command_output(
        command_output,
        callback=make_aws_callback(pattern),
        expected_results=expected_results,
        error_message=INCORRECT_MARKER
    )


def check_service_processed_logs_from_output(
        command_output, events_sent, service_type, expected_results=1
):
    analyze_command_output(
        command_output=command_output,
        callback=callback_detect_service_event_processed(events_sent, service_type),
        expected_results=expected_results,
        error_message=INCORRECT_EVENT_NUMBER
    )


def check_service_non_processed_logs_from_output(command_output, service_type, expected_results=1):
    if service_type == INSPECTOR_TYPE:
        pattern = NO_NEW_EVENTS
    else:
        pattern = EVENT_SENT

    analyze_command_output(
        command_output,
        callback=make_aws_callback(pattern),
        expected_results=expected_results,
        error_message=POSSIBLY_PROCESSED_LOGS
    )
