# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import re

def tail_log(file, expected_lines, found_lines, timeout, logger):
    """
    Reads the specified log file and searches for the expected lines.

    Args:
        file (str): The path to the log file.
        expected_lines (list): A list of strings representing the expected lines to search for.
        found_lines (dict): A dictionary mapping expected lines to boolean values indicating if they have been found.
        timeout (int): The maximum time (in seconds) to wait for the expected lines to be found.
        logger: The logger object used for logging.
    """
    start_time = time.time()
    with open(file, "r") as f:
        while not all(found_lines.values()) and (time.time() - start_time <= timeout):
            line = f.readline()
            if not line:
                continue
            # Check if the line contains the expected output
            for expected in expected_lines:
                if expected in line and not found_lines[expected]:
                    logger.info(f"Found log line: {line}")
                    found_lines[expected] = True


def find_regex_in_file(regex, file, logger, times=1, max_timeout=50):
    """
    Searches for a regular expression pattern in a file.

    Args:
        regex (str): The regular expression pattern to search for.
        file (str): The path to the file to search in.
        logger (Logger): The logger object to log debug messages.
        times (int, optional): The number of expected matches of the regex pattern.
        max_timeout (int, optional): The maximum timeout in seconds to wait for the expected matches.

    Returns:
        bool: True if the expected number of matches is found within the timeout, False otherwise.
    """

    pattern = re.compile(regex)
    start_time = time.time()

    while time.time() - start_time < max_timeout:
        count = 0
        with open(file, 'r') as f:
            content = f.read()
            count = len(pattern.findall(content))
            logger.debug(f"Found '{count}' matches of a total of '{times}' expected of regex '{regex}'.")
            if count == times:
                return True
        logger.debug(f"Waiting for regex: '{regex}'")
        time.sleep(1)
    return False
