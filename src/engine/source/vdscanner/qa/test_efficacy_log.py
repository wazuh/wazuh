# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
import subprocess
import socket
import os
import time
from pathlib import Path
import glob
import logging
import pytest
import requests_unixsocket
import requests

from helpers import tail_log, find_regex_in_file


LOGGER = logging.getLogger(__name__)
socket_path = 'test.sock'
endpoint = '/vulnerability/scan'
MAX_RETRY = 3

def send_http_request_unixsocket(data):
    """
    Sends a http data to a Unix socket.

    Args:
        data (bytes): The http data to be sent.

    Returns:
        None: If the socket does not exist or an error occurs during the socket connection or data sending.
    """

    # Connect to http server using Unix socket
    try:
        # Use requests to send data to the socket

        url = f"http+unix://{socket_path.replace('/', '%2F')}{endpoint}"

        # Send the data
        response = requests_unixsocket.post(url, json=data)

        assert response.status_code == 200, f"Error sending data to the socket: {response.status_code}"

    except Exception as e:
        LOGGER.info(f"Socket error {e}")
        return None

def send_input_files(test_folder):
    """
    Sends input files to a specified test folder.

    Args:
        test_folder (str): The path to the test folder.

    Returns:
        None
    """
    json_files = sorted(Path(test_folder).glob("input_*.json"))
    for json_file in json_files:
        LOGGER.debug(f"Running test {json_file}")
        with open(json_file):
            # Set the output file
            file = str(json_file)

            # Parse json file and print the data
            json_data = json.load(open(file))

            # After start to read lines, send the json data
            send_http_request_unixsocket(json_data)


@pytest.fixture
def run_process_and_monitor_log(request, run_on_end):
    """
    Runs the vulnerability scanner test tool and monitors the log file for expected lines.

    Args:
        request: The request object containing the test parameters.
        run_on_end: A fixture that runs after the test.
    Returns:
        A dictionary containing the found lines and their status.

    Raises:
        AssertionError: If the binary does not exist or the log file does not exist.
        AssertionError: If the decompression of the DB did not start.
        AssertionError: If the process is not initialized.
        AssertionError: If the scan is not finished or some events were not processed.
        AssertionError: If a timeout occurs while waiting for a log line.
    """
    test_folder = request.param

    # We verify if the tests will use a compressed content or not
    if Path("queue/vd/feed/").exists():
        if test_folder.name == '000':
            pytest.skip("The decompression test is skipped because there is a compressed content in queue folder")
        else:
            LOGGER.info("The decompressed content will be used")
    else:
        if test_folder.name == '000':
            LOGGER.info("The content will be decompressed")
        else:
            pytest.fail("The test can't continue because there isn't a decompressed content in queue folder")

    # Delete previous inventory directory if exists
    if Path("queue/vd/inventory").exists():
        for file in Path("queue/vd/inventory").glob("*"):
            file.unlink()
        Path("queue/vd/inventory").rmdir()

    # Set the path to the binary
    cmd = Path("engine/build/source/vdscanner/tools/scanner", "vdscanner_tool")
    cmd_alt = Path("engine/source/vdscanner/tools/scanner", "vdscanner_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exists"

    args = ["-l", "log.out",
            "-s", "test.sock"]

    command = [cmd] + args
    LOGGER.debug(f"Running test {test_folder}")

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    found_lines = {}
    with subprocess.Popen(command) as process:
        start_time = time.time()
        log_file = "log.out"

        # Check if the log file exists, if the line is not found, try again in 1 second
        while not Path(log_file).exists() and (time.time() - start_time <= 10):
            time.sleep(1)
        assert Path(log_file).exists(), "The log file does not exists"

        if test_folder.name == '000':
            LOGGER.debug("Waiting for the decompression to start.")
            found = find_regex_in_file(r"Starting database file decompression.", log_file, LOGGER)
            assert found, "The decompression of the DB did not start."
            LOGGER.info("Decompression started")
        else:
            # Check if the process is initialized
            LOGGER.debug("Waiting for the process to be initialized")
            found = find_regex_in_file(r"Vulnerability scanner module started", log_file, LOGGER)
            assert found, "The process is not initialized, timeout waiting vulnerability scanner module to start."
            LOGGER.info("Process initialized")

        expected_json_files = sorted(Path(test_folder).glob("expected_*.out"))
        expected_lines = []
        # Read expected output if it exists, this is an json with and array of lines.
        for expected_json_file in expected_json_files:
            # Parse json and add the string elements of te array to the expected lines
            json_data = json.load(open(expected_json_file))
            for line in json_data:
                expected_lines.append(line)

        LOGGER.debug(f"Expected lines: {expected_lines}")
        quantity_expected_lines = len(expected_lines)
        LOGGER.debug(f"Quantity expected lines: {quantity_expected_lines}")

        found_lines = {line: False for line in expected_lines}
        timeout = 10
        # We set a higher timeout for the decompression test
        if test_folder.name == '000':
            timeout = 30

        # Iterate over json files in the test directory, convert to flatbuffer and send through unix socket
        send_input_files(test_folder)

        # Wait until the scan is finished
        if test_folder.name != '000':
            regex = r"Event type: (.*) processed"
            found = find_regex_in_file(regex, log_file, LOGGER, len(expected_json_files))
            assert found, "The scan is not finished, some events were not processed"
            LOGGER.info("Scan finished, all events were processed")

        retry = 0
        for expected_line in expected_lines:
            while not found_lines[expected_line]:
                if retry < MAX_RETRY:
                    LOGGER.debug(f"Waiting for log line: {expected_line}")
                    tail_log(log_file, expected_lines, found_lines, timeout, LOGGER)
                    retry += 1
                else:
                    # TODO: This shouldn't be an error log in false negative tests
                    LOGGER.error(f"Timeout waiting for log line: {expected_line}")
                    retry = 0
                    break

        process.terminate()

    LOGGER.debug("Waiting for the process to finish")
    return found_lines


test_false_negative_folders = sorted(Path("engine/source/vdscanner/qa/test_false_negative_data").glob(os.getenv('WAZUH_VD_TEST_FN_GLOB', '*')))
test_false_positive_folders = sorted(Path("engine/source/vdscanner/qa/test_false_positive_data").glob(os.getenv('WAZUH_VD_TEST_FP_GLOB', '*')))

# If only variable WAZUH_VD_TEST_FN_GLOB is set, we only run the false negative tests
if os.getenv('WAZUH_VD_TEST_FN_GLOB') and not os.getenv('WAZUH_VD_TEST_FP_GLOB'):
    test_false_positive_folders = []
elif os.getenv('WAZUH_VD_TEST_FP_GLOB') and not os.getenv('WAZUH_VD_TEST_FN_GLOB'):
    test_false_negative_folders = []

@pytest.mark.parametrize("run_process_and_monitor_log", test_false_negative_folders, indirect=True)
def test_false_negatives(run_process_and_monitor_log):
    """
    Test function to verify the accuracy of the vulnerability scanner module.

    Args:
        run_process_and_monitor_log: Fixture that runs the vulnerability scanner test tool and monitors the log file for expected lines.

    Raises:
        AssertionError: If some expected lines were not found in the log.

    Returns:
        None
    """
    # change working directory to the root of the project parent directory
    # This is required to run the binary
    os.chdir(Path(__file__).parent.parent.parent.parent.parent)

    LOGGER.info("Running false negative test")

    found_lines = run_process_and_monitor_log
    for line, found in found_lines.items():
        if not found:
            LOGGER.error(f"Log entry not found: {line}")
    assert all(found_lines.values()), "The test failed because some expected lines were not found"

@pytest.mark.parametrize("run_process_and_monitor_log", test_false_positive_folders, indirect=True)
def test_false_positives(run_process_and_monitor_log):
    """
    Test function to verify the accuracy of the vulnerability scanner module.

    Args:
        run_process_and_monitor_log: Fixture that runs the vulnerability scanner test tool and monitors the log file for not expected lines.

    Raises:
        AssertionError: If some unexpected lines were found in the log.

    Returns:
        None
    """
    # Change working directory to the root of the project parent directory.
    # This is required to run the binary.
    os.chdir(Path(__file__).parent.parent.parent.parent.parent)
    LOGGER.info("Running false positive test")
    found_lines = run_process_and_monitor_log
    for line, found in found_lines.items():
        assert not found, f"The test failed because some unexpected line ({line}) was found."
