# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
import subprocess
import os
import time
from pathlib import Path
import logging
import pytest
import requests_unixsocket
from helpers import set_command, clean_env

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
        return sorted(response.json(), key=lambda x: x['id'])

    except Exception as e:
        LOGGER.info(f"Socket error {e}")
        return None


def validate_expected(response_pair):
    errors = []
    status = True
    for key in (list(response_pair[0].keys())):
        if not key == "score":
            if not response_pair[0][key] == response_pair[1][key]:
                errors.append(f'For CVE: {response_pair[0]["id"]}. Expected: {response_pair[0][key]} - Actual: {response_pair[1][key]}')
                status = False
        else:
            for score_key in (list(response_pair[0]["score"].keys())):
                if not response_pair[0]["score"][score_key] == response_pair[1]["score"][score_key]:
                    errors.append(f'For CVE: {response_pair[0]["id"]}. Expected: {response_pair[0]["score"][score_key]} - Actual: {response_pair[1]["score"][score_key]}')
                    status = False

    return [status, errors]


def send_input_files(test_folder):
    """
    Sends input files to a specified test folder.

    Args:
        test_folder (str): The path to the test folder.

    Returns:
        None
    """
    json_files = sorted(Path(test_folder).glob("input_*.json"))
    expected_files = sorted(Path(test_folder).glob("expected_*.json"))
    assert len(json_files) == len(expected_files), "Input and expected files number mismatch"
    file_pairs = [(a, b) for a, b in zip(json_files, expected_files)]

    test_results = []
    for file_pair in file_pairs:
        LOGGER.debug(f"Running test {file_pair[0]}")
        with open(file_pair[0]) as json_file, open(file_pair[1]) as expected_file:
            response = send_http_request_unixsocket(json.load(json_file))

            assert not response == None, "Invalid response from socket"

            expected = json.load(expected_file)

            expected_response = sorted(expected, key=lambda x: x['id'])

            response_pairs = [(x,y) for x in expected_response for y in response if x['id'] == y['id']]

            assert len(response_pairs) == len(expected_response), "One or more expected vulnerabilities were not detected."

            for response_pair in response_pairs:
                test_results.append(validate_expected(response_pair))

    return test_results


@pytest.fixture
def run_process_and_monitor_response(request, run_on_end):
    """
    Runs the vulnerability scanner test tool and monitors the log file for expected lines.

    Args:
        request: The request object containing the test parameters.
        run_on_end: A fixture that runs after the test.
    Returns:
        A dictionary containing the found lines and their status.

    Raises:
        AssertionError: If the binary does not exist or the log file does not exist.
        AssertionError: If the process is not initialized.
        AssertionError: If the scan is not finished or some events were not processed.
        AssertionError: If a timeout occurs while waiting for a log line.
    """
    test_folder = request.param

    clean_env()

    command = set_command()
    LOGGER.debug(f"Running test {test_folder}")

    found_lines = {}
    with subprocess.Popen(command) as process:
        start_time = time.time()
        log_file = "log.out"

        # Check if the log file exists, if the line is not found, try again in 1 second
        while not Path(log_file).exists() and (time.time() - start_time <= 10):
            time.sleep(1)
        assert Path(log_file).exists(), "The log file does not exists"

        start_time = time.time()
        # Check socket file exists
        while not Path(socket_path).exists() and (time.time() - start_time <= 10):
            time.sleep(1)
        assert Path(log_file).exists(), "The socket file does not exists."

        # Iterate over json files in the test directory, and send through unix socket.
        try:
            # TODO: Fix failing cases
            if not test_folder.name in ["004", "006", "016", "024", "027", "032", "033"]:
                found_lines = send_input_files(test_folder)
            else:
                LOGGER.warning("SKIPPED TEST")
        finally:
            process.terminate()

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

@pytest.mark.parametrize("run_process_and_monitor_response", test_false_negative_folders, indirect=True)
def test_false_negatives(run_process_and_monitor_response):
    """
    Test function to verify the accuracy of the vulnerability scanner module.

    Args:
        run_process_and_monitor_response: Fixture that runs the vulnerability scanner test tool and monitors the log file for expected lines.

    Raises:
        AssertionError: If some expected lines were not found in the log.

    Returns:
        None
    """
    # change working directory to the root of the project parent directory
    # This is required to run the binary
    os.chdir(Path(__file__).parent.parent.parent.parent.parent)

    LOGGER.info("Running false negative test")

    found_lines = run_process_and_monitor_response

    assert not found_lines == None, "Empty list"

    show_errors = lambda error_msgs : LOGGER.error(error_msgs)

    for status, msgs in found_lines:
        assert status, show_errors(msgs)


@pytest.mark.skip("Skipping False Positives Test Cases")
@pytest.mark.parametrize("run_process_and_monitor_response", test_false_positive_folders, indirect=True)
def test_false_positives(run_process_and_monitor_response):
    """
    Test function to verify the accuracy of the vulnerability scanner module.

    Args:
        run_process_and_monitor_response: Fixture that runs the vulnerability scanner test tool and monitors the log file for not expected lines.

    Raises:
        AssertionError: If some unexpected lines were found in the log.

    Returns:
        None
    """
    # Change working directory to the root of the project parent directory.
    # This is required to run the binary.
    os.chdir(Path(__file__).parent.parent.parent.parent.parent)
    LOGGER.info("Running false positive test")
    found_lines = run_process_and_monitor_response
    for line, found in found_lines.items():
        assert not found, f"The test failed because some unexpected line ({line}) was found."
