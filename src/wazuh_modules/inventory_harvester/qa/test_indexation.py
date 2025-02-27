"""
Integration Test for the Inventory Harvester with OpenSearch

This test suite uses pytest and Docker to:
1. Spin up an OpenSearch container (single-node, security disabled).
2. Index test data using the 'inventory_harvester_testtool'.
3. Validate that the expected indexes and data are properly created in OpenSearch.

Usage:
- Adjust the 'GLOBAL_URL' and container environment variables as needed.
- Provide test data in subfolders under 'wazuh_modules/inventory_harvester/qa/test_data'
  with names starting with digits (e.g., '000_test' or '100_featureX').

Dependencies:
- pytest
- docker (Docker SDK for Python)
- requests

Run the test:
    python3 -m pytest -xvv wazuh_modules/inventory_harvester/qa/ --log-cli-level=DEBUG
"""

import pytest
import docker
import time
import requests
import logging
import os
import subprocess
import shutil
import json
import re
from pathlib import Path

LOGGER = logging.getLogger(__name__)

#: OpenSearch URL used by the tests.
GLOBAL_URL = 'localhost:9200'


def wait_for_opensearch(url: str, timeout: int = 60) -> None:
    """
    Repeatedly checks if OpenSearch is ready by sending an HTTP GET request.

    :param url: The base URL for checking OpenSearch health.
    :param timeout: Maximum wait time in seconds before giving up.
    :raises RuntimeError: If OpenSearch does not respond in the given timeout.
    """
    for _ in range(timeout):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                LOGGER.info("OpenSearch is ready.")
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    raise RuntimeError(f"OpenSearch not ready after {timeout} seconds.")


def init_opensearch(low_resources: bool) -> docker.DockerClient:
    """
    Initializes and runs an OpenSearch container in single-node mode.

    :param low_resources: Whether to set a lower content-length limit.
    :return: Docker client instance with the container running.
    :raises docker.errors.ContainerError: If container fails to start.
    :raises docker.errors.APIError: If Docker engine encounters an error.
    """
    client = docker.from_env()
    env_vars = {
        'discovery.type': 'single-node',
        'plugins.security.disabled': 'true',
        'OPENSEARCH_INITIAL_ADMIN_PASSWORD': 'WazuhTest99$'
    }

    if low_resources:
        env_vars['http.max_content_length'] = '4mb'

    # If a container named 'opensearch' is running, remove it to avoid naming conflicts
    existing = client.containers.list(all=True, filters={"name": "opensearch"})
    for cnt in existing:
        LOGGER.warning("Removing existing container named 'opensearch'")
        cnt.stop()
        cnt.remove()

    LOGGER.info("Pulling and running opensearchproject/opensearch container...")
    client.containers.run(
        "opensearchproject/opensearch",
        detach=True,
        ports={'9200/tcp': 9200},
        environment=env_vars,
        name='opensearch',
        stdout=True,
        stderr=True
    )

    # Wait until OpenSearch is ready to accept connections
    wait_for_opensearch(f"http://{GLOBAL_URL}")
    return client


@pytest.fixture(scope='function')
def opensearch(request):
    """
    Pytest fixture to manage the lifecycle of the OpenSearch container.

    Param:
    - request.param (bool): If True, limits max content length in the container.

    Yields:
    - docker.DockerClient: The Docker client with the OpenSearch container running.

    Teardown:
    - Stops and removes the container named 'opensearch'.
    """
    low_resources = request.param
    client = init_opensearch(low_resources)
    yield client

    LOGGER.info("Stopping and removing the 'opensearch' container...")
    for container in client.containers.list():
        if container.name == 'opensearch':
            container.stop()
            container.remove()


def is_test_folder_name(name: str) -> bool:
    """
    Checks if the folder name starts with one or more digits (e.g., '000_test').

    :param name: The folder name.
    :return: True if the folder name starts with digits, otherwise False.
    """
    return bool(re.match(r'^\d+', name))


# Collect test folders whose names start with digits (e.g., '000_test')
test_data_path = Path("wazuh_modules/inventory_harvester/qa/test_data")
test_folders = [
    folder for folder in test_data_path.rglob('*')
    if folder.is_dir() and is_test_folder_name(folder.name)
]
test_folders = sorted(str(folder) for folder in test_folders)


@pytest.fixture
def test_folder(request):
    """
    Fixture that returns the current test folder path.
    """
    return request.param


@pytest.mark.parametrize('opensearch', [False], indirect=True)
@pytest.mark.parametrize("test_folder", test_folders, indirect=True)
def test_data_indexation(opensearch, test_folder):
    """
    End-to-end test to verify data indexation in OpenSearch.

    1. Switches to the repository root directory.
    2. Locates the 'inventory_harvester_testtool' binary.
    3. Cleans up logs/queues and runs the test tool with the specified config/template.
    4. Validates index creation and document insertion in OpenSearch.
    """
    # Move to the repository root directory
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    # Attempt to locate the binary in two possible build paths
    cmd = Path(
        "build/wazuh_modules/inventory_harvester/testtool/inventory_harvester_testtool")
    cmd_alt = Path(
        "wazuh_modules/inventory_harvester/build/testtool/inventory_harvester_testtool")

    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The 'inventory_harvester_testtool' binary does not exist."

    # Prepare the log file name
    log_file = f"log_{test_folder.replace('/', '_')}.out"

    # Clean up any previous log file or queue folder
    if Path(log_file).exists():
        Path(log_file).unlink()
    if Path("queue").exists():
        shutil.rmtree("queue")

    LOGGER.debug(f"Running test in folder: '{test_folder}'")
    
    input_dir = Path(test_folder, "inputs/")

    # Build the command with arguments
    args = [
        "-c", str(Path(test_folder, "config.json")),
        "-t", str(Path(test_folder, "template.json")),
        "-l", log_file,
        "-i", str(input_dir)
    ]
    command = [str(cmd)] + args

    LOGGER.info(f"Executing command: {command}")
    process = subprocess.Popen(command)

    # Ensure the process actually started
    assert process.poll() is None, "The inventory harvester test tool failed to start."

    # Load expected result data
    result_json_path = Path(test_folder, "result.json")
    with open(result_json_path, encoding="utf-8") as f:
        result_data = json.load(f)

    # Wait for the process to complete
    process.wait()
    assert process.returncode == 0, "The test tool process exited with an error."

    # Check each index definition in result.json
    for index_info in result_data:
        index_name = index_info["index_name"]
        index_url = f"http://{GLOBAL_URL}/_cat/indices/{index_name}?format=json"
        LOGGER.info(f"Validating index creation: {index_url}")

        # Poll OpenSearch to ensure the index is created
        for attempt in range(10):
            resp = requests.get(index_url)
            if resp.status_code == 200 and len(resp.json()) > 0:
                break
            time.sleep(1)
        else:
            pytest.fail(
                f"The index '{index_name}' was not created within the expected time. "
                f"Response: {resp.text}"
            )

    # Validate the number of documents indexed matches expected data
    for index_info in result_data:
        index_name = index_info["index_name"]
        index_url = f"http://{GLOBAL_URL}/{index_name}/_search"
        resp = requests.get(index_url)
        assert resp.status_code == 200, f"Search request to index '{index_name}' failed."
        hits = resp.json()["hits"]

        expected_size = len(index_info["data"])
        actual_size = hits["total"]["value"]
        assert actual_size == expected_size, (
            f"Mismatch in document count for index '{index_name}'. "
            f"Expected {expected_size}, got {actual_size}."
        )

        # Verify each expected document is present in the hits
        for expected_doc in index_info["data"]:
            found = any(expected_doc == hit["_source"] for hit in hits["hits"])
            assert found, (
                f"Expected document '{expected_doc}' not found in index '{index_name}'. "
                f"Actual hits: {hits['hits']}"
            )
