"""
Integration Test Suite for the Inventory Harvester with Pre-Existing Data in OpenSearch

Enhancement:
- Clear all indices in OpenSearch before each test runs, ensuring a clean slate.

Usage:
    python3 -m pytest -vv path/to/tests.py --log-cli-level=DEBUG

Dependencies:
- Python 3
- pytest
- docker (Docker SDK for Python)
- requests
"""

import pytest
import docker
import time
import requests
import logging
import os
import subprocess
import json
import shutil
from pathlib import Path

LOGGER = logging.getLogger(__name__)

#: URL for the OpenSearch container
GLOBAL_URL = 'localhost:9300'


def wait_for_opensearch(url: str, timeout: int = 60) -> None:
    """
    Polls the given URL until OpenSearch responds or until the timeout is reached.
    Raises RuntimeError if OpenSearch does not become ready in time.
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
    raise RuntimeError(f"OpenSearch was not ready after {timeout} seconds.")


@pytest.fixture(scope='session')
def opensearch():
    """
    Starts a single OpenSearch container (single-node mode) for the entire test session.
    Removes the container after all tests have finished.

    Yields:
        docker.DockerClient: Docker client with the OpenSearch container running.
    """
    client = docker.from_env()

    # Remove any container named 'opensearch' if it exists, to avoid conflicts
    existing = client.containers.list(all=True, filters={"name": "opensearch"})
    for cnt in existing:
        LOGGER.warning("Removing existing container named 'opensearch'.")
        cnt.stop()
        cnt.remove()

    env_vars = {
        'discovery.type': 'single-node',
        'plugins.security.disabled': 'true',
        'OPENSEARCH_INITIAL_ADMIN_PASSWORD': 'WazuhTest99$'
    }

    LOGGER.info(
        "Starting a single-node OpenSearch container for the test session.")
    client.containers.run(
        "opensearchproject/opensearch",
        detach=True,
        ports={'9200/tcp': 9200},
        environment=env_vars,
        name='opensearch',
        stdout=True,
        stderr=True
    )

    try:
        wait_for_opensearch(f"http://{GLOBAL_URL}")
        LOGGER.info("OpenSearch container is up for the session.")
        yield client
    finally:
        LOGGER.info(
            "Stopping and removing the 'opensearch' container after all tests.")
        for container in client.containers.list():
            if container.name == 'opensearch':
                container.stop()
                container.remove()


@pytest.fixture(scope='function', autouse=True)
def clear_all_indices():
    """
    Automatically deletes all indexes before each test,
    ensuring each test begins with a clean OpenSearch state.
    """
    delete_url = f"http://{GLOBAL_URL}/_all"
    try:
        LOGGER.info("Deleting all indices from OpenSearch before test.")
        resp = requests.delete(delete_url)
        # 200 OK or 404 Not Found are typically acceptable responses when deleting
        if resp.status_code not in (200, 404):
            raise RuntimeError(
                f"Failed to delete all indices. Status: {resp.status_code}, body: {resp.text}"
            )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Error deleting all indices: {e}")
    yield
    # No teardown needed; we only clear before the test.


def is_test_folder_name(name: str) -> bool:
    """
    Returns True if the folder name begins with digits (e.g., '000_test').
    """
    return name and name[0].isdigit()


# Locate test folders under 'wazuh_modules/inventory_harvester/qa/test_data'
# whose names begin with digits (e.g., '000_test')
test_data_path = Path("wazuh_modules/inventory_harvester/qa/test_data")
test_folders = [
    folder for folder in test_data_path.rglob('*')
    if folder.is_dir() and is_test_folder_name(folder.name)
]
test_folders = sorted(str(folder) for folder in test_folders)


@pytest.fixture
def test_folder(request):
    """
    Provides the path to the current test folder.
    """
    return request.param


@pytest.mark.parametrize("test_folder", test_folders, indirect=True)
def test_data_indexation(opensearch, test_folder):
    """
    Integration test that verifies data indexation in OpenSearch, optionally loading pre-existing data.

    Steps:
        1. Move to the repository root directory.
        2. (Optional) If 'pre_existing_data.json' exists, create required indexes
           and insert that data into OpenSearch before running the main test.
        3. Run the 'inventory_harvester_testtool' with the specified config, template, and inputs.
        4. Validate that the final indexes match the expected documents in 'result.json'.

    Logs and 'queue' directories are retained only if the test fails; otherwise, they are removed.
    """
    # Change working directory to the repository root
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current working directory: {os.getcwd()}")

    # Locate the test tool binary in one of two possible paths
    cmd_primary = Path(
        "build/wazuh_modules/inventory_harvester/testtool/inventory_harvester_testtool")
    cmd_alternate = Path(
        "wazuh_modules/inventory_harvester/build/testtool/inventory_harvester_testtool")
    cmd = cmd_primary if cmd_primary.exists() else cmd_alternate
    assert cmd.exists(), "The 'inventory_harvester_testtool' binary does not exist."

    log_file = f"log_{test_folder.replace('/', '_')}.out"
    queue_dir = Path("queue")
    pre_existing_file = Path(test_folder, "pre_existing_data.json")

    try:
        # Clean up logs and queue from any previous runs
        if Path(log_file).exists():
            Path(log_file).unlink()
        if queue_dir.exists():
            shutil.rmtree(queue_dir)

        # If pre_existing_data.json exists, load its data before running the main test
        if pre_existing_file.exists():
            LOGGER.info(
                f"Pre-existing data file found: '{pre_existing_file}'. Loading data...")

            # First, create indexes using config and template
            create_command = [
                str(cmd),
                "-c", str(Path(test_folder, "config.json")),
                "-t", str(Path(test_folder, "template.json"))
            ]
            LOGGER.debug(f"Creating indexes with: {create_command}")
            proc_create = subprocess.Popen(
                create_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_create.wait()
            stderr_create = proc_create.stderr.read().decode('utf-8')
            assert proc_create.returncode == 0, (
                f"Failed to create indexes. Return code: {proc_create.returncode}\n"
                f"Stderr: {stderr_create}"
            )
            LOGGER.info(
                "Indexes created successfully for pre-existing data insertion.")

            # Insert documents from pre_existing_data.json
            with pre_existing_file.open('r', encoding='utf-8') as f:
                pre_existing_data = json.load(f)

            for idx in pre_existing_data:
                index_name = idx["index_name"]
                index_url = f"http://{GLOBAL_URL}/{index_name}/_doc"
                for doc in idx["data"]:
                    LOGGER.debug(
                        f"Inserting document into '{index_name}': {doc}")
                    resp = requests.post(index_url, json=doc)
                    assert resp.status_code == 201, (
                        f"Failed to load pre-existing data into '{index_name}'. "
                        f"Status: {resp.status_code}, Response: {resp.text}"
                    )
            LOGGER.info("Pre-existing data loaded successfully.")

        # Prepare main command
        main_command = [
            str(cmd),
            "-c", f"{test_folder}/config.json",
            "-t", f"{test_folder}/template.json",
            "-l", log_file,
            "-i", f"{test_folder}/inputs/"
        ]
        LOGGER.info(f"Running main test command: {main_command}")
        proc_test = subprocess.Popen(
            main_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc_test.poll() is None, "The inventory harvester test tool failed to start."

        # Load the expected results
        result_file = Path(test_folder, "result.json")
        with result_file.open('r', encoding='utf-8') as f:
            expected_results = json.load(f)

        # Wait for the test tool process to complete
        proc_test.wait()
        stderr_output = proc_test.stderr.read().decode('utf-8')
        assert proc_test.returncode == 0, (
            f"Test tool process exited with code {proc_test.returncode}.\n"
            f"Stderr: {stderr_output}"
        )

        # Validate index creation
        for idx_def in expected_results:
            index_name = idx_def["index_name"]
            cat_url = f"http://{GLOBAL_URL}/_cat/indices/{index_name}?format=json"
            LOGGER.info(
                f"Verifying creation of index '{index_name}' at: {cat_url}")
            found_index = False
            for _ in range(10):
                resp_cat = requests.get(cat_url)
                if resp_cat.status_code == 200 and len(resp_cat.json()) > 0:
                    found_index = True
                    break
                time.sleep(1)
            assert found_index, (
                f"Index '{index_name}' was not created within the expected time. "
                f"Response: {resp_cat.text}"
            )

        # Validate document counts and contents
        for idx_def in expected_results:
            index_name = idx_def["index_name"]
            search_url = f"http://{GLOBAL_URL}/{index_name}/_search"
            LOGGER.debug(
                f"Searching documents in index '{index_name}' at: {search_url}")
            resp_search = requests.get(search_url)
            assert resp_search.status_code == 200, (
                f"Search request for index '{index_name}' failed (status {resp_search.status_code})."
            )

            hits_obj = resp_search.json()["hits"]
            actual_count = hits_obj["total"]["value"]
            expected_count = len(idx_def["data"])
            assert actual_count == expected_count, (
                f"Mismatch in document count for index '{index_name}': "
                f"expected {expected_count}, got {actual_count}."
            )

            # Check if each expected document is present
            for expected_doc in idx_def["data"]:
                if not any(expected_doc == hit["_source"] for hit in hits_obj["hits"]):
                    pytest.fail(
                        f"Document {expected_doc} not found in index '{index_name}'. "
                        f"Actual hits: {hits_obj['hits']}"
                    )

    except Exception as exc:
        LOGGER.error(f"Test for '{test_folder}' failed: {exc}")
        # Preserve logs and queue directory for debugging
        raise
    else:
        # Test passed: remove logs and queue directory to keep workspace clean
        if Path(log_file).exists():
            Path(log_file).unlink()
        if queue_dir.exists():
            shutil.rmtree(queue_dir)
