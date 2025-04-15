"""
Integration Test Suite for the Inventory Harvester with Pre-Existing Data in OpenSearch

Enhancement:
- Loads index templates before each test, skipping updates and redundant templates.
- Clears all indices before each test to ensure a clean OpenSearch state.

Usage:
    python3 -m pytest -vv path/to/tests.py --log-cli-level=DEBUG

Dependencies:
- Python 3
- pytest
- docker
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
from urllib.parse import quote
from pathlib import Path

# ---------- Global Constants ----------

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

GLOBAL_URL = "localhost:9200"
TEST_DATA_ROOT = Path("wazuh_modules/inventory_harvester/qa/test_data")
QUEUE_DIR = Path("queue")


# ---------- Utility Functions ----------


def wait_for_opensearch(url: str, timeout: int = 60):
    for _ in range(timeout):
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                LOGGER.info("OpenSearch is ready.")
                return
        except requests.ConnectionError:
            pass
        time.sleep(1)
    raise RuntimeError("OpenSearch was not ready in time.")


# ---------- Pytest Fixtures ----------


@pytest.fixture(scope="session")
def opensearch():
    """
    Starts OpenSearch in a container for the test session.
    """
    client = docker.from_env()
    for cnt in client.containers.list(all=True, filters={"name": "opensearch"}):
        LOGGER.warning("Removing pre-existing 'opensearch' container.")
        cnt.stop()
        cnt.remove()

    LOGGER.info("Starting OpenSearch container...")
    client.containers.run(
        "opensearchproject/opensearch",
        detach=True,
        ports={"9200/tcp": 9200},
        environment={
            "discovery.type": "single-node",
            "plugins.security.disabled": "true",
            "OPENSEARCH_INITIAL_ADMIN_PASSWORD": "WazuhTest99$",
        },
        name="opensearch",
        stdout=True,
        stderr=True,
    )

    try:
        wait_for_opensearch(f"http://{GLOBAL_URL}")
        yield client
    finally:
        LOGGER.info("Cleaning up OpenSearch container.")
        for container in client.containers.list():
            if container.name == "opensearch":
                container.stop()
                container.remove()


@pytest.fixture(scope="function", autouse=True)
def clear_all_indices():
    """
    Deletes all indices in OpenSearch before every test.
    """
    LOGGER.info("Clearing OpenSearch indices...")
    resp = requests.delete(f"http://{GLOBAL_URL}/_all")
    if resp.status_code not in (200, 404):
        raise RuntimeError(f"Failed to delete indices: {resp.text}")
    yield


@pytest.fixture
def test_folder(request):
    return request.param


# ---------- Parametrization ----------


def is_test_folder_name(name: str) -> bool:
    return name and name[0].isdigit()


test_folders = sorted(
    str(folder)
    for folder in TEST_DATA_ROOT.rglob("*")
    if folder.is_dir() and is_test_folder_name(folder.name)
)


# ---------- Test Case ----------


@pytest.mark.parametrize("test_folder", test_folders, indirect=True)
def test_data_indexation(opensearch, test_folder):
    """
    Runs the inventory harvester tool and verifies that the indexed documents match expected results.
    """
    os.chdir(Path(__file__).parent.parent.parent.parent)
    test_path = Path(test_folder)
    log_file = f"log_{test_path.name}.out"
    pre_existing_file = test_path / "pre_existing_data.json"

    cmd = (
        Path(
            "build/wazuh_modules/inventory_harvester/testtool/inventory_harvester_testtool"
        )
        if Path(
            "build/wazuh_modules/inventory_harvester/testtool/inventory_harvester_testtool"
        ).exists()
        else Path(
            "wazuh_modules/inventory_harvester/build/testtool/inventory_harvester_testtool"
        )
    )
    assert cmd.exists(), "Missing compiled inventory_harvester_testtool"

    try:
        if Path(log_file).exists():
            Path(log_file).unlink()
        if QUEUE_DIR.exists():
            shutil.rmtree(QUEUE_DIR)

        # Optional: Insert pre-existing data
        if pre_existing_file.exists():
            LOGGER.info("Loading pre-existing data...")
            subprocess.run([str(cmd), "-c", str(test_path / "config.json")], check=True)

            with pre_existing_file.open("r", encoding="utf-8") as f:
                pre_data = json.load(f)

            for idx in pre_data:
                index_name = idx["index_name"]
                ids_map = idx.get("ids", {})

                for doc in idx["data"]:
                    agent_id = doc["agent"]["id"]
                    raw_id = ids_map.get(agent_id)
                    assert raw_id, f"No _id defined for agent.id = '{agent_id}'"

                    encoded_id = quote(
                        raw_id, safe=""
                    )  # encode everything that might break the path
                    index_url = f"http://{GLOBAL_URL}/{index_name}/_doc/{encoded_id}"
                    resp = requests.put(index_url, json=doc)
                    assert resp.status_code in (200, 201), (
                        f"Insert failed: {resp.status_code} {resp.text}"
                    )

        # Run test tool
        command = [
            str(cmd),
            "-c",
            str(test_path / "config.json"),
            "-l",
            log_file,
            "-i",
            str(test_path / "inputs/"),
        ]
        LOGGER.info(f"Running: {' '.join(command)}")
        proc = subprocess.run(command, capture_output=True, text=True)
        assert proc.returncode == 0, f"Test tool error:\n{proc.stderr}"

        # Validate results
        with (test_path / "result.json").open("r", encoding="utf-8") as f:
            expected = json.load(f)

        for idx_def in expected:
            index = idx_def["index_name"]
            resp = requests.get(f"http://{GLOBAL_URL}/{index}/_search")
            assert resp.status_code == 200, f"Search failed: {resp.text}"

            hits = resp.json()["hits"]
            LOGGER.debug(f"Fetched documents: {hits['hits']}")
            LOGGER.debug(f"Expected documents: {idx_def['data']}")
            assert hits["total"]["value"] == len(idx_def["data"]), (
                f"Mismatch in '{index}': expected {len(idx_def['data'])}, got {hits['total']['value']}"
            )

            for doc in idx_def["data"]:
                if not any(doc == hit["_source"] for hit in hits["hits"]):
                    LOGGER.debug(f"Fetched document: {idx_def['data']}")
                    LOGGER.debug(f"Expected document: {doc}")
                    pytest.fail(
                        f"Missing document in '{index}': {json.dumps(doc, indent=2)}"
                    )

    except Exception as exc:
        LOGGER.error(f"Test failed for '{test_folder}': {exc}")
        LOGGER.error(f"Log retained: {log_file}")
        raise
    else:
        if Path(log_file).exists():
            Path(log_file).unlink()
        if QUEUE_DIR.exists():
            shutil.rmtree(QUEUE_DIR)
