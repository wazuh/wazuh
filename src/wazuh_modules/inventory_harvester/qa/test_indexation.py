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
TEMPLATE_ROOT = Path("wazuh_modules/inventory_harvester/indexer/template")

# ---------- Utility Functions ----------


def discover_templates():
    """
    Discovers all valid template files in TEMPLATE_ROOT.
    Skips 'update', 'fim-files', and 'fim-registries' (normalized to 'files' and 'registries').
    """

    def valid(path: Path):
        name = path.name
        return "update" not in name

    return [path for path in TEMPLATE_ROOT.rglob("wazuh-states-*.json") if valid(path)]


def create_index_from_template(template_path: Path):
    """
    Uploads the template and recreates the index that matches its pattern,
    deleting it first if it already exists.
    """
    with template_path.open("r", encoding="utf-8") as f:
        template_data = json.load(f)

    template_name = template_path.stem
    url = f"http://{GLOBAL_URL}/_index_template/{template_name}"
    resp = requests.put(url, json=template_data)
    assert resp.status_code in (200, 201), (
        f"Failed to upload template {template_name}: {resp.text}"
    )

    pattern = template_data.get("index_patterns", [None])[0]
    if pattern and "*" in pattern:
        if "fim-files" in template_name:
            index_name = "wazuh-states-files-cluster01"
        elif "fim-registries" in template_name:
            index_name = "wazuh-states-registries-cluster01"
        else:
            index_name = pattern.replace("*", "-cluster01")

        index_url = f"http://{GLOBAL_URL}/{index_name}"

        # Delete index if it exists
        delete_resp = requests.delete(index_url)
        if delete_resp.status_code not in (200, 404):
            raise RuntimeError(
                f"Failed to delete index {index_name}: {delete_resp.status_code} {delete_resp.text}"
            )
        LOGGER.info(f"Index '{index_name}' deleted (if existed).")

        # Create index again
        create_resp = requests.put(index_url)
        assert create_resp.status_code in (200, 201), (
            f"Failed to recreate index '{index_name}': {create_resp.status_code} {create_resp.text}"
        )
        LOGGER.info(f"Index '{index_name}' recreated successfully.")


def load_all_templates():
    """
    Uploads all relevant templates and creates matching indices.
    """
    templates = discover_templates()
    LOGGER.info(f"Loading {len(templates)} templates...")
    for template in templates:
        create_index_from_template(template)


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
    is_wazuh_db = "wazuh_db" in str(test_path)

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
                    index_url = f"http://{GLOBAL_URL}/{index_name}/_doc/{encoded_id}?refresh=wait_for"
                    resp = requests.put(index_url, json=doc)
                    assert resp.status_code in (200, 201), (
                        f"Insert failed: {resp.status_code} {resp.text}"
                    )

        if is_wazuh_db:
            command = [
                str(cmd),
                "-c",
                str(test_path / "config.json"),
                "-l",
                log_file,
                "-t",
                str(test_path / "template.json"),
                "-i",
                str(test_path / "inputs/"),
            ]
        else:
            command = [
                str(cmd),
                "-c",
                str(test_path / "config.json"),
                "-l",
                log_file,
                "-i",
                str(test_path / "inputs/"),
            ]

        # Run test tool

        LOGGER.info(f"Running: {' '.join(command)}")
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Optional: wait a bit if needed
        time.sleep(1)

        # Load templates *after* the tool has started
        if is_wazuh_db:
            LOGGER.info("Loading templates manually for 'wazuh_db' test case...")
            load_all_templates()

        # Wait for the tool to finish
        stdout, stderr = proc.communicate()
        assert proc.returncode == 0, f"Test tool error:\n{stderr}"

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
