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
from pathlib import Path

# ---------- Global Constants ----------

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

GLOBAL_URL = "localhost:9200"
TEMPLATE_ROOT = Path("wazuh_modules/inventory_harvester/indexer/template")
TEST_DATA_ROOT = Path("wazuh_modules/inventory_harvester/qa/test_data")
QUEUE_DIR = Path("queue")


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
    Uploads a template and creates a dummy index that matches its index_patterns.
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
            concrete_index = "wazuh-states-files-cluster01"
        elif "fim-registries" in template_name:
            concrete_index = "wazuh-states-registries-cluster01"
        else:
            concrete_index = pattern.replace("*", "-cluster01")

        index_url = f"http://{GLOBAL_URL}/{concrete_index}"
        for _ in range(5):
            create_resp = requests.put(index_url)
            if create_resp.status_code in (200, 201):
                return
            if "resource_already_exists_exception" in create_resp.text:
                LOGGER.info(f"Index '{concrete_index}' already exists. Skipping.")
                return
            time.sleep(1)
        raise AssertionError(
            f"Failed to create index '{concrete_index}': {create_resp.text}"
        )


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


@pytest.fixture(autouse=True)
def load_all_templates():
    """
    Uploads all relevant templates and creates matching indices.
    """
    templates = discover_templates()
    LOGGER.info(f"Loading {len(templates)} templates...")
    for template in templates:
        create_index_from_template(template)


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
                index_url = f"http://{GLOBAL_URL}/{idx['index_name']}/_doc"
                for doc in idx["data"]:
                    resp = requests.post(index_url, json=doc)
                    assert resp.status_code == 201, f"Insert failed: {resp.text}"

        # Run test tool
        command = [
            str(cmd),
            "-c",
            str(test_path / "config.json"),
            "-l",
            log_file,
            "-t",
            "dummy_template.json",
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
            assert hits["total"]["value"] == len(idx_def["data"]), (
                f"Mismatch in '{index}': expected {len(idx_def['data'])}, got {hits['total']['value']}"
            )

            for doc in idx_def["data"]:
                if not any(doc == hit["_source"] for hit in hits["hits"]):
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
