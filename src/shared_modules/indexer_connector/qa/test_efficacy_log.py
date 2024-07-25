import pytest
import docker
import time
import requests
import logging
import os
import subprocess
import inspect
import json
from pathlib import Path

LOGGER = logging.getLogger(__name__)
TEMPLATE_PATH='shared_modules/indexer_connector/qa/test_data/template.json'

def init_template_and_index():
    with open(TEMPLATE_PATH, 'r') as template_file:
        template_json = json.load(template_file)
        headers = {"Content-Type": "application/json"}
        url = f'http://localhost:9200/_index_template/{template_json["index_patterns"][0]}'
        if requests.put(url, data = json.dumps(template_json), headers = headers).status_code == 200:
            url = f'http://localhost:9200/{template_json["index_patterns"][0]}'
            return requests.put(url, data = json.dumps(template_json["template"]), headers = headers)


def init_opensearch():
    client = docker.from_env()
    env_vars = {
        'discovery.type': 'single-node',
        'plugins.security.disabled': 'true',
        'OPENSEARCH_INITIAL_ADMIN_PASSWORD': 'WazuhTest99$',
    }
    client.containers.run("opensearchproject/opensearch", detach=True, ports={'9200/tcp': 9200},
                          environment=env_vars, name='opensearch', stdout=True, stderr=True)
    ## Wait for the container is running and opensearch is ready
    while True:
        try:
            response = requests.get('http://localhost:9200')
            if response.status_code == 200:
                if init_template_and_index().status_code == 200:
                    break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    return client


@pytest.fixture(scope='session')
def opensearch():
    client = init_opensearch()
    yield client
    # Stop all containers
    for container in client.containers.list():
        container.stop()
    client.containers.prune()

def test_opensearch_health(opensearch):
    url = 'http://localhost:9200/_cluster/health?wait_for_status=green&timeout=10s'
    response = requests.get(url)
    assert response.status_code == 200
    assert response.json()['status'] == 'green'

def test_initialize_indexer_connector(opensearch):
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    response = requests.get('http://localhost:9200/_cat/templates')
    if response.status_code == 200:
        LOGGER.info(f'RESPONSE: {response.content}')

    ## Remove folder queue/indexer/db/wazuh-states-vulnerabilities
    if Path("queue/indexer/db/wazuh-states-vulnerabilities").exists():
        for file in Path("queue/indexer/db/wazuh-states-vulnerabilities").glob("*"):
            file.unlink()
        Path("queue/indexer/db/wazuh-states-vulnerabilities").rmdir()

    # Run indexer connector testtool out of the container
    cmd = Path("build/shared_modules/indexer_connector/testtool/", "indexer_connector_tool")
    cmdAlt = Path("shared_modules/indexer_connector/build/testtool/", "indexer_connector_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmdAlt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
                "-w", "120"]

    command = [cmd] + args

    LOGGER.debug(f"Running command: {command}")
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Query to check if the index is created and template is applied
    counter = 0
    while counter < 10:
        url = 'http://localhost:9200/_cat/indices'
        response = requests.get(url)
        if response.status_code == 200 and 'wazuh-states-vulnerabilities' in response.text:
            LOGGER.debug(f"Index created {response.text}")
            break
        time.sleep(1)
        counter += 1

    process.terminate()
    assert counter < 10, "The index was not created"

def test_add_bulk_indexer_connector(opensearch):
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    ## Remove folder queue/indexer/db/wazuh-states-vulnerabilities
    if Path("queue/indexer/db/wazuh-states-vulnerabilities").exists():
        for file in Path("queue/indexer/db/wazuh-states-vulnerabilities").glob("*"):
            file.unlink()
        Path("queue/indexer/db/wazuh-states-vulnerabilities").rmdir()

    # Run indexer connector testtool out of the container
    cmd = Path("build/shared_modules/indexer_connector/testtool/", "indexer_connector_tool")
    cmdAlt = Path("shared_modules/indexer_connector/build/testtool/", "indexer_connector_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmdAlt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-e", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/event_insert.json",
            "-w", "120",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Query to check if the index is created and template is applied
    counter = 0
    while counter < 10:
        url = 'http://localhost:9200/wazuh-states-vulnerabilities/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        LOGGER.debug(f"Info {response.text}")
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 1:
            LOGGER.debug(f"Document created {response.text}")
            break
        time.sleep(1)
        counter += 1
    assert counter < 10, "The document was not created"
    process.terminate()

    # Delete the document to test the resync.
    url = 'http://localhost:9200/wazuh-states-vulnerabilities/_delete_by_query?refresh=true'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.post(url, json=query)
    assert response.status_code == 200

    url = 'http://localhost:9200/wazuh-states-vulnerabilities/_search'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.get(url, json=query)

    # Run the process again to check the resync
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
            "-s", "000",
            "-w", "120"]
    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element is resynced
    counter = 0
    while counter < 10:
        url = 'http://localhost:9200/wazuh-states-vulnerabilities/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        LOGGER.debug(f"Info {response.text}")
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 1:
            LOGGER.debug(f"Document created in sync {response.text}")
            break
        time.sleep(1)
        counter += 1

    assert counter < 10, "The document was not resynced"
    process.terminate()

    # Delete element
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-e", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/event_delete.json",
            "-w", "120",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)

    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Query to check if the element is deleted
    counter = 0
    while counter < 10:
        url = 'http://localhost:9200/wazuh-states-vulnerabilities/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        LOGGER.debug(f"Info {response.text}")
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 0:
            LOGGER.debug(f"Document deleted {response.text}")
            break
        time.sleep(1)
        counter += 1

    assert counter < 10, "The document was not deleted"

    process.terminate()

    # Manual insert and check if resync clean the element.
    url = 'http://localhost:9200/wazuh-states-vulnerabilities/_doc/000_pkghash_CVE-2022-123456?refresh=true'
    query = """{
      "agent": {
        "build": {
          "original": "sample_build_1"
        },
        "ephemeral_id": "eph_id_1",
        "id": "000",
        "name": "agent_name_1",
        "type": "agent_type_1",
        "version": "1.0.0"
      },
      "message": "Sample message",
      "package": {
        "architecture": "x64",
        "build_version": "1.0.0",
        "checksum": "checksum_value",
        "description": "Sample package description",
        "install_scope": "global",
        "installed": "2023-09-17T12:00:00Z",
        "license": "MIT",
        "name": "sample_package",
        "path": "/path/to/package",
        "reference": "sample_reference",
        "size": 12345,
        "type": "sample_package_type",
        "version": "1.0.0"
      },
      "tags": ["sample", "tag1"],
      "vulnerability": {
        "detected_at": "2023-09-18T12:00:00Z",
        "published_at": "2023-01-18T12:00:00Z",
        "category": "sample_category",
        "classification": "sample_classification",
        "description": "Sample vulnerability description",
        "enumeration": "sample_enumeration",
        "id": "vuln_id_1",
        "reference": "sample_reference",
        "report_id": "report_id_1",
        "scanner": {
          "vendor": "sample_vendor"
        },
        "score": {
          "base": 5.0,
          "environmental": 5.5,
          "temporal": 4.5,
          "version": "1.0.0"
        },
        "severity": "medium"
      }
    }"""
    response = requests.put(url, data=query)
    LOGGER.debug(f"Manual insert info {response.text}")

    # Run the process again to check the resync
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
            "-s", "000",
            "-w", "120"]
    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element is resynced
    counter = 0
    while counter < 10:
        url = 'http://localhost:9200/wazuh-states-vulnerabilities/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        LOGGER.debug(f"Info {response.text}")
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 0:
            LOGGER.debug(f"Document deleted in sync {response.text}")
            break
        time.sleep(1)
        counter += 1

    assert counter < 10, "The document was not resynced"
    process.terminate()
