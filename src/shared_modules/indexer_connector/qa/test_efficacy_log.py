import pytest
import docker
import time
import requests
import logging
import os
import subprocess
import inspect
from pathlib import Path
import json
import shutil

LOGGER = logging.getLogger(__name__)

def init_opensearch(low_resources):
    client = docker.from_env()
    env_vars = {
            'discovery.type': 'single-node',
            'plugins.security.disabled': 'true',
            'OPENSEARCH_INITIAL_ADMIN_PASSWORD': 'WazuhTest99$'
        }

    if low_resources:
        env_vars['http.max_content_length'] = '4mb'

    client.containers.run("opensearchproject/opensearch", detach=True, ports={'9200/tcp': 9200},
                          environment=env_vars, name='opensearch', stdout=True, stderr=True)
    ## Wait for the container is running and opensearch is ready
    while True:
        try:
            response = requests.get('http://localhost:9200')
            if response.status_code == 200:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    return client


@pytest.fixture(scope='function')
def opensearch(request):
    low_resources = request.param
    client = init_opensearch(low_resources)
    yield client
    # Stop all containers
    for container in client.containers.list():
        container.stop()
    client.containers.prune()

@pytest.mark.parametrize('opensearch', [False], indirect=True)
def test_opensearch_health(opensearch):
    url = 'http://localhost:9200/_cluster/health'
    response = requests.get(url)
    assert response.status_code == 200
    assert response.json()['status'] == 'green' or response.json()['status'] == 'yellow'

@pytest.mark.parametrize('opensearch', [False], indirect=True)
def test_initialize_indexer_connector(opensearch):
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    ## Remove folder queue/indexer/
    if os.path.exists("queue/indexer/"):
        shutil.rmtree("queue/indexer/")

    # Run indexer connector testtool out of the container
    cmd = Path("build/shared_modules/indexer_connector/testtool/", "indexer_connector_tool")
    cmd_alt = Path("shared_modules/indexer_connector/build/testtool/", "indexer_connector_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
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
        if response.status_code == 200 and 'wazuh-states-vulnerabilities-default' in response.text:
            LOGGER.debug(f"Index created {response.text}")
            break
        time.sleep(1)
        counter += 1

    process.terminate()
    assert counter < 10, "The index was not created"

@pytest.mark.parametrize('opensearch', [False], indirect=True)
def test_add_bulk_indexer_connector(opensearch):
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    ## Remove folder queue/indexer/
    if os.path.exists("queue/indexer/"):
        shutil.rmtree("queue/indexer/")

    # Run indexer connector testtool out of the container
    cmd = Path("build/shared_modules/indexer_connector/testtool/", "indexer_connector_tool")
    cmd_alt = Path("shared_modules/indexer_connector/build/testtool/", "indexer_connector_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
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
        url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
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
    url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_delete_by_query?refresh=true'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.post(url, json=query)
    assert response.status_code == 200

    url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.get(url, json=query)
    assert response.status_code == 200

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
        url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
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
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
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
        url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
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
    url = 'http://localhost:9200/wazuh-states-vulnerabilities-cluster/_doc/000_pkghash_CVE-2022-123456?refresh=true'
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
        url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
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


@pytest.mark.parametrize('opensearch', [True], indirect=True)
def test_bulk_indexer_413_connector(opensearch):
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    ## Remove folder queue/indexer/
    if os.path.exists("queue/indexer/"):
        shutil.rmtree("queue/indexer/")

    # Run indexer connector testtool out of the container
    cmd = Path("build/shared_modules/indexer_connector/testtool/", "indexer_connector_tool")
    cmd_alt = Path("shared_modules/indexer_connector/build/testtool/", "indexer_connector_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    test_name = inspect.currentframe().f_code.co_name

    path_base_data = Path("shared_modules/indexer_connector/qa/test_data",test_name,"base.json")

    # create a json with an array of x elements using the base json and adding an authonumeric id to each element
    json_data = []  # Declare the json_data variable as an empty list

    #Elements to create and test.
    elements = 6250
    with open(path_base_data, 'r') as file:
        # Json array create.
        data = file.read()
        for i in range(elements):
            json_data.append(json.loads(data))
            json_data[i]["id"] = "000_" + str(i)

        file = Path("shared_modules/indexer_connector/qa/test_data/" + test_name + "/data.json")
        if file.exists():
            file.unlink()


        with open("shared_modules/indexer_connector/qa/test_data/" + test_name + "/data.json", 'w') as file:
            file.write(json.dumps(json_data))

    LOGGER.debug(f"Running test {test_name}")

    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
            "-e", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/data.json",
            "-w", "120",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Query to check if the index is created and template is applied
    counter = 0
    while counter < 60:
        url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        if response.status_code == 200:
            LOGGER.debug(f"Elements on the index {response.json()['hits']['total']['value']}")
            if response.json()['hits']['total']['value'] == elements:
                LOGGER.debug(f"Documents created {elements}")
                break
        time.sleep(1)
        counter += 1
    assert counter < 60, "The documents was not created"
    process.terminate()

    # Delete the document to test the resync.
    url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_delete_by_query?refresh=true'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.post(url, json=query)
    assert response.status_code == 200

    url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.get(url, json=query)

    assert response.status_code == 200, "Documents was not deleted"
    assert response.json()['hits']['total']['value'] == 0, "Documents was not deleted"

    # Run the process again to check the resync
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
            "-s", "000",
            "-w", "120"]
    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element is resynced
    counter = 0
    while counter < 60:
        url = 'http://localhost:9200/wazuh-states-vulnerabilities-default/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        if response.status_code == 200:
            LOGGER.debug(f"Elements on the index {response.json()['hits']['total']['value']}")
            if response.json()['hits']['total']['value'] == elements:
                LOGGER.debug(f"Document created in sync {elements}")
                break
        time.sleep(1)
        counter += 1

    assert counter < 60, "The document was not resynced"
    process.terminate()
