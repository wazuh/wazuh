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
GLOBAL_URL = 'localhost:9200'

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
            response = requests.get('http://'+GLOBAL_URL+'')
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
    url = 'http://'+GLOBAL_URL+'/_cluster/health'
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
            "-w", "120",
            "-l", "log.out"]

    command = [cmd] + args

    LOGGER.debug(f"Running command: {command}")
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Query to check if the index is created and template is applied
    counter = 0
    while counter < 10:
        url = 'http://'+GLOBAL_URL+'/_cat/indices'
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
        url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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
    url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_delete_by_query?refresh=true'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.post(url, json=query)
    assert response.status_code == 200

    url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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
            "-w", "120",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element is resynced
    counter = 0
    while counter < 10:
        url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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
        url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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
    url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-cluster/_doc/000_pkghash_CVE-2022-123456?refresh=true'
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
            "-w", "120",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element is resynced
    counter = 0
    while counter < 10:
        url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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
        url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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
    url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_delete_by_query?refresh=true'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.post(url, json=query)
    assert response.status_code == 200

    url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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
            "-w", "120",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element is resynced
    counter = 0
    while counter < 60:
        url = 'http://'+GLOBAL_URL+'/wazuh-states-vulnerabilities-default/_search'
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


@pytest.mark.parametrize('opensearch', [True], indirect=True)
def test_update_mappings_connector(opensearch):
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

    # -------------------------------------------
    # Create the index and try to insert a document with old mapping, this should fail and the element queue in the persistent rocksdb queue.
    # -------------------------------------------
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
            "-e", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/event_insert_1.json",
            "-w", "10",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Wait for the process to finish, 10 seconds is the time to wait for the process to finish (defined in the command line)
    counter = 0
    while counter < 15:
        if process.poll() is not None:
            LOGGER.debug("Process finished")
            break
        time.sleep(1)
        counter += 1
    assert counter < 15, "Process still running"
    process.terminate()

    # Check if the index is created.
    url = 'http://' + GLOBAL_URL + '/wazuh-states-vulnerabilities-default/'
    response = requests.get(url)
    if response.status_code == 200:
        LOGGER.debug("Index created")

    # Check if the document was not inserted
    counter = 0
    while counter < 10:
        url = 'http://' + GLOBAL_URL + '/wazuh-states-vulnerabilities-default/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 0:
            LOGGER.debug("Document not exists.")
            break
        time.sleep(1)
        counter += 1
    assert counter < 10, "The document exists"

    # -------------------------------------------
    # Run the process again to update the mapping and check if the document is inserted, because now the queue have one pending element.
    # -------------------------------------------
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template2.json",
            "-u", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/update.json",
             "-e", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/event_insert_2.json",
            "-w", "120",
            "-l", "log2.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element exists
    counter = 0
    while counter < 10:
        url = 'http://' + GLOBAL_URL + '/wazuh-states-vulnerabilities-default/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 1:
            LOGGER.debug(f"Document created after updated the mapping {response.text}")
            break
        time.sleep(1)
        counter += 1

    assert counter < 10, "The document was not inserted"
    process.terminate()


@pytest.mark.parametrize('opensearch', [True], indirect=True)
def test_update_mappings_connector_legacy(opensearch):
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

    # -------------------------------------------
    # Create the index and try to insert a document with old mapping, this should fail and the element queue in the persistent rocksdb queue.
    # -------------------------------------------
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template.json",
            "-e", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/event_insert_1.json",
            "-w", "10",
            "-l", "log.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Wait for the process to finish, 10 seconds is the time to wait for the process to finish (defined in the command line)
    counter = 0
    while counter < 15:
        if process.poll() is not None:
            LOGGER.debug("Process finished")
            break
        time.sleep(1)
        counter += 1
    assert counter < 15, "Process still running"
    process.terminate()

    # Check if the index is created.
    url = 'http://' + GLOBAL_URL + '/wazuh-states-vulnerabilities-default/'
    response = requests.get(url)
    if response.status_code == 200:
        LOGGER.debug("Index created")

    # Check if the document was not inserted
    counter = 0
    while counter < 10:
        url = 'http://' + GLOBAL_URL + '/wazuh-states-vulnerabilities-default/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 0:
            LOGGER.debug("Document not exists.")
            break
        time.sleep(1)
        counter += 1
    assert counter < 10, "The document exists"

    # -------------------------------------------
    # Run the process again to update the mapping and check if the document is inserted, because now the queue have one pending element.
    # -------------------------------------------
    args = ["-c", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/config.json",
            "-t", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/template2.json",
            "-u", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/update.json",
             "-e", "shared_modules/indexer_connector/qa/test_data/" + test_name + "/event_insert_2.json",
            "-w", "120",
            "-l", "log2.out"]

    command = [cmd] + args
    process = subprocess.Popen(command)

    # Query to check if the element exists
    counter = 0
    while counter < 10:
        url = 'http://' + GLOBAL_URL + '/wazuh-states-vulnerabilities-default/_search'
        query = {
            "query": {
                "match_all": {}
            }
        }
        response = requests.get(url, json=query)
        if response.status_code == 200 and response.json()['hits']['total']['value'] == 1:
            LOGGER.debug(f"Document created after updated the mapping {response.text}")
            break
        time.sleep(1)
        counter += 1

    assert counter < 10, "The document was not inserted"
    process.terminate()


@pytest.mark.parametrize("opensearch", [True], indirect=True)
def test_error_handling_shard_limit_exceeded(opensearch):
    """
    Test that shard limit validation error is logged with recommendation.

    Scenario:
    1. Configure OpenSearch with very low shard limit (e.g., 1)
    2. Try to create multiple indices
    3. Verify WARNING log contains recommendation to increase cluster.max_shards_per_node

    Note: This requires OpenSearch configuration change to set low shard limit.
    """
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    # Set very low shard limit on OpenSearch
    url = f'http://{GLOBAL_URL}/_cluster/settings'
    settings = {"persistent": {"cluster.max_shards_per_node": 1}}
    response = requests.put(url, json=settings)
    assert response.status_code == 200, "Failed to set shard limit"

    # Clean up
    if os.path.exists("queue/indexer/"):
        shutil.rmtree("queue/indexer/")

    cmd = Path(
        "build/shared_modules/indexer_connector/testtool/", "indexer_connector_tool"
    )
    cmd_alt = Path(
        "shared_modules/indexer_connector/build/testtool/", "indexer_connector_tool"
    )
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exist"

    log_file = Path("log.out")
    if log_file.exists():
        log_file.unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    # Try to create index (should fail with shard limit error)
    args = [
        "-c",
        f"shared_modules/indexer_connector/qa/test_data/{test_name}/config.json",
        "-t",
        f"shared_modules/indexer_connector/qa/test_data/{test_name}/template.json",
        "-w",
        "10",
        "-l",
        str(log_file),
    ]

    command = [cmd] + args
    process = subprocess.Popen(command)
    time.sleep(5)
    process.terminate()

    # Verify log contains recommendation
    with open(log_file, "r") as f:
        log_content = f.read()
        assert "validation_exception" in log_content, (
            "Expected validation_exception not found"
        )
        assert "maximum shards open" in log_content, (
            "Expected shard limit error not found"
        )
        assert (
            "Consider increasing cluster.max_shards_per_node setting" in log_content
        ), "Expected recommendation not found in log"

    # Restore shard limit
    settings = {"persistent": {"cluster.max_shards_per_node": None}}
    requests.put(url, json=settings)

    LOGGER.info("Shard limit error logged with recommendation")


@pytest.mark.parametrize("opensearch", [True], indirect=True)
def test_error_handling_404_index_not_found(opensearch):
    """
    Test 404 index not found error handling.

    Scenario:
    1. Try to sync with non-existent index (don't create it first)
    2. Verify WARNING with type: 'index_not_found_exception'
    """
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    # Clean up
    if os.path.exists("queue/indexer/"):
        shutil.rmtree("queue/indexer/")

    # Ensure test index does NOT exist
    index_url = f'http://{GLOBAL_URL}/wazuh-nonexistent-index-404'
    response = requests.delete(index_url)
    LOGGER.debug(f"Deleted test index (if existed): {response.status_code}")

    cmd = Path(
        "build/shared_modules/indexer_connector/testtool/", "indexer_connector_tool"
    )
    cmd_alt = Path(
        "shared_modules/indexer_connector/build/testtool/", "indexer_connector_tool"
    )
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exist"

    log_file = Path("log.out")
    if log_file.exists():
        log_file.unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    # Try to sync with non-existent index (no template, no creation)
@pytest.mark.parametrize("opensearch", [False], indirect=True)
def test_abuse_control_indexer_connector(opensearch):
    os.chdir(Path(__file__).parent.parent.parent.parent)
    test_name = inspect.currentframe().f_code.co_name

    cmd = Path("build/shared_modules/indexer_connector/testtool/indexer_connector_tool")
    cmd_alt = Path(
        "shared_modules/indexer_connector/build/testtool/indexer_connector_tool"
    )
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists()

    if Path("log.out").exists():
        Path("log.out").unlink()

    args = [
        "-c",
        f"shared_modules/indexer_connector/qa/test_data/{test_name}/config.json",
        "-t",
        f"shared_modules/indexer_connector/qa/test_data/{test_name}/template.json",
        "-e",
        f"shared_modules/indexer_connector/qa/test_data/{test_name}/event_insert.json",
        "-s",
        "000",
        "-L",
        "30",  # new flag to simulate 30 rapid syncs
        "-w",
        "30",
        "-D",
        "0",  # 0 seconds delay (immediate/rapid)
        "-l",
        "log.out",
    ]

    subprocess.run([cmd] + args, check=True)

    # verify only 1 document created
    url = f"http://{GLOBAL_URL}/wazuh-states-vulnerabilities-default/_search"
    r = requests.get(url, json={"query": {"match_all": {}}})
    count = r.json()["hits"]["total"]["value"]
    assert count == 1, f"Expected 1 doc, found {count}"

    logs = Path("log.out").read_text()
    blocked = logs.count("sync blocked by rate limit")
    assert blocked >= 25, f"Expected most syncs to be blocked, found {blocked}"

@pytest.mark.parametrize("opensearch", [False], indirect=True)
def test_abuse_control_no_data_loss_on_indexer_failure(opensearch):
    """
    Real-world scenario test: Verify no data loss when indexer goes down
    
    Steps:
    1. Start indexer - publish event - succeeds
    2. Stop indexer (simulate outage)
    3. Re-run tool with sync - fails (indexer down)
    4. Re-run tool with sync AGAIN - should NOT be blocked (this is the bug fix!)
    5. Restart indexer
    6. Re-run tool with sync - succeeds and data is preserved
    """
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.info("="*80)
    LOGGER.info("TEST: No Data Loss on Indexer Failure")
    LOGGER.info("="*80)

    test_name = inspect.currentframe().f_code.co_name

    # Clean up
    if os.path.exists("queue/indexer/"):
        shutil.rmtree("queue/indexer/")

    cmd = Path("build/shared_modules/indexer_connector/testtool/indexer_connector_tool")
    cmd_alt = Path("shared_modules/indexer_connector/build/testtool/indexer_connector_tool")
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "Binary does not exist"

    client = opensearch

    # ========================================================================
    # STEP 1: Indexer UP - Publish event (succeeds)
    # ========================================================================
    LOGGER.info("\n[STEP 1] Publishing event with indexer UP...")
    
    if Path("log_publish.out").exists():
        Path("log_publish.out").unlink()

    args_publish = [
        "-c", f"shared_modules/indexer_connector/qa/test_data/{test_name}/config.json",
        "-t", f"shared_modules/indexer_connector/qa/test_data/{test_name}/template.json",
        "-e", f"shared_modules/indexer_connector/qa/test_data/{test_name}/event_insert.json",
        "-w", "10",
        "-l", "log_publish.out",
    ]

    subprocess.run([cmd] + args_publish, check=True)

    # Verify document was created
    time.sleep(2)
    url = f"http://{GLOBAL_URL}/wazuh-states-vulnerabilities-default/_search"
    response = requests.get(url, json={"query": {"match_all": {}}})
    assert response.status_code == 200
    initial_count = response.json()["hits"]["total"]["value"]
    assert initial_count == 1, f"Expected 1 document, got {initial_count}"
    
    LOGGER.info(f"✓ Event published successfully, {initial_count} document(s) in index")

    # ========================================================================
    # STEP 2: STOP INDEXER (simulate outage)
    # ========================================================================
    LOGGER.info("\n[STEP 2] Stopping indexer (simulating outage)...")
    
    for container in client.containers.list():
        if "opensearch" in container.name.lower():
            container.stop()
            LOGGER.info("✓ OpenSearch stopped")
            break
    
    time.sleep(3)

    # ========================================================================
    # STEP 3: Re-run tool with SYNC (will fail - indexer down)
    # ========================================================================
    LOGGER.info("\n[STEP 3] Running sync with indexer DOWN (will fail)...")
    
    if Path("log_sync_fail.out").exists():
        Path("log_sync_fail.out").unlink()

    args_sync = [
        "-c", f"shared_modules/indexer_connector/qa/test_data/{test_name}/config.json",
        "-t", f"shared_modules/indexer_connector/qa/test_data/{test_name}/template.json",
        "-s", "000",  # Trigger sync for agent 000
        "-w", "5",
        "-l", "log_sync_fail.out",
    ]

    # Run and expect it to complete (even though sync fails internally)
    subprocess.run([cmd] + args_sync, check=True)

    # Verify sync failed
    log_fail = Path("log_sync_fail.out").read_text()
    has_error = any(word in log_fail.lower() for word in ["error", "fail", "refused", "timeout", "connection"])
    assert has_error, "Expected sync to fail when indexer is down"
    
    LOGGER.info("✓ Sync failed as expected (indexer down)")

    # ========================================================================
    # STEP 4: CRITICAL TEST - Re-run sync AGAIN (should NOT be blocked!)
    # ========================================================================
    LOGGER.info("\n[STEP 4] CRITICAL: Re-run sync immediately (should NOT be blocked by rate limit)...")
    
    if Path("log_sync_retry.out").exists():
        Path("log_sync_retry.out").unlink()

    args_retry = [
        "-c", f"shared_modules/indexer_connector/qa/test_data/{test_name}/config.json",
        "-t", f"shared_modules/indexer_connector/qa/test_data/{test_name}/template.json",
        "-s", "000",
        "-w", "5",
        "-l", "log_sync_retry.out",
    ]

    subprocess.run([cmd] + args_retry, check=True)

    # Check if retry was attempted or blocked
    log_retry = Path("log_sync_retry.out").read_text()
    
    # BUG CHECK: Was retry blocked by rate limit?
    blocked_by_rate_limit = "sync blocked by rate limit" in log_retry.lower()
    
    if blocked_by_rate_limit:
        LOGGER.error("❌ BUG DETECTED: Retry was blocked by rate limit after failed sync!")
        LOGGER.error("This means timestamp was updated BEFORE sync completed (original bug)")
        assert False, "BUG: Failed sync should NOT block immediate retry"
    
    # Retry should be attempted (will fail again, but that's OK)
    retry_attempted = "syncing agent" in log_retry.lower() or "starting sync" in log_retry.lower()
    
    if not retry_attempted:
        LOGGER.warning("⚠️ Sync might be in progress from previous attempt, checking logs...")
        LOGGER.debug(f"Retry log:\n{log_retry}")
    
    LOGGER.info("✓ Retry was NOT blocked by rate limit (bug is FIXED!)")

    # ========================================================================
    # STEP 5: RESTART INDEXER
    # ========================================================================
    LOGGER.info("\n[STEP 5] Restarting indexer...")
    
    for container in client.containers.list(all=True):
        if "opensearch" in container.name.lower():
            container.start()
            LOGGER.info("✓ OpenSearch restarted")
            break

    # Wait for indexer to be ready
    counter = 0
    while counter < 30:
        try:
            response = requests.get(f"http://{GLOBAL_URL}")
            if response.status_code == 200:
                LOGGER.info("✓ OpenSearch is ready")
                break
        except:
            pass
        time.sleep(1)
        counter += 1
    
    assert counter < 30, "OpenSearch did not restart in time"

    # ========================================================================
    # STEP 6: Re-run sync (should succeed and preserve data)
    # ========================================================================
    LOGGER.info("\n[STEP 6] Running sync after indexer recovery (should succeed)...")
    
    if Path("log_sync_success.out").exists():
        Path("log_sync_success.out").unlink()

    args_success = [
        "-c", f"shared_modules/indexer_connector/qa/test_data/{test_name}/config.json",
        "-t", f"shared_modules/indexer_connector/qa/test_data/{test_name}/template.json",
        "-s", "000",
        "-w", "10",
        "-l", "log_sync_success.out",
    ]

    subprocess.run([cmd] + args_success, check=True)

    # Verify sync succeeded
    log_success = Path("log_sync_success.out").read_text()
    sync_succeeded = "sync succeeded" in log_success.lower() or "syncing agent" in log_success.lower()
    
    assert sync_succeeded, "Sync should succeed after indexer recovery"
    LOGGER.info("✓ Sync succeeded after indexer recovery")

    # ========================================================================
    # STEP 7: Verify data integrity - no data loss
    # ========================================================================
    LOGGER.info("\n[STEP 7] Verifying data integrity...")
    
    time.sleep(2)
    response = requests.get(url, json={"query": {"match_all": {}}})
    assert response.status_code == 200
    
    final_count = response.json()["hits"]["total"]["value"]
    
    # Should still have the original document (no data loss)
    assert final_count >= initial_count, \
        f"Data loss detected! Initial: {initial_count}, Final: {final_count}"
    
    LOGGER.info(f"✓ Data preserved: {final_count} document(s) in index")
