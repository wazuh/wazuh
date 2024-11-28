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
TEMPLATE_PATH='engine/source/indexerconnector/qa/test_data/template.json'
OPENSEARCH_PASSWORD='WazuhTest99$'
KEYSTORE_PATH='./keystore'

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
        'OPENSEARCH_INITIAL_ADMIN_PASSWORD': OPENSEARCH_PASSWORD,
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

def run_command(command):
    """ Runs a command using subprocess.Popen. In case of failure, it logs the error and fails the test.

    Args:
        command (str): The command to run

    """
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) as process:
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            LOGGER.error("Error running command: %s", command)
            LOGGER.error("stdout: %s", stdout.decode())
            LOGGER.error("stderr: %s", stderr.decode())
            pytest.fail()

@pytest.fixture(scope='session')
def wazuh_keystore():
    # Save credentials in the keystore
    wazuh_keystore_path = Path("engine/build/source/keystore/", "wazuh-keystore")

    keystore_args = ["-f", "indexer", "-k", "username", "-v", "admin", "-p", KEYSTORE_PATH]
    kesytore_command = [wazuh_keystore_path] + keystore_args
    run_command(kesytore_command)

    keystore_args = ["-f", "indexer", "-k", "password", "-v", OPENSEARCH_PASSWORD, "-p", KEYSTORE_PATH]
    kesytore_command = [wazuh_keystore_path] + keystore_args
    run_command(kesytore_command)

def test_opensearch_health(opensearch):
    url = 'http://localhost:9200/_cluster/health?wait_for_status=green&timeout=10s'
    response = requests.get(url)
    assert response.status_code == 200
    assert response.json()['status'] == 'green'

def test_initialize_indexer_connector(opensearch):
    os.chdir(Path(__file__).parent.parent.parent.parent.parent)
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
    cmd = Path("engine/build/source/indexerconnector/tool/", "indexer_connector_tool")
    cmdAlt = Path("engine/source/indexerconnector/build/tool/", "indexer_connector_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmdAlt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    args = ["-c", "engine/source/indexerconnector/qa/test_data/" + test_name + "/config.json",
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
    os.chdir(Path(__file__).parent.parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    ## Remove folder queue/indexer/db/wazuh-states-vulnerabilities
    if Path("queue/indexer/db/wazuh-states-vulnerabilities").exists():
        for file in Path("queue/indexer/db/wazuh-states-vulnerabilities").glob("*"):
            file.unlink()
        Path("queue/indexer/db/wazuh-states-vulnerabilities").rmdir()

    # Run indexer connector testtool out of the container
    cmd = Path("engine/build/source/indexerconnector/tool/", "indexer_connector_tool")
    cmdAlt = Path("engine/source/indexerconnector/build/tool/", "indexer_connector_tool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmdAlt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    test_name = inspect.currentframe().f_code.co_name

    LOGGER.debug(f"Running test {test_name}")

    args = ["-c", "engine/source/indexerconnector/qa/test_data/" + test_name + "/config.json",
            "-e", "engine/source/indexerconnector/qa/test_data/" + test_name + "/event_insert.json",
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

    # Delete element
    args = ["-c", "engine/source/indexerconnector/qa/test_data/" + test_name + "/config.json",
            "-e", "engine/source/indexerconnector/qa/test_data/" + test_name + "/event_delete.json",
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
