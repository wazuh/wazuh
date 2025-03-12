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

test_folders = sorted(Path("wazuh_modules/inventory_harvester/qa/test_data").glob(os.getenv('WAZUH_IH_TEST_GLOB', '*')))

@pytest.fixture
def test_folder(request):
    return request.param

@pytest.mark.parametrize('opensearch', [False], indirect=True)
@pytest.mark.parametrize("test_folder", test_folders, indirect=True)
def test_data_indexation(opensearch, test_folder):
    os.chdir(Path(__file__).parent.parent.parent.parent)
    LOGGER.debug(f"Current directory: {os.getcwd()}")

    # Run indexer connector testtool out of the container
    cmd = Path("build/wazuh_modules/inventory_harvester/testtool/", "inventory_harvester_testtool")
    cmd_alt = Path("wazuh_modules/inventory_harvester/build/testtool/", "inventory_harvester_testtool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exists"

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()

    LOGGER.debug(f"Running test {test_folder.name}")

    args = ["-c", "wazuh_modules/inventory_harvester/qa/test_data/" + test_folder.name + "/config.json",
            "-t", "wazuh_modules/inventory_harvester/qa/test_data/" + test_folder.name + "/template.json",
            "-l", "log.out", "-i", "wazuh_modules/inventory_harvester/qa/test_data/" + test_folder.name + "/inputs/"]

    command = [cmd] + args

    LOGGER.debug(f"Running command: {command}")
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Query to check if the index is created and template is applied
    counter = 0
    response = None
    while counter < 10:
        url = 'http://'+GLOBAL_URL+'/_cat/indices'
        response = requests.get(url)
        if response.status_code == 200 and 'wazuh-states-' in response.text:
            LOGGER.debug(f"Index created {response.text}")
            break
        time.sleep(1)
        counter += 1

    assert counter < 10, f"The index was not created. Response: {response.text}"

    # Wait for process to finish
    process.wait()
    assert process.returncode == 0, "The process failed"

    # Get index name
    index_name = None
    for line in response.text.splitlines():
        if 'wazuh-states-' in line:
            index_name = line.split()[2]
            break

    LOGGER.info(f"Index name: {index_name}")

    # Query to check if the index content is the same as result.json file
    url = 'http://'+GLOBAL_URL+'/'+index_name+'/_search'
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = requests.get(url, json=query)
    assert response.status_code == 200

    # Check if the content is the same as result.json
    with open(Path("wazuh_modules/inventory_harvester/qa/test_data", test_folder, "result.json")) as f:
        result = json.load(f)
    assert response.json() == result
