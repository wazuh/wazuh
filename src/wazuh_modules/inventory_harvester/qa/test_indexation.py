import pytest
import docker
import time
import requests
import logging
import os
import subprocess
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
        if container.name == 'opensearch':
            container.stop()
            container.remove()

test_folders = [folder for folder in Path("wazuh_modules/inventory_harvester/qa/test_data").rglob('*') if folder.is_dir() and folder.name.isdigit()]
test_folders = sorted([str(folder) for folder in test_folders])

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

    log_file = 'log_' + test_folder.replace('/', '_') + '.out'

    # Remove previous log file if exists
    if Path(log_file).exists():
        Path(log_file).unlink()

    if Path("queue").exists():
        shutil.rmtree("queue")

    LOGGER.debug(f"Running test at '{test_folder}'")

    args = ["-c", test_folder + "/config.json",
            "-t", test_folder + "/template.json",
            "-l", log_file, "-i", test_folder + "/inputs/"]

    command = [cmd] + args

    LOGGER.info(f"Running command: {command}")
    process = subprocess.Popen(command)
    # if the process is not running fail the test
    assert process.poll() is None, "The process is not running"

    # Parse result.json file to get expected indexes and data
    with open(Path(test_folder, "result.json")) as f:
        result = json.load(f)

    # Wait for process to finish
    process.wait()
    assert process.returncode == 0, "The process failed"

    # We validate the index was created
    counter = 0
    for index in result:
        url = 'http://'+ GLOBAL_URL +'/_cat/indices/' + index["index_name"] + '?format=json'
        LOGGER.info("Checking if the index was created at: " + url)
        while counter < 10:
            response = requests.get(url)
            if response.status_code == 200 and len(response.json()) > 0:
                break
            time.sleep(1)
            counter += 1
        assert counter < 10, f"The index was not created. Response: {response.text}"

    # Query to check if the index content is the same as result.json file
    for index in result:
        url = 'http://'+ GLOBAL_URL +'/'+ index["index_name"] +'/_search'
        response = requests.get(url)
        assert response.status_code == 200

        # Check if the data is the same as the expected
        response_json = response.json()
        assert response_json["hits"]["total"]["value"] == len(index["data"]), f"The number of hits is not the expected: {response_json['hits']['hits']}"

        for expected_data in index["data"]:
            found = False
            for hit in response_json["hits"]["hits"]:
                if expected_data == hit["_source"]:
                    found = True
                    break
            assert found, f"The data '{expected_data}' is not in the response: {response_json['hits']['hits']}"
