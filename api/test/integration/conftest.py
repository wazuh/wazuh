import pytest
import time
import os
import subprocess


def build_and_up(env: str):
    pwd = os.path.abspath(os.path.dirname(__file__))
    test_path = os.path.join(pwd, 'env', 'docker-compose.yml')
    values = {
        'interval': 10,
        'max_retries': 30,
        'retries': 0,
        'test_path': test_path
    }
    current_process = subprocess.Popen(
        ["docker-compose", "-f", test_path, "build", "--build-arg", "ENVIRONMENT={}".format(env)])
    current_process.wait()
    current_process = subprocess.Popen(["docker-compose", "-f", test_path, "up", "-d"])
    current_process.wait()

    return values


def down_env(test_path: str):
    current_process = subprocess.Popen(["docker-compose", "-f", test_path, "down"])
    current_process.wait()


def check_health(interval=10, node_type='master', agents=None):
    time.sleep(interval)
    if node_type == 'master':
        health = subprocess.check_output(
            "docker inspect env_wazuh-master_1 -f '{{json .State.Health.Status}}'", shell=True)
        return False if not health.startswith(b'"healthy"') else True
    elif node_type == 'agent':
        for agent in agents:
            health = subprocess.check_output(
                "docker inspect env_wazuh-agent{}_1 -f '{{json .State.Health.Status}}'".format(agent), shell=True)
            if not health.startswith(b'"healthy"'):
                return False
        return True


@pytest.fixture(name="base_tests", scope="session")
def environment_base():
    values = build_and_up("base")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env(values['test_path'])


@pytest.fixture(name="security_tests", scope="session")
def environment_security():
    values = build_and_up("security")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env(values['test_path'])


@pytest.fixture(name="manager_tests", scope="session")
def environment_manager():
    values = build_and_up("manager")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env(values['test_path'])


@pytest.fixture(name="cluster_tests", scope="session")
def environment_cluster():
    values = build_and_up("cluster")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env(values['test_path'])


@pytest.fixture(name="syscollector_tests", scope="session")
def environment_syscollector():
    values = build_and_up("syscollector")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env(values['test_path'])


@pytest.fixture(name="ciscat_tests", scope="session")
def environment_ciscat():
    values = build_and_up("ciscat")
    while values['retries'] < values['max_retries']:
        master_health = check_health()
        if master_health:
            agents_healthy = check_health(node_type='agent', agents=[1, 2, 3])
            if agents_healthy is True:
                time.sleep(10)
                yield
                break
        else:
            values['retries'] += 1
    down_env(values['test_path'])
