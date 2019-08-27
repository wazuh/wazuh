import pytest
import time
import os
import subprocess


def build_and_up(test_path: str, env: str):
    current_process = subprocess.Popen(
        ["docker-compose", "-f", test_path, "build", "--build-arg", "ENVIRONMENT={}".format(env)])
    current_process.wait()
    current_process = subprocess.Popen(["docker-compose", "-f", test_path, "up", "-d"])
    current_process.wait()


def down_env(test_path: str):
    current_process = subprocess.Popen(["docker-compose", "-f", test_path, "down"])
    current_process.wait()


@pytest.fixture(scope="session")
def environment(request):
    marks = request.node.own_markers
    mark_names = [m.name for m in marks]
    pwd = os.path.abspath(os.path.dirname(__file__))
    test_path = os.path.join(pwd, 'env', 'docker-compose.yml')
    env = None
    if 'base' in mark_names:
        env = 'base'
    elif 'security' in mark_names:
        env = 'security'
    elif 'manager' in mark_names:
        env = 'manager'
    elif 'syscollector' in mark_names:
        env = 'syscollector'
    if env:
        build_and_up(test_path, env)
        max_retries = 30
        interval = 10  # seconds
        retries = 0
        while retries < max_retries:
            time.sleep(interval)
            health = subprocess.check_output(
                "docker inspect env_wazuh-master_1 -f '{{json .State.Health.Status}}'", shell=True)
            if health.startswith(b'"healthy"'):
                yield
                retries = max_retries
            else:
                retries += 1
        down_env(test_path)


@pytest.fixture(name="ciscat_tests", scope="session")
def default_with_ciscat_environment():
    pwd = os.path.abspath(os.path.dirname(__file__))
    test_path = os.path.join(pwd, 'env', 'docker-compose.yml')
    build_and_up(test_path, "ciscat")
    max_retries = 30
    interval = 10  # seconds
    retries = 0
    while retries < max_retries:
        time.sleep(interval)
        master_health = subprocess.check_output(
            "docker inspect env_wazuh-master_1 -f '{{json .State.Health.Status}}'", shell=True)
        if master_health.startswith(b'"healthy"'):
            agents_healthy = True
            for i in [1, 2, 3]:
                state_str = "'{{json .State.Health.Status}}'"
                health = subprocess.check_output('docker inspect env_wazuh-agent{}_1 -f {}'.format(
                    i, state_str), shell=True)
                if not health.startswith(b'"healthy"'):
                    agents_healthy = False
                    break
            if agents_healthy is True:
                yield
                retries = max_retries
        else:
            retries += 1
    down_env(test_path)
