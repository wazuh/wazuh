import pytest
import time
import os
import subprocess

# @pytest.fixture(name="agents_test", scope="session")
# def fix_test():
#     os.chdir("./agent_enviroment")
#     os.system("docker-compose up --build -d")
#     time.sleep(60)
#     print('Entorno configurado - Comienzan los test')
#     yield
#     print('Test finalizados')
#     os.system("docker-compose down")
#
#
# @pytest.fixture(name="agent_tests", scope="session")
# def fix_test():
#     here = os.path.abspath(os.path.dirname(__file__))
#     test_path = os.path.join(here, 'environment', 'agents', 'docker-compose.yml')
#     os.system("docker-compose -f {} up --build -d".format(test_path))
#     time.sleep(90)
#     yield
#     os.system("docker-compose -f {} down".format(test_path))


@pytest.fixture(name="ciscat_tests", scope="session")
def fix_test():
    here = os.path.abspath(os.path.dirname(__file__))
    test_path = os.path.join(here, 'environment', 'ciscat', 'docker-compose.yml')
    os.system("docker-compose -f {0} up --build -d --scale wazuh-agent-ciscat=3".format(test_path))
    time.sleep(150)
    yield
    os.system("docker-compose -f {0} down".format(test_path))


@pytest.fixture(name="default_tests", scope="session")
def fix_test():
    here = os.path.abspath(os.path.dirname(__file__))
    test_path = os.path.join(here, 'environment', 'default', 'docker-compose.yml')
    os.system("docker-compose -f {0} up --build -d".format(test_path))
    max_retries = 30
    interval = 10  # seconds
    retries = 0
    while retries < max_retries:
        time.sleep(interval)
        health = subprocess.check_output(
            "docker inspect default_wazuh-master_1 -f '{{json .State.Health.Status}}'", shell=True)
        if health.startswith(b'"healthy"'):
            yield
            retries = max_retries
        else:
            retries += 1
    os.system("docker-compose -f {0} down".format(test_path))


@pytest.fixture(name="ciscat_tests", scope="session")
def fix_test():
    here = os.path.abspath(os.path.dirname(__file__))
    test_path = os.path.join(here, 'environment', 'default', 'docker-compose.yml')
    os.system("docker-compose -f {0} up --build -d".format(test_path))
    max_retries = 30
    interval = 10  # seconds
    retries = 0
    while retries < max_retries:
        time.sleep(interval)
        master_health = subprocess.check_output(
            "docker inspect default_wazuh-master_1 -f '{{json .State.Health.Status}}'", shell=True)
        if master_health.startswith(b'"healthy"'):
            agents_healthy = True
            for i in [1, 2, 3]:
                state_str = "'{{json .State.Health.Status}}'"
                health = subprocess.check_output(f"docker inspect default_wazuh-agent{i}_1 -f {state_str}", shell=True)
                if not health.startswith(b'"healthy"'):
                    agents_healthy = False
                    break
            if agents_healthy is True:
                yield
                retries = max_retries
        else:
            retries += 1
    os.system("docker-compose -f {0} down".format(test_path))
