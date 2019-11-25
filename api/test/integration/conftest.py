import pytest
import time
import os
import subprocess


def build_and_up(env: str):
    pwd = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'env')
    os.chdir(pwd)
    values = {
        'interval': 10,
        'max_retries': 30,
        'retries': 0
    }
    current_process = subprocess.Popen(
        ["docker-compose", "build", "--build-arg", "ENVIRONMENT={}".format(env)])
    current_process.wait()
    current_process = subprocess.Popen(["docker-compose", "up", "-d"])
    current_process.wait()

    return values


def down_env():
    pwd = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'env')
    os.chdir(pwd)
    current_process = subprocess.Popen(["docker-compose", "down", "-t", "0"])
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
                f"docker inspect env_wazuh-agent{agent}_1 -f '{{{{json .State.Health.Status}}}}'", shell=True)
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
    down_env()


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
    down_env()


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
    down_env()


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
    down_env()


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
    down_env()


@pytest.fixture(name="ciscat_tests", scope="session")
def environment_ciscat():
    values = build_and_up("ciscat")
    while values['retries'] < values['max_retries']:
        master_health = check_health()
        if master_health:
            agents_healthy = check_health(node_type='agent', agents=[1, 2, 3])
            if agents_healthy:
                time.sleep(10)
                yield
                break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="sca_tests", scope="session")
def environment_sca():
    values = build_and_up("sca")
    while values['retries'] < values['max_retries']:
        master_health = check_health()
        if master_health:
            agents_healthy = check_health(node_type='agent', agents=[1, 2, 3])
            if agents_healthy:
                time.sleep(10)
                yield
                break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="syscheck_tests", scope="session")
def environment_sca():
    values = build_and_up("syscheck")
    while values['retries'] < values['max_retries']:
        master_health = check_health()
        if master_health:
            agents_healthy = check_health(node_type='agent', agents=[1, 2, 3])
            if agents_healthy:
                time.sleep(10)
                yield
                break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="security_white_rbac_tests", scope="session")
def environment_white_security_rbac():
    values = build_and_up("security_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="security_black_rbac_tests", scope="session")
def environment_black_security_rbac():
    values = build_and_up("security_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="agents_white_rbac_tests", scope="session")
def environment_white_security_rbac():
    values = build_and_up("agents_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="agents_black_rbac_tests", scope="session")
def environment_black_security_rbac():
    values = build_and_up("agents_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="ciscat_white_rbac_tests", scope="session")
def environment_white_ciscat_rbac():
    values = build_and_up("ciscat_white_rbac")
    while values['retries'] < values['max_retries']:
        master_health = check_health()
        if master_health:
            agents_healthy = check_health(node_type='agent', agents=[1, 2, 3])
            if agents_healthy:
                time.sleep(10)
                yield
                break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="ciscat_black_rbac_tests", scope="session")
def environment_black_ciscat_rbac():
    values = build_and_up("ciscat_black_rbac")
    while values['retries'] < values['max_retries']:
        master_health = check_health()
        if master_health:
            agents_healthy = check_health(node_type='agent', agents=[1, 2, 3])
            if agents_healthy:
                time.sleep(10)
                yield
                break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="decoders_white_rbac_tests", scope="session")
def environment_white_decoders_rbac():
    values = build_and_up("decoders_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="decoders_black_rbac_tests", scope="session")
def environment_black_decoders_rbac():
    values = build_and_up("decoders_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="rules_white_rbac_tests", scope="session")
def environment_white_rules_rbac():
    values = build_and_up("rules_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="rules_black_rbac_tests", scope="session")
def environment_black_rules_rbac():
    values = build_and_up("rules_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="syscollector_white_rbac_tests", scope="session")
def environment_white_syscollector_rbac():
    values = build_and_up("syscollector_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="syscollector_black_rbac_tests", scope="session")
def environment_black_syscollector_rbac():
    values = build_and_up("syscollector_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="active-response_white_rbac_tests", scope="session")
def environment_white_active_response_rbac():
    values = build_and_up("active-response_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="active-response_black_rbac_tests", scope="session")
def environment_black_active_response_rbac():
    values = build_and_up("active-response_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="overview_white_rbac_tests", scope="session")
def environment_white_overview_rbac():
    values = build_and_up("overview_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="overview_black_rbac_tests", scope="session")
def environment_black_overview_rbac():
    values = build_and_up("overview_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="lists_white_rbac_tests", scope="session")
def environment_white_lists_rbac():
    values = build_and_up("lists_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="lists_black_rbac_tests", scope="session")
def environment_black_lists_rbac():
    values = build_and_up("lists_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="sca_white_rbac_tests", scope="session")
def environment_white_sca_rbac():
    values = build_and_up("sca_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="sca_black_rbac_tests", scope="session")
def environment_black_sca_rbac():
    values = build_and_up("sca_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="syscheck_white_rbac_tests", scope="session")
def environment_white_syscheck_rbac():
    values = build_and_up("syscheck_white_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()


@pytest.fixture(name="syscheck_black_rbac_tests", scope="session")
def environment_black_syscheck_rbac():
    values = build_and_up("syscheck_black_rbac")
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(10)
            yield
            break
        else:
            values['retries'] += 1
    down_env()
