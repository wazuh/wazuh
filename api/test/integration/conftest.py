# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from base64 import b64encode

import _pytest.fixtures
import pytest
import requests
import urllib3
import yaml
from py.xml import html

current_path = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_path, 'env')
common_file = os.path.join(current_path, 'common.yaml')
test_logs_path = os.path.join(current_path, '_test_results', 'logs')
docker_log_path = os.path.join(test_logs_path, 'docker.log')
results = dict()

with open(common_file, 'r') as stream:
    common = yaml.safe_load(stream)['variables']
login_url = f"{common['protocol']}://{common['host']}:{common['master_port']}/{common['login_endpoint']}"
basic_auth = f"{common['user']}:{common['pass']}".encode()
login_headers = {'Content-Type': 'application/json',
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
environment_status = None
env_cluster_nodes = ['master', 'worker1', 'worker2']
basic_daemons = ('wazuh-modulesd', 'wazuh-analysisd', 'wazuh-execd', 'wazuh-db', 'wazuh-remoted')
# Administrator account: the test user has restricted permissions in the RBAC suites
admin_login_headers = {'Content-Type': 'application/json',
                       'Authorization': f"Basic {common['basic_auth_context']}"}
agent_names = ['agent1', 'agent2', 'agent3', 'agent4', 'agent5', 'agent6', 'agent7', 'agent8']

standalone_env_mode = 'standalone'
cluster_env_mode = 'cluster'

# Host ports published by env/docker-compose.yml
host_ports = (55000, 55001, 55002, 55010, 1514, 1515)


def pytest_addoption(parser):
    parser.addoption('--nobuild', action='store_false', help='Do not run docker compose build.')


def pytest_collection_modifyitems(items: list):
    """Pytest hook used to add standalone and cluster marks to tests having none of them.

    Parameters
    ----------
    items : list[pytest.Item]
        List of pytest items collected in the pytest session.
    """
    for item in items:
        test_name = item.nodeid.split('::')[0]
        if 'rbac' not in test_name and not {standalone_env_mode, cluster_env_mode} & {m.name for m in item.own_markers}:
            item.add_marker(standalone_env_mode)
            item.add_marker(cluster_env_mode)


def get_token_login_api(headers: dict = login_headers):
    """Get the API token for the test

    Parameters
    ----------
    headers : dict
        Login request headers.

    Returns
    -------
    str
        API token
    """
    response = requests.post(login_url, headers=headers, verify=False)
    if response.status_code == 200:
        return json.loads(response.content.decode())['data']['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")


@pytest.hookimpl(optionalhook=True)
def pytest_tavern_beta_before_every_test_run(test_dict, variables):
    """Disable HTTPS verification warnings."""
    urllib3.disable_warnings()
    variables["test_login_token"] = get_token_login_api()


def port_is_free(port: int) -> bool:
    """Check whether a host port can be bound the way the docker proxy does.

    Parameters
    ----------
    port : int
        Port number.

    Returns
    -------
    bool
        True if the port can be bound, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', port))
        except OSError:
            return False

    return True


def wait_for_free_ports(timeout: int = 60, interval: int = 5) -> list:
    """Wait until the host ports used by the environment can be bound.

    Parameters
    ----------
    timeout : int
        Maximum time in seconds to wait.
    interval : int
        Time interval in seconds between checks.

    Returns
    -------
    list
        Ports that are still in use after the timeout.
    """
    deadline = time.time() + timeout
    while True:
        busy_ports = [port for port in host_ports if not port_is_free(port)]
        if not busy_ports or time.time() >= deadline:
            return busy_ports
        time.sleep(interval)


def get_port_holders(ports: list) -> str:
    """Get the sockets that have the given ports as local port.

    Parameters
    ----------
    ports : list
        Port numbers.

    Returns
    -------
    str
        Matching `ss` output lines.
    """
    try:
        sockets = subprocess.run(['ss', '-H', '-tanp'], stdout=subprocess.PIPE, universal_newlines=True).stdout
    except OSError:
        return 'ss is not available'

    return ''.join(f'{line}\n' for line in sockets.splitlines()
                   if len(line.split()) > 3 and int(line.split()[3].rsplit(':', 1)[-1]) in ports)


def build_and_up(env_mode: str, interval: int = 10, build: bool = True):
    """Build all Docker environments needed for the current test.

    Parameters
    ----------
    env_mode : str
        Indicates the environment to be used in the process.
    interval : int
        Time interval between every build.
    build : bool
        Flag to indicate if images need to be built.
    """
    # Get current branch or tag
    with open('../../../.git/HEAD', 'r') as f:
        ref = f.readline().strip()

    if ref.startswith("ref:"):
        current_branch = ref.split("refs/heads/")[1]
    else:
        current_branch = ref.split("/")[-1]

    if build:
        # Ping the current branch tarball used to build the manager image.
        response = requests.get(f"https://github.com/wazuh/wazuh/tarball/{current_branch}")
        if response.status_code == 404:
            pytest.fail("Current branch tarball doesn't exist")
        elif not response.ok:
            pytest.fail(f"Couldn't obtain branch tarball: {response.reason}")

    busy_ports = wait_for_free_ports()
    if busy_ports:
        pytest.fail(f"Host ports already in use: {busy_ports}\n{get_port_holders(busy_ports)}")

    os.chdir(env_path)
    max_retries = 3
    retries = 0

    with open(docker_log_path, mode='w') as f_docker:
        while retries < max_retries:
            if build:
                build_process = subprocess.Popen(["docker", "compose", "--profile", env_mode,
                    "build", "--build-arg", f"WAZUH_BRANCH={current_branch}",
                    "--build-arg", f"ENV_MODE={env_mode}", "--no-cache"],
                    stdout=f_docker, stderr=subprocess.STDOUT, universal_newlines=True)
                build_process.wait()
            up_process = subprocess.Popen(
                ["docker", "compose", "--profile", env_mode, "up", "-d"],
                env=dict(os.environ, ENV_MODE=env_mode),
                stdout=f_docker, stderr=subprocess.STDOUT, universal_newlines=True)
            up_process.wait()

            if up_process.returncode == 0:
                break

            time.sleep(interval)
            retries += 1

    os.chdir(current_path)

    if up_process.returncode != 0:
        with open(docker_log_path, 'r') as f_docker:
            pytest.fail(f"docker compose up failed {max_retries} times:\n{''.join(f_docker.readlines()[-20:])}")


def down_env(env_mode: str):
    """Stop and remove all Docker containers."""
    os.chdir(env_path)
    with open(docker_log_path, mode='a') as f_docker:
        current_process = subprocess.Popen(["docker", "compose", "--profile", env_mode, "down", "-v"],
                                           stdout=f_docker, stderr=subprocess.STDOUT, universal_newlines=True)
        current_process.wait()
    os.chdir(current_path)


def container_is_healthy(container: str) -> bool:
    """Check whether a container reports a healthy status.

    A container that has no healthcheck state yet (docker inspect fails) is not healthy.

    Parameters
    ----------
    container : str
        Container name.

    Returns
    -------
    bool
        True if the container is healthy, False otherwise.
    """
    try:
        health = subprocess.check_output(
            ['docker', 'inspect', container, '-f', '{{json .State.Health.Status}}'], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return False

    return health.startswith(b'"healthy"')


def check_health(node_type: str = 'manager', agents: list = None,
                 only_check_master_health: bool = False):
    """Check the Wazuh nodes health.

    Parameters
    ----------
    node_type : str
        Can be agent, manager or haproxy-lb.
    agents : list
        List of active agents for the current test
        (only needed if the agents need a custom healthcheck).
    only_check_master_health : bool
        Indicates whether the only node which health needs to be checked is master or not.

    Returns
    -------
    bool
        True if all healthchecks passed, False otherwise.
    """
    if node_type == 'manager':
        nodes_to_check = ['master'] if only_check_master_health else env_cluster_nodes
        for node in nodes_to_check:
            if not container_is_healthy(f'env-wazuh-{node}-1'):
                return False
    elif node_type == 'agent':
        for agent in agents:
            if not container_is_healthy(f'env-wazuh-agent{agent}-1'):
                return False
    elif node_type == 'haproxy-lb':
        if not container_is_healthy('env-haproxy-lb-1'):
            return False
    else:
        raise ValueError(f"Invalid node_type value: '{node_type}'.")

    return True


def check_api_ready(env_mode: str) -> bool:
    """Check that every node answers API requests and has its basic daemons running.

    The status endpoints go through the DAPI daemons check, so they fail while a daemon is failed, restarting or
    stopped. The cluster ones also fail while the node is not connected to the master.

    Parameters
    ----------
    env_mode : str
        Environment mode: standalone or cluster.

    Returns
    -------
    bool
        True if all the nodes are ready, False otherwise.
    """
    try:
        token = get_token_login_api(admin_login_headers)
    except Exception:  # The login fails until the API is up
        return False

    endpoints = ['manager/status']
    if env_mode == cluster_env_mode:
        endpoints += [f'cluster/{node}/status' for node in env_cluster_nodes[1:]]

    for endpoint in endpoints:
        try:
            response = requests.get(f"{common['protocol']}://{common['host']}:{common['master_port']}/{endpoint}",
                                    headers={'Authorization': f'Bearer {token}'}, verify=False, timeout=15)
            daemons = response.json()['data']['affected_items'][0]
        except (requests.RequestException, ValueError, KeyError, IndexError):
            return False
        if response.status_code != 200 or any(daemons.get(daemon) != 'running' for daemon in basic_daemons):
            return False

    return True


def general_procedure(module: str):
    """Copy the configurations files of the specified module to temporal folder.
    The temporal folder will be processed in the environments' entrypoints.

    Parameters
    ----------
    module : str
        Name of the tested module.
    """
    base_content = os.path.join(env_path, 'configurations', 'base')
    module_content = os.path.join(env_path, 'configurations', module)
    tmp_content = os.path.join(env_path, 'configurations', 'tmp')
    with contextlib.suppress(FileNotFoundError):
        shutil.copytree(base_content, tmp_content, dirs_exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        shutil.copytree(module_content, tmp_content, dirs_exist_ok=True)


def change_rbac_mode(rbac_mode: str = 'white'):
    """Modify security.yaml in base folder to change RBAC mode for the current test.

    Parameters
    ----------
    rbac_mode : str
        RBAC Mode: Black (by default: all allowed), White (by default: all denied)
    """
    with open(os.path.join(env_path, 'configurations', 'base', 'manager', 'config', 'api', 'configuration', 'security',
                           'security.yaml'), 'r+') as rbac_conf:
        content = rbac_conf.read()
        rbac_conf.seek(0)
        rbac_conf.write(re.sub(r'rbac_mode: (white|black)', f'rbac_mode: {rbac_mode}', content))


def enable_white_mode():
    """Set white mode for non-rbac integration tests
    """
    with open(os.path.join(env_path, 'configurations', 'base', 'manager', 'config', 'api', 'configuration', 'security',
                           'security.yaml'), '+r') as rbac_conf:
        content = rbac_conf.read()
        rbac_conf.seek(0)
        rbac_conf.write(re.sub(r'rbac_mode: (white|black)', 'rbac_mode: white', content))


def clean_tmp_folder():
    """Remove temporal folder used te configure the environment and set RBAC mode to Black.
    """
    shutil.rmtree(os.path.join(env_path, 'configurations', 'tmp', 'manager'), ignore_errors=True)
    shutil.rmtree(os.path.join(env_path, 'configurations', 'tmp', 'agent'), ignore_errors=True)


def generate_rbac_pair(index: int, permission: dict):
    """Generate a policy and the relationship between it and the testing role.

    Parameters
    ----------
    index : int
        Integer that is used to define a policy and a relationship id that are not used in the database
    permission : dict
        Dict containing the policy information

    Returns
    -------
    list
        List with two SQL sentences, the first creates the policy and the second links it with the testing role
    """
    role_policy_pair = [
        f'INSERT INTO policies VALUES({1000 + index},\'testing{index}\',\'{json.dumps(permission)}\','
        f'\'1970-01-01 00:00:00\');\n',
        f'INSERT INTO roles_policies VALUES({1000 + index},99,{1000 + index},{index},\'1970-01-01 00:00:00\');\n'
    ]

    return role_policy_pair


def rbac_custom_config_generator(module: str, rbac_mode: str):
    """Create a custom SQL script for RBAC integrated tests.
    This is achieved by reading the permissions information in the RBAC folder of the specific module.

    Parameters
    ----------
    module : str
        Name of the tested module
    rbac_mode : str
        RBAC Mode: Black (by default: all allowed), White (by default: all denied)
    """
    custom_rbac_path = os.path.join(env_path, 'configurations', 'tmp', 'manager', 'configuration_files',
                                    'custom_rbac_schema.sql')

    try:
        with open(os.path.join(env_path, 'configurations', 'rbac', module,
                               f'{rbac_mode}_config.yaml')) as configuration_sentences:
            list_custom_policy = yaml.safe_load(configuration_sentences.read())
    except FileNotFoundError:
        return

    sql_sentences = []
    sql_sentences.append('PRAGMA foreign_keys=OFF;\n')
    sql_sentences.append('BEGIN TRANSACTION;\n')
    sql_sentences.append('DELETE FROM user_roles WHERE user_id=99;\n')  # Current DB status: User 99 - Role 1 (Base)
    for index, permission in enumerate(list_custom_policy):
        sql_sentences.extend(generate_rbac_pair(index, permission))
    sql_sentences.append('INSERT INTO user_roles VALUES(99,99,99,0,\'1970-01-01 00:00:00\');')
    sql_sentences.append('COMMIT')

    os.makedirs(os.path.dirname(custom_rbac_path), exist_ok=True)
    with open(custom_rbac_path, 'w') as rbac_config:
        rbac_config.writelines(sql_sentences)


def save_logs(test_name: str):
    """Save API, cluster and Wazuh logs from every cluster node and Wazuh logs from every agent if tests fail.
    Save haproxy-lb log.

    Examples:
    "test_{test_name}-{node/agent}-{log}" -> "test_decoder-worker1-api.log"
    "test_{test_name}-{node/agent}-{log}" -> "test_decoder-agent4-ossec.log"

    Parameters
    ----------
    test_name : str
        Name of the test.
    """
    logs_path = '/var/ossec/logs'

    # Save cluster nodes' logs
    logs = ['api.log', 'cluster.log', 'ossec.log']
    for node in env_cluster_nodes:
        for log in logs:
            try:
                subprocess.check_output(
                    f"docker cp env-wazuh-{node}-1:{os.path.join(logs_path, log)} "
                    f"{os.path.join(test_logs_path, f'test_{test_name}-{node}-{log}')}",
                    shell=True)
            except subprocess.CalledProcessError:
                continue

    # Save agents' logs
    for agent in agent_names:
        try:
            subprocess.check_output(
                f"docker cp env-wazuh-{agent}-1:{os.path.join(logs_path, 'ossec.log')} "
                f"{os.path.join(test_logs_path, f'test_{test_name}-{agent}-ossec.log')}",
                shell=True)
        except subprocess.CalledProcessError:
            continue

    # Save haproxy-lb log
    with open(os.path.join(test_logs_path, f'test_{test_name}-haproxy-lb.log'), mode='w') as f_log:
        current_process = subprocess.Popen(
                ["docker", "logs", "env-haproxy-lb-1"],
                stdout=f_log, stderr=subprocess.STDOUT, universal_newlines=True)
        current_process.wait()


@pytest.fixture(scope='session', autouse=True)
def api_test(request: _pytest.fixtures.SubRequest):
    """This function is responsible for setting up the Docker environment necessary for every test.
    This function will be executed with all the integrated API tests.

    Parameters
    ----------
    request : _pytest.fixtures.SubRequest
        Object that contains information about the current test
    """

    def clean_up_env(env_mode: str):
        """Clean temporary folder, save environment logs and status; and stop and remove all Docker containers."""
        clean_tmp_folder()
        if request.session.testsfailed > 0:
            save_logs(f"{rbac_mode}_{module.split('.')[0]}" if rbac_mode else f"{module.split('.')[0]}")

        # Get the environment current status
        global environment_status
        environment_status = get_health()
        down_env(env_mode)

    # Get the value of the mark indicating the test mode. This value will vary between 'cluster' or 'standalone'
    mode = request.node.config.getoption("-m")
    env_mode = standalone_env_mode if mode == 'standalone' else cluster_env_mode
    os.makedirs(test_logs_path, exist_ok=True)

    # Add clean_up_env as fixture finalizer
    request.addfinalizer(lambda: clean_up_env(env_mode))

    test_filename = request.node.config.args[0].split('_')
    if 'rbac' in test_filename:
        rbac_mode = test_filename[2]
        module = test_filename[3]
    else:
        rbac_mode = None
        module = test_filename[1]

    clean_tmp_folder()

    if rbac_mode:
        change_rbac_mode(rbac_mode)
        rbac_custom_config_generator(module, rbac_mode)
    else:
        enable_white_mode()

    general_procedure(module)
    build_and_up(build=request.config.getoption('--nobuild'), env_mode=env_mode)

    max_retries = 30
    retries = 0

    while retries < max_retries:
        managers_health = check_health(only_check_master_health=env_mode == standalone_env_mode)
        agents_health = check_health(node_type='agent', agents=list(range(1, 9)))
        haproxy_health = check_health(node_type='haproxy-lb')

        # Check if entrypoint was successful
        try:
            error_message = subprocess.check_output(["docker", "exec", "-t", "env-wazuh-master-1", "sh", "-c",
                                                     "cat /entrypoint_error"]).decode().strip()
            pytest.fail(error_message)
        except subprocess.CalledProcessError:
            pass

        if managers_health and agents_health and haproxy_health and check_api_ready(env_mode):
            return

        retries += 1
        time.sleep(10)


def get_health():
    """Get the current status of the integration environment

    Returns
    -------
    str
        Current status
    """
    health = "\nEnvironment final status\n"
    health += subprocess.check_output(
        "docker ps --format 'table {{.Names}}\t{{.RunningFor}}\t{{.Status}}'"
        " --filter name=^env-wazuh",
        shell=True).decode()
    health += '\n'

    return health


# HTML report
class HTMLStyle(html):
    class body(html.body):
        style = html.Style(background_color='#F0F0EE')

    class table(html.table):
        style = html.Style(border='2px solid #005E8C', margin='16px 0px', color='#005E8C',
                           font_size='15px')

    class colored_td(html.td):
        style = html.Style(color='#005E8C', padding='5px', border='2px solid #005E8C', text_align='left',
                           white_space='pre-wrap', font_size='14px')

    class td(html.td):
        style = html.Style(padding='5px', border='2px solid #005E8C', text_align='left',
                           white_space='pre-wrap', font_size='14px')

    class th(html.th):
        style = html.Style(color='#0094ce', padding='5px', border='2px solid #005E8C', text_align='left',
                           font_weight='bold', font_size='15px')

    class h1(html.h1):
        style = html.Style(color='#0094ce')

    class h2(html.h2):
        style = html.Style(color='#0094ce')

    class h3(html.h3):
        style = html.Style(color='#0094ce')


@pytest.hookimpl(optionalhook=True)
def pytest_html_results_table_header(cells):
    cells.insert(2, html.th('Stages'))
    # Remove links
    cells.pop()


@pytest.hookimpl(optionalhook=True)
def pytest_html_results_table_row(report, cells):
    try:
        # Replace the original full name for the test case name
        cells[1] = HTMLStyle.colored_td(report.test_name)
        # Insert test stages
        cells.insert(2, HTMLStyle.colored_td(report.stages))
        # Replace duration with the colored_td style
        cells[3] = HTMLStyle.colored_td(cells[3][0])
        # Remove link rows
        cells.pop()
    except AttributeError:
        pass


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Define HTML style
    pytest_html = item.config.pluginmanager.getplugin('html')
    pytest_html.html.body = HTMLStyle.body
    pytest_html.html.table = HTMLStyle.table
    pytest_html.html.th = HTMLStyle.th
    pytest_html.html.td = HTMLStyle.td
    pytest_html.html.h1 = HTMLStyle.h1
    pytest_html.html.h2 = HTMLStyle.h2
    pytest_html.html.h3 = HTMLStyle.h3

    outcome = yield
    report = outcome.get_result()

    # Store the test case name
    report.test_name = item.spec['test_name']

    # Store the test case stages
    report.stages = []
    for stage in item.spec['stages']:
        report.stages.extend((stage['name'], html.br()))

    if report.location[0] not in results:
        results[report.location[0]] = {'passed': 0, 'failed': 0, 'skipped': 0, 'xfailed': 0, 'error': 0}

    if report.when == 'call':
        if report.longrepr is not None and report.longreprtext.split()[-1] == 'XFailed':
            results[report.location[0]]['xfailed'] += 1
        else:
            results[report.location[0]][report.outcome] += 1

    elif report.outcome == 'failed':
        results[report.location[0]]['error'] += 1

    if report.when == 'setup' and \
            report.longrepr and ('api_test did not yield a value' in report.longrepr.reprcrash.message or
                                 'StopIteration' in report.longrepr.reprcrash.message):
        report.sections.append(('Environment section', environment_status))


@pytest.hookimpl(optionalhook=True)
def pytest_html_results_summary(prefix, summary, postfix):
    postfix.extend([HTMLStyle.table(
        html.thead(
            html.tr([
                HTMLStyle.th("Tests"),
                HTMLStyle.th("Success"),
                HTMLStyle.th("Failed"),
                HTMLStyle.th("XFail"),
                HTMLStyle.th("Error")]
            ),
        ),
        [html.tbody(
            html.tr([
                HTMLStyle.td(k),
                HTMLStyle.td(v['passed']),
                HTMLStyle.td(v['failed']),
                HTMLStyle.td(v['xfailed']),
                HTMLStyle.td(v['error']),
            ])
        ) for k, v in results.items()])])


@pytest.fixture(scope='function', autouse=True)
def big_events_payload() -> list:
    """Return a payload with a number of events larger than the maximum allowed.

    Returns
    -------
    list
        Events payload.
    """
    return [f"Event {i}" for i in range(101)]


@pytest.fixture(scope='function', autouse=True)
def max_size_event() -> str:
    """Return an event with the max size allowed.

    Returns
    -------
    str
        The max size event.
    """
    return " ".join(str(i) for i in range(12772))


@pytest.fixture(scope='function', autouse=True)
def large_event() -> str:
    """Return an event with the size larger than the maximum allowed.

    Returns
    -------
    str
        The larger event.
    """
    return " ".join(str(i) for i in range(12773))
