import json
import os
import re
import shutil
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
test_logs_path = os.path.join(current_path, '_test_results', 'logs')
docker_log_path = os.path.join(test_logs_path, 'docker.log')
results = dict()

with open('common.yaml', 'r') as stream:
    common = yaml.safe_load(stream)['variables']
login_url = f"{common['protocol']}://{common['host']}:{common['port']}/{common['login_endpoint']}"
basic_auth = f"{common['user']}:{common['pass']}".encode()
login_headers = {'Content-Type': 'application/json',
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
environment_status = None
env_cluster_nodes = ['master', 'worker1', 'worker2']
agent_names = ['agent1', 'agent2', 'agent3', 'agent4', 'agent5', 'agent6', 'agent7', 'agent8']

standalone_env_mode = 'standalone'
cluster_env_mode = 'cluster'


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


def get_token_login_api():
    """Get the API token for the test

    Returns
    -------
    str
        API token
    """
    response = requests.post(login_url, headers=login_headers, verify=False)
    if response.status_code == 200:
        return json.loads(response.content.decode())['data']['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")


def pytest_tavern_beta_before_every_test_run(test_dict, variables):
    """Disable HTTPS verification warnings."""
    urllib3.disable_warnings()
    variables["test_login_token"] = get_token_login_api()


def build_and_up(env_mode: str, interval: int = 10, interval_build_env: int = 10,
                 build: bool = True) -> dict:
    """Build all Docker environments needed for the current test.

    Parameters
    ----------
    env_mode : str
        Indicates the environment to be used in the process.
    interval : int
        Time interval between every healthcheck.
    interval_build_env : int
        Time interval between every docker environment healthcheck.
    build : bool
        Flag to indicate if images need to be built.

    Returns
    -------
    dict
        Dict with healthchecks parameters.
    """
    os.chdir(env_path)
    values = {
        'interval': interval,
        'max_retries': 90,
        'retries': 0
    }
    values_build_env = {
        'interval': interval_build_env,
        'max_retries': 3,
        'retries': 0
    }
    # Get current branch
    current_branch = '/'.join(open('../../../../.git/HEAD', 'r').readline().split('/')[2:])
    os.makedirs(test_logs_path, exist_ok=True)
    with open(docker_log_path, mode='w') as f_docker:
        while values_build_env['retries'] < values_build_env['max_retries']:
            if build:
                current_process = subprocess.Popen(["docker", "compose", "--profile", env_mode,
                    "build", "--build-arg", f"WAZUH_BRANCH={current_branch}", 
                    "--build-arg", f"ENV_MODE={env_mode}",
                    "--no-cache"],
                    stdout=f_docker, stderr=subprocess.STDOUT, universal_newlines=True)
                current_process.wait()
            current_process = subprocess.Popen(
                ["docker", "compose", "--profile", env_mode, "up", "-d"],
                env=dict(os.environ, ENV_MODE=env_mode),
                stdout=f_docker, stderr=subprocess.STDOUT, universal_newlines=True)
            current_process.wait()

            if current_process.returncode == 0:
                time.sleep(values_build_env['interval'])
                break
            else:
                time.sleep(values_build_env['interval'])
                values_build_env['retries'] += 1
    os.chdir(current_path)

    return values


def down_env():
    """Stop and remove all Docker containers."""
    os.chdir(env_path)
    with open(docker_log_path, mode='a') as f_docker:
        current_process = subprocess.Popen(["docker", "compose",
                                            "down", "--remove-orphans", "-t0" ],
                                           stdout=f_docker,
                                           stderr=subprocess.STDOUT, universal_newlines=True)
        current_process.wait()
    os.chdir(current_path)


def check_health(interval: int = 10, node_type: str = 'manager', agents: list = None,
                 only_check_master_health: bool = False):
    """Check the Wazuh nodes health.

    Parameters
    ----------
    interval : int
        Time interval between every healthcheck.
    node_type : str
        Can be agent, manager or nginx-lb.
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
    time.sleep(interval)
    if node_type == 'manager':
        nodes_to_check = ['master'] if only_check_master_health else env_cluster_nodes
        for node in nodes_to_check:
            health = subprocess.check_output(
                f"docker inspect env-wazuh-{node}-1 -f '{{{{json .State.Health.Status}}}}'",
                shell=True)
            if not health.startswith(b'"healthy"'):
                return False
    elif node_type == 'agent':
        for agent in agents:
            health = subprocess.check_output(
                f"docker inspect env-wazuh-agent{agent}-1 -f '{{{{json .State.Health.Status}}}}'",
                shell=True)
            if not health.startswith(b'"healthy"'):
                return False
    elif node_type == 'nginx-lb':
        health = subprocess.check_output(
            f"docker inspect env-nginx-lb-1 -f '{{{{json .State.Health.Status}}}}'", shell=True)
        if not health.startswith(b'"healthy"'):
            return False
    else:
        raise ValueError(f"Invalid node_type value: '{node_type}'.")

    return True


def general_procedure(module: str):
    """Copy the configurations files of the specified module to temporal folder.
    The temporal folder will be processed in the environments' entrypoints.

    Parameters
    ----------
    module : str
        Name of the tested module.
    """
    base_content = os.path.join(env_path, 'configurations', 'base', '*')
    module_content = os.path.join(env_path, 'configurations', module, '*')
    tmp_content = os.path.join(env_path, 'configurations', 'tmp')
    os.makedirs(tmp_content, exist_ok=True)
    os.popen(f'cp -rf {base_content} {tmp_content}').close()
    os.popen(f'cp -rf {module_content} {tmp_content}').close()


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
        rbac_conf.write(re.sub(r'rbac_mode: (white|black)', f'rbac_mode: white', content))


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
    Save nginx-lb log.

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

    # Save nginx-lb log
    with open(os.path.join(test_logs_path, f'test_{test_name}-nginx-lb.log'), mode='w') as f_log:
        current_process = subprocess.Popen(
                ["docker", "logs", "env-nginx-lb-1"],
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

    def clean_up_env():
        """Clean temporary folder, save environment logs and status; and stop and remove all Docker containers."""
        clean_tmp_folder()
        if request.session.testsfailed > 0:
            save_logs(f"{rbac_mode}_{module.split('.')[0]}" if rbac_mode else f"{module.split('.')[0]}")

        # Get the environment current status
        global environment_status
        environment_status = get_health()
        down_env()

    # Get the value of the mark indicating the test mode. This value will vary between 'cluster' or 'standalone'
    mode = request.node.config.getoption("-m")
    env_mode = standalone_env_mode if mode == 'standalone' else cluster_env_mode

    # Add clean_up_env as fixture finalizer
    request.addfinalizer(clean_up_env)

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
    values = build_and_up(interval=10, build=request.config.getoption('--nobuild'), env_mode=env_mode)

    while values['retries'] < values['max_retries']:
        managers_health = check_health(interval=values['interval'],
                                       only_check_master_health=env_mode == standalone_env_mode)
        agents_health = check_health(interval=values['interval'], node_type='agent', agents=list(range(1, 9)))
        nginx_health = check_health(interval=values['interval'], node_type='nginx-lb')
        # Check if entrypoint was successful
        try:
            error_message = subprocess.check_output(["docker", "exec", "-t",
                                                     "env-wazuh-master-1", "sh", "-c",
                                                     "cat /entrypoint_error"]).decode().strip()
            pytest.fail(error_message)
        except subprocess.CalledProcessError:
            pass

        if managers_health and agents_health and nginx_health:
            time.sleep(values['interval'])
            return
        else:
            values['retries'] += 1


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


def pytest_html_results_table_header(cells):
    cells.insert(2, html.th('Stages'))
    # Remove links
    cells.pop()


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


@pytest.fixture
def big_events_payload() -> list:
    """Return a payload with a number of events larger than the maximum allowed.

    Returns
    -------
    list
        Events payload.
    """
    return [f"Event {i}" for i in range(101)]


@pytest.fixture
def max_size_event() -> str:
    """Return an event with the max size allowed.

    Returns
    -------
    str
        The max size event.
    """
    return " ".join(str(i) for i in range(12772))


@pytest.fixture
def large_event() -> str:
    """Return an event with the size larger than the maximum allowed.

    Returns
    -------
    str
        The larger event.
    """
    return " ".join(str(i) for i in range(12773))
