import json
import os
import re
import shutil
import subprocess
import time
from base64 import b64encode

import pytest
import requests
import urllib3
import yaml

current_path = os.path.dirname(os.path.abspath(__file__))


with open('common.yaml', 'r') as stream:
    common = yaml.safe_load(stream)['variables']
login_url = f"{common['protocol']}://{common['host']}:{common['port']}/{common['version']}{common['login_endpoint']}"
basic_auth = f"{common['user']}:{common['pass']}".encode()
login_headers = {'Content-Type': 'application/json',
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_token_login_api():
    response = requests.get(login_url, headers=login_headers, verify=False)
    if response.status_code == 200:
        return json.loads(response.content.decode())['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")


def pytest_tavern_beta_before_every_test_run(test_dict, variables):
    # Disable HTTPS verification warnings
    urllib3.disable_warnings()
    variables["test_login_token"] = get_token_login_api()


def build_and_up():
    pwd = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'env')
    os.chdir(pwd)
    values = {
        'interval': 10,
        'max_retries': 30,
        'retries': 0
    }
    current_process = subprocess.Popen(["docker-compose", "build"])
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


def create_tmp_folders():
    os.makedirs(os.path.join(current_path, 'env', 'configurations', 'tmp', 'manager'), exist_ok=True)
    os.makedirs(os.path.join(current_path, 'env', 'configurations', 'tmp', 'agent'), exist_ok=True)


def general_procedure(module):
    folder_content = os.path.join(current_path, 'env', 'configurations', module, '*')
    tmp_content = os.path.join(current_path, 'env', 'configurations', 'tmp')
    os.makedirs(tmp_content, exist_ok=True)
    os.popen(f'cp -rf {folder_content} {tmp_content}')
    healthcheck_procedure(module)


def healthcheck_procedure(module):
    manager_folder = os.path.join(current_path, 'env', 'configurations', module, 'manager', 'healthcheck')
    agent_folder = os.path.join(current_path, 'env', 'configurations', module, 'agent', 'healthcheck')
    base_folder = os.path.join(current_path, 'env', 'configurations', 'base', 'wazuh-master', 'healthcheck')
    tmp_content = os.path.join(current_path, 'env', 'configurations', 'tmp')

    os.popen(f'cp -rf {base_folder} {os.path.join(tmp_content, "manager")}')
    if os.path.exists(manager_folder):
        os.popen(f'cp -rf {manager_folder} {os.path.join(tmp_content, "manager")}')
    elif os.path.exists(agent_folder):
        os.popen(f'cp -rf {agent_folder} {os.path.join(tmp_content, "agent")}')


def change_rbac_mode(rbac_mode):
    with open(os.path.join(current_path, 'env', 'configurations', 'base', 'wazuh-master', 'api.yaml'),
              'r+') as api_conf:
        content = api_conf.read()
        api_conf.seek(0)
        api_conf.write(re.sub(r'mode: (white|black)', f'mode: {rbac_mode}', content))


def clear_tmp_folder():
    with open(os.path.join(current_path, 'env', 'configurations', 'base', 'wazuh-master', 'api.yaml'),
              'r+') as api_conf:
        content = api_conf.read()
        api_conf.seek(0)
        api_conf.write(re.sub(r'mode: (white|black)', f'mode: black', content))

    shutil.rmtree(os.path.join(current_path, 'env', 'configurations', 'tmp'), ignore_errors=True)


def generate_rbac_pair(index, permission):
    role_policy_pair = [
        f'INSERT INTO policies VALUES({99 + index},\'testing{index}\',\'{json.dumps(permission)}\',\'1970-01-01 00:00:00\');\n',
        f'INSERT INTO roles_policies VALUES({99 + index},99,{99 + index},{index},\'1970-01-01 00:00:00\');\n'
    ]

    return role_policy_pair


def rbac_custom_config_generator(module, rbac_mode, custom_rbac_path):
    with open(os.path.join(current_path, 'env', 'configurations', 'rbac', module,
                           f'{rbac_mode}_config.yaml')) as configuration_sentences:
        list_custom_policy = yaml.safe_load(configuration_sentences.read())

    sql_sentences = list()
    sql_sentences.append('PRAGMA foreign_keys=OFF;\n')
    sql_sentences.append('BEGIN TRANSACTION;\n')
    sql_sentences.append('DELETE FROM roles_policies WHERE role_id=99;\n')
    for index, permission in enumerate(list_custom_policy):
        sql_sentences.extend(generate_rbac_pair(index, permission))
    sql_sentences.append('COMMIT')

    os.makedirs(os.path.dirname(custom_rbac_path), exist_ok=True)
    with open(custom_rbac_path, 'w') as rbac_config:
        rbac_config.writelines(sql_sentences)


@pytest.fixture(scope='session', autouse=True)
def api_test(request):
    test_filename = request.node.config.args[0].split('_')
    if 'rbac' in test_filename:
        rbac_mode = test_filename[2]
        module = test_filename[3]
    else:
        rbac_mode = None
        module = test_filename[1]
    create_tmp_folders()
    general_procedure(module)
    if rbac_mode:
        custom_rbac_path = os.path.join(current_path, 'env', 'configurations', 'tmp',
                                        'manager', 'custom_rbac_schema.sql')
        change_rbac_mode(rbac_mode)
        rbac_custom_config_generator(module, rbac_mode, custom_rbac_path)

    values = build_and_up()
    while values['retries'] < values['max_retries']:
        health = check_health()
        if health:
            time.sleep(values['interval'])
            yield
            break
        else:
            values['retries'] += 1
    clear_tmp_folder()
    down_env()
