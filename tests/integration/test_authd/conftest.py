import shutil
import pytest
import time
import os
import yaml

from wazuh_testing import logger
from wazuh_testing.tools import LOG_FILE_PATH, CLIENT_KEYS_PATH, API_LOG_FILE_PATH
from wazuh_testing.wazuh_db import insert_agent_in_db, clean_agents_from_db
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, AUTHD_DETECTOR_PREFIX
from wazuh_testing.tools.configuration import write_wazuh_conf, get_wazuh_conf, set_section_wazuh_conf,\
                                              load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.authd import DAEMON_NAME
from wazuh_testing.api import get_api_details_dict
from wazuh_testing.tools.wazuh_manager import remove_agents
from wazuh_testing.modules.api import event_monitor as evm


AUTHD_STARTUP_TIMEOUT = 30


def truncate_client_keys_file():
    """
    Cleans any previous key in client.keys file.
    """
    try:
        control_service("stop", DAEMON_NAME)
    except Exception:
        pass
    truncate_file(CLIENT_KEYS_PATH)


@pytest.fixture(scope='function')
def clean_client_keys_file_function():
    """
    Cleans any previous key in client.keys file at function scope.
    """
    truncate_client_keys_file()


@pytest.fixture(scope='module')
def clean_client_keys_file_module():
    """
    Cleans any previous key in client.keys file at module scope.
    """
    truncate_client_keys_file()


@pytest.fixture(scope='module')
def restart_authd(get_configuration):
    """
    Restart Authd.
    """
    truncate_file(LOG_FILE_PATH)
    control_service("restart", daemon=DAEMON_NAME)


@pytest.fixture(scope='function')
def restart_authd_function():
    """
    Restart Authd.
    """
    truncate_file(LOG_FILE_PATH)
    control_service("restart", daemon=DAEMON_NAME)


@pytest.fixture(scope='function')
def stop_authd_function():
    """
    Stop Authd.
    """
    control_service("stop", daemon=DAEMON_NAME)


@pytest.fixture(scope='module')
def wait_for_authd_startup_module(get_configuration):
    """Wait until authd has begun"""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT,
                      callback=make_callback('Accepting connections on port 1515', prefix=AUTHD_DETECTOR_PREFIX,
                                             escape=True),
                      error_message='Authd doesn´t started correctly.')


@pytest.fixture(scope='function')
def wait_for_authd_startup_function():
    """Wait until authd has begun with function scope"""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT,
                      callback=make_callback('Accepting connections on port 1515', prefix=AUTHD_DETECTOR_PREFIX,
                                             escape=True),
                      error_message='Authd doesn´t started correctly.')


@pytest.fixture(scope='module')
def tear_down():
    """
    Roll back the daemon and client.keys state after the test ends.
    """
    yield
    # Stop Wazuh
    control_service('stop')
    truncate_file(CLIENT_KEYS_PATH)
    control_service('start')


def create_force_config_block(param, config_path):
    """
    Creates a temporal config file.
    """
    temp = os.path.join(os.path.dirname(config_path), 'temp.yaml')

    with open(config_path, 'r') as conf_file:
        temp_conf_file = yaml.safe_load(conf_file)
        for elem in param:
            temp_conf_file[0]['sections'][0]['elements'].append(elem)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


@pytest.fixture(scope='function')
def format_configuration(get_current_test_case, request):
    """
    Get configuration block from current test case
    """
    test_name = request.node.originalname
    configuration = get_current_test_case.get('configuration', {})

    # Configuration for testing
    temp = create_force_config_block(configuration, request.module.configurations_path)
    conf = load_wazuh_configurations(temp, test_name)
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])

    return test_config


@pytest.fixture(scope='function')
def override_authd_force_conf(format_configuration):
    """
    Re-writes Wazuh configuration file with new configurations from the test case.
    """
    # Save current configuration
    backup_config = get_wazuh_conf()

    # Set new configuration
    write_wazuh_conf(format_configuration)

    yield

    # Restore previous configuration
    write_wazuh_conf(backup_config)


@pytest.fixture(scope='module')
def get_api_details():
    return get_api_details_dict


@pytest.fixture(scope='module')
def restart_api_module():
    # Stop Wazuh and Wazuh API
    control_service('stop')
    truncate_file(API_LOG_FILE_PATH)
    control_service('start')


@pytest.fixture(scope='module')
def wait_for_start_module():
    """Monitor the API log file to detect whether it has been started or not."""
    evm.check_api_start_log()


@pytest.fixture(scope='function')
def insert_pre_existent_agents(get_current_test_case, stop_authd_function):
    agents = get_current_test_case.get('pre_existent_agents', [])
    time_now = int(time.time())
    try:
        keys_file = open(CLIENT_KEYS_PATH, 'w')
    except IOError as exception:
        raise exception

    clean_agents_from_db()

    for agent in agents:
        id = agent['id'] if 'id' in agent else '001'
        name = agent['name'] if 'name' in agent else f"TestAgent{id}"
        ip = agent['ip'] if 'ip' in agent else 'any'
        key = agent['key'] if 'key' in agent else 'TopSecret'
        connection_status = agent['connection_status'] if 'connection_status' in agent else 'never_connected'
        if 'disconnection_time' in agent and 'delta' in agent['disconnection_time']:
            disconnection_time = time_now + agent['disconnection_time']['delta']
        elif 'disconnection_time' in agent and 'value' in agent['disconnection_time']:
            disconnection_time = agent['disconnection_time']['value']
        else:
            disconnection_time = time_now
        if 'registration_time' in agent and 'delta' in agent['registration_time']:
            registration_time = time_now + agent['registration_time']['delta']
        elif 'registration_time' in agent and 'value' in agent['registration_time']:
            registration_time = agent['registration_time']['value']
        else:
            registration_time = time_now

        # Write agent in client.keys
        keys_file.write(f"{id} {name} {ip} {key}\n")

        # Write agent in global.db
        insert_agent_in_db(id, name, ip, registration_time, connection_status, disconnection_time)

    keys_file.close()


@pytest.fixture(scope='function')
def copy_tmp_script(request):
    """
    Copy the script named 'script_filename' and found in 'script_path' to a temporary folder for use in the test.
    """
    try:
        script_filename = getattr(request.module, 'script_filename')
    except AttributeError as script_filename_not_set:
        logger.debug('script_filename is not set')
        raise script_filename_not_set

    try:
        script_path = getattr(request.module, 'script_path')
    except AttributeError as script_path_not_set:
        logger.debug('script_path is not set')
        raise script_path_not_set

    shutil.copy(os.path.join(script_path, script_filename), os.path.join("/tmp", script_filename))


@pytest.fixture(scope='function')
def delete_agents():

    yield

    remove_agents('all', 'api')
